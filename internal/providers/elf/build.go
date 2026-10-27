package elf

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	reeelf "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/elf"
)

// Payload table shares, in percent. Shares are applied to the budget that is
// still unspent, so a table that uses less leaves the remainder to later
// tables. The percentages sum to 100.
const (
	shareSections    = 25
	shareSegments    = 10
	shareSymbols     = 30
	shareRelocations = 25
	shareNotes       = 5
	shareComments    = 5
)

const (
	sectionTypeDynamic    = 6
	sectionFlagCompressed = 0x800

	// maxNoteHexBytes bounds an inline note descriptor. Larger descriptors are
	// represented by their digest so a single note stays below the evidence
	// string limit.
	maxNoteHexBytes = 4 << 10
)

// buildPayload projects a parsed file into the ree.payload.elf/1 shape.
//
// Tables are emitted in artifact order and trimmed to a prefix when the
// payload budget is exhausted. Read failures propagate; per-entry defects and
// configured limits become adapter limitations or unknowns.
func buildPayload(file *reeelf.File, opts Options, notes *collector) (Payload, error) {
	payload := Payload{
		Schema:      PayloadSchema,
		Header:      payloadHeader(file),
		Sections:    []PayloadSection{},
		Segments:    []PayloadSegment{},
		Symbols:     []PayloadSymbol{},
		Relocations: []PayloadRelocation{},
		Notes:       []PayloadNote{},
		Comments:    []string{},
	}

	for _, limitation := range file.Limitations {
		notes.addLimitation(limitation)
	}

	budget := newPayloadBudget(opts.PayloadBytes)
	budget.reserve(jsonSize(payload.Header) + 1)

	hasher := newContentHasher(file, opts.ContentBytes)
	names := &failureTally{}

	if err := buildSections(file, &payload, budget, hasher, names, notes); err != nil {
		return Payload{}, err
	}
	if err := buildSegments(file, &payload, budget, hasher, notes); err != nil {
		return Payload{}, err
	}
	if err := buildSymbols(file, &payload, budget, notes); err != nil {
		return Payload{}, err
	}
	if err := buildRelocations(file, &payload, budget, notes); err != nil {
		return Payload{}, err
	}
	if err := buildNotes(file, &payload, budget, notes); err != nil {
		return Payload{}, err
	}
	if err := buildComments(file, &payload, budget, notes); err != nil {
		return Payload{}, err
	}

	if names.count > 0 {
		notes.addLimitation(fmt.Sprintf(
			"section names unavailable for %d sections: %s", names.count, names.first,
		))
	}
	if empty := hasher.omitted; empty > 0 {
		notes.addLimitation(fmt.Sprintf(
			"content hashing budget omitted %d section or segment digests", empty,
		))
	}
	if unavailable := hasher.unavailable; unavailable > 0 {
		notes.addLimitation(fmt.Sprintf(
			"%d section or segment digests unavailable: %s", unavailable, hasher.firstUnavailable,
		))
	}
	if failed := hasher.failed; failed > 0 {
		notes.addLimitation(fmt.Sprintf(
			"%d section or segment digests failed: %s", failed, hasher.firstFailure,
		))
	}
	collectUnknowns(file, &payload, notes)
	return payload, nil
}

func buildSections(
	file *reeelf.File,
	payload *Payload,
	budget *payloadBudget,
	hasher *contentHasher,
	names *failureTally,
	notes *collector,
) error {
	budget.start(shareSections)
	omitted := 0
	for i, sh := range file.SectionHeaders {
		name := ""
		nameAvailable := false
		switch resolved, err := file.SectionName(sh.Index); {
		case err == nil:
			name = resolved
			nameAvailable = true
		case errors.Is(err, reeelf.ErrRead):
			return err
		default:
			names.fail(err)
		}

		digest, err := hasher.section(sh)
		if err != nil {
			return err
		}
		entry := payloadSection(sh.Index, sh, name, nameAvailable, digest)
		size := jsonSize(entry) + 1
		if !budget.fits(size) {
			omitted = len(file.SectionHeaders) - i
			break
		}
		budget.add(size)
		payload.Sections = append(payload.Sections, entry)
	}
	budget.finish()
	if omitted > 0 {
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d sections", omitted))
	}
	return nil
}

func buildSegments(
	file *reeelf.File,
	payload *Payload,
	budget *payloadBudget,
	hasher *contentHasher,
	notes *collector,
) error {
	budget.start(shareSegments)
	omitted := 0
	for i, ph := range file.ProgramHeaders {
		digest, err := hasher.segment(ph)
		if err != nil {
			return err
		}
		entry := payloadSegment(ph.Index, ph, digest)
		size := jsonSize(entry) + 1
		if !budget.fits(size) {
			omitted = len(file.ProgramHeaders) - i
			break
		}
		budget.add(size)
		payload.Segments = append(payload.Segments, entry)
	}
	budget.finish()
	if omitted > 0 {
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d segments", omitted))
	}
	return nil
}

func buildSymbols(file *reeelf.File, payload *Payload, budget *payloadBudget, notes *collector) error {
	set, err := file.Symbols()
	if err != nil {
		return err
	}
	for _, limitation := range set.Limitations {
		notes.addLimitation(limitation)
	}
	if set.Truncated {
		notes.addLimitation("symbol coverage is partial")
	}

	budget.start(shareSymbols)
	omitted := 0
	for i, sym := range set.Symbols {
		entry := payloadSymbol(sym)
		size := jsonSize(entry) + 1
		if !budget.fits(size) {
			omitted = len(set.Symbols) - i
			break
		}
		budget.add(size)
		payload.Symbols = append(payload.Symbols, entry)
	}
	budget.finish()
	if omitted > 0 {
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d symbols", omitted))
	}
	return nil
}

func buildRelocations(file *reeelf.File, payload *Payload, budget *payloadBudget, notes *collector) error {
	set, err := file.Relocations()
	if err != nil {
		return err
	}
	for _, limitation := range set.Limitations {
		notes.addLimitation(limitation)
	}
	if set.Truncated {
		notes.addLimitation("relocation coverage is partial")
	}

	budget.start(shareRelocations)
	omitted := 0
	for i, rel := range set.Relocations {
		entry := payloadRelocation(rel)
		size := jsonSize(entry) + 1
		if !budget.fits(size) {
			omitted = len(set.Relocations) - i
			break
		}
		budget.add(size)
		payload.Relocations = append(payload.Relocations, entry)
	}
	budget.finish()
	if omitted > 0 {
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d relocations", omitted))
	}
	return nil
}

func buildNotes(file *reeelf.File, payload *Payload, budget *payloadBudget, notes *collector) error {
	budget.start(shareNotes)

	buildID, err := file.BuildID()
	switch {
	case err == nil:
		entry := &PayloadBuildID{Hex: hex.EncodeToString(buildID), Size: len(buildID)}
		size := jsonSize(entry) + 1
		if budget.fits(size) {
			budget.add(size)
			payload.BuildID = entry
		} else {
			notes.addLimitation("payload budget omitted the GNU build-id")
		}
	case errors.Is(err, reeelf.ErrRead):
		return err
	case errors.Is(err, reeelf.ErrNotFound):
		// The artifact has no GNU build-id note. Absence is not a limitation.
	default:
		notes.addLimitation(fmt.Sprintf("GNU build-id unavailable: %v", err))
	}

	set, err := file.Notes()
	if err != nil {
		budget.finish()
		return err
	}
	for _, limitation := range set.Limitations {
		notes.addLimitation(limitation)
	}
	if set.Truncated {
		notes.addLimitation("note coverage is partial")
	}

	omitted := 0
	for i, note := range set.Notes {
		sum := sha256.Sum256(note.Desc)
		entry := PayloadNote{
			SectionIndex:     note.SectionIndex,
			Name:             note.Name,
			Type:             note.Type,
			DescriptorSize:   len(note.Desc),
			DescriptorSHA256: hex.EncodeToString(sum[:]),
		}
		if len(note.Desc) <= maxNoteHexBytes {
			encoded := hex.EncodeToString(note.Desc)
			entry.DescriptorHex = &encoded
		}
		size := jsonSize(entry) + 1
		if !budget.fits(size) {
			omitted = len(set.Notes) - i
			break
		}
		budget.add(size)
		payload.Notes = append(payload.Notes, entry)
	}
	budget.finish()
	if omitted > 0 {
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d notes", omitted))
	}
	return nil
}

func buildComments(file *reeelf.File, payload *Payload, budget *payloadBudget, notes *collector) error {
	entries, err := file.Comment()
	switch {
	case err == nil:
	case errors.Is(err, reeelf.ErrRead):
		return err
	case errors.Is(err, reeelf.ErrNotFound):
		return nil
	default:
		notes.addLimitation(fmt.Sprintf(".comment unavailable: %v", err))
		return nil
	}

	budget.start(shareComments)
	omitted := 0
	for i, entry := range entries {
		size := jsonSize(entry) + 1
		if !budget.fits(size) {
			omitted = len(entries) - i
			break
		}
		budget.add(size)
		payload.Comments = append(payload.Comments, entry)
	}
	budget.finish()
	if omitted > 0 {
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d .comment entries", omitted))
	}
	return nil
}

// collectUnknowns records structures the adapter observes but does not decode.
func collectUnknowns(file *reeelf.File, payload *Payload, notes *collector) {
	for _, sh := range file.SectionHeaders {
		switch sh.Type {
		case sectionTypeGNUVersym, sectionTypeGNUVerneed, sectionTypeGNUVerdef:
			notes.addUnknown("symbol versioning and version requirements are not decoded")
		case sectionTypeDynamic:
			notes.addUnknown("dynamic section entries and needed libraries are not decoded")
		}
		if sh.Flags&sectionFlagCompressed != 0 {
			notes.addUnknown("compressed section contents are not decompressed")
		}
	}
	for _, rel := range payload.Relocations {
		if !rel.HasAddend {
			notes.addUnknown("relocations without an explicit addend are not resolved")
			break
		}
	}
}

// failureTally aggregates per-entry failures into one limitation.
type failureTally struct {
	count int
	first string
}

func (t *failureTally) fail(err error) {
	if err == nil {
		return
	}
	if t.count == 0 {
		t.first = err.Error()
	}
	t.count++
}

// contentKey identifies a file range for digest caching. A section and a
// segment that cover the same bytes share one digest.
type contentKey struct {
	offset uint64
	size   uint64
}

type contentHasher struct {
	file      *reeelf.File
	remaining int64
	cache     map[contentKey]*string

	omitted          int
	unavailable      int
	failed           int
	firstUnavailable string
	firstFailure     string
}

func newContentHasher(file *reeelf.File, budget int64) *contentHasher {
	return &contentHasher{
		file:      file,
		remaining: budget,
		cache:     make(map[contentKey]*string),
	}
}

func (h *contentHasher) section(sh reeelf.SectionHeader) (*string, error) {
	if sh.Size == 0 || sh.Type == sectionTypeNoBits {
		return nil, nil
	}
	key := contentKey{offset: sh.Offset, size: sh.Size}
	return h.digest(key, func() ([]byte, error) { return h.file.SectionData(sh.Index) })
}

func (h *contentHasher) segment(ph reeelf.ProgramHeader) (*string, error) {
	if ph.FileSize == 0 {
		return nil, nil
	}
	key := contentKey{offset: ph.Offset, size: ph.FileSize}
	return h.digest(key, func() ([]byte, error) { return h.file.SegmentData(ph.Index) })
}

func (h *contentHasher) digest(key contentKey, read func() ([]byte, error)) (*string, error) {
	if digest, ok := h.cache[key]; ok {
		return digest, nil
	}
	if int64(key.size) > h.remaining {
		h.omitted++
		return nil, nil
	}
	data, err := read()
	if err != nil {
		if errors.Is(err, reeelf.ErrRead) {
			return nil, err
		}
		if errors.Is(err, reeelf.ErrUnavailable) {
			if h.unavailable == 0 {
				h.firstUnavailable = err.Error()
			}
			h.unavailable++
			return nil, nil
		}
		if h.failed == 0 {
			h.firstFailure = err.Error()
		}
		h.failed++
		return nil, nil
	}
	h.remaining -= int64(len(data))
	sum := sha256.Sum256(data)
	encoded := hex.EncodeToString(sum[:])
	h.cache[key] = &encoded
	return &encoded, nil
}
