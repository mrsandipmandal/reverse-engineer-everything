package pe

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	repe "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/pe"
)

// Payload table shares, in percent. Shares are applied to the budget that is
// still unspent, so a table that uses less leaves the remainder to later
// tables. The percentages sum to 100.
const (
	shareSections     = 30
	shareImports      = 30
	shareExports      = 20
	shareResources    = 10
	shareCertificates = 10
)

// buildPayload projects a parsed file into the ree.payload.pe/1 shape.
//
// Tables are emitted in artifact order and trimmed to a prefix when the payload
// budget is exhausted. Read failures propagate; per-entry defects and
// configured limits become adapter limitations or unknowns.
func buildPayload(file *repe.File, opts Options, notes *collector) (Payload, error) {
	payload := Payload{
		Schema:          PayloadSchema,
		Header:          payloadHeader(file),
		DataDirectories: []PayloadDataDirectory{},
		Sections:        []PayloadSection{},
	}

	for _, limitation := range file.Limitations {
		notes.addLimitation(limitation)
	}
	if file.Truncated {
		notes.addLimitation("section table coverage is partial")
	}
	for _, directory := range file.DataDirectories {
		payload.DataDirectories = append(payload.DataDirectories, PayloadDataDirectory{
			Index:          directory.Index,
			VirtualAddress: directory.VirtualAddress,
			Size:           directory.Size,
		})
	}
	if file.OverlaySize > 0 {
		payload.Overlay = &PayloadOverlay{
			Offset: uint64String(file.OverlayOffset),
			Size:   uint64String(file.OverlaySize),
		}
	}

	budget := newPayloadBudget(opts.PayloadBytes)
	budget.reserve(jsonSize(payload.Header) + 1)
	budget.reserve(jsonSize(payload.DataDirectories) + 1)
	if payload.Overlay != nil {
		budget.reserve(jsonSize(payload.Overlay) + 1)
	}

	hasher := newContentHasher(file, opts.ContentBytes)
	if err := buildSections(file, &payload, budget, hasher, notes); err != nil {
		return Payload{}, err
	}
	if err := buildImports(file, &payload, budget, notes); err != nil {
		return Payload{}, err
	}
	if err := buildExports(file, &payload, budget, notes); err != nil {
		return Payload{}, err
	}
	if err := buildResources(file, &payload, budget, notes); err != nil {
		return Payload{}, err
	}
	if err := buildCertificates(file, &payload, budget, notes); err != nil {
		return Payload{}, err
	}

	if empty := hasher.omitted; empty > 0 {
		notes.addLimitation(fmt.Sprintf("content hashing budget omitted %d section digests", empty))
	}
	if unavailable := hasher.unavailable; unavailable > 0 {
		notes.addLimitation(fmt.Sprintf(
			"%d section digests unavailable: %s", unavailable, hasher.firstUnavailable,
		))
	}
	if failed := hasher.failed; failed > 0 {
		notes.addLimitation(fmt.Sprintf(
			"%d section digests failed: %s", failed, hasher.firstFailure,
		))
	}
	collectUnknowns(file, &payload, notes)
	return payload, nil
}

// noteUnavailable turns a directory read error into a limitation. A reader
// failure is returned unchanged so Observe fails closed; an absent directory is
// not a limitation.
func noteUnavailable(notes *collector, label string, err error) error {
	if errors.Is(err, repe.ErrRead) {
		return err
	}
	if errors.Is(err, repe.ErrNotFound) {
		return nil
	}
	notes.addLimitation(fmt.Sprintf("%s directory unavailable: %v", label, err))
	return nil
}

func buildSections(
	file *repe.File,
	payload *Payload,
	budget *payloadBudget,
	hasher *contentHasher,
	notes *collector,
) error {
	budget.start(shareSections)
	omitted := 0
	for i, section := range file.Sections {
		digest, err := hasher.section(section)
		if err != nil {
			return err
		}
		entry := payloadSection(section, digest)
		size := jsonSize(entry) + 1
		if !budget.fits(size) {
			omitted = len(file.Sections) - i
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

func buildImports(file *repe.File, payload *Payload, budget *payloadBudget, notes *collector) error {
	table, err := file.Imports()
	if err != nil {
		if fatal := noteUnavailable(notes, "import", err); fatal != nil {
			return fatal
		}
		return nil
	}
	for _, limitation := range table.Limitations {
		notes.addLimitation(limitation)
	}
	if table.Truncated {
		notes.addLimitation("import coverage is partial")
	}

	budget.start(shareImports)
	out := &PayloadImports{Modules: []PayloadImportModule{}, Truncated: table.Truncated}
	omittedModules := 0
	omittedThunks := 0
	stop := false
	for i, module := range table.Modules {
		entry := payloadImportModule(module)
		baseSize := jsonSize(entry) + 1
		if !budget.fits(baseSize) {
			omittedModules = len(table.Modules) - i
			for k := i; k < len(table.Modules); k++ {
				omittedThunks += len(table.Modules[k].Thunks)
			}
			break
		}
		budget.add(baseSize)
		for j, thunk := range module.Thunks {
			thunkEntry := payloadImportThunk(thunk)
			thunkSize := jsonSize(thunkEntry) + 1
			if !budget.fits(thunkSize) {
				omittedThunks += len(module.Thunks) - j
				for k := i + 1; k < len(table.Modules); k++ {
					omittedThunks += len(table.Modules[k].Thunks)
				}
				omittedModules += len(table.Modules) - i - 1
				entry.Truncated = true
				stop = true
				break
			}
			budget.add(thunkSize)
			entry.Thunks = append(entry.Thunks, thunkEntry)
		}
		out.Modules = append(out.Modules, entry)
		if stop {
			break
		}
	}
	budget.finish()
	if omittedModules > 0 {
		out.Truncated = true
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d import modules", omittedModules))
	}
	if omittedThunks > 0 {
		out.Truncated = true
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d import thunks", omittedThunks))
	}
	payload.Imports = out
	return nil
}

func buildExports(file *repe.File, payload *Payload, budget *payloadBudget, notes *collector) error {
	table, err := file.Exports()
	if err != nil {
		if fatal := noteUnavailable(notes, "export", err); fatal != nil {
			return fatal
		}
		return nil
	}
	for _, limitation := range table.Limitations {
		notes.addLimitation(limitation)
	}
	if table.Truncated {
		notes.addLimitation("export coverage is partial")
	}

	budget.start(shareExports)
	out := &PayloadExports{
		Name:                  table.Name,
		NameAvailable:         table.NameAvailable,
		NameRVA:               table.NameRVA,
		TimeDateStamp:         table.TimeDateStamp,
		MajorVersion:          table.MajorVersion,
		MinorVersion:          table.MinorVersion,
		Base:                  table.Base,
		NumberOfFunctions:     table.NumberOfFunctions,
		NumberOfNames:         table.NumberOfNames,
		AddressOfFunctions:    table.AddressOfFunctions,
		AddressOfNames:        table.AddressOfNames,
		AddressOfNameOrdinals: table.AddressOfNameOrdinals,
		Exports:               []PayloadExport{},
		Truncated:             table.Truncated,
	}
	omitted := 0
	for i, entry := range table.Exports {
		projected := payloadExport(entry)
		size := jsonSize(projected) + 1
		if !budget.fits(size) {
			omitted = len(table.Exports) - i
			break
		}
		budget.add(size)
		out.Exports = append(out.Exports, projected)
	}
	budget.finish()
	if omitted > 0 {
		out.Truncated = true
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d exports", omitted))
	}
	payload.Exports = out
	return nil
}

func buildResources(file *repe.File, payload *Payload, budget *payloadBudget, notes *collector) error {
	table, err := file.Resources()
	if err != nil {
		if fatal := noteUnavailable(notes, "resource", err); fatal != nil {
			return fatal
		}
		return nil
	}
	for _, limitation := range table.Limitations {
		notes.addLimitation(limitation)
	}
	if table.Truncated {
		notes.addLimitation("resource coverage is partial")
	}

	budget.start(shareResources)
	out := &PayloadResources{Resources: []PayloadResource{}, Truncated: table.Truncated}
	omitted := 0
	for i, resource := range table.Resources {
		projected := payloadResource(resource)
		size := jsonSize(projected) + 1
		if !budget.fits(size) {
			omitted = len(table.Resources) - i
			break
		}
		budget.add(size)
		out.Resources = append(out.Resources, projected)
	}
	budget.finish()
	if omitted > 0 {
		out.Truncated = true
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d resources", omitted))
	}
	payload.Resources = out
	return nil
}

func buildCertificates(file *repe.File, payload *Payload, budget *payloadBudget, notes *collector) error {
	table, err := file.Certificates()
	if err != nil {
		if fatal := noteUnavailable(notes, "security", err); fatal != nil {
			return fatal
		}
		return nil
	}
	for _, limitation := range table.Limitations {
		notes.addLimitation(limitation)
	}
	if table.Truncated {
		notes.addLimitation("certificate coverage is partial")
	}

	budget.start(shareCertificates)
	out := &PayloadCertificates{
		Offset:       uint64String(table.Offset),
		Size:         table.Size,
		Certificates: []PayloadCertificate{},
		Truncated:    table.Truncated,
	}
	omitted := 0
	for i, certificate := range table.Certificates {
		projected := payloadCertificate(certificate)
		size := jsonSize(projected) + 1
		if !budget.fits(size) {
			omitted = len(table.Certificates) - i
			break
		}
		budget.add(size)
		out.Certificates = append(out.Certificates, projected)
	}
	budget.finish()
	if omitted > 0 {
		out.Truncated = true
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d certificates", omitted))
	}
	payload.Certificates = out
	return nil
}

// collectUnknowns records structures the adapter observes but does not decode.
func collectUnknowns(file *repe.File, payload *Payload, notes *collector) {
	header := file.Header
	if header.PointerToSymbolTable != 0 && header.NumberOfSymbols != 0 {
		notes.addUnknown("COFF symbols are not decoded")
	}
	for _, directory := range file.DataDirectories {
		if directory.VirtualAddress == 0 && directory.Size == 0 {
			continue
		}
		switch directory.Index {
		case 5:
			notes.addUnknown("base relocations are not decoded")
		case 6:
			notes.addUnknown("debug directory and PDB references are not decoded")
		case 9:
			notes.addUnknown("TLS callbacks are not decoded")
		case 11:
			notes.addUnknown("bound imports are not decoded")
		case 13:
			notes.addUnknown("delay-load imports are not decoded")
		case 14:
			notes.addUnknown("CLR metadata is not decoded")
		}
	}
	if payload.Certificates != nil && len(payload.Certificates.Certificates) > 0 {
		notes.addUnknown("certificate signatures are not validated")
	}
	if payload.Resources != nil && len(payload.Resources.Resources) > 0 {
		notes.addUnknown("resource data is not interpreted")
	}
}

// contentKey identifies a file range for digest caching.
type contentKey struct {
	offset uint64
	size   uint64
}

type contentHasher struct {
	file      *repe.File
	remaining int64
	cache     map[contentKey]*string

	omitted          int
	unavailable      int
	failed           int
	firstUnavailable string
	firstFailure     string
}

func newContentHasher(file *repe.File, budget int64) *contentHasher {
	return &contentHasher{
		file:      file,
		remaining: budget,
		cache:     make(map[contentKey]*string),
	}
}

func (h *contentHasher) section(section repe.SectionHeader) (*string, error) {
	if section.SizeOfRawData == 0 {
		return nil, nil
	}
	key := contentKey{offset: uint64(section.PointerToRawData), size: uint64(section.SizeOfRawData)}
	return h.digest(key, func() ([]byte, error) { return h.file.SectionData(section.Index) })
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
		if errors.Is(err, repe.ErrRead) {
			return nil, err
		}
		if errors.Is(err, repe.ErrUnavailable) || errors.Is(err, repe.ErrLimit) {
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
