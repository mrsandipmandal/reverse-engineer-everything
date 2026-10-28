// Package pe turns a bounded PE32 or PE32+ read into ree.evidence/1 evidence
// with a ree.payload.pe/1 payload.
//
// Observe hashes the artifact, parses it with the read-only reader in
// internal/formats/pe, and projects the observed headers, data directories,
// sections, imports, exports, resources, and certificate records into a
// deterministic payload. It never executes, maps, decompresses, or writes
// artifact content. Text in the payload comes from reader-validated UTF-8 or
// UTF-16 names; raw bytes appear only as SHA-256 digests or bounded
// hexadecimal.
package pe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	repe "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/pe"
)

// ErrOptions reports an invalid adapter configuration.
var ErrOptions = errors.New("pe provider: invalid options")

const (
	maxRecordLimitations = 128
	maxRecordUnknowns    = 32
)

// Options configure Observe.
type Options struct {
	// ProviderVersion is recorded in provider.version. It is required.
	ProviderVersion string
	// Limits bounds the PE read. Zero fields select the reader defaults.
	Limits repe.Limits
	// PayloadBytes bounds the variable part of the payload. Zero selects
	// DefaultPayloadBytes; values are clamped to MinPayloadBytes and
	// MaxPayloadBytes.
	PayloadBytes int
	// ContentBytes bounds section bytes hashed for payload digests. Zero
	// selects DefaultContentBytes; values are clamped to MaxContentBytes.
	ContentBytes int64
}

func (o Options) withDefaults() Options {
	if o.PayloadBytes <= 0 {
		o.PayloadBytes = DefaultPayloadBytes
	}
	if o.PayloadBytes < MinPayloadBytes {
		o.PayloadBytes = MinPayloadBytes
	}
	if o.PayloadBytes > MaxPayloadBytes {
		o.PayloadBytes = MaxPayloadBytes
	}
	if o.ContentBytes <= 0 {
		o.ContentBytes = DefaultContentBytes
	}
	if o.ContentBytes > MaxContentBytes {
		o.ContentBytes = MaxContentBytes
	}
	return o
}

// Observe returns unsealed evidence for the PE artifact exposed by r and size.
// Callers seal and serialize the record with evidence.Encode.
//
// The artifact is hashed in a separate bounded pass after parsing, so the
// digest covers exactly size bytes. A readable artifact is still required:
// parse and reader failures return an error instead of partial evidence.
//
// Coverage is complete only when every table the reader returned was included
// in the payload, every name and content digest was available, and no
// out-of-scope structure such as COFF symbols, base relocations, or an
// unvalidated certificate signature is present. Otherwise coverage is partial
// and Limitations or Unknowns state why.
func Observe(r io.ReaderAt, size int64, opts Options) (evidence.Evidence, error) {
	opts = opts.withDefaults()
	if opts.ProviderVersion == "" {
		return evidence.Evidence{}, fmt.Errorf("%w: provider version is required", ErrOptions)
	}

	file, err := repe.ParseWithLimits(r, size, opts.Limits)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("pe provider: parse: %w", err)
	}
	digest, err := hashArtifact(r, size)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("pe provider: subject digest: %w", err)
	}

	notes := &collector{}
	payload, err := buildPayload(file, opts, notes)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("pe provider: payload: %w", err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("pe provider: payload encoding: %w", err)
	}
	limitations, unknowns := notes.finish()

	coverage := evidence.CoverageComplete
	if len(limitations) > 0 || len(unknowns) > 0 {
		coverage = evidence.CoveragePartial
	}
	record := evidence.Evidence{
		Schema:      evidence.Schema,
		Subject:     evidence.Subject{SHA256: digest, Size: size},
		Provider:    evidence.Provider{ID: ProviderID, Version: opts.ProviderVersion, Profile: ProviderProfile},
		Authority:   evidence.AuthorityObserved,
		Coverage:    coverage,
		Limitations: limitations,
		Unknowns:    unknowns,
		Payload:     raw,
	}
	if _, err := evidence.Encode(record); err != nil {
		return evidence.Evidence{}, fmt.Errorf("pe provider: record: %w", err)
	}
	return record, nil
}

func hashArtifact(r io.ReaderAt, size int64) (string, error) {
	hash := sha256.New()
	section := io.NewSectionReader(r, 0, size)
	buffer := make([]byte, 32<<10)
	written, err := io.CopyBuffer(hash, section, buffer)
	if err != nil {
		return "", fmt.Errorf("%w: reading artifact: %w", repe.ErrRead, err)
	}
	if written != size {
		return "", fmt.Errorf("%w: hashed %d of %d bytes", repe.ErrRead, written, size)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type collector struct {
	limitations []string
	unknowns    []string
	seenLimits  map[string]struct{}
	seenUnknown map[string]struct{}
	dropped     bool
	droppedQ    bool
}

func (c *collector) addLimitation(reason string) {
	if reason == "" {
		return
	}
	if c.seenLimits == nil {
		c.seenLimits = make(map[string]struct{})
	}
	if _, ok := c.seenLimits[reason]; ok {
		return
	}
	if len(c.limitations) >= maxRecordLimitations-1 {
		c.dropped = true
		return
	}
	c.seenLimits[reason] = struct{}{}
	c.limitations = append(c.limitations, reason)
}

func (c *collector) addUnknown(reason string) {
	if reason == "" {
		return
	}
	if c.seenUnknown == nil {
		c.seenUnknown = make(map[string]struct{})
	}
	if _, ok := c.seenUnknown[reason]; ok {
		return
	}
	if len(c.unknowns) >= maxRecordUnknowns-1 {
		c.droppedQ = true
		return
	}
	c.seenUnknown[reason] = struct{}{}
	c.unknowns = append(c.unknowns, reason)
}

func (c *collector) finish() ([]string, []string) {
	limitations := append([]string(nil), c.limitations...)
	if c.dropped {
		limitations = append(limitations, "additional limitations omitted")
	}
	unknowns := append([]string(nil), c.unknowns...)
	if c.droppedQ {
		unknowns = append(unknowns, "additional unknowns omitted")
	}
	return limitations, unknowns
}

func payloadHeader(file *repe.File) PayloadHeader {
	header := file.Header
	return PayloadHeader{
		DOSMagic:              header.DOSMagic,
		PEHeaderOffset:        header.PEHeaderOffset,
		Machine:               header.Machine,
		NumberOfSections:      header.NumberOfSections,
		TimeDateStamp:         header.TimeDateStamp,
		PointerToSymbolTable:  header.PointerToSymbolTable,
		NumberOfSymbols:       header.NumberOfSymbols,
		SizeOfOptionalHeader:  header.SizeOfOptionalHeader,
		Characteristics:       header.Characteristics,
		Optional:              payloadOptionalHeader(header.Optional),
		LoadedDataDirectories: len(file.DataDirectories),
		LoadedSections:        len(file.Sections),
	}
}

func payloadOptionalHeader(optional repe.OptionalHeader) PayloadOptionalHeader {
	return PayloadOptionalHeader{
		Magic:                       optional.Magic,
		MajorLinkerVersion:          optional.MajorLinkerVersion,
		MinorLinkerVersion:          optional.MinorLinkerVersion,
		SizeOfCode:                  optional.SizeOfCode,
		SizeOfInitializedData:       optional.SizeOfInitializedData,
		SizeOfUninitializedData:     optional.SizeOfUninitializedData,
		AddressOfEntryPoint:         optional.AddressOfEntryPoint,
		BaseOfCode:                  optional.BaseOfCode,
		BaseOfData:                  optional.BaseOfData,
		ImageBase:                   uint64String(optional.ImageBase),
		SectionAlignment:            optional.SectionAlignment,
		FileAlignment:               optional.FileAlignment,
		MajorOperatingSystemVersion: optional.MajorOperatingSystemVersion,
		MinorOperatingSystemVersion: optional.MinorOperatingSystemVersion,
		MajorImageVersion:           optional.MajorImageVersion,
		MinorImageVersion:           optional.MinorImageVersion,
		MajorSubsystemVersion:       optional.MajorSubsystemVersion,
		MinorSubsystemVersion:       optional.MinorSubsystemVersion,
		Win32VersionValue:           optional.Win32VersionValue,
		SizeOfImage:                 optional.SizeOfImage,
		SizeOfHeaders:               optional.SizeOfHeaders,
		CheckSum:                    optional.CheckSum,
		Subsystem:                   optional.Subsystem,
		DllCharacteristics:          optional.DllCharacteristics,
		SizeOfStackReserve:          uint64String(optional.SizeOfStackReserve),
		SizeOfStackCommit:           uint64String(optional.SizeOfStackCommit),
		SizeOfHeapReserve:           uint64String(optional.SizeOfHeapReserve),
		SizeOfHeapCommit:            uint64String(optional.SizeOfHeapCommit),
		LoaderFlags:                 optional.LoaderFlags,
		NumberOfRvaAndSizes:         optional.NumberOfRvaAndSizes,
	}
}

func payloadSection(section repe.SectionHeader, digest *string) PayloadSection {
	return PayloadSection{
		Index:                section.Index,
		Name:                 section.Name,
		NameAvailable:        section.NameAvailable,
		NameHex:              hex.EncodeToString(section.NameBytes[:]),
		VirtualSize:          section.VirtualSize,
		VirtualAddress:       section.VirtualAddress,
		SizeOfRawData:        section.SizeOfRawData,
		PointerToRawData:     section.PointerToRawData,
		PointerToRelocations: section.PointerToRelocations,
		PointerToLinenumbers: section.PointerToLinenumbers,
		NumberOfRelocations:  section.NumberOfRelocations,
		NumberOfLinenumbers:  section.NumberOfLinenumbers,
		Characteristics:      section.Characteristics,
		DataSHA256:           digest,
	}
}

func payloadImportModule(module repe.ImportModule) PayloadImportModule {
	return PayloadImportModule{
		Index:              module.Index,
		Name:               module.Name,
		NameAvailable:      module.NameAvailable,
		NameRVA:            module.NameRVA,
		TimeDateStamp:      module.TimeDateStamp,
		ForwarderChain:     module.ForwarderChain,
		OriginalFirstThunk: module.OriginalFirstThunk,
		FirstThunk:         module.FirstThunk,
		ThunkSource:        string(module.ThunkSource),
		Thunks:             []PayloadImportThunk{},
		Truncated:          module.Truncated,
	}
}

func payloadImportThunk(thunk repe.ImportThunk) PayloadImportThunk {
	return PayloadImportThunk{
		Index:         thunk.Index,
		ByOrdinal:     thunk.ByOrdinal,
		Ordinal:       thunk.Ordinal,
		Hint:          thunk.Hint,
		Name:          thunk.Name,
		NameAvailable: thunk.NameAvailable,
		NameRVA:       thunk.NameRVA,
	}
}

func payloadExport(entry repe.Export) PayloadExport {
	return PayloadExport{
		Index:              entry.Index,
		Ordinal:            entry.Ordinal,
		RVA:                entry.RVA,
		Name:               entry.Name,
		NameAvailable:      entry.NameAvailable,
		NameRVA:            entry.NameRVA,
		Forwarder:          entry.Forwarder,
		ForwarderAvailable: entry.ForwarderAvailable,
	}
}

func payloadResource(resource repe.Resource) PayloadResource {
	path := make([]PayloadResourceIdentifier, len(resource.Path))
	for i, identifier := range resource.Path {
		path[i] = PayloadResourceIdentifier{
			IsName:        identifier.IsName,
			Name:          identifier.Name,
			NameAvailable: identifier.NameAvailable,
			ID:            identifier.ID,
		}
	}
	return PayloadResource{
		Path:          path,
		DataRVA:       resource.DataRVA,
		DataSize:      resource.DataSize,
		CodePage:      resource.CodePage,
		DataAvailable: resource.DataAvailable,
	}
}

func payloadCertificate(certificate repe.Certificate) PayloadCertificate {
	return PayloadCertificate{
		Index:      certificate.Index,
		Offset:     uint64String(certificate.Offset),
		Length:     certificate.Length,
		Revision:   certificate.Revision,
		Type:       certificate.Type,
		DataOffset: uint64String(certificate.DataOffset),
		DataSize:   certificate.DataSize,
	}
}
