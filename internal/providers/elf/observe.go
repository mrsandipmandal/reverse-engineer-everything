// Package elf turns a bounded ELF read into ree.evidence/1 evidence with a
// ree.payload.elf/1 payload.
//
// Observe hashes the artifact, parses it with the read-only reader in
// internal/formats/elf, and projects the observed headers, tables, notes, and
// build metadata into a deterministic payload. It never executes, maps, or
// writes artifact content. All text in the payload comes from the reader's
// UTF-8-validated section names, symbol names, note owner names, and .comment
// entries; raw bytes appear only as SHA-256 digests or bounded hexadecimal.
package elf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	reeelf "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/elf"
)

// ErrOptions reports an invalid adapter configuration.
var ErrOptions = errors.New("elf provider: invalid options")

const (
	maxRecordLimitations = 128
	maxRecordUnknowns    = 32
)

// Options configure Observe.
type Options struct {
	// ProviderVersion is recorded in provider.version. It is required.
	ProviderVersion string
	// Limits bounds the ELF read. Zero fields select the reader defaults.
	Limits reeelf.Limits
	// PayloadBytes bounds the variable part of the payload. Zero selects
	// DefaultPayloadBytes; values are clamped to MinPayloadBytes and
	// MaxPayloadBytes.
	PayloadBytes int
	// ContentBytes bounds section and segment bytes hashed for payload
	// digests. Zero selects DefaultContentBytes; values are clamped to
	// MaxContentBytes.
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

// Observe returns unsealed evidence for the ELF artifact exposed by r and
// size. Callers seal and serialize the record with evidence.Encode.
//
// The artifact is hashed in a separate bounded pass after parsing, so the
// digest covers exactly size bytes. A readable artifact is still required:
// parse and reader failures return an error instead of partial evidence.
//
// Coverage is complete only when every table the reader returned was included
// in the payload, every name and content digest was available, and no
// out-of-scope structure such as symbol versioning or an implicit relocation
// addend is present. Otherwise coverage is partial and Limitations or
// Unknowns state why.
func Observe(r io.ReaderAt, size int64, opts Options) (evidence.Evidence, error) {
	opts = opts.withDefaults()
	if opts.ProviderVersion == "" {
		return evidence.Evidence{}, fmt.Errorf("%w: provider version is required", ErrOptions)
	}

	file, err := reeelf.ParseWithLimits(r, size, opts.Limits)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("elf provider: parse: %w", err)
	}
	digest, err := hashArtifact(r, size)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("elf provider: subject digest: %w", err)
	}

	notes := &collector{}
	payload, err := buildPayload(file, opts, notes)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("elf provider: payload: %w", err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("elf provider: payload encoding: %w", err)
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
		return evidence.Evidence{}, fmt.Errorf("elf provider: record: %w", err)
	}
	return record, nil
}

func hashArtifact(r io.ReaderAt, size int64) (string, error) {
	hash := sha256.New()
	section := io.NewSectionReader(r, 0, size)
	buffer := make([]byte, 32<<10)
	written, err := io.CopyBuffer(hash, section, buffer)
	if err != nil {
		return "", fmt.Errorf("%w: reading artifact: %w", reeelf.ErrRead, err)
	}
	if written != size {
		return "", fmt.Errorf("%w: hashed %d of %d bytes", reeelf.ErrRead, written, size)
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

func payloadHeader(file *reeelf.File) PayloadHeader {
	header := file.Header
	return PayloadHeader{
		Class:                      header.Class.String(),
		Data:                       header.Data.String(),
		IdentVersion:               header.IdentVersion,
		OSABI:                      header.OSABI,
		ABIVersion:                 header.ABIVersion,
		Type:                       header.Type,
		Machine:                    header.Machine,
		Version:                    header.Version,
		Entry:                      uint64String(header.Entry),
		Flags:                      header.Flags,
		HeaderSize:                 header.HeaderSize,
		ProgramHeaderOffset:        uint64String(header.ProgramHeaderOffset),
		SectionHeaderOffset:        uint64String(header.SectionHeaderOffset),
		ProgramHeaderEntrySize:     header.ProgramHeaderEntrySize,
		SectionHeaderEntrySize:     header.SectionHeaderEntrySize,
		ProgramHeaderCount:         uint64String(header.ProgramHeaderCount),
		SectionHeaderCount:         uint64String(header.SectionHeaderCount),
		SectionNameIndex:           header.SectionNameIndex,
		LoadedProgramHeaderCount:   len(file.ProgramHeaders),
		LoadedSectionHeaderCount:   len(file.SectionHeaders),
		ExtendedProgramHeaderCount: header.ExtendedProgramHeaderCount,
		ExtendedSectionHeaderCount: header.ExtendedSectionHeaderCount,
		ExtendedSectionNameIndex:   header.ExtendedSectionNameIndex,
	}
}

func payloadSection(index int, sh reeelf.SectionHeader, name string, nameAvailable bool, digest *string) PayloadSection {
	return PayloadSection{
		Index:         index,
		Name:          name,
		NameAvailable: nameAvailable,
		Type:          sh.Type,
		Flags:         uint64String(sh.Flags),
		Address:       uint64String(sh.Address),
		Offset:        uint64String(sh.Offset),
		Size:          uint64String(sh.Size),
		Link:          sh.Link,
		Info:          sh.Info,
		AddressAlign:  uint64String(sh.AddressAlign),
		EntrySize:     uint64String(sh.EntrySize),
		DataSHA256:    digest,
	}
}

func payloadSegment(index int, ph reeelf.ProgramHeader, digest *string) PayloadSegment {
	return PayloadSegment{
		Index:           index,
		Type:            ph.Type,
		Flags:           ph.Flags,
		Offset:          uint64String(ph.Offset),
		VirtualAddress:  uint64String(ph.VirtualAddress),
		PhysicalAddress: uint64String(ph.PhysicalAddress),
		FileSize:        uint64String(ph.FileSize),
		MemorySize:      uint64String(ph.MemorySize),
		Align:           uint64String(ph.Align),
		DataSHA256:      digest,
	}
}

func payloadSymbol(sym reeelf.Symbol) PayloadSymbol {
	return PayloadSymbol{
		TableIndex:           sym.TableIndex,
		Index:                sym.Index,
		Name:                 sym.Name,
		NameOffset:           sym.NameOffset,
		Info:                 sym.Info,
		Other:                sym.Other,
		SectionIndex:         sym.SectionIndex,
		ExtendedSectionIndex: sym.ExtendedSectionIndex,
		Value:                uint64String(sym.Value),
		Size:                 uint64String(sym.Size),
	}
}

func payloadRelocation(rel reeelf.Relocation) PayloadRelocation {
	return PayloadRelocation{
		SectionIndex:       rel.SectionIndex,
		TargetSectionIndex: rel.TargetSectionIndex,
		Index:              rel.Index,
		Offset:             uint64String(rel.Offset),
		Info:               uint64String(rel.Info),
		SymbolIndex:        rel.SymIndex,
		Type:               rel.Type,
		Addend:             int64String(rel.Addend),
		HasAddend:          rel.HasAddend,
	}
}
