// Package elf reads ELF32 and ELF64 artifact headers without executing the
// artifact.
//
// Parse validates the ELF identifier and file header, resolves extended
// numbering, and loads the raw section and program header tables behind
// explicit size, count, and allocation limits. Section contents, symbols,
// relocations, notes, and build metadata are read by later layers that build
// on this foundation.
//
// Input is untrusted. Structural defects fail with a sentinel error. A table
// that is cut short by the artifact end or by a configured limit yields the
// complete entries that fit, sets File.Truncated, and records a limitation
// instead of silently presenting a partial table as complete. The package
// never executes, maps, or writes artifact content.
//
// Parse is safe for concurrent use provided the underlying io.ReaderAt is. A
// File is immutable after Parse except for the caller-visible slices, which
// callers must not mutate while sharing the File.
package elf

import (
	"errors"
	"fmt"
	"io"
)

// Package limits. Callers may lower them through Limits but cannot raise them
// above these values.
const (
	// MaxArtifactBytes bounds the artifact size accepted by Parse.
	MaxArtifactBytes int64 = 2 << 30
	// MaxSectionHeaders bounds the number of section headers loaded.
	MaxSectionHeaders = 16_384
	// MaxProgramHeaders bounds the number of program headers loaded.
	MaxProgramHeaders = 16_384
)

// Sentinel errors. Errors returned by this package wrap exactly one of these
// values unless a reader itself fails, in which case ErrRead wraps the cause.
var (
	// ErrInvalid reports a structurally invalid ELF artifact, including a bad
	// identifier, inconsistent header fields, or contradictory counts.
	ErrInvalid = errors.New("elf: invalid artifact")
	// ErrTruncated reports that a structure required to interpret the header
	// extends beyond the artifact end.
	ErrTruncated = errors.New("elf: truncated artifact")
	// ErrLimit reports an artifact larger than the configured byte limit.
	ErrLimit = errors.New("elf: limit exceeded")
	// ErrRead reports a failure or short read from the underlying reader.
	ErrRead = errors.New("elf: read failed")
)

// Class identifies the ELF word size.
type Class uint8

// Supported ELF classes.
const (
	ClassNone Class = 0
	Class32   Class = 1
	Class64   Class = 2
)

// String returns the class name, or "unknown" for an unsupported value.
func (c Class) String() string {
	switch c {
	case Class32:
		return "ELF32"
	case Class64:
		return "ELF64"
	default:
		return "unknown"
	}
}

// Data identifies the ELF byte order.
type Data uint8

// Supported ELF data encodings.
const (
	DataNone   Data = 0
	DataLittle Data = 1
	DataBig    Data = 2
)

// String returns the data encoding name, or "unknown" for an unsupported
// value.
func (d Data) String() string {
	switch d {
	case DataLittle:
		return "little-endian"
	case DataBig:
		return "big-endian"
	default:
		return "unknown"
	}
}

// Header holds the validated ELF file header.
//
// SectionHeaderCount and ProgramHeaderCount are the declared counts after
// extended-numbering resolution, not the number of entries loaded. Cap them
// with len(File.SectionHeaders) and len(File.ProgramHeaders), and inspect
// File.Truncated before treating the loaded tables as complete.
type Header struct {
	Class        Class
	Data         Data
	IdentVersion uint8
	OSABI        uint8
	ABIVersion   uint8

	Type    uint16
	Machine uint16
	Version uint32
	Entry   uint64
	Flags   uint32

	HeaderSize             uint16
	ProgramHeaderOffset    uint64
	SectionHeaderOffset    uint64
	ProgramHeaderEntrySize uint16
	SectionHeaderEntrySize uint16

	ProgramHeaderCount uint64
	SectionHeaderCount uint64
	SectionNameIndex   uint32

	// ExtendedProgramHeaderCount reports that e_phnum was PN_XNUM and the
	// real count came from section header 0.
	ExtendedProgramHeaderCount bool
	// ExtendedSectionHeaderCount reports that e_shnum was zero and the real
	// count came from section header 0.
	ExtendedSectionHeaderCount bool
	// ExtendedSectionNameIndex reports that e_shstrndx was SHN_XINDEX and the
	// real index came from section header 0.
	ExtendedSectionNameIndex bool
}

// SectionHeader is one raw entry from the section header table.
type SectionHeader struct {
	Index        int
	NameOffset   uint32
	Type         uint32
	Flags        uint64
	Address      uint64
	Offset       uint64
	Size         uint64
	Link         uint32
	Info         uint32
	AddressAlign uint64
	EntrySize    uint64
}

// ProgramHeader is one raw entry from the program header table.
type ProgramHeader struct {
	Index           int
	Type            uint32
	Flags           uint32
	Offset          uint64
	VirtualAddress  uint64
	PhysicalAddress uint64
	FileSize        uint64
	MemorySize      uint64
	Align           uint64
}

// File is the parsed header and the raw tables loaded by Parse.
type File struct {
	Header Header

	// SectionHeaders holds up to Header.SectionHeaderCount entries.
	SectionHeaders []SectionHeader
	// ProgramHeaders holds up to Header.ProgramHeaderCount entries.
	ProgramHeaders []ProgramHeader

	// Truncated reports that at least one table is incomplete because the
	// artifact ended early or a configured count limit was reached.
	Truncated bool
	// Limitations states, in deterministic order, why a table is incomplete.
	// It is empty when both loaded tables match the declared counts.
	Limitations []string

	size int64
}

// Size returns the artifact size supplied to Parse.
func (f *File) Size() int64 {
	if f == nil {
		return 0
	}
	return f.size
}

// Limits bounds parsing work. A zero or negative field selects the package
// default. Values above the package maximum are clamped to that maximum.
type Limits struct {
	ArtifactBytes  int64
	SectionHeaders int
	ProgramHeaders int
}

// DefaultLimits returns the package limits.
func DefaultLimits() Limits {
	return Limits{
		ArtifactBytes:  MaxArtifactBytes,
		SectionHeaders: MaxSectionHeaders,
		ProgramHeaders: MaxProgramHeaders,
	}
}

// Parse reads an ELF header and its raw section and program header tables
// using the default limits.
func Parse(r io.ReaderAt, size int64) (*File, error) {
	return ParseWithLimits(r, size, DefaultLimits())
}

// ParseWithLimits reads an ELF header and its raw section and program header
// tables using the given limits.
//
// A physical table truncation or a count limit produces a non-nil File with
// Truncated set and a nil error. A header that cannot be interpreted returns a
// nil File and an error wrapping ErrInvalid, ErrTruncated, or ErrLimit. Reader
// failures wrap ErrRead.
func ParseWithLimits(r io.ReaderAt, size int64, limits Limits) (*File, error) {
	limits = limits.withDefaults()
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", ErrInvalid)
	}
	if size < 0 {
		return nil, fmt.Errorf("%w: negative artifact size", ErrInvalid)
	}
	if size > limits.ArtifactBytes {
		return nil, fmt.Errorf("%w: artifact size %d exceeds limit %d", ErrLimit, size, limits.ArtifactBytes)
	}
	if size < identSize {
		return nil, fmt.Errorf("%w: artifact size %d is smaller than the ELF identifier", ErrTruncated, size)
	}

	ident := make([]byte, identSize)
	if err := readAt(r, 0, ident, size); err != nil {
		return nil, err
	}
	class, data, err := decodeIdent(ident)
	if err != nil {
		return nil, err
	}

	headerSize := elf32HeaderSize
	if class == Class64 {
		headerSize = elf64HeaderSize
	}
	if size < int64(headerSize) {
		return nil, fmt.Errorf("%w: artifact size %d is smaller than the %s header", ErrTruncated, size, class)
	}
	raw := make([]byte, headerSize)
	copy(raw, ident)
	if err := readAt(r, int64(identSize), raw[identSize:], size); err != nil {
		return nil, err
	}

	p := &parser{
		r:      r,
		size:   size,
		limits: limits,
		class:  class,
		data:   data,
		order:  byteOrder(data),
		file:   &File{size: size},
	}
	p.decodeHeader(raw)
	if err := p.resolve(); err != nil {
		return nil, err
	}
	sections, err := p.loadSectionHeaders()
	if err != nil {
		return nil, err
	}
	programs, err := p.loadProgramHeaders()
	if err != nil {
		return nil, err
	}
	p.file.SectionHeaders = sections
	p.file.ProgramHeaders = programs
	return p.file, nil
}

func (l Limits) withDefaults() Limits {
	if l.ArtifactBytes <= 0 || l.ArtifactBytes > MaxArtifactBytes {
		l.ArtifactBytes = MaxArtifactBytes
	}
	if l.SectionHeaders <= 0 || l.SectionHeaders > MaxSectionHeaders {
		l.SectionHeaders = MaxSectionHeaders
	}
	if l.ProgramHeaders <= 0 || l.ProgramHeaders > MaxProgramHeaders {
		l.ProgramHeaders = MaxProgramHeaders
	}
	return l
}
