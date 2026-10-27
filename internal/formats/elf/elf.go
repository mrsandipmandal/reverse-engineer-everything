// Package elf reads ELF32 and ELF64 artifact headers without executing the
// artifact.
//
// Parse validates the ELF identifier and file header, resolves extended
// numbering, and loads the raw section and program header tables behind
// explicit size, count, and allocation limits. Section names, section and
// segment contents, notes, GNU build-id, .comment entries, symbols, and
// relocations are read on demand under separate limits. Decompilation and
// disassembly are left to later layers.
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
	// MaxSectionDataBytes bounds one section data read.
	MaxSectionDataBytes int64 = 64 << 20
	// MaxSegmentDataBytes bounds one segment data read.
	MaxSegmentDataBytes int64 = 64 << 20
	// MaxStringTableBytes bounds a section string table or .comment section
	// considered for metadata.
	MaxStringTableBytes int64 = 8 << 20
	// MaxNameBytes bounds one section or note name.
	MaxNameBytes = 4 << 10
	// MaxNotes bounds the notes scanned from all SHT_NOTE sections.
	MaxNotes = 4_096
	// MaxNoteDataBytes bounds the total note section bytes read.
	MaxNoteDataBytes int64 = 4 << 20
	// MaxBuildIDBytes bounds one GNU build-id descriptor.
	MaxBuildIDBytes = 4 << 10
	// MaxCommentStrings bounds the entries returned from .comment sections.
	MaxCommentStrings = 4_096
	// MaxSymbolTables bounds the symbol table sections scanned.
	MaxSymbolTables = 64
	// MaxSymbols bounds the symbols returned across all symbol tables.
	MaxSymbols = 262_144
	// MaxSymbolStringBytes bounds the string table bytes loaded while
	// resolving symbol names in one call.
	MaxSymbolStringBytes int64 = 32 << 20
	// MaxRelocationSections bounds the relocation sections scanned.
	MaxRelocationSections = 4_096
	// MaxRelocations bounds the relocations returned across all sections.
	MaxRelocations = 262_144
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
	// ErrLimit reports an artifact larger than the configured byte limit, or
	// requested content above a configured content limit.
	ErrLimit = errors.New("elf: limit exceeded")
	// ErrRead reports a failure or short read from the underlying reader.
	ErrRead = errors.New("elf: read failed")
	// ErrOutOfRange reports an index outside the declared table.
	ErrOutOfRange = errors.New("elf: index out of range")
	// ErrUnavailable reports content that is not loaded or not present in the
	// artifact, such as a header beyond a truncated table, SHT_NOBITS data, or
	// bytes outside the declared artifact size.
	ErrUnavailable = errors.New("elf: content unavailable")
	// ErrNotFound reports metadata that the artifact does not contain.
	ErrNotFound = errors.New("elf: metadata not found")
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
//
// Truncated and Limitations describe the section and program header tables
// only. Content methods read from the original io.ReaderAt on demand and
// report their own coverage through errors and, for notes, NoteSet.
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

	reader io.ReaderAt
	size   int64
	limits Limits
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

	SectionDataBytes   int64
	SegmentDataBytes   int64
	StringTableBytes   int64
	NameBytes          int
	Notes              int
	NoteDataBytes      int64
	BuildIDBytes       int
	CommentStrings     int
	SymbolTables       int
	Symbols            int
	SymbolStringBytes  int64
	RelocationSections int
	Relocations        int
}

// DefaultLimits returns the package limits.
func DefaultLimits() Limits {
	return Limits{
		ArtifactBytes:      MaxArtifactBytes,
		SectionHeaders:     MaxSectionHeaders,
		ProgramHeaders:     MaxProgramHeaders,
		SectionDataBytes:   MaxSectionDataBytes,
		SegmentDataBytes:   MaxSegmentDataBytes,
		StringTableBytes:   MaxStringTableBytes,
		NameBytes:          MaxNameBytes,
		Notes:              MaxNotes,
		NoteDataBytes:      MaxNoteDataBytes,
		BuildIDBytes:       MaxBuildIDBytes,
		CommentStrings:     MaxCommentStrings,
		SymbolTables:       MaxSymbolTables,
		Symbols:            MaxSymbols,
		SymbolStringBytes:  MaxSymbolStringBytes,
		RelocationSections: MaxRelocationSections,
		Relocations:        MaxRelocations,
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
		file:   &File{size: size, reader: r, limits: limits},
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
	if l.SectionDataBytes <= 0 || l.SectionDataBytes > MaxSectionDataBytes {
		l.SectionDataBytes = MaxSectionDataBytes
	}
	if l.SegmentDataBytes <= 0 || l.SegmentDataBytes > MaxSegmentDataBytes {
		l.SegmentDataBytes = MaxSegmentDataBytes
	}
	if l.StringTableBytes <= 0 || l.StringTableBytes > MaxStringTableBytes {
		l.StringTableBytes = MaxStringTableBytes
	}
	if l.NameBytes <= 0 || l.NameBytes > MaxNameBytes {
		l.NameBytes = MaxNameBytes
	}
	if l.Notes <= 0 || l.Notes > MaxNotes {
		l.Notes = MaxNotes
	}
	if l.NoteDataBytes <= 0 || l.NoteDataBytes > MaxNoteDataBytes {
		l.NoteDataBytes = MaxNoteDataBytes
	}
	if l.BuildIDBytes <= 0 || l.BuildIDBytes > MaxBuildIDBytes {
		l.BuildIDBytes = MaxBuildIDBytes
	}
	if l.CommentStrings <= 0 || l.CommentStrings > MaxCommentStrings {
		l.CommentStrings = MaxCommentStrings
	}
	if l.SymbolTables <= 0 || l.SymbolTables > MaxSymbolTables {
		l.SymbolTables = MaxSymbolTables
	}
	if l.Symbols <= 0 || l.Symbols > MaxSymbols {
		l.Symbols = MaxSymbols
	}
	if l.SymbolStringBytes <= 0 || l.SymbolStringBytes > MaxSymbolStringBytes {
		l.SymbolStringBytes = MaxSymbolStringBytes
	}
	if l.RelocationSections <= 0 || l.RelocationSections > MaxRelocationSections {
		l.RelocationSections = MaxRelocationSections
	}
	if l.Relocations <= 0 || l.Relocations > MaxRelocations {
		l.Relocations = MaxRelocations
	}
	return l
}
