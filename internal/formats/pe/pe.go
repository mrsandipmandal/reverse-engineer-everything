// Package pe reads PE32 and PE32+ artifact headers, optional headers, data
// directories, and section tables without executing the artifact.
//
// Parse validates the DOS header, the PE signature, the COFF file header, and
// the optional header, then loads the data directory and section tables behind
// explicit size, count, and allocation limits. Section names are decoded with
// the header; section contents, imports, and exports are read on demand under
// separate limits. Resources, certificates, and COFF symbols are left to later
// layers.
//
// Input is untrusted. A structurally inconsistent header fails with a sentinel
// error. A section table that is cut short by the artifact end or by a
// configured limit yields the complete entries that fit, sets File.Truncated,
// and records a limitation instead of silently presenting a partial table as
// complete. The package never executes, maps, or writes artifact content.
//
// A File is immutable after Parse except for the caller-visible slices, which
// callers must not mutate while sharing it.
package pe

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
	// MaxSections bounds the section headers loaded and the values accepted in
	// the COFF header. The Windows loader also rejects images above 96.
	MaxSections = 96
	// MaxDataDirectories bounds the optional header data directories loaded.
	MaxDataDirectories = 16
	// MaxSectionDataBytes bounds one section content read.
	MaxSectionDataBytes int64 = 64 << 20
	// MaxImportModules bounds the import descriptors loaded.
	MaxImportModules = 4096
	// MaxImportThunks bounds the total import thunks loaded across modules.
	MaxImportThunks = 65536
	// MaxExports bounds the exported functions and names loaded.
	MaxExports = 65536
	// MaxStringBytes bounds one import, export, forwarder, or DLL name.
	MaxStringBytes = 4 << 10
	// MaxImportStringBytes bounds all import strings read in one call.
	MaxImportStringBytes int64 = 16 << 20
	// MaxExportStringBytes bounds all export strings read in one call.
	MaxExportStringBytes int64 = 16 << 20
)

// Sentinel errors. Errors returned by this package wrap exactly one of these
// values unless a reader itself fails, in which case ErrRead wraps the cause.
var (
	// ErrInvalid reports a structurally invalid PE artifact, including a bad
	// DOS signature, an unsupported optional header, or contradictory sizes.
	ErrInvalid = errors.New("pe: invalid artifact")
	// ErrTruncated reports that a structure required to interpret the header
	// extends beyond the artifact end.
	ErrTruncated = errors.New("pe: truncated artifact")
	// ErrLimit reports an artifact larger than the configured byte limit, or
	// requested content above a configured content limit.
	ErrLimit = errors.New("pe: limit exceeded")
	// ErrRead reports a failure or short read from the underlying reader.
	ErrRead = errors.New("pe: read failed")
	// ErrOutOfRange reports a section index outside the declared table.
	ErrOutOfRange = errors.New("pe: index out of range")
	// ErrUnavailable reports section content that is not present in the
	// artifact, such as a raw range beyond the artifact end.
	ErrUnavailable = errors.New("pe: content unavailable")
	// ErrNotFound reports metadata that the artifact does not declare, such as
	// an import or export directory with no address and no size.
	ErrNotFound = errors.New("pe: metadata not found")
)

// Optional header magic values.
const (
	MagicPE32  uint16 = 0x10b
	MagicPE32P uint16 = 0x20b
)

// Header is the validated DOS, PE, and COFF header.
type Header struct {
	// DOSMagic is the DOS signature. It is always 0x5a4d for a parsed file.
	DOSMagic uint16
	// PEHeaderOffset is e_lfanew, the file offset of the PE signature.
	PEHeaderOffset uint32

	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16

	Optional OptionalHeader
}

// OptionalHeader is the decoded PE32 or PE32+ optional header.
//
// Fields absent from PE32+ keep their zero value: BaseOfData is only present in
// PE32, and the image base and stack and heap sizes are 64-bit in PE32+.
type OptionalHeader struct {
	Magic                   uint16
	MajorLinkerVersion      uint8
	MinorLinkerVersion      uint8
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32
	BaseOfData              uint32
	ImageBase               uint64
	SectionAlignment        uint32
	FileAlignment           uint32

	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	// NumberOfRvaAndSizes is the raw declared directory count. It may exceed
	// the number of directories that could be loaded.
	NumberOfRvaAndSizes uint32
}

// DataDirectory is one optional header data directory entry.
type DataDirectory struct {
	// Index is the directory slot, zero through fifteen.
	Index int
	// VirtualAddress is the directory RVA. The security directory stores a
	// file offset instead.
	VirtualAddress uint32
	Size           uint32
}

// SectionHeader is one entry from the section table.
type SectionHeader struct {
	Index int
	// Name is the decoded section name, truncated at the first NUL. It is
	// empty when NameAvailable is false.
	Name string
	// NameAvailable reports that the raw name was non-empty and valid UTF-8.
	NameAvailable bool
	// NameBytes is the raw eight-byte name field.
	NameBytes [8]byte

	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

// File is the parsed headers and the tables loaded by Parse.
//
// Truncated describes the section table. Limitations records every reason the
// loaded header, data directory, section, or overlay view is incomplete.
// SectionData reads from the original io.ReaderAt on demand and reports its own
// coverage through errors.
type File struct {
	Header          Header
	DataDirectories []DataDirectory
	Sections        []SectionHeader

	// OverlayOffset and OverlaySize describe bytes after the last section or
	// the headers, whichever ends later. Both are zero when the artifact has no
	// overlay or when the overlay cannot be determined.
	OverlayOffset uint64
	OverlaySize   uint64

	// Truncated reports that the section table is incomplete because the
	// artifact ended early or a configured count limit was reached.
	Truncated bool
	// Limitations states, in deterministic order, why the loaded header, data
	// directory, section, or overlay view is incomplete. It is empty only when
	// every loaded table matches its declared count, every section name is
	// usable, and the overlay bounds are known.
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
	// ArtifactBytes bounds the artifact size accepted by Parse.
	ArtifactBytes int64
	// Sections bounds the section headers loaded.
	Sections int
	// DataDirectories bounds the data directory entries loaded.
	DataDirectories int
	// SectionDataBytes bounds one section content read.
	SectionDataBytes int64
	// ImportModules bounds the import descriptors loaded.
	ImportModules int
	// ImportThunks bounds all import thunks loaded across modules.
	ImportThunks int
	// Exports bounds the exported functions and the exported names loaded.
	Exports int
	// StringBytes bounds one import, export, or forwarder name.
	StringBytes int
	// ImportStringBytes bounds all import strings read in one Imports call.
	ImportStringBytes int64
	// ExportStringBytes bounds all export strings read in one Exports call.
	ExportStringBytes int64
}

// DefaultLimits returns the package limits.
func DefaultLimits() Limits {
	return Limits{
		ArtifactBytes:     MaxArtifactBytes,
		Sections:          MaxSections,
		DataDirectories:   MaxDataDirectories,
		SectionDataBytes:  MaxSectionDataBytes,
		ImportModules:     MaxImportModules,
		ImportThunks:      MaxImportThunks,
		Exports:           MaxExports,
		StringBytes:       MaxStringBytes,
		ImportStringBytes: MaxImportStringBytes,
		ExportStringBytes: MaxExportStringBytes,
	}
}

func (l Limits) withDefaults() Limits {
	defaults := DefaultLimits()
	if l.ArtifactBytes <= 0 {
		l.ArtifactBytes = defaults.ArtifactBytes
	}
	if l.ArtifactBytes > MaxArtifactBytes {
		l.ArtifactBytes = MaxArtifactBytes
	}
	if l.Sections <= 0 {
		l.Sections = defaults.Sections
	}
	if l.Sections > MaxSections {
		l.Sections = MaxSections
	}
	if l.DataDirectories <= 0 {
		l.DataDirectories = defaults.DataDirectories
	}
	if l.DataDirectories > MaxDataDirectories {
		l.DataDirectories = MaxDataDirectories
	}
	if l.SectionDataBytes <= 0 {
		l.SectionDataBytes = defaults.SectionDataBytes
	}
	if l.SectionDataBytes > MaxSectionDataBytes {
		l.SectionDataBytes = MaxSectionDataBytes
	}
	if l.ImportModules <= 0 {
		l.ImportModules = defaults.ImportModules
	}
	if l.ImportModules > MaxImportModules {
		l.ImportModules = MaxImportModules
	}
	if l.ImportThunks <= 0 {
		l.ImportThunks = defaults.ImportThunks
	}
	if l.ImportThunks > MaxImportThunks {
		l.ImportThunks = MaxImportThunks
	}
	if l.Exports <= 0 {
		l.Exports = defaults.Exports
	}
	if l.Exports > MaxExports {
		l.Exports = MaxExports
	}
	if l.StringBytes <= 0 {
		l.StringBytes = defaults.StringBytes
	}
	if l.StringBytes > MaxStringBytes {
		l.StringBytes = MaxStringBytes
	}
	if l.ImportStringBytes <= 0 {
		l.ImportStringBytes = defaults.ImportStringBytes
	}
	if l.ImportStringBytes > MaxImportStringBytes {
		l.ImportStringBytes = MaxImportStringBytes
	}
	if l.ExportStringBytes <= 0 {
		l.ExportStringBytes = defaults.ExportStringBytes
	}
	if l.ExportStringBytes > MaxExportStringBytes {
		l.ExportStringBytes = MaxExportStringBytes
	}
	return l
}

func (f *File) sectionHeader(index int) (SectionHeader, error) {
	if index < 0 {
		return SectionHeader{}, fmt.Errorf("%w: section %d", ErrOutOfRange, index)
	}
	if index < len(f.Sections) {
		return f.Sections[index], nil
	}
	if uint64(index) < uint64(f.Header.NumberOfSections) {
		return SectionHeader{}, fmt.Errorf("%w: section %d is not loaded", ErrUnavailable, index)
	}
	return SectionHeader{}, fmt.Errorf("%w: section %d", ErrOutOfRange, index)
}
