// Package macho reads Mach-O and universal (fat) binary headers, load commands,
// segments, sections, dylibs, build metadata, symbols, and code signature
// headers without executing the artifact.
//
// Parse accepts thin 32-bit and 64-bit Mach-O images in either byte order and
// universal binaries whose fat header lists one image per architecture. Each
// image is loaded behind explicit size, count, and allocation limits. Segment
// and section names are decoded with the table that declares them; section
// contents, dylib names, symbols, and code signature headers are read on demand
// under separate limits. Code signature bytes are never validated.
//
// Input is untrusted. A structurally impossible header fails with a sentinel
// error. A load command table or section table cut short by the artifact end or
// by a configured limit yields the entries that fit, sets File.Truncated, and
// records a limitation instead of presenting a partial table as complete. A
// universal binary keeps every slice: a slice that cannot be parsed carries an
// error and does not hide the slices that can. The package never executes,
// maps, decompresses, or writes artifact content.
//
// A File is immutable after Parse except for the caller-visible slices, which
// callers must not mutate while sharing it.
package macho

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
	// MaxFatSlices bounds the architecture entries loaded from a fat header.
	MaxFatSlices = 32
	// MaxLoadCommands bounds the load commands loaded from one image.
	MaxLoadCommands = 4096
	// MaxLoadCommandBytes bounds the declared load command table size.
	MaxLoadCommandBytes int64 = 4 << 20
	// MaxSegments bounds the segment commands loaded from one image.
	MaxSegments = 256
	// MaxSections bounds the sections loaded from one image.
	MaxSections = 4096
	// MaxSectionDataBytes bounds one section content read.
	MaxSectionDataBytes int64 = 64 << 20
	// MaxDylibs bounds the dylib load commands loaded from one image.
	MaxDylibs = 2048
	// MaxStringBytes bounds one dylib, symbol, or other decoded name.
	MaxStringBytes = 4 << 10
	// MaxBuildTools bounds the LC_BUILD_VERSION tool records loaded.
	MaxBuildTools = 128
	// MaxSymbols bounds the symbol table entries loaded from one image.
	MaxSymbols = 262_144
	// MaxSymbolStringBytes bounds the symbol string table size loaded.
	MaxSymbolStringBytes int64 = 32 << 20
	// MaxCodeSignBlobs bounds the code signature blob index entries loaded.
	MaxCodeSignBlobs = 64
	// MaxCodeSignBytes bounds the code signature data read.
	MaxCodeSignBytes int64 = 8 << 20
)

// Sentinel errors. Errors returned by this package wrap exactly one of these
// values unless a reader itself fails, in which case ErrRead wraps the cause.
var (
	// ErrInvalid reports a structurally invalid Mach-O or fat artifact,
	// including a bad magic, a load command chain that contradicts the header,
	// or a fat entry that cannot describe a slice.
	ErrInvalid = errors.New("macho: invalid artifact")
	// ErrTruncated reports that a structure required to interpret a header
	// extends beyond the artifact end.
	ErrTruncated = errors.New("macho: truncated artifact")
	// ErrLimit reports an artifact larger than the configured byte limit, or
	// requested content above a configured content limit.
	ErrLimit = errors.New("macho: limit exceeded")
	// ErrRead reports a failure or short read from the underlying reader.
	ErrRead = errors.New("macho: read failed")
	// ErrOutOfRange reports a segment, section, command, or slice index outside
	// the loaded table.
	ErrOutOfRange = errors.New("macho: index out of range")
	// ErrUnavailable reports section content that is not present in the
	// artifact, such as a range beyond the slice end.
	ErrUnavailable = errors.New("macho: content unavailable")
	// ErrNotFound reports a load command that the artifact does not declare,
	// such as a dylib, symbol table, or code signature command.
	ErrNotFound = errors.New("macho: metadata not found")
)

// Canonical magic values reported by Header.Magic and Artifact.Magic.
//
// The on-disk byte order is normalized: a little-endian 32-bit image stores the
// bytes 0xce 0xfa 0xed 0xfe and is reported as Magic32.
const (
	Magic32    uint32 = 0xfeedface
	Magic64    uint32 = 0xfeedfacf
	FatMagic   uint32 = 0xcafebabe
	FatMagic64 uint32 = 0xcafebabf
)

// Load command numbers decoded by this package.
const (
	// CommandSegment is LC_SEGMENT, the 32-bit segment command.
	CommandSegment uint32 = 0x1
	// CommandSegment64 is LC_SEGMENT_64, the 64-bit segment command.
	CommandSegment64 uint32 = 0x19
)

// Data is the byte order of a Mach-O header or fat header.
type Data uint8

// Byte orders reported by Header.Data and Artifact.Data.
const (
	// DataNone is the zero value and never describes a parsed artifact.
	DataNone Data = 0
	// DataLittle is little-endian, the order used by every current platform.
	DataLittle Data = 1
	// DataBig is big-endian, used by legacy PowerPC images.
	DataBig Data = 2
)

// Header is the validated Mach-O image header.
type Header struct {
	// Magic is Magic32 or Magic64, normalized from the on-disk byte order.
	Magic uint32
	// Is64 reports a 64-bit image, which carries the reserved header field.
	Is64 bool
	// Data is the byte order of every field in the image.
	Data Data

	CPUType    uint32
	CPUSubtype uint32
	FileType   uint32
	// NumberOfCommands and SizeOfCommands are the declared values. The loaded
	// counts are next to them so a trimmed table cannot look complete.
	NumberOfCommands uint32
	SizeOfCommands   uint32
	Flags            uint32
	// Reserved is present only in a 64-bit header.
	Reserved uint32

	// LoadedCommandCount is the number of load commands actually loaded.
	LoadedCommandCount int
	// LoadedSegmentCount is the number of segment commands actually loaded.
	LoadedSegmentCount int
	// LoadedSectionCount is the number of sections actually loaded.
	LoadedSectionCount int
}

// LoadCommand is one entry from the load command table.
type LoadCommand struct {
	// Index is the position in the load command table.
	Index int
	// Command is the raw cmd value. Unknown commands are reported as stored.
	Command uint32
	// Size is the raw cmdsize value.
	Size uint32
}

// Segment is one decoded LC_SEGMENT or LC_SEGMENT_64 command.
//
// Only the command header and its section records are decoded here. The bytes a
// segment describes are read on demand through File.SectionData.
type Segment struct {
	// Index is the position among the loaded segment commands.
	Index int
	// Command is CommandSegment or CommandSegment64.
	Command uint32
	// Name is the decoded segment name, truncated at the first NUL. It is empty
	// when NameAvailable is false.
	Name string
	// NameAvailable reports that the raw name was non-empty and valid UTF-8.
	NameAvailable bool
	// NameBytes is the raw sixteen-byte segment name field.
	NameBytes [16]byte

	VMAddress uint64
	VMSize    uint64
	// FileOffset and FileSize are the range the segment declares in the slice.
	FileOffset uint64
	FileSize   uint64

	MaxProtection  uint32
	InitProtection uint32
	Flags          uint32

	// DeclaredSectionCount is nsects from the command. FirstSection and
	// SectionCount describe the records actually loaded into File.Sections.
	DeclaredSectionCount uint32
	FirstSection         int
	SectionCount         int
}

// Section is one section record from a segment command.
type Section struct {
	// Index is the position in File.Sections, across every segment.
	Index int
	// SegmentIndex is the loaded segment that declared the section.
	SegmentIndex int

	// Name and NameAvailable describe the decoded section name. Name is empty
	// when decoding failed, so an empty Name is not proof of an unnamed section.
	Name          string
	NameAvailable bool
	// NameBytes is the raw sixteen-byte section name field.
	NameBytes [16]byte

	Address uint64
	Size    uint64
	// Offset is the file offset of the section within the slice.
	Offset              uint32
	Alignment           uint32
	RelocationOffset    uint32
	NumberOfRelocations uint32
	Flags               uint32
	Reserved1           uint32
	Reserved2           uint32
	// Reserved3 is present only in a 64-bit image.
	Reserved3 uint32
}

// File is one parsed Mach-O image: either the whole artifact or one slice of a
// universal binary.
//
// Truncated describes the load command and section tables. Limitations records
// every reason the loaded view is incomplete, including unusable names and
// declared ranges that fall outside the slice. SectionData reads from the
// original io.ReaderAt on demand and reports its own coverage through errors.
type File struct {
	Header   Header
	Commands []LoadCommand
	Segments []Segment
	Sections []Section

	// Truncated reports that the load command or section table is incomplete
	// because the image ended early or a configured count limit was reached.
	Truncated bool
	// Limitations states, in deterministic order, why the loaded view is
	// incomplete. It is empty only when every loaded table matches its declared
	// count, every name is usable, and every declared range is inside the slice.
	Limitations []string

	// reader is a section reader bounded to this slice, and size is its
	// length, so every range reported by the image is relative to the slice.
	reader io.ReaderAt
	size   int64
	limits Limits
	// commandBytes is the number of load command table bytes loaded.
	commandBytes int

	// Aggregated defects, reported once at the end of Parse so a crafted image
	// cannot inflate the limitation list past its table sizes.
	invalidNames    int
	outsideSegments int
	outsideSections int
	// segmentStop and sectionStop report that a configured count limit was
	// reached, so later commands do not repeat the same limitation.
	segmentStop bool
	sectionStop bool
}

// Size returns the size of the slice this image was parsed from.
func (f *File) Size() int64 {
	if f == nil {
		return 0
	}
	return f.size
}

// SectionData returns the stored bytes of the loaded section at index.
//
// A zero-length section returns an empty slice. A section above the configured
// content limit returns ErrLimit; a declared range outside the slice returns
// ErrUnavailable. The bytes are returned as stored: nothing is decompressed,
// relocated, or applied.
func (f *File) SectionData(index int) ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("%w: section %d", ErrOutOfRange, index)
	}
	if index < 0 || index >= len(f.Sections) {
		return nil, fmt.Errorf("%w: section %d", ErrOutOfRange, index)
	}
	section := f.Sections[index]
	if section.Size == 0 {
		return []byte{}, nil
	}
	if section.Size > uint64(f.limits.SectionDataBytes) {
		return nil, fmt.Errorf("%w: section %d size %d exceeds limit %d",
			ErrLimit, index, section.Size, f.limits.SectionDataBytes)
	}
	offset := uint64(section.Offset)
	if offset > uint64(f.size) || section.Size > uint64(f.size)-offset {
		return nil, fmt.Errorf("%w: section %d range is outside the slice", ErrUnavailable, index)
	}
	buf := make([]byte, int(section.Size))
	if err := readAt(f.reader, int64(offset), buf, f.size); err != nil {
		return nil, err
	}
	return buf, nil
}

// Slice is one image of a universal binary, or the single image of a thin one.
type Slice struct {
	// Index is the position in the fat header, or zero for a thin artifact.
	Index int
	// CPUType and CPUSubtype are the fat entry values. A thin artifact copies
	// them from its image header.
	CPUType    uint32
	CPUSubtype uint32
	// Offset and Size bound the slice within the artifact.
	Offset    int64
	Size      int64
	Alignment uint32
	// File is the parsed image, or nil when Err reports why it could not be
	// loaded. One unreadable slice never hides the others.
	File *File
	// Err is a sentinel-wrapped reason when File is nil.
	Err error
}

// Artifact is one parsed Mach-O artifact, thin or universal.
type Artifact struct {
	// Magic is Magic32 or Magic64 for a thin image, FatMagic or FatMagic64 for
	// a universal binary.
	Magic uint32
	// Fat reports that the artifact carries a universal header.
	Fat bool
	// Data is the byte order of the header. The byte order of each image is in
	// its own File.Header.Data.
	Data Data
	// Slices holds one entry per image, in fat header order. A thin artifact
	// has exactly one.
	Slices []Slice

	// Truncated reports that the fat header or slice table is incomplete.
	Truncated bool
	// Limitations states, in deterministic order, why the artifact-level view
	// is incomplete. Image-level limitations live in File.Limitations.
	Limitations []string

	reader io.ReaderAt
	size   int64
	limits Limits
}

// Size returns the artifact size supplied to Parse.
func (a *Artifact) Size() int64 {
	if a == nil {
		return 0
	}
	return a.size
}

// Limits bounds parsing work. A zero or negative field selects the package
// default. Values above the package maximum are clamped to that maximum.
type Limits struct {
	// ArtifactBytes bounds the artifact size accepted by Parse.
	ArtifactBytes int64
	// FatSlices bounds the architecture entries loaded from a fat header.
	FatSlices int
	// LoadCommands bounds the load commands loaded from one image.
	LoadCommands int
	// LoadCommandBytes bounds the declared load command table size.
	LoadCommandBytes int64
	// Segments bounds the segment commands loaded from one image.
	Segments int
	// Sections bounds the sections loaded from one image.
	Sections int
	// SectionDataBytes bounds one section content read.
	SectionDataBytes int64
	// Dylibs bounds the dylib load commands loaded from one image.
	Dylibs int
	// StringBytes bounds one decoded name.
	StringBytes int
	// BuildTools bounds the LC_BUILD_VERSION tool records loaded.
	BuildTools int
	// Symbols bounds the symbol table entries loaded from one image.
	Symbols int
	// SymbolStringBytes bounds the symbol string table size loaded.
	SymbolStringBytes int64
	// CodeSignBlobs bounds the code signature blob index entries loaded.
	CodeSignBlobs int
	// CodeSignBytes bounds the code signature data read.
	CodeSignBytes int64
}

// DefaultLimits returns the package limits.
func DefaultLimits() Limits {
	return Limits{
		ArtifactBytes:     MaxArtifactBytes,
		FatSlices:         MaxFatSlices,
		LoadCommands:      MaxLoadCommands,
		LoadCommandBytes:  MaxLoadCommandBytes,
		Segments:          MaxSegments,
		Sections:          MaxSections,
		SectionDataBytes:  MaxSectionDataBytes,
		Dylibs:            MaxDylibs,
		StringBytes:       MaxStringBytes,
		BuildTools:        MaxBuildTools,
		Symbols:           MaxSymbols,
		SymbolStringBytes: MaxSymbolStringBytes,
		CodeSignBlobs:     MaxCodeSignBlobs,
		CodeSignBytes:     MaxCodeSignBytes,
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
	if l.FatSlices <= 0 {
		l.FatSlices = defaults.FatSlices
	}
	if l.FatSlices > MaxFatSlices {
		l.FatSlices = MaxFatSlices
	}
	if l.LoadCommands <= 0 {
		l.LoadCommands = defaults.LoadCommands
	}
	if l.LoadCommands > MaxLoadCommands {
		l.LoadCommands = MaxLoadCommands
	}
	if l.LoadCommandBytes <= 0 {
		l.LoadCommandBytes = defaults.LoadCommandBytes
	}
	if l.LoadCommandBytes > MaxLoadCommandBytes {
		l.LoadCommandBytes = MaxLoadCommandBytes
	}
	if l.Segments <= 0 {
		l.Segments = defaults.Segments
	}
	if l.Segments > MaxSegments {
		l.Segments = MaxSegments
	}
	if l.Sections <= 0 {
		l.Sections = defaults.Sections
	}
	if l.Sections > MaxSections {
		l.Sections = MaxSections
	}
	if l.SectionDataBytes <= 0 {
		l.SectionDataBytes = defaults.SectionDataBytes
	}
	if l.SectionDataBytes > MaxSectionDataBytes {
		l.SectionDataBytes = MaxSectionDataBytes
	}
	if l.Dylibs <= 0 {
		l.Dylibs = defaults.Dylibs
	}
	if l.Dylibs > MaxDylibs {
		l.Dylibs = MaxDylibs
	}
	if l.StringBytes <= 0 {
		l.StringBytes = defaults.StringBytes
	}
	if l.StringBytes > MaxStringBytes {
		l.StringBytes = MaxStringBytes
	}
	if l.BuildTools <= 0 {
		l.BuildTools = defaults.BuildTools
	}
	if l.BuildTools > MaxBuildTools {
		l.BuildTools = MaxBuildTools
	}
	if l.Symbols <= 0 {
		l.Symbols = defaults.Symbols
	}
	if l.Symbols > MaxSymbols {
		l.Symbols = MaxSymbols
	}
	if l.SymbolStringBytes <= 0 {
		l.SymbolStringBytes = defaults.SymbolStringBytes
	}
	if l.SymbolStringBytes > MaxSymbolStringBytes {
		l.SymbolStringBytes = MaxSymbolStringBytes
	}
	if l.CodeSignBlobs <= 0 {
		l.CodeSignBlobs = defaults.CodeSignBlobs
	}
	if l.CodeSignBlobs > MaxCodeSignBlobs {
		l.CodeSignBlobs = MaxCodeSignBlobs
	}
	if l.CodeSignBytes <= 0 {
		l.CodeSignBytes = defaults.CodeSignBytes
	}
	if l.CodeSignBytes > MaxCodeSignBytes {
		l.CodeSignBytes = MaxCodeSignBytes
	}
	return l
}

// Parse reads a thin or universal Mach-O artifact with the package limits.
func Parse(r io.ReaderAt, size int64) (*Artifact, error) {
	return ParseWithLimits(r, size, Limits{})
}

// ParseWithLimits reads a thin or universal Mach-O artifact using limits.
//
// A load command or section table cut short by the slice end or a count limit
// produces a non-nil artifact with Truncated set and a nil error. A universal
// binary keeps a slice that cannot be parsed as a nil File with Err set, and
// still returns the slices that parse. A header that cannot be interpreted
// returns a nil artifact and an error wrapping ErrInvalid, ErrTruncated, or
// ErrLimit. Reader failures wrap ErrRead.
func ParseWithLimits(r io.ReaderAt, size int64, limits Limits) (*Artifact, error) {
	limits = limits.withDefaults()
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", ErrInvalid)
	}
	if size < 0 {
		return nil, fmt.Errorf("%w: negative artifact size", ErrInvalid)
	}
	if size > limits.ArtifactBytes {
		return nil, fmt.Errorf("%w: artifact size %d exceeds limit %d",
			ErrLimit, size, limits.ArtifactBytes)
	}
	if size < magicSize {
		return nil, fmt.Errorf("%w: artifact size %d is smaller than the Mach-O magic", ErrTruncated, size)
	}

	var raw [magicSize]byte
	if err := readAt(r, 0, raw[:], size); err != nil {
		return nil, err
	}
	magic := readUint32(raw[:], DataBig)
	switch magic {
	case FatMagic, FatMagic64, swappedFatMagic, swappedFatMagic64:
		return parseFat(r, size, limits, magic)
	case Magic32, Magic64, swappedMagic32, swappedMagic64:
		file, err := parseImage(r, 0, size, limits)
		if err != nil {
			return nil, err
		}
		return &Artifact{
			Magic:  file.Header.Magic,
			Data:   file.Header.Data,
			Slices: []Slice{{Index: 0, CPUType: file.Header.CPUType, CPUSubtype: file.Header.CPUSubtype, Offset: 0, Size: size, File: file}},
			reader: r,
			size:   size,
			limits: limits,
		}, nil
	default:
		return nil, fmt.Errorf("%w: bad Mach-O magic %#08x", ErrInvalid, magic)
	}
}

// readAt reads exactly buf at offset inside an artifact of size bytes.
func readAt(r io.ReaderAt, offset int64, buf []byte, size int64) error {
	if offset < 0 || offset > size || int64(len(buf)) > size-offset {
		return fmt.Errorf("%w: %d bytes at offset %d extend beyond artifact size %d",
			ErrTruncated, len(buf), offset, size)
	}
	n, err := r.ReadAt(buf, offset)
	if n == len(buf) {
		return nil
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %w", ErrRead, err)
	}
	return fmt.Errorf("%w: short read of %d bytes at offset %d", ErrRead, len(buf)-n, offset)
}
