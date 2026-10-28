// Package archive reads ZIP, tar, and gzip containers without extracting them.
//
// Parse inventories the entries a container declares and never writes, links,
// maps, or executes entry content. ZIP central directories, tar headers, and
// gzip member headers are bounded by explicit byte and count limits. Entry data
// is read on demand through EntryData or EntryPrefix under a separate byte
// limit and is returned in memory only. Names are decoded as UTF-8 and checked
// for absolute paths, drive letters, backslash separators, NUL bytes, and
// parent-directory segments; an entry whose name fails a check is still
// inventoried, but its content is never read.
//
// Input is untrusted. A container that cannot be recognized fails with a
// sentinel error. A directory, header chain, or entry table cut short by the
// artifact end or a configured limit yields the entries that fit, sets
// Archive.Truncated, and records a limitation instead of presenting a partial
// inventory as complete. Reader failures wrap ErrRead.
//
// A gzip artifact is inventoried as one stream entry. Its member boundaries and
// uncompressed size are not enumerated, so Entry.UncompressedSizeKnown is false
// and EntryData decodes the concatenated members on demand under the content
// limit.
package archive

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
	// MaxEntries bounds the entries loaded from one container.
	MaxEntries = 20_000
	// MaxNameBytes bounds one stored or decoded entry name.
	MaxNameBytes = 4 << 10
	// MaxDirectoryBytes bounds the ZIP central directory bytes loaded.
	MaxDirectoryBytes int64 = 8 << 20
	// MaxEntryDataBytes bounds one entry content read.
	MaxEntryDataBytes int64 = 64 << 20
	// MaxExtraBytes bounds one ZIP extra field block or the gzip extra field.
	MaxExtraBytes int64 = 64 << 10
	// MaxPaxBytes bounds one PAX extended header record block.
	MaxPaxBytes int64 = 1 << 20
	// MaxGzipCommentBytes bounds a gzip comment field.
	MaxGzipCommentBytes = 4 << 10
)

// Sentinel errors. Errors returned by this package wrap exactly one of these
// values unless a reader itself fails, in which case ErrRead wraps the cause.
var (
	// ErrInvalid reports a structurally invalid ZIP, tar, or gzip artifact,
	// including a bad signature, a contradictory header, or a checksum that
	// does not match the data.
	ErrInvalid = errors.New("archive: invalid artifact")
	// ErrTruncated reports that a structure required to interpret a header
	// extends beyond the artifact end.
	ErrTruncated = errors.New("archive: truncated artifact")
	// ErrLimit reports an artifact larger than the configured byte limit, or
	// requested content above a configured content limit.
	ErrLimit = errors.New("archive: limit exceeded")
	// ErrRead reports a failure or short read from the underlying reader.
	ErrRead = errors.New("archive: read failed")
	// ErrOutOfRange reports an entry index outside the loaded table.
	ErrOutOfRange = errors.New("archive: index out of range")
	// ErrUnavailable reports entry content that is not available: an unsafe
	// name, encryption, an unsupported compression method, or a non-file entry.
	ErrUnavailable = errors.New("archive: content unavailable")
)

// Container is the recognized archive format.
type Container uint8

// Containers recognized by Parse.
const (
	// ContainerUnknown is the zero value and never describes a parsed archive.
	ContainerUnknown Container = 0
	// ContainerZIP is a ZIP archive, including ZIP64.
	ContainerZIP Container = 1
	// ContainerTar is a POSIX ustar, PAX, or GNU tar archive.
	ContainerTar Container = 2
	// ContainerGZIP is a gzip stream, possibly with concatenated members.
	ContainerGZIP Container = 3
)

// String returns the container name used in evidence.
func (c Container) String() string {
	switch c {
	case ContainerZIP:
		return "zip"
	case ContainerTar:
		return "tar"
	case ContainerGZIP:
		return "gzip"
	default:
		return "unknown"
	}
}

// EntryType is the kind of filesystem object an entry describes.
type EntryType uint8

// Entry types reported by this package.
const (
	// EntryUnknown is the zero value and never describes a loaded entry.
	EntryUnknown EntryType = 0
	// EntryFile is a regular file.
	EntryFile EntryType = 1
	// EntryDirectory is a directory.
	EntryDirectory EntryType = 2
	// EntrySymlink is a symbolic link. Its target is never followed.
	EntrySymlink EntryType = 3
	// EntryHardlink is a hard link. Its target is never followed.
	EntryHardlink EntryType = 4
	// EntryFIFO is a named pipe.
	EntryFIFO EntryType = 5
	// EntryCharacterDevice is a character device.
	EntryCharacterDevice EntryType = 6
	// EntryBlockDevice is a block device.
	EntryBlockDevice EntryType = 7
	// EntryOther is an entry whose type this package does not decode.
	EntryOther EntryType = 8
)

// String returns the entry type name used in evidence.
func (t EntryType) String() string {
	switch t {
	case EntryFile:
		return "file"
	case EntryDirectory:
		return "directory"
	case EntrySymlink:
		return "symlink"
	case EntryHardlink:
		return "hardlink"
	case EntryFIFO:
		return "fifo"
	case EntryCharacterDevice:
		return "character-device"
	case EntryBlockDevice:
		return "block-device"
	case EntryOther:
		return "other"
	default:
		return "unknown"
	}
}

// Method is the compression method of an entry. ZIP method numbers are used;
// tar entries are stored and gzip entries are deflate.
type Method uint16

// Compression methods reported by this package.
const (
	// MethodStored stores entry bytes without compression.
	MethodStored Method = 0
	// MethodDeflate is the DEFLATE stream, the only method this package decodes
	// besides stored bytes.
	MethodDeflate Method = 8
	// MethodDeflate64 is the proprietary extended DEFLATE variant. It is
	// reported but not decoded.
	MethodDeflate64 Method = 9
	// MethodBzip2 is bzip2. It is reported but not decoded.
	MethodBzip2 Method = 12
	// MethodLZMA is LZMA. It is reported but not decoded.
	MethodLZMA Method = 14
	// MethodZstandard is Zstandard. It is reported but not decoded.
	MethodZstandard Method = 93
)

// String returns the method name used in evidence.
func (m Method) String() string {
	switch m {
	case MethodStored:
		return "stored"
	case MethodDeflate:
		return "deflate"
	case MethodDeflate64:
		return "deflate64"
	case MethodBzip2:
		return "bzip2"
	case MethodLZMA:
		return "lzma"
	case MethodZstandard:
		return "zstandard"
	default:
		return fmt.Sprintf("method-%d", uint16(m))
	}
}

// supported reports whether EntryData can produce the entry bytes.
func (m Method) supported() bool {
	return m == MethodStored || m == MethodDeflate
}

// Entry is one file, directory, or link declared by a container.
//
// Only the header fields are loaded by Parse. DataOffset, CompressedSize, and
// UncompressedSize describe where the bytes are and what they claim to be;
// EntryData reads and verifies them on demand.
//
// NameBytes holds the raw name bytes, truncated to the configured name limit.
// Name and NameAvailable describe the decoded UTF-8 name. NameUnsafe is empty
// only when the name is usable and does not escape the archive root; an entry
// with a non-empty NameUnsafe is inventoried but its content is never read.
type Entry struct {
	// Index is the position in Archive.Entries.
	Index int

	// Name is the decoded name, empty when NameAvailable is false.
	Name          string
	NameAvailable bool
	// NameBytes is the raw name field, capped at the configured name limit.
	NameBytes []byte
	// NameUnsafe states why the name cannot be used, empty when it is safe.
	NameUnsafe string

	// Type is the filesystem object the entry describes.
	Type EntryType
	// Method is the compression method used for the entry bytes.
	Method Method
	// Mode is the Unix permission and type bits when the container stores them.
	Mode          uint32
	ModeAvailable bool

	// Flags holds the ZIP general purpose bit flags; it is zero for tar and
	// gzip entries.
	Flags uint16
	// Encrypted reports that ZIP entry data is encrypted. Encrypted content is
	// never read.
	Encrypted bool

	// CompressedSize and UncompressedSize are the declared sizes in bytes.
	// CompressedSizeKnown reports that the container stores the compressed
	// size, and UncompressedSizeKnown reports that it stores the uncompressed
	// size.
	CompressedSize        uint64
	CompressedSizeKnown   bool
	UncompressedSize      uint64
	UncompressedSizeKnown bool

	// CRC32 is the declared CRC-32 of the uncompressed bytes when the container
	// stores one, such as ZIP and gzip.
	CRC32          uint32
	CRC32Available bool

	// ModifiedUnix is the declared modification time in Unix seconds.
	ModifiedUnix      int64
	ModifiedAvailable bool

	// HeaderOffset is the start of the entry header, and DataOffset is the
	// start of the stored bytes, when the container stores them.
	HeaderOffset int64
	DataOffset   int64

	// LinkTarget is the declared link target for tar links. A ZIP symbolic
	// link target is stored as entry data and is not decoded here.
	LinkTarget          string
	LinkTargetAvailable bool

	// Sparse reports a GNU sparse tar entry whose layout is not decoded.
	Sparse bool

	// Limitations states, in deterministic order, why this entry's view is
	// incomplete or why its content cannot be read.
	Limitations []string
}

// GZIPHeader is the parsed gzip member header. It describes the first member
// only; concatenated members are decoded by EntryData.
type GZIPHeader struct {
	// Name is the decoded original file name, empty when NameAvailable is false.
	Name          string
	NameAvailable bool
	// NameBytes is the raw name field, capped at the configured name limit.
	NameBytes []byte
	// Comment is the decoded comment, empty when CommentAvailable is false.
	Comment          string
	CommentAvailable bool
	// ModifiedUnix is the declared modification time in Unix seconds.
	ModifiedUnix      int64
	ModifiedAvailable bool
	// OS is the gzip operating system identifier.
	OS uint8
	// ExtraBytes is the declared extra field length.
	ExtraBytes uint16
	// HeaderBytes is the number of header bytes before the compressed data.
	HeaderBytes int64
}

// Archive is one parsed ZIP, tar, or gzip artifact.
//
// Truncated describes the directory or header chain. Limitations records every
// reason the loaded inventory is incomplete. Entry data is read from the
// original io.ReaderAt on demand and is never written to disk.
type Archive struct {
	// Container is the recognized format.
	Container Container
	// Entries is the inventory in container order.
	Entries []Entry
	// GZIP is the parsed gzip header, nil for other containers.
	GZIP *GZIPHeader

	// Truncated reports that the directory or header chain is incomplete
	// because the artifact ended early or a configured limit was reached.
	Truncated bool
	// Limitations states, in deterministic order, why the loaded inventory is
	// incomplete. It is empty only when the whole inventory was read.
	Limitations []string

	reader io.ReaderAt
	size   int64
	limits Limits
}

// Size returns the artifact size supplied to Parse.
func (a *Archive) Size() int64 {
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
	// Entries bounds the entries loaded from one container.
	Entries int
	// NameBytes bounds one stored or decoded entry name.
	NameBytes int
	// DirectoryBytes bounds the ZIP central directory bytes loaded.
	DirectoryBytes int64
	// EntryDataBytes bounds one entry content read.
	EntryDataBytes int64
	// ExtraBytes bounds one ZIP or gzip extra field block.
	ExtraBytes int64
	// PaxBytes bounds one PAX extended header record block.
	PaxBytes int64
	// GzipCommentBytes bounds a gzip comment field.
	GzipCommentBytes int
}

// DefaultLimits returns the package limits.
func DefaultLimits() Limits {
	return Limits{
		ArtifactBytes:    MaxArtifactBytes,
		Entries:          MaxEntries,
		NameBytes:        MaxNameBytes,
		DirectoryBytes:   MaxDirectoryBytes,
		EntryDataBytes:   MaxEntryDataBytes,
		ExtraBytes:       MaxExtraBytes,
		PaxBytes:         MaxPaxBytes,
		GzipCommentBytes: MaxGzipCommentBytes,
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
	if l.Entries <= 0 {
		l.Entries = defaults.Entries
	}
	if l.Entries > MaxEntries {
		l.Entries = MaxEntries
	}
	if l.NameBytes <= 0 {
		l.NameBytes = defaults.NameBytes
	}
	if l.NameBytes > MaxNameBytes {
		l.NameBytes = MaxNameBytes
	}
	if l.DirectoryBytes <= 0 {
		l.DirectoryBytes = defaults.DirectoryBytes
	}
	if l.DirectoryBytes > MaxDirectoryBytes {
		l.DirectoryBytes = MaxDirectoryBytes
	}
	if l.EntryDataBytes <= 0 {
		l.EntryDataBytes = defaults.EntryDataBytes
	}
	if l.EntryDataBytes > MaxEntryDataBytes {
		l.EntryDataBytes = MaxEntryDataBytes
	}
	if l.ExtraBytes <= 0 {
		l.ExtraBytes = defaults.ExtraBytes
	}
	if l.ExtraBytes > MaxExtraBytes {
		l.ExtraBytes = MaxExtraBytes
	}
	if l.PaxBytes <= 0 {
		l.PaxBytes = defaults.PaxBytes
	}
	if l.PaxBytes > MaxPaxBytes {
		l.PaxBytes = MaxPaxBytes
	}
	if l.GzipCommentBytes <= 0 {
		l.GzipCommentBytes = defaults.GzipCommentBytes
	}
	if l.GzipCommentBytes > MaxGzipCommentBytes {
		l.GzipCommentBytes = MaxGzipCommentBytes
	}
	return l
}

// Detect recognizes a container from its prefix. It needs up to 263 bytes to
// recognize tar, and fewer for ZIP and gzip. It returns ContainerUnknown when
// the prefix is too short or the magic is unknown.
func Detect(prefix []byte) Container {
	if len(prefix) >= 10 && prefix[0] == 0x1f && prefix[1] == 0x8b && prefix[2] == 8 {
		return ContainerGZIP
	}
	if len(prefix) >= 4 {
		switch string(prefix[:4]) {
		case "PK\x03\x04", "PK\x05\x06":
			return ContainerZIP
		}
	}
	if len(prefix) >= tarMagicOffset+5 && string(prefix[tarMagicOffset:tarMagicOffset+5]) == "ustar" {
		return ContainerTar
	}
	return ContainerUnknown
}

// Parse reads a ZIP, tar, or gzip artifact with the package limits.
func Parse(r io.ReaderAt, size int64) (*Archive, error) {
	return ParseWithLimits(r, size, Limits{})
}

// ParseWithLimits reads a ZIP, tar, or gzip artifact using limits.
//
// A directory or header chain cut short by the artifact end or a count limit
// produces a non-nil archive with Truncated set and a nil error. A container
// whose first header cannot be interpreted returns a nil archive and an error
// wrapping ErrInvalid, ErrTruncated, or ErrLimit. Reader failures wrap ErrRead.
func ParseWithLimits(r io.ReaderAt, size int64, limits Limits) (*Archive, error) {
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
	if size == 0 {
		return nil, fmt.Errorf("%w: empty artifact", ErrTruncated)
	}

	prefixSize := size
	if prefixSize > tarMagicOffset+8 {
		prefixSize = tarMagicOffset + 8
	}
	prefix := make([]byte, prefixSize)
	if err := readAt(r, 0, prefix, size); err != nil {
		return nil, err
	}
	switch Detect(prefix) {
	case ContainerZIP:
		return parseZIP(r, size, limits)
	case ContainerTar:
		return parseTar(r, size, limits)
	case ContainerGZIP:
		return parseGZIP(r, size, limits)
	default:
		return nil, fmt.Errorf("%w: unrecognized archive container", ErrInvalid)
	}
}

// EntryData returns the stored, decompressed bytes of an entry.
//
// A zero-length entry returns an empty slice. A directory returns an empty
// slice. A symbolic link returns its target bytes when the container stores
// them, but a tar link target lives in the header and is reported in
// Entry.LinkTarget instead. Encrypted, unsupported, unsafe, and non-file
// entries return ErrUnavailable; a declared size above the content limit
// returns ErrLimit; a range outside the artifact returns ErrTruncated.
//
// The bytes are returned in memory. Nothing is extracted, linked, or written.
func (a *Archive) EntryData(index int) ([]byte, error) {
	entry, err := a.entry(index)
	if err != nil {
		return nil, err
	}
	if entry.NameUnsafe != "" {
		return nil, fmt.Errorf("%w: entry %d name is unsafe: %s", ErrUnavailable, index, entry.NameUnsafe)
	}
	if entry.Encrypted {
		return nil, fmt.Errorf("%w: entry %d is encrypted", ErrUnavailable, index)
	}
	if !entry.Method.supported() {
		return nil, fmt.Errorf("%w: entry %d uses compression method %s", ErrUnavailable, index, entry.Method)
	}
	if entry.UncompressedSizeKnown && entry.UncompressedSize > uint64(a.limits.EntryDataBytes) {
		return nil, fmt.Errorf("%w: entry %d size %d exceeds limit %d",
			ErrLimit, index, entry.UncompressedSize, a.limits.EntryDataBytes)
	}
	switch a.Container {
	case ContainerZIP:
		return a.zipData(entry, -1)
	case ContainerTar:
		return a.tarData(entry, -1)
	case ContainerGZIP:
		return a.gzipData(entry, -1)
	default:
		return nil, fmt.Errorf("%w: entry %d has no container", ErrUnavailable, index)
	}
}

// EntryPrefix returns at most n bytes from the start of an entry, decompressed
// when needed. It does not verify the entry checksum, because a prefix is not
// the whole entry. n above the content limit returns ErrLimit.
func (a *Archive) EntryPrefix(index int, n int) ([]byte, error) {
	if n < 0 || int64(n) > a.limits.EntryDataBytes {
		return nil, fmt.Errorf("%w: prefix %d exceeds limit %d", ErrLimit, n, a.limits.EntryDataBytes)
	}
	entry, err := a.entry(index)
	if err != nil {
		return nil, err
	}
	if entry.NameUnsafe != "" {
		return nil, fmt.Errorf("%w: entry %d name is unsafe: %s", ErrUnavailable, index, entry.NameUnsafe)
	}
	if entry.Encrypted {
		return nil, fmt.Errorf("%w: entry %d is encrypted", ErrUnavailable, index)
	}
	if !entry.Method.supported() {
		return nil, fmt.Errorf("%w: entry %d uses compression method %s", ErrUnavailable, index, entry.Method)
	}
	switch a.Container {
	case ContainerZIP:
		return a.zipData(entry, int64(n))
	case ContainerTar:
		return a.tarData(entry, int64(n))
	case ContainerGZIP:
		return a.gzipData(entry, int64(n))
	default:
		return nil, fmt.Errorf("%w: entry %d has no container", ErrUnavailable, index)
	}
}

func (a *Archive) entry(index int) (*Entry, error) {
	if a == nil {
		return nil, fmt.Errorf("%w: entry %d of a nil archive", ErrOutOfRange, index)
	}
	if index < 0 || index >= len(a.Entries) {
		return nil, fmt.Errorf("%w: entry %d of %d", ErrOutOfRange, index, len(a.Entries))
	}
	return &a.Entries[index], nil
}

func (a *Archive) note(format string, args ...any) {
	a.Limitations = append(a.Limitations, fmt.Sprintf(format, args...))
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
