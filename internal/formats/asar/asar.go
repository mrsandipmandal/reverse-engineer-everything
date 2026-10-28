// Package asar reads Electron ASAR archives without extracting them.
//
// Parse validates the Chromium Pickle header, decodes the JSON directory, and
// inventories every directory, file, and link it declares. Nothing is written,
// linked, mapped, or executed. File content is read on demand through EntryData
// or EntryPrefix and returned in memory only.
//
// Input is untrusted. A header whose sizes contradict the artifact fails with a
// sentinel error. A directory past the depth limit, an entry past the entry
// limit, or a file whose declared range lies outside the artifact is
// inventoried with a limitation and sets Archive.Truncated instead of being
// presented as complete. Paths are decoded as UTF-8 and checked for absolute
// paths, drive letters, backslash separators, NUL bytes, and parent-directory
// segments; an entry with an unsafe path is still inventoried, but its content
// is never read. Links are inventoried with their declared target and are never
// followed.
//
// JSON object order is not preserved by decoding, so entries are emitted in
// sorted path order: a directory's children are visited in byte order and the
// resulting inventory is deterministic for a given header.
package asar

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
	// MaxHeaderBytes bounds the JSON header bytes loaded.
	MaxHeaderBytes int64 = 8 << 20
	// MaxEntries bounds the inventory entries loaded from one archive.
	MaxEntries = 20_000
	// MaxPathBytes bounds one stored or decoded entry path.
	MaxPathBytes = 4 << 10
	// MaxDepth bounds nested directory depth in the JSON directory.
	MaxDepth = 32
	// MaxEntryDataBytes bounds one file content read.
	MaxEntryDataBytes int64 = 64 << 20
)

// Sentinel errors. Errors returned by this package wrap exactly one of these
// values unless a reader itself fails, in which case ErrRead wraps the cause.
var (
	// ErrInvalid reports a structurally invalid ASAR header.
	ErrInvalid = errors.New("asar: invalid artifact")
	// ErrTruncated reports that the artifact ends before a required structure
	// does, or that an entry range lies outside the artifact.
	ErrTruncated = errors.New("asar: truncated artifact")
	// ErrLimit reports a header, entry count, path, or content size above the
	// configured limit.
	ErrLimit = errors.New("asar: limit exceeded")
	// ErrRead reports a failure or short read from the underlying reader.
	ErrRead = errors.New("asar: read failed")
	// ErrOutOfRange reports an entry index outside the loaded inventory.
	ErrOutOfRange = errors.New("asar: index out of range")
	// ErrUnavailable reports file content that cannot be produced: an unsafe
	// path, an unpacked file, a link, or a non-file entry.
	ErrUnavailable = errors.New("asar: content unavailable")
)

// EntryType is the kind of object an inventory entry describes.
type EntryType uint8

// Entry types reported by this package.
const (
	// EntryUnknown is the zero value and never describes a loaded entry.
	EntryUnknown EntryType = 0
	// EntryFile is a stored file.
	EntryFile EntryType = 1
	// EntryDirectory is a directory.
	EntryDirectory EntryType = 2
	// EntryLink is a symbolic link. Its target is never followed.
	EntryLink EntryType = 3
	// EntryOther is a node whose type the header does not declare.
	EntryOther EntryType = 4
)

// String returns the entry type name used in evidence.
func (t EntryType) String() string {
	switch t {
	case EntryFile:
		return "file"
	case EntryDirectory:
		return "directory"
	case EntryLink:
		return "link"
	case EntryOther:
		return "other"
	default:
		return "unknown"
	}
}

// Integrity is the declared content integrity metadata of one file.
type Integrity struct {
	// Algorithm is the declared hash algorithm, empty when unavailable.
	Algorithm          string
	AlgorithmAvailable bool
	// Hash is the declared digest, lowercase hex when the header stores hex.
	Hash          string
	HashAvailable bool
	// BlockCount is the number of declared block digests, zero when none are
	// declared or the list could not be read.
	BlockCount int
}

// Entry is one directory, file, or link declared by the archive.
//
// Offset is relative to Archive.DataOffset. Size and Offset are known only when
// the header stores a usable value. A directory has no content; a file that is
// unpacked or outside the artifact has no readable content; a link is never
// followed.
type Entry struct {
	// Index is the position in Archive.Entries.
	Index int

	// Path is the decoded path relative to the archive root, empty when
	// PathAvailable is false.
	Path          string
	PathAvailable bool
	// PathBytes is the raw path bytes, capped at the configured path limit.
	PathBytes []byte
	// PathUnsafe states why the path cannot be used, empty when it is safe.
	PathUnsafe string

	// Type is the object the node describes.
	Type EntryType

	// Size is the declared file size and Offset its declared data offset.
	Size        uint64
	SizeKnown   bool
	Offset      uint64
	OffsetKnown bool
	// DataOffset is the absolute artifact offset of the file data, valid when
	// DataKnown is true.
	DataOffset int64
	DataKnown  bool

	// Executable reports the declared executable bit.
	Executable bool
	// Unpacked reports that the file data lives outside the archive.
	Unpacked bool
	// Integrity is the declared integrity metadata, nil when absent.
	Integrity *Integrity
	// RangeOutside reports that the declared range lies outside the artifact.
	RangeOutside bool
	// LinkTarget is the declared link target, empty when unavailable.
	LinkTarget          string
	LinkTargetAvailable bool

	// Limitations states, in deterministic order, why this entry's view is
	// incomplete or why its content cannot be read.
	Limitations []string
}

// Archive is one parsed ASAR artifact. File data is read from the original
// io.ReaderAt on demand and is never written to disk.
type Archive struct {
	// HeaderBytes is the declared header pickle payload size.
	HeaderBytes int64
	// JSONBytes is the declared JSON string payload size, including padding.
	JSONBytes int64
	// DataOffset is the absolute offset where file data begins.
	DataOffset int64
	// Entries is the inventory in sorted path order.
	Entries []Entry

	// Truncated reports that the inventory is incomplete because a depth or
	// entry limit was reached.
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
	// HeaderBytes bounds the JSON header bytes loaded.
	HeaderBytes int64
	// Entries bounds the inventory entries loaded.
	Entries int
	// PathBytes bounds one stored or decoded entry path.
	PathBytes int
	// Depth bounds nested directory depth.
	Depth int
	// EntryDataBytes bounds one file content read.
	EntryDataBytes int64
}

// DefaultLimits returns the package limits.
func DefaultLimits() Limits {
	return Limits{
		ArtifactBytes:  MaxArtifactBytes,
		HeaderBytes:    MaxHeaderBytes,
		Entries:        MaxEntries,
		PathBytes:      MaxPathBytes,
		Depth:          MaxDepth,
		EntryDataBytes: MaxEntryDataBytes,
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
	if l.HeaderBytes <= 0 {
		l.HeaderBytes = defaults.HeaderBytes
	}
	if l.HeaderBytes > MaxHeaderBytes {
		l.HeaderBytes = MaxHeaderBytes
	}
	if l.Entries <= 0 {
		l.Entries = defaults.Entries
	}
	if l.Entries > MaxEntries {
		l.Entries = MaxEntries
	}
	if l.PathBytes <= 0 {
		l.PathBytes = defaults.PathBytes
	}
	if l.PathBytes > MaxPathBytes {
		l.PathBytes = MaxPathBytes
	}
	if l.Depth <= 0 {
		l.Depth = defaults.Depth
	}
	if l.Depth > MaxDepth {
		l.Depth = MaxDepth
	}
	if l.EntryDataBytes <= 0 {
		l.EntryDataBytes = defaults.EntryDataBytes
	}
	if l.EntryDataBytes > MaxEntryDataBytes {
		l.EntryDataBytes = MaxEntryDataBytes
	}
	return l
}

// Parse reads an ASAR artifact with the package limits.
func Parse(r io.ReaderAt, size int64) (*Archive, error) {
	return ParseWithLimits(r, size, Limits{})
}

// ParseWithLimits reads an ASAR artifact using limits.
//
// A header larger than the artifact, a bad pickle size, or a directory that
// cannot be decoded returns a nil archive and an error wrapping ErrInvalid,
// ErrTruncated, or ErrLimit. A depth or entry limit produces a non-nil archive
// with Truncated set and a nil error. Reader failures wrap ErrRead.
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
	if size < headerFixedBytes {
		return nil, fmt.Errorf("%w: artifact size %d is smaller than the ASAR header", ErrTruncated, size)
	}

	header, err := readHeader(r, size, limits)
	if err != nil {
		return nil, err
	}
	archive := &Archive{
		HeaderBytes: header.headerBytes,
		JSONBytes:   header.jsonBytes,
		DataOffset:  header.dataOffset,
		reader:      r,
		size:        size,
		limits:      limits,
	}
	state := &walkState{}
	if err := archive.walk(header.root, "", 0, true, state); err != nil {
		return nil, err
	}
	return archive, nil
}

// EntryData returns the stored bytes of a file entry.
//
// A zero-length file returns an empty slice. A directory, a link, an unpacked
// file, an unsafe path, and an entry without a usable range return
// ErrUnavailable; a declared size above the content limit returns ErrLimit; a
// range outside the artifact returns ErrTruncated.
//
// The bytes are returned in memory. Nothing is extracted, linked, or written.
func (a *Archive) EntryData(index int) ([]byte, error) {
	entry, err := a.entry(index)
	if err != nil {
		return nil, err
	}
	if err := a.checkContent(entry); err != nil {
		return nil, err
	}
	if entry.Size == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, entry.Size)
	if err := readAt(a.reader, entry.DataOffset, buf, a.size); err != nil {
		return nil, err
	}
	return buf, nil
}

// EntryPrefix returns at most n bytes from the start of a file entry. n above
// the content limit returns ErrLimit.
func (a *Archive) EntryPrefix(index int, n int) ([]byte, error) {
	if n < 0 || int64(n) > a.limits.EntryDataBytes {
		return nil, fmt.Errorf("%w: prefix %d exceeds limit %d", ErrLimit, n, a.limits.EntryDataBytes)
	}
	entry, err := a.entry(index)
	if err != nil {
		return nil, err
	}
	if err := a.checkContent(entry); err != nil {
		return nil, err
	}
	want := entry.Size
	if uint64(n) < want {
		want = uint64(n)
	}
	buf := make([]byte, want)
	if want > 0 {
		if err := readAt(a.reader, entry.DataOffset, buf, a.size); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// checkContent validates that an entry's content can be read.
func (a *Archive) checkContent(entry *Entry) error {
	if entry.PathUnsafe != "" {
		return fmt.Errorf("%w: entry %d path is unsafe: %s", ErrUnavailable, entry.Index, entry.PathUnsafe)
	}
	if entry.Type != EntryFile {
		return fmt.Errorf("%w: entry %d is a %s", ErrUnavailable, entry.Index, entry.Type)
	}
	if entry.Unpacked {
		return fmt.Errorf("%w: entry %d is unpacked", ErrUnavailable, entry.Index)
	}
	if entry.RangeOutside {
		return fmt.Errorf("%w: entry %d range is outside the artifact", ErrTruncated, entry.Index)
	}
	if !entry.SizeKnown || !entry.OffsetKnown || !entry.DataKnown {
		return fmt.Errorf("%w: entry %d has no usable range", ErrUnavailable, entry.Index)
	}
	if entry.Size > uint64(a.limits.EntryDataBytes) {
		return fmt.Errorf("%w: entry %d size %d exceeds limit %d",
			ErrLimit, entry.Index, entry.Size, a.limits.EntryDataBytes)
	}
	return nil
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
