// Package plist reads Apple property lists without extracting them.
//
// Parse detects the binary (`bplist00`) and XML representations, validates the
// structure, and inventories every object in the document as a flat table. An
// object carries its type, its scalar value, and the object indices it refers
// to, so a dictionary and an array stay navigable without a second record.
//
// Input is untrusted. A trailer whose sizes contradict the artifact, an object
// offset outside the object area, or a reference past the object table fails
// with a sentinel error. An object count, string size, or graph depth above the
// configured limit is reported through Truncated and a limitation instead of
// being presented as complete.
//
// The package never writes, executes, or follows a reference outside the
// document. Nothing is decoded into a live object graph: the inventory is a
// table of validated values.
package plist

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// Package limits. Callers may lower them through Limits but cannot raise them
// above these values.
const (
	// MaxArtifactBytes bounds the artifact size accepted by Parse.
	MaxArtifactBytes int64 = 2 << 30
	// MaxObjects bounds the objects loaded from one property list.
	MaxObjects = 20_000
	// MaxDepth bounds how deep the object graph is walked from the top object.
	MaxDepth = 32
	// MaxStringBytes bounds one decoded string.
	MaxStringBytes = 1 << 20
)

// Sentinel errors. Errors returned by this package wrap exactly one of these
// values unless a reader itself fails, in which case ErrRead wraps the cause.
var (
	// ErrInvalid reports a structurally invalid property list.
	ErrInvalid = errors.New("plist: invalid artifact")
	// ErrTruncated reports that the artifact ends before a required structure
	// does.
	ErrTruncated = errors.New("plist: truncated artifact")
	// ErrLimit reports an object, string, or depth count above the configured
	// limit at a point where no coherent inventory can be produced.
	ErrLimit = errors.New("plist: limit exceeded")
	// ErrRead reports a failure or short read from the underlying reader.
	ErrRead = errors.New("plist: read failed")
	// ErrOutOfRange reports an object index outside the loaded inventory.
	ErrOutOfRange = errors.New("plist: index out of range")
)

// Format is the property list representation that was parsed.
type Format uint8

// Formats reported by this package.
const (
	// FormatUnknown is the zero value and never describes a parsed artifact.
	FormatUnknown Format = 0
	// FormatBinary is the binary `bplist` representation.
	FormatBinary Format = 1
	// FormatXML is the XML representation.
	FormatXML Format = 2
)

// String returns the format name used in evidence.
func (f Format) String() string {
	switch f {
	case FormatBinary:
		return "binary"
	case FormatXML:
		return "xml"
	default:
		return "unknown"
	}
}

// Type is the value type of one inventory object.
type Type uint8

// Object types reported by this package.
const (
	// TypeUnknown is the zero value and never describes a parsed object.
	TypeUnknown Type = 0
	// TypeDictionary is a keyed collection.
	TypeDictionary Type = 1
	// TypeArray is an ordered collection.
	TypeArray Type = 2
	// TypeSet is an unordered collection.
	TypeSet Type = 3
	// TypeString is text.
	TypeString Type = 4
	// TypeInteger is a signed or unsigned integer.
	TypeInteger Type = 5
	// TypeReal is a floating-point number.
	TypeReal Type = 6
	// TypeBoolean is a boolean.
	TypeBoolean Type = 7
	// TypeDate is an absolute timestamp.
	TypeDate Type = 8
	// TypeData is an opaque byte string.
	TypeData Type = 9
	// TypeUID is a keyed-archiver unique identifier.
	TypeUID Type = 10
	// TypeNull is the explicit null value.
	TypeNull Type = 11
)

// String returns the type name used in evidence.
func (t Type) String() string {
	switch t {
	case TypeDictionary:
		return "dictionary"
	case TypeArray:
		return "array"
	case TypeSet:
		return "set"
	case TypeString:
		return "string"
	case TypeInteger:
		return "integer"
	case TypeReal:
		return "real"
	case TypeBoolean:
		return "boolean"
	case TypeDate:
		return "date"
	case TypeData:
		return "data"
	case TypeUID:
		return "uid"
	case TypeNull:
		return "null"
	default:
		return "unknown"
	}
}

// Object is one value in the inventory.
//
// Only the fields that belong to Type carry meaning: Keys and Values for a
// dictionary, Refs for an array or set, Text for a string, Integer for an
// integer, Real for a real, Boolean for a boolean, DateUnix for a date,
// DataBytes for a data value, and UID for a UID. The others keep their zero
// value.
type Object struct {
	// Index is the position in Plist.Objects.
	Index int
	// Type is the value type.
	Type Type

	// Keys and Values are parallel reference lists of a dictionary. Keys are
	// indices of string objects.
	Keys   []uint64
	Values []uint64
	// Refs is the element list of an array or set.
	Refs []uint64

	// Text is the decoded string, empty when TextAvailable is false.
	Text          string
	TextAvailable bool
	// TextBytes is the raw stored string bytes, capped at the string limit.
	TextBytes []byte

	// Boolean is the value of a boolean object.
	Boolean bool
	// Integer is the canonical decimal text of an integer object.
	Integer string
	// Real is the value of a real object.
	Real float64
	// DateUnix is a date object's value in Unix seconds, meaningful only when
	// DateAvailable is true.
	DateUnix      int64
	DateAvailable bool
	// DataBytes is the declared length of a data object.
	DataBytes uint64
	// UID is the value of a UID object.
	UID uint64

	// Reachable reports that the object is reachable from TopObject within the
	// depth limit. An unreachable object is still inventoried.
	Reachable bool
	// Depth is the distance from TopObject, zero for the top object itself.
	Depth int
	// Limitations states, in deterministic order, why this object's view is
	// incomplete.
	Limitations []string
}

// Plist is one parsed property list.
type Plist struct {
	// Format is the representation that was parsed.
	Format Format
	// Version is the binary plist version such as "00", empty for XML.
	Version string
	// Objects is the inventory in document or object-table order.
	Objects []Object
	// TopObject is the index of the root value, or -1 when the root was
	// skipped by a limit.
	TopObject int
	// Truncated reports that the inventory is incomplete because an object,
	// string, or depth limit was reached.
	Truncated bool
	// Limitations states, in deterministic order, why the loaded inventory is
	// incomplete. It is empty only when the whole document was read.
	Limitations []string

	size   int64
	limits Limits
}

// Size returns the artifact size supplied to Parse.
func (p *Plist) Size() int64 {
	if p == nil {
		return 0
	}
	return p.size
}

// ObjectAt returns the object at index.
func (p *Plist) ObjectAt(index int) (*Object, error) {
	if p == nil || index < 0 || index >= len(p.Objects) {
		return nil, fmt.Errorf("%w: object %d", ErrOutOfRange, index)
	}
	return &p.Objects[index], nil
}

// Limits bounds parsing work. A zero or negative field selects the package
// default. Values above the package maximum are clamped to that maximum.
type Limits struct {
	// ArtifactBytes bounds the artifact size accepted by Parse.
	ArtifactBytes int64
	// Objects bounds the objects loaded.
	Objects int
	// Depth bounds how deep the object graph is walked.
	Depth int
	// StringBytes bounds one decoded string.
	StringBytes int
}

// DefaultLimits returns the package limits.
func DefaultLimits() Limits {
	return Limits{
		ArtifactBytes: MaxArtifactBytes,
		Objects:       MaxObjects,
		Depth:         MaxDepth,
		StringBytes:   MaxStringBytes,
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
	if l.Objects <= 0 {
		l.Objects = defaults.Objects
	}
	if l.Objects > MaxObjects {
		l.Objects = MaxObjects
	}
	if l.Depth <= 0 {
		l.Depth = defaults.Depth
	}
	if l.Depth > MaxDepth {
		l.Depth = MaxDepth
	}
	if l.StringBytes <= 0 {
		l.StringBytes = defaults.StringBytes
	}
	if l.StringBytes > MaxStringBytes {
		l.StringBytes = MaxStringBytes
	}
	return l
}

// Detect reports the representation of a property list from its first bytes.
// It returns FormatUnknown when the prefix does not look like a property list.
func Detect(prefix []byte) Format {
	if len(prefix) >= 8 && string(prefix[:6]) == "bplist" {
		return FormatBinary
	}
	trimmed := bytes.TrimLeft(prefix, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '<' {
		return FormatXML
	}
	return FormatUnknown
}

// Parse reads a property list with the package limits.
func Parse(r io.ReaderAt, size int64) (*Plist, error) {
	return ParseWithLimits(r, size, Limits{})
}

// ParseWithLimits reads a property list using limits.
//
// A structurally invalid artifact returns a nil plist and an error wrapping
// ErrInvalid, ErrTruncated, ErrLimit, or ErrRead. An object, string, or depth
// limit reached after the structure was validated returns a non-nil plist with
// Truncated set.
func ParseWithLimits(r io.ReaderAt, size int64, limits Limits) (*Plist, error) {
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

	prefix, err := readPrefix(r, size, 512)
	if err != nil {
		return nil, err
	}
	switch Detect(prefix) {
	case FormatBinary:
		return parseBinary(r, size, limits)
	case FormatXML:
		return parseXML(r, size, limits)
	default:
		return nil, fmt.Errorf("%w: not a property list", ErrInvalid)
	}
}

func (p *Plist) note(format string, args ...any) {
	p.Limitations = append(p.Limitations, fmt.Sprintf(format, args...))
}

// readPrefix returns up to n leading bytes without failing on a short artifact.
func readPrefix(r io.ReaderAt, size int64, n int) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}
	if int64(n) > size {
		n = int(size)
	}
	return readBytes(r, 0, n, size)
}

// readBytes reads exactly n bytes at offset inside an artifact of size bytes.
func readBytes(r io.ReaderAt, offset int64, n int, size int64) ([]byte, error) {
	if offset < 0 || n < 0 || offset > size || int64(n) > size-offset {
		return nil, fmt.Errorf("%w: %d bytes at offset %d extend beyond artifact size %d",
			ErrTruncated, n, offset, size)
	}
	buf := make([]byte, n)
	if n == 0 {
		return buf, nil
	}
	read, err := r.ReadAt(buf, offset)
	if read == n {
		return buf, nil
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("%w: %w", ErrRead, err)
	}
	return nil, fmt.Errorf("%w: short read of %d bytes at offset %d", ErrRead, n-read, offset)
}
