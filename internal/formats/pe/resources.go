package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf16"
)

const (
	resourceDirectorySize  = 16
	resourceEntrySize      = 8
	resourceDataEntrySize  = 16
	resourceSubdirectory   = 0x80000000
	resourceNameOffsetMask = 0x7fffffff
)

// ResourceIdentifier is one level of a resource path: a named type, name, or
// language, or an integer identifier.
type ResourceIdentifier struct {
	// IsName reports that the level was stored as a name rather than an
	// integer identifier.
	IsName bool
	// Name is the decoded UTF-16 name. It is empty when NameAvailable is false.
	Name string
	// NameAvailable reports that Name was read and is valid UTF-16.
	NameAvailable bool
	// ID is the integer identifier. It is zero for a named level.
	ID uint32
}

// Resource is one leaf data entry with its path from the root type level.
type Resource struct {
	// Path holds the identifiers from the root directory down to the leaf.
	Path []ResourceIdentifier
	// DataRVA and DataSize are the declared resource data address and length.
	// The data is not read by Resources.
	DataRVA  uint32
	DataSize uint32
	CodePage uint32
	// DataAvailable reports that the declared data range is file-backed. An
	// empty resource is available.
	DataAvailable bool
}

// ResourceTable is the decoded resource directory tree.
type ResourceTable struct {
	// Resources holds the leaves in depth-first on-disk order.
	Resources []Resource

	// Truncated reports that the tree is incomplete because of a configured
	// limit, a short directory, or an exhausted string budget.
	Truncated bool
	// Limitations states, in deterministic order, why the tree is incomplete
	// or which names and data ranges could not be used.
	Limitations []string
}

func (t *ResourceTable) limit(format string, args ...any) {
	t.Limitations = append(t.Limitations, fmt.Sprintf(format, args...))
}

// Resources reads the resource directory tree.
//
// An absent directory returns ErrNotFound. An inconsistent directory address
// or size returns ErrInvalid. A directory range outside the artifact returns
// ErrUnavailable. A tree that is cut short by the artifact or a configured
// limit returns a partial table with Truncated set and a deterministic
// limitation. Resource data is not read; only its declared range is checked.
func (f *File) Resources() (*ResourceTable, error) {
	directory, err := f.metadataDirectory(2, "resource")
	if err != nil {
		return nil, err
	}
	start, maximum, err := f.fileRange(directory.VirtualAddress)
	if err != nil {
		return nil, err
	}
	size := uint64(directory.Size)
	if int64(size) > maximum {
		return nil, fmt.Errorf("%w: resource directory range is outside the file-backed region", ErrUnavailable)
	}

	table := &ResourceTable{}
	state := &resourceState{
		file:   f,
		table:  table,
		start:  start,
		size:   size,
		budget: f.limits.ResourceStringBytes,
	}
	if err := state.walk(); err != nil {
		return nil, err
	}
	state.finish()
	return table, nil
}

// resourceState tracks one resource walk, including the shared entry and name
// budgets.
type resourceState struct {
	file   *File
	table  *ResourceTable
	start  uint64
	size   uint64
	budget int64

	entries int
	stopped bool

	namesUnavailable int
	namesInvalid     int
	namesLimited     int
	dataOutside      int
	dataNotBacked    int
	budgetHit        bool
}

// resourceItem is a pending directory or leaf. The stack holds items in the
// reverse of on-disk order so that popping yields depth-first on-disk order.
type resourceItem struct {
	directory bool
	offset    uint32
	depth     int
	path      []ResourceIdentifier
	leaf      Resource
}

func (s *resourceState) walk() error {
	stack := []resourceItem{{directory: true, offset: 0}}
	for len(stack) > 0 && !s.stopped {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if !item.directory {
			s.table.Resources = append(s.table.Resources, item.leaf)
			continue
		}
		children, err := s.directory(item)
		if err != nil {
			return err
		}
		for i := len(children) - 1; i >= 0; i-- {
			stack = append(stack, children[i])
		}
	}
	return nil
}

func (s *resourceState) directory(item resourceItem) ([]resourceItem, error) {
	header, err := s.read(item.offset, resourceDirectorySize)
	if err != nil {
		if errors.Is(err, ErrRead) {
			return nil, err
		}
		s.table.Truncated = true
		s.table.limit("resource directory at offset %#x is unavailable", item.offset)
		return nil, nil
	}

	named := int(binary.LittleEndian.Uint16(header[12:]))
	identifiers := int(binary.LittleEndian.Uint16(header[14:]))
	declared := named + identifiers
	if declared == 0 {
		return nil, nil
	}

	remaining := s.size - uint64(item.offset) - resourceDirectorySize
	fits := int(remaining / resourceEntrySize)
	loaded := declared
	if loaded > fits {
		s.table.Truncated = true
		s.table.limit("resource directory at offset %#x declares %d entries but only %d fit",
			item.offset, declared, fits)
		loaded = fits
	}
	limited := false
	if loaded > s.file.limits.ResourceEntries-s.entries {
		loaded = s.file.limits.ResourceEntries - s.entries
		s.table.Truncated = true
		s.table.limit("resource entry count exceeds limit %d", s.file.limits.ResourceEntries)
		limited = true
	}
	if loaded <= 0 {
		return nil, nil
	}

	offset := uint64(item.offset) + resourceDirectorySize
	raw, err := s.read(uint32(offset), loaded*resourceEntrySize)
	if err != nil {
		if errors.Is(err, ErrRead) {
			return nil, err
		}
		s.table.Truncated = true
		s.table.limit("resource directory entries at offset %#x are unavailable", item.offset)
		return nil, nil
	}
	s.entries += loaded

	children := make([]resourceItem, 0, loaded)
	for i := 0; i < loaded; i++ {
		entry := raw[i*resourceEntrySize:]
		nameField := binary.LittleEndian.Uint32(entry[0:])
		offsetField := binary.LittleEndian.Uint32(entry[4:])

		identifier := ResourceIdentifier{}
		if nameField&resourceSubdirectory != 0 {
			identifier.IsName = true
			offset := nameField & resourceNameOffsetMask
			name, issue, err := s.name(offset)
			if err != nil {
				return nil, err
			}
			switch issue {
			case resourceNameOK:
				identifier.Name = name
				identifier.NameAvailable = true
			case resourceNameInvalid:
				s.namesInvalid++
			case resourceNameLimit:
				s.namesLimited++
				if s.budget <= 0 {
					s.budgetHit = true
				}
			default:
				s.namesUnavailable++
			}
		} else {
			identifier.ID = nameField
		}
		path := append(append([]ResourceIdentifier(nil), item.path...), identifier)

		if offsetField&resourceSubdirectory != 0 {
			childOffset := offsetField & resourceNameOffsetMask
			if item.depth >= s.file.limits.ResourceDepth {
				s.table.Truncated = true
				s.table.limit("resource directory nesting exceeds limit %d", s.file.limits.ResourceDepth)
				continue
			}
			if uint64(childOffset)+resourceDirectorySize > s.size {
				s.table.Truncated = true
				s.table.limit("resource subdirectory at offset %#x is outside the resource directory", childOffset)
				continue
			}
			children = append(children, resourceItem{
				directory: true,
				offset:    childOffset,
				depth:     item.depth + 1,
				path:      path,
			})
			continue
		}

		leaf, err := s.leaf(offsetField, path)
		if err != nil {
			return nil, err
		}
		if leaf == nil {
			continue
		}
		children = append(children, resourceItem{leaf: *leaf})
	}
	if limited {
		// The declared entry list does not fit the shared budget. Stop the walk
		// instead of reporting a prefix as if it were the whole directory.
		s.stopped = true
		return nil, nil
	}
	return children, nil
}

// leaf reads one resource data entry and checks whether its declared data
// range is file-backed.
func (s *resourceState) leaf(offset uint32, path []ResourceIdentifier) (*Resource, error) {
	raw, err := s.read(offset, resourceDataEntrySize)
	if err != nil {
		if errors.Is(err, ErrRead) {
			return nil, err
		}
		s.dataOutside++
		s.table.Truncated = true
		return nil, nil
	}
	resource := &Resource{
		Path:     path,
		DataRVA:  binary.LittleEndian.Uint32(raw[0:]),
		DataSize: binary.LittleEndian.Uint32(raw[4:]),
		CodePage: binary.LittleEndian.Uint32(raw[8:]),
	}
	if resource.DataSize == 0 {
		resource.DataAvailable = true
		return resource, nil
	}
	_, maximum, mappingErr := s.file.fileRange(resource.DataRVA)
	if mappingErr == nil && int64(resource.DataSize) <= maximum {
		resource.DataAvailable = true
		return resource, nil
	}
	s.dataNotBacked++
	return resource, nil
}

type resourceNameIssue int

const (
	resourceNameOK resourceNameIssue = iota
	resourceNameUnavailable
	resourceNameInvalid
	resourceNameLimit
)

// name reads an IMAGE_RESOURCE_DIR_STRING_U at a directory-relative offset.
func (s *resourceState) name(offset uint32) (string, resourceNameIssue, error) {
	if s.budget <= 0 {
		return "", resourceNameLimit, nil
	}
	raw, err := s.read(offset, 2)
	if err != nil {
		if errors.Is(err, ErrRead) {
			return "", resourceNameUnavailable, err
		}
		return "", resourceNameUnavailable, nil
	}
	units := uint64(binary.LittleEndian.Uint16(raw))
	length := units * 2
	if length > uint64(s.file.limits.StringBytes) {
		return "", resourceNameLimit, nil
	}
	if int64(length)+2 > s.budget {
		s.budget = 0
		return "", resourceNameLimit, nil
	}
	if length > 0 {
		raw, err = s.read(offset+2, int(length))
		if err != nil {
			if errors.Is(err, ErrRead) {
				return "", resourceNameUnavailable, err
			}
			return "", resourceNameUnavailable, nil
		}
	}
	s.budget -= int64(length) + 2
	name, ok := decodeResourceName(raw[:length])
	if !ok {
		return "", resourceNameInvalid, nil
	}
	return name, resourceNameOK, nil
}

// decodeResourceName converts little-endian UTF-16 bytes to a string, rejecting
// unpaired surrogates instead of replacing them.
func decodeResourceName(raw []byte) (string, bool) {
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	for i := 0; i < len(units); i++ {
		unit := units[i]
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if i+1 >= len(units) {
				return "", false
			}
			low := units[i+1]
			if low < 0xdc00 || low > 0xdfff {
				return "", false
			}
			i++
		case unit >= 0xdc00 && unit <= 0xdfff:
			return "", false
		}
	}
	return string(utf16.Decode(units)), true
}

// read returns length bytes at a resource-directory-relative offset. The whole
// range must fit inside the declared resource directory.
func (s *resourceState) read(offset uint32, length int) ([]byte, error) {
	if uint64(offset) > s.size || uint64(length) > s.size-uint64(offset) {
		return nil, fmt.Errorf("%w: resource structure at offset %#x is outside the %d-byte directory",
			ErrUnavailable, offset, s.size)
	}
	if uint64(length) > math.MaxInt32 {
		return nil, fmt.Errorf("%w: resource read of %d bytes", ErrLimit, length)
	}
	buf := make([]byte, length)
	if err := readAt(s.file.reader, int64(s.start+uint64(offset)), buf, s.file.size); err != nil {
		return nil, err
	}
	return buf, nil
}

func (s *resourceState) finish() {
	table := s.table
	if s.budgetHit {
		table.Truncated = true
		table.limit("resource string budget exhausted; later names are unavailable")
	}
	if s.namesUnavailable > 0 {
		table.limit("%d resource names are unavailable", s.namesUnavailable)
	}
	if s.namesInvalid > 0 {
		table.limit("%d resource names are not valid UTF-16", s.namesInvalid)
	}
	if s.namesLimited > 0 {
		table.limit("%d resource names exceed the string limit", s.namesLimited)
	}
	if s.dataOutside > 0 {
		table.limit("%d resource data entries are outside the resource directory", s.dataOutside)
	}
	if s.dataNotBacked > 0 {
		table.limit("%d resource data ranges are not file-backed", s.dataNotBacked)
	}
}
