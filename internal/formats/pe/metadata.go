package pe

import (
	"errors"
	"fmt"
)

// SectionData returns a copy of the raw contents of section index.
//
// A section with a zero SizeOfRawData has no file contents and returns an empty
// slice. The declared range must be fully present and no larger than the
// configured section data limit; partial content is not returned.
func (f *File) SectionData(index int) ([]byte, error) {
	section, err := f.sectionHeader(index)
	if err != nil {
		return nil, err
	}
	length := uint64(section.SizeOfRawData)
	if length == 0 {
		return []byte{}, nil
	}
	if length > uint64(f.limits.SectionDataBytes) {
		return nil, fmt.Errorf("%w: section %d size %d exceeds limit %d",
			ErrLimit, index, length, f.limits.SectionDataBytes)
	}
	offset := uint64(section.PointerToRawData)
	if offset > uint64(f.size) || length > uint64(f.size)-offset {
		return nil, fmt.Errorf("%w: section %d range is outside the artifact", ErrUnavailable, index)
	}
	buf := make([]byte, int(length))
	if err := readAt(f.reader, int64(offset), buf, f.size); err != nil {
		return nil, err
	}
	return buf, nil
}

// DataDirectory returns the loaded directory at index.
//
// A directory declared by the optional header but not loaded returns
// ErrUnavailable; an index outside the sixteen defined slots returns
// ErrOutOfRange.
func (f *File) DataDirectory(index int) (DataDirectory, error) {
	if index < 0 || index >= MaxDataDirectories {
		return DataDirectory{}, fmt.Errorf("%w: data directory %d", ErrOutOfRange, index)
	}
	if index < len(f.DataDirectories) {
		return f.DataDirectories[index], nil
	}
	if uint64(index) < uint64(f.Header.Optional.NumberOfRvaAndSizes) {
		return DataDirectory{}, fmt.Errorf("%w: data directory %d is not loaded", ErrUnavailable, index)
	}
	return DataDirectory{}, fmt.Errorf("%w: data directory %d", ErrOutOfRange, index)
}

// RVAMapping is the result of resolving a relative virtual address to a file
// offset.
type RVAMapping struct {
	// Offset is the file offset of the mapped byte. It is zero when FileBacked
	// is false.
	Offset uint64
	// SectionIndex is the section that contains the address, or -1 when the
	// address is inside the headers region or not mapped.
	SectionIndex int
	// FileBacked reports that the address has file bytes. A virtual-only tail,
	// such as uninitialized data beyond SizeOfRawData, is not file-backed.
	FileBacked bool
	// Ambiguous reports that more than one region contains the address. The
	// headers region wins over sections, and otherwise the first matching
	// section in table order wins.
	Ambiguous bool
}

// MapRVA resolves a relative virtual address through the headers region and
// the section table.
//
// A section covers an address from VirtualAddress up to the larger of
// VirtualSize and SizeOfRawData. The first match in table order wins; a second
// match only sets Ambiguous. Addresses outside every region return a mapping
// with SectionIndex -1 and FileBacked false.
func (f *File) MapRVA(rva uint32) RVAMapping {
	mapping := RVAMapping{SectionIndex: -1}
	matches := 0

	inHeaders := uint64(rva) < uint64(f.Header.Optional.SizeOfHeaders)
	if inHeaders {
		matches++
		mapping.Offset = uint64(rva)
		mapping.FileBacked = true
	}

	for _, section := range f.Sections {
		if rva < section.VirtualAddress {
			continue
		}
		delta := uint64(rva) - uint64(section.VirtualAddress)
		extent := uint64(section.VirtualSize)
		if uint64(section.SizeOfRawData) > extent {
			extent = uint64(section.SizeOfRawData)
		}
		if delta >= extent {
			continue
		}
		matches++
		if inHeaders || mapping.SectionIndex != -1 {
			continue
		}
		mapping.SectionIndex = section.Index
		if delta < uint64(section.SizeOfRawData) {
			mapping.FileBacked = true
			mapping.Offset = uint64(section.PointerToRawData) + delta
			continue
		}
		mapping.FileBacked = false
		mapping.Offset = 0
	}

	mapping.Ambiguous = matches > 1
	return mapping
}

// metadataDirectory returns the loaded directory at index and rejects absent or
// internally inconsistent address and size fields.
func (f *File) metadataDirectory(index int, name string) (DataDirectory, error) {
	directory, err := f.DataDirectory(index)
	if err != nil {
		if errors.Is(err, ErrOutOfRange) {
			return DataDirectory{}, fmt.Errorf("%w: %s directory is not declared", ErrNotFound, name)
		}
		if errors.Is(err, ErrUnavailable) {
			return DataDirectory{}, fmt.Errorf("%w: %s directory is not loaded", ErrUnavailable, name)
		}
		return DataDirectory{}, err
	}
	if directory.VirtualAddress == 0 && directory.Size == 0 {
		return DataDirectory{}, fmt.Errorf("%w: %s directory is absent", ErrNotFound, name)
	}
	if directory.VirtualAddress == 0 || directory.Size == 0 {
		return DataDirectory{}, fmt.Errorf("%w: %s directory has address %#x and size %d",
			ErrInvalid, name, directory.VirtualAddress, directory.Size)
	}
	return directory, nil
}
