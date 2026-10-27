package elf

import (
	"bytes"
	"fmt"
	"unicode/utf8"
)

const (
	sectionTypeStrtab  = 3
	sectionTypeNote    = 7
	sectionTypeNoBits  = 8
	noteTypeGNUBuildID = 3

	maxNoteLimitations = 64
)

// SectionName returns the name stored for section index.
//
// Section 0 may have an empty name. A file with no section name table yields
// ErrUnavailable for other sections. Names longer than the configured limit,
// unterminated names, invalid UTF-8, and a name table of the wrong type are
// rejected.
func (f *File) SectionName(index int) (string, error) {
	sh, err := f.sectionHeader(index)
	if err != nil {
		return "", err
	}
	return f.sectionName(sh)
}

// SectionData returns a copy of the file contents of section index.
//
// SHT_NOBITS sections have no file contents and return ErrUnavailable. The
// declared range must be fully present and no larger than the configured
// section data limit; partial content is not returned.
func (f *File) SectionData(index int) ([]byte, error) {
	sh, err := f.sectionHeader(index)
	if err != nil {
		return nil, err
	}
	if sh.Type == sectionTypeNoBits {
		return nil, fmt.Errorf("%w: section %d has no file data", ErrUnavailable, index)
	}
	return f.readExactRange(sh.Offset, sh.Size, uint64(f.limits.SectionDataBytes), fmt.Sprintf("section %d", index))
}

// SegmentData returns a copy of the file contents covered by program header
// index.
//
// The declared file range must be fully present and no larger than the
// configured segment data limit.
func (f *File) SegmentData(index int) ([]byte, error) {
	ph, err := f.programHeader(index)
	if err != nil {
		return nil, err
	}
	return f.readExactRange(ph.Offset, ph.FileSize, uint64(f.limits.SegmentDataBytes), fmt.Sprintf("segment %d", index))
}

// Note is one entry from an SHT_NOTE section.
type Note struct {
	// SectionIndex is the section header index that contained the note.
	SectionIndex int
	// Name is the note owner name, with the trailing NUL removed. It is
	// limited to valid UTF-8.
	Name string
	// Type is the raw note type.
	Type uint32
	// Desc is a copy of the descriptor bytes.
	Desc []byte
}

// NoteSet is the result of scanning SHT_NOTE sections.
//
// Truncated reports that at least one note or note section was omitted because
// of a configured limit, a missing byte range, malformed note data, or an
// incomplete section header table. Limitations records the reasons in section
// order.
type NoteSet struct {
	Notes       []Note
	Truncated   bool
	Limitations []string
}

// Notes scans every loaded SHT_NOTE section for notes.
//
// Note headers use the artifact byte order. Incomplete, oversized, or
// non-UTF-8 entries are skipped with a limitation. Reader failures stop the
// scan and return ErrRead together with the notes collected so far.
func (f *File) Notes() (NoteSet, error) {
	var set NoteSet
	if uint64(len(f.SectionHeaders)) < f.Header.SectionHeaderCount {
		set.addLimitation("section header table is incomplete; note coverage is partial")
	}

	remaining := f.limits.NoteDataBytes
	for i, sh := range f.SectionHeaders {
		if sh.Type != sectionTypeNote || sh.Size == 0 {
			continue
		}
		if len(set.Notes) >= f.limits.Notes {
			set.addLimitation(fmt.Sprintf("note count exceeds limit %d", f.limits.Notes))
			break
		}
		if remaining <= 0 {
			set.addLimitation("note data limit reached")
			break
		}

		want := sh.Size
		if want > uint64(remaining) {
			want = uint64(remaining)
		}
		data, truncated, err := f.readSectionPrefix(sh, want)
		if err != nil {
			return set, err
		}
		remaining -= int64(len(data))
		if truncated {
			set.addLimitation(fmt.Sprintf("note section %d data truncated at %d bytes", i, len(data)))
		}
		if f.parseNotes(i, data, &set) {
			break
		}
	}
	return set, nil
}

// BuildID returns the descriptor of the unique GNU build-id note.
//
// Duplicate identical notes are accepted. Conflicting build IDs, an empty
// descriptor, and a descriptor above the configured limit are rejected. When
// the note scan is incomplete and no build-id was found, BuildID returns
// ErrUnavailable instead of claiming that the artifact has none.
func (f *File) BuildID() ([]byte, error) {
	set, err := f.Notes()
	if err != nil {
		return nil, err
	}

	var buildID []byte
	for _, note := range set.Notes {
		if note.Name != "GNU" || note.Type != noteTypeGNUBuildID {
			continue
		}
		if len(note.Desc) > f.limits.BuildIDBytes {
			return nil, fmt.Errorf("%w: GNU build-id descriptor exceeds %d bytes", ErrLimit, f.limits.BuildIDBytes)
		}
		if len(note.Desc) == 0 {
			return nil, fmt.Errorf("%w: empty GNU build-id descriptor", ErrInvalid)
		}
		if buildID == nil {
			buildID = note.Desc
			continue
		}
		if !bytes.Equal(buildID, note.Desc) {
			return nil, fmt.Errorf("%w: conflicting GNU build-id notes", ErrInvalid)
		}
	}
	if buildID == nil {
		if set.Truncated {
			return nil, fmt.Errorf("%w: GNU build-id not found in partial note coverage", ErrUnavailable)
		}
		return nil, fmt.Errorf("%w: GNU build-id", ErrNotFound)
	}
	return append([]byte(nil), buildID...), nil
}

// Comment returns the NUL-separated entries from every loaded section named
// .comment, in section and entry order.
//
// Empty entries are ignored. Entries must be UTF-8 and within the configured
// name, count, and section size limits. If no .comment section is present,
// Comment returns ErrNotFound; if the section table is incomplete, it returns
// ErrUnavailable rather than claiming absence.
func (f *File) Comment() ([]string, error) {
	entries := make([]string, 0)
	found := false
	for i, sh := range f.SectionHeaders {
		name, err := f.sectionName(sh)
		if err != nil {
			return nil, err
		}
		if name != ".comment" {
			continue
		}
		found = true
		if sh.Type == sectionTypeNoBits {
			if sh.Size > 0 {
				return nil, fmt.Errorf("%w: .comment section %d has no file data", ErrUnavailable, i)
			}
			continue
		}
		data, err := f.readExactRange(sh.Offset, sh.Size, uint64(f.limits.StringTableBytes), fmt.Sprintf(".comment section %d", i))
		if err != nil {
			return nil, err
		}
		for start := 0; start < len(data); {
			end := bytes.IndexByte(data[start:], 0)
			if end < 0 {
				end = len(data)
			} else {
				end += start
			}
			entry := data[start:end]
			if len(entry) > 0 {
				if len(entries) >= f.limits.CommentStrings {
					return nil, fmt.Errorf("%w: .comment entries exceed limit %d", ErrLimit, f.limits.CommentStrings)
				}
				if len(entry) > f.limits.NameBytes {
					return nil, fmt.Errorf("%w: .comment entry exceeds %d bytes", ErrLimit, f.limits.NameBytes)
				}
				if !utf8.Valid(entry) {
					return nil, fmt.Errorf("%w: .comment entry is not valid UTF-8", ErrInvalid)
				}
				entries = append(entries, string(entry))
			}
			start = end + 1
		}
	}
	if !found {
		if uint64(len(f.SectionHeaders)) < f.Header.SectionHeaderCount {
			return nil, fmt.Errorf("%w: .comment not found in partial section table", ErrUnavailable)
		}
		return nil, fmt.Errorf("%w: .comment", ErrNotFound)
	}
	return entries, nil
}

func (f *File) sectionHeader(index int) (SectionHeader, error) {
	if index < 0 {
		return SectionHeader{}, fmt.Errorf("%w: section %d", ErrOutOfRange, index)
	}
	if uint64(index) < uint64(len(f.SectionHeaders)) {
		return f.SectionHeaders[index], nil
	}
	if uint64(index) < f.Header.SectionHeaderCount {
		return SectionHeader{}, fmt.Errorf("%w: section %d is not loaded", ErrUnavailable, index)
	}
	return SectionHeader{}, fmt.Errorf("%w: section %d", ErrOutOfRange, index)
}

func (f *File) programHeader(index int) (ProgramHeader, error) {
	if index < 0 {
		return ProgramHeader{}, fmt.Errorf("%w: program %d", ErrOutOfRange, index)
	}
	if uint64(index) < uint64(len(f.ProgramHeaders)) {
		return f.ProgramHeaders[index], nil
	}
	if uint64(index) < f.Header.ProgramHeaderCount {
		return ProgramHeader{}, fmt.Errorf("%w: program %d is not loaded", ErrUnavailable, index)
	}
	return ProgramHeader{}, fmt.Errorf("%w: program %d", ErrOutOfRange, index)
}

func (f *File) sectionName(sh SectionHeader) (string, error) {
	tableIndex := f.Header.SectionNameIndex
	if tableIndex == 0 {
		if sh.Index == 0 {
			return "", nil
		}
		return "", fmt.Errorf("%w: no section name table", ErrUnavailable)
	}
	table, err := f.sectionHeader(int(tableIndex))
	if err != nil {
		return "", fmt.Errorf("%w: section name table %d", ErrUnavailable, tableIndex)
	}
	if table.Type != sectionTypeStrtab {
		return "", fmt.Errorf("%w: section name table has type %d", ErrInvalid, table.Type)
	}
	if table.Size > uint64(f.limits.StringTableBytes) {
		return "", fmt.Errorf("%w: section name table size %d exceeds %d", ErrLimit, table.Size, f.limits.StringTableBytes)
	}
	if table.Offset > uint64(f.size) || table.Size > uint64(f.size)-table.Offset {
		return "", fmt.Errorf("%w: section name table range is outside the artifact", ErrUnavailable)
	}
	nameOffset := uint64(sh.NameOffset)
	if nameOffset >= table.Size {
		return "", fmt.Errorf("%w: section name offset %d is outside table size %d", ErrInvalid, nameOffset, table.Size)
	}
	readSize := table.Size - nameOffset
	if readSize > uint64(f.limits.NameBytes) {
		readSize = uint64(f.limits.NameBytes)
	}
	buf := make([]byte, int(readSize))
	offset := table.Offset + nameOffset
	if err := readAt(f.reader, int64(offset), buf, f.size); err != nil {
		return "", err
	}
	nul := bytes.IndexByte(buf, 0)
	if nul < 0 {
		if readSize == uint64(f.limits.NameBytes) {
			return "", fmt.Errorf("%w: section name exceeds %d bytes", ErrLimit, f.limits.NameBytes)
		}
		return "", fmt.Errorf("%w: section name is not terminated", ErrInvalid)
	}
	name := buf[:nul]
	if !utf8.Valid(name) {
		return "", fmt.Errorf("%w: section name is not valid UTF-8", ErrInvalid)
	}
	return string(name), nil
}

func (f *File) readExactRange(offset, length, limit uint64, label string) ([]byte, error) {
	if length > limit {
		return nil, fmt.Errorf("%w: %s size %d exceeds limit %d", ErrLimit, label, length, limit)
	}
	if length == 0 {
		return []byte{}, nil
	}
	if offset > uint64(f.size) || length > uint64(f.size)-offset {
		return nil, fmt.Errorf("%w: %s range is outside the artifact", ErrUnavailable, label)
	}
	buf := make([]byte, int(length))
	if err := readAt(f.reader, int64(offset), buf, f.size); err != nil {
		return nil, err
	}
	return buf, nil
}

func (f *File) readSectionPrefix(sh SectionHeader, want uint64) ([]byte, bool, error) {
	if want > sh.Size {
		want = sh.Size
	}
	var available uint64
	if sh.Offset <= uint64(f.size) {
		available = uint64(f.size) - sh.Offset
	}
	length := want
	if length > available {
		length = available
	}
	truncated := length < sh.Size
	if length == 0 {
		return []byte{}, truncated, nil
	}
	buf := make([]byte, int(length))
	if err := readAt(f.reader, int64(sh.Offset), buf, f.size); err != nil {
		return nil, truncated, err
	}
	return buf, truncated, nil
}

func (f *File) parseNotes(sectionIndex int, data []byte, set *NoteSet) bool {
	order := byteOrder(f.Header.Data)
	for pos := 0; pos < len(data); {
		if len(set.Notes) >= f.limits.Notes {
			set.addLimitation(fmt.Sprintf("note count exceeds limit %d", f.limits.Notes))
			return true
		}
		if len(data)-pos < 12 {
			set.addLimitation(fmt.Sprintf("note section %d has %d trailing bytes", sectionIndex, len(data)-pos))
			return false
		}

		namesz := order.Uint32(data[pos : pos+4])
		descsz := order.Uint32(data[pos+4 : pos+8])
		noteType := order.Uint32(data[pos+8 : pos+12])
		nameStart := uint64(pos) + 12
		nameEnd := nameStart + uint64(namesz)
		descStart := nameStart + align4(uint64(namesz))
		descEnd := descStart + uint64(descsz)
		next := descStart + align4(uint64(descsz))
		if next > uint64(len(data)) {
			set.addLimitation(fmt.Sprintf("note section %d has an incomplete note at offset %d", sectionIndex, pos))
			return false
		}
		if namesz > uint32(f.limits.NameBytes) {
			set.addLimitation(fmt.Sprintf("note section %d note name exceeds limit %d", sectionIndex, f.limits.NameBytes))
			pos = int(next)
			continue
		}

		rawName := data[int(nameStart):int(nameEnd)]
		if nul := bytes.IndexByte(rawName, 0); nul >= 0 {
			rawName = rawName[:nul]
		}
		if !utf8.Valid(rawName) {
			set.addLimitation(fmt.Sprintf("note section %d note name is not valid UTF-8", sectionIndex))
			pos = int(next)
			continue
		}

		desc := append([]byte(nil), data[int(descStart):int(descEnd)]...)
		set.Notes = append(set.Notes, Note{
			SectionIndex: sectionIndex,
			Name:         string(rawName),
			Type:         noteType,
			Desc:         desc,
		})
		pos = int(next)
	}
	return false
}

func (s *NoteSet) addLimitation(reason string) {
	s.Truncated = true
	if len(s.Limitations) >= maxNoteLimitations {
		return
	}
	if len(s.Limitations) == maxNoteLimitations-1 {
		reason = "additional note limitations omitted"
	}
	s.Limitations = append(s.Limitations, reason)
}

func align4(value uint64) uint64 {
	return (value + 3) &^ 3
}
