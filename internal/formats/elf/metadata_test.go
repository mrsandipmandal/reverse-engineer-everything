package elf_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	reeelf "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/elf"
)

var (
	metadataNames = []byte("\x00.shstrtab\x00.note.gnu.build-id\x00.comment\x00.text\x00.bss\x00")
	testBuildID   = []byte{
		0x2e, 0x1a, 0x9f, 0x4c, 0x11, 0x8b, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	metadataComment = []byte("Go\tgo1.26.10\x00gcc 13.2.0\x00\x00")
	metadataText    = []byte{0x90, 0xc3}
)

func buildMetadataFixture(class reeelf.Class, data reeelf.Data, noteData []byte) fixture {
	return buildMetadataFixtureWithComment(class, data, noteData, metadataComment)
}

func buildMetadataFixtureWithComment(class reeelf.Class, data reeelf.Data, noteData, commentData []byte) fixture {
	f := fixture{class: class, order: binary.LittleEndian}
	if data == reeelf.DataBig {
		f.order = binary.BigEndian
	}
	switch class {
	case reeelf.Class64:
		f.headerSize = 64
		f.sectionSize = 64
		f.programSize = 56
	case reeelf.Class32:
		f.headerSize = 52
		f.sectionSize = 40
		f.programSize = 32
	default:
		panic("unsupported fixture class")
	}
	f.programStart = f.headerSize
	f.sectionStart = f.programStart + 2*f.programSize
	tableEnd := f.sectionStart + 6*f.sectionSize

	cursor := alignUp(tableEnd, 8)
	f.nameTableOffset = cursor
	cursor = alignUp(cursor+len(metadataNames), 4)
	f.noteOffset = cursor
	cursor = alignUp(cursor+len(noteData), 4)
	f.commentOffset = cursor
	cursor = alignUp(cursor+len(commentData), 4)
	f.textOffset = cursor
	cursor = alignUp(cursor+len(metadataText), 8)
	f.data = make([]byte, cursor)

	buf := f.data
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = byte(class)
	buf[5] = byte(data)
	buf[6] = 1

	machine := uint16(62)
	entry := uint64(0x401000)
	base := uint64(0x400000)
	if class == reeelf.Class32 {
		machine = 3
		entry = 0x8049000
		base = 0x8048000
	}
	f.put16(16, elfTypeExec)
	f.put16(18, machine)
	f.put32(20, 1)
	if class == reeelf.Class64 {
		f.put64(24, entry)
		f.put64(32, uint64(f.programStart))
		f.put64(40, uint64(f.sectionStart))
	} else {
		f.put32(24, uint32(entry))
		f.put32(28, uint32(f.programStart))
		f.put32(32, uint32(f.sectionStart))
	}
	f.put16(f.headerSizeOffset(), uint16(f.headerSize))
	f.put16(f.programEntrySizeOffset(), uint16(f.programSize))
	f.put16(f.programCountOffset(), 2)
	f.put16(f.sectionEntrySizeOffset(), uint16(f.sectionSize))
	f.put16(f.sectionCountOffset(), 6)
	f.put16(f.sectionNameIndexOffset(), 1)

	total := uint64(len(buf))
	f.writeProgram(0, programTypeLoad, 5, 0, base, base, total, total+0x1000, 0x1000)
	f.writeProgram(1, 4, 4, uint64(f.noteOffset), base+uint64(f.noteOffset), base+uint64(f.noteOffset),
		uint64(len(noteData)), uint64(len(noteData)), 4)

	f.writeSection(1, metadataName(".shstrtab"), 3, 0, 0, uint64(f.nameTableOffset), uint64(len(metadataNames)), 1)
	f.writeSection(2, metadataName(".note.gnu.build-id"), 7, 2, 0, uint64(f.noteOffset), uint64(len(noteData)), 4)
	f.writeSection(3, metadataName(".comment"), 1, 0, 0, uint64(f.commentOffset), uint64(len(commentData)), 1)
	f.writeSection(4, metadataName(".text"), 1, 6, base+0x1000, uint64(f.textOffset), uint64(len(metadataText)), 16)
	f.writeSection(5, metadataName(".bss"), 8, 3, base+0x2000, 0, 0x1000, 16)

	copy(buf[f.nameTableOffset:], metadataNames)
	copy(buf[f.noteOffset:], noteData)
	copy(buf[f.commentOffset:], commentData)
	copy(buf[f.textOffset:], metadataText)
	return f
}

func metadataName(name string) uint32 {
	return uint32(bytes.Index(metadataNames, []byte(name)))
}

func alignUp(value, alignment int) int {
	return (value + alignment - 1) &^ (alignment - 1)
}

func buildNote(order binary.ByteOrder, name string, noteType uint32, desc []byte) []byte {
	nameBytes := append([]byte(name), 0)
	namesz := alignUp(len(nameBytes), 4)
	descsz := alignUp(len(desc), 4)
	buf := make([]byte, 12+namesz+descsz)
	order.PutUint32(buf[0:4], uint32(len(nameBytes)))
	order.PutUint32(buf[4:8], uint32(len(desc)))
	order.PutUint32(buf[8:12], noteType)
	copy(buf[12:], nameBytes)
	copy(buf[12+namesz:], desc)
	return buf
}

func metadataNotes(data reeelf.Data) []byte {
	order := byteOrderFor(data)
	first := buildNote(order, "GNU", 3, testBuildID)
	second := buildNote(order, "CORE", 1, []byte{1, 2, 3, 4})
	return append(first, second...)
}

func byteOrderFor(data reeelf.Data) binary.ByteOrder {
	if data == reeelf.DataBig {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func parseMetadata(t *testing.T, f fixture, limits reeelf.Limits) *reeelf.File {
	t.Helper()
	got, err := parse(t, f.data, int64(len(f.data)), limits)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return got
}

func TestSectionNames(t *testing.T) {
	t.Parallel()

	f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
	got := parseMetadata(t, f, reeelf.DefaultLimits())
	want := []string{"", ".shstrtab", ".note.gnu.build-id", ".comment", ".text", ".bss"}
	for i, name := range want {
		actual, err := got.SectionName(i)
		if err != nil {
			t.Fatalf("SectionName(%d) error = %v", i, err)
		}
		if actual != name {
			t.Fatalf("SectionName(%d) = %q, want %q", i, actual, name)
		}
	}
	if _, err := got.SectionName(-1); !errors.Is(err, reeelf.ErrOutOfRange) {
		t.Fatalf("SectionName(-1) error = %v, want ErrOutOfRange", err)
	}
	if _, err := got.SectionName(6); !errors.Is(err, reeelf.ErrOutOfRange) {
		t.Fatalf("SectionName(6) error = %v, want ErrOutOfRange", err)
	}
}

func TestSectionNameErrors(t *testing.T) {
	t.Parallel()

	t.Run("no name table", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		f.put16(f.sectionNameIndexOffset(), 0)
		got := parseMetadata(t, f, reeelf.DefaultLimits())
		if name, err := got.SectionName(0); err != nil || name != "" {
			t.Fatalf("SectionName(0) = %q, %v; want empty string", name, err)
		}
		if _, err := got.SectionName(1); !errors.Is(err, reeelf.ErrUnavailable) {
			t.Fatalf("SectionName(1) error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("truncated section table", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		cut := f.sectionStart + f.sectionSize
		got, err := parse(t, f.data[:cut], int64(cut), reeelf.DefaultLimits())
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if _, err := got.SectionName(5); !errors.Is(err, reeelf.ErrUnavailable) {
			t.Fatalf("SectionName(5) error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("invalid name offset", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		f.put32(f.sectionStart+f.sectionSize, uint32(len(metadataNames)))
		got := parseMetadata(t, f, reeelf.DefaultLimits())
		if _, err := got.SectionName(1); !errors.Is(err, reeelf.ErrInvalid) {
			t.Fatalf("SectionName(1) error = %v, want ErrInvalid", err)
		}
	})

	t.Run("wrong table type", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		f.put32(f.sectionStart+f.sectionSize+4, 1)
		got := parseMetadata(t, f, reeelf.DefaultLimits())
		if _, err := got.SectionName(1); !errors.Is(err, reeelf.ErrInvalid) {
			t.Fatalf("SectionName(1) error = %v, want ErrInvalid", err)
		}
	})

	t.Run("table size limit", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		limits := reeelf.DefaultLimits()
		limits.StringTableBytes = 4
		got := parseMetadata(t, f, limits)
		if _, err := got.SectionName(1); !errors.Is(err, reeelf.ErrLimit) {
			t.Fatalf("SectionName(1) error = %v, want ErrLimit", err)
		}
	})

	t.Run("data outside artifact", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		cut := f.sectionStart + 6*f.sectionSize
		got, err := parse(t, f.data[:cut], int64(cut), reeelf.DefaultLimits())
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if _, err := got.SectionName(1); !errors.Is(err, reeelf.ErrUnavailable) {
			t.Fatalf("SectionName(1) error = %v, want ErrUnavailable", err)
		}
	})
}

func TestSectionData(t *testing.T) {
	t.Parallel()

	f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
	got := parseMetadata(t, f, reeelf.DefaultLimits())

	tests := []struct {
		index int
		want  []byte
	}{
		{index: 1, want: metadataNames},
		{index: 2, want: metadataNotes(reeelf.DataLittle)},
		{index: 3, want: metadataComment},
		{index: 4, want: metadataText},
	}
	for _, tt := range tests {
		data, err := got.SectionData(tt.index)
		if err != nil {
			t.Fatalf("SectionData(%d) error = %v", tt.index, err)
		}
		if !bytes.Equal(data, tt.want) {
			t.Fatalf("SectionData(%d) = %x, want %x", tt.index, data, tt.want)
		}
	}
	if _, err := got.SectionData(5); !errors.Is(err, reeelf.ErrUnavailable) {
		t.Fatalf("SectionData(5) error = %v, want ErrUnavailable", err)
	}
	if _, err := got.SectionData(6); !errors.Is(err, reeelf.ErrOutOfRange) {
		t.Fatalf("SectionData(6) error = %v, want ErrOutOfRange", err)
	}
}

func TestSectionDataLimitsAndRanges(t *testing.T) {
	t.Parallel()

	t.Run("limit", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		limits := reeelf.DefaultLimits()
		limits.SectionDataBytes = 3
		got := parseMetadata(t, f, limits)
		if _, err := got.SectionData(1); !errors.Is(err, reeelf.ErrLimit) {
			t.Fatalf("SectionData(1) error = %v, want ErrLimit", err)
		}
	})

	t.Run("outside artifact", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		cut := f.sectionStart + 6*f.sectionSize
		got, err := parse(t, f.data[:cut], int64(cut), reeelf.DefaultLimits())
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if _, err := got.SectionData(4); !errors.Is(err, reeelf.ErrUnavailable) {
			t.Fatalf("SectionData(4) error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("reader failure", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		reader := &limitedReader{data: f.data, failAt: int64(f.nameTableOffset)}
		got, err := reeelf.Parse(reader, int64(len(f.data)))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if _, err := got.SectionData(1); !errors.Is(err, reeelf.ErrRead) {
			t.Fatalf("SectionData(1) error = %v, want ErrRead", err)
		}
	})
}

func TestSegmentData(t *testing.T) {
	t.Parallel()

	f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
	got := parseMetadata(t, f, reeelf.DefaultLimits())

	data, err := got.SegmentData(0)
	if err != nil {
		t.Fatalf("SegmentData(0) error = %v", err)
	}
	if !bytes.Equal(data, f.data) {
		t.Fatalf("SegmentData(0) length = %d, want %d", len(data), len(f.data))
	}
	noteData := metadataNotes(reeelf.DataLittle)
	data, err = got.SegmentData(1)
	if err != nil {
		t.Fatalf("SegmentData(1) error = %v", err)
	}
	if !bytes.Equal(data, noteData) {
		t.Fatalf("SegmentData(1) = %x, want %x", data, noteData)
	}
	if _, err := got.SegmentData(2); !errors.Is(err, reeelf.ErrOutOfRange) {
		t.Fatalf("SegmentData(2) error = %v, want ErrOutOfRange", err)
	}
	if _, err := got.SegmentData(-1); !errors.Is(err, reeelf.ErrOutOfRange) {
		t.Fatalf("SegmentData(-1) error = %v, want ErrOutOfRange", err)
	}

	limits := reeelf.DefaultLimits()
	limits.SegmentDataBytes = 3
	limited := parseMetadata(t, f, limits)
	if _, err := limited.SegmentData(1); !errors.Is(err, reeelf.ErrLimit) {
		t.Fatalf("limited SegmentData(1) error = %v, want ErrLimit", err)
	}

	limits = reeelf.DefaultLimits()
	limits.ProgramHeaders = 1
	partial := parseMetadata(t, f, limits)
	if _, err := partial.SegmentData(1); !errors.Is(err, reeelf.ErrUnavailable) {
		t.Fatalf("partial SegmentData(1) error = %v, want ErrUnavailable", err)
	}
}

func TestNotes(t *testing.T) {
	t.Parallel()

	class := reeelf.Class64
	data := reeelf.DataLittle
	noteData := metadataNotes(data)
	f := buildMetadataFixture(class, data, noteData)
	got := parseMetadata(t, f, reeelf.DefaultLimits())

	set, err := got.Notes()
	if err != nil {
		t.Fatalf("Notes() error = %v", err)
	}
	if set.Truncated || len(set.Limitations) != 0 {
		t.Fatalf("Notes() truncation = %t, limitations = %v", set.Truncated, set.Limitations)
	}
	if len(set.Notes) != 2 {
		t.Fatalf("Notes() count = %d, want 2", len(set.Notes))
	}
	if note := set.Notes[0]; note.SectionIndex != 2 || note.Name != "GNU" || note.Type != 3 || !bytes.Equal(note.Desc, testBuildID) {
		t.Fatalf("note 0 = %+v", note)
	}
	if note := set.Notes[1]; note.SectionIndex != 2 || note.Name != "CORE" || note.Type != 1 || !bytes.Equal(note.Desc, []byte{1, 2, 3, 4}) {
		t.Fatalf("note 1 = %+v", note)
	}
}

func TestNotesBigEndian32(t *testing.T) {
	t.Parallel()

	data := reeelf.DataBig
	noteData := metadataNotes(data)
	f := buildMetadataFixture(reeelf.Class32, data, noteData)
	got := parseMetadata(t, f, reeelf.DefaultLimits())

	set, err := got.Notes()
	if err != nil {
		t.Fatalf("Notes() error = %v", err)
	}
	if set.Truncated || len(set.Notes) != 2 {
		t.Fatalf("Notes() = %d notes, truncated %t", len(set.Notes), set.Truncated)
	}
	if set.Notes[0].Name != "GNU" || !bytes.Equal(set.Notes[0].Desc, testBuildID) {
		t.Fatalf("note 0 = %+v", set.Notes[0])
	}
	id, err := got.BuildID()
	if err != nil {
		t.Fatalf("BuildID() error = %v", err)
	}
	if !bytes.Equal(id, testBuildID) {
		t.Fatalf("BuildID() = %x, want %x", id, testBuildID)
	}
}

func TestNotesLimitsAndMalformedData(t *testing.T) {
	t.Parallel()

	t.Run("note count limit", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		limits := reeelf.DefaultLimits()
		limits.Notes = 1
		got := parseMetadata(t, f, limits)
		set, err := got.Notes()
		if err != nil {
			t.Fatalf("Notes() error = %v", err)
		}
		if !set.Truncated || len(set.Notes) != 1 {
			t.Fatalf("Notes() = %d notes, truncated %t", len(set.Notes), set.Truncated)
		}
		if len(set.Limitations) == 0 || set.Limitations[0] != "note count exceeds limit 1" {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("note data limit", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		limits := reeelf.DefaultLimits()
		limits.NoteDataBytes = 16
		got := parseMetadata(t, f, limits)
		set, err := got.Notes()
		if err != nil {
			t.Fatalf("Notes() error = %v", err)
		}
		if !set.Truncated || len(set.Notes) != 0 {
			t.Fatalf("Notes() = %d notes, truncated %t", len(set.Notes), set.Truncated)
		}
	})

	t.Run("malformed descriptor size", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		f.order.PutUint32(f.data[f.noteOffset+4:f.noteOffset+8], 0xfffffff0)
		got := parseMetadata(t, f, reeelf.DefaultLimits())
		set, err := got.Notes()
		if err != nil {
			t.Fatalf("Notes() error = %v", err)
		}
		if !set.Truncated || len(set.Notes) != 0 {
			t.Fatalf("Notes() = %d notes, truncated %t", len(set.Notes), set.Truncated)
		}
	})

	t.Run("invalid note name", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		f.data[f.noteOffset+12] = 0xff
		got := parseMetadata(t, f, reeelf.DefaultLimits())
		set, err := got.Notes()
		if err != nil {
			t.Fatalf("Notes() error = %v", err)
		}
		if !set.Truncated || len(set.Notes) != 1 || set.Notes[0].Name != "CORE" {
			t.Fatalf("Notes() = %+v, truncated %t", set.Notes, set.Truncated)
		}
	})

	t.Run("note data outside artifact", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		cut := f.noteOffset
		got, err := parse(t, f.data[:cut], int64(cut), reeelf.DefaultLimits())
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		set, err := got.Notes()
		if err != nil {
			t.Fatalf("Notes() error = %v", err)
		}
		if !set.Truncated || len(set.Notes) != 0 {
			t.Fatalf("Notes() = %d notes, truncated %t", len(set.Notes), set.Truncated)
		}
	})
}

func TestBuildID(t *testing.T) {
	t.Parallel()

	f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
	got := parseMetadata(t, f, reeelf.DefaultLimits())
	id, err := got.BuildID()
	if err != nil {
		t.Fatalf("BuildID() error = %v", err)
	}
	if !bytes.Equal(id, testBuildID) {
		t.Fatalf("BuildID() = %x, want %x", id, testBuildID)
	}

	base := buildFixture(reeelf.Class64, reeelf.DataLittle)
	plain := parseMetadata(t, base, reeelf.DefaultLimits())
	if _, err := plain.BuildID(); !errors.Is(err, reeelf.ErrNotFound) {
		t.Fatalf("BuildID() error = %v, want ErrNotFound", err)
	}
}

func TestBuildIDErrors(t *testing.T) {
	t.Parallel()

	t.Run("descriptor limit", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		limits := reeelf.DefaultLimits()
		limits.BuildIDBytes = 4
		got := parseMetadata(t, f, limits)
		if _, err := got.BuildID(); !errors.Is(err, reeelf.ErrLimit) {
			t.Fatalf("BuildID() error = %v, want ErrLimit", err)
		}
	})

	t.Run("unavailable notes", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		limits := reeelf.DefaultLimits()
		limits.NoteDataBytes = 8
		got := parseMetadata(t, f, limits)
		if _, err := got.BuildID(); !errors.Is(err, reeelf.ErrUnavailable) {
			t.Fatalf("BuildID() error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("conflicting notes", func(t *testing.T) {
		t.Parallel()

		other := append([]byte(nil), testBuildID...)
		other[0] ^= 0xff
		order := byteOrderFor(reeelf.DataLittle)
		notes := append(buildNote(order, "GNU", 3, testBuildID), buildNote(order, "GNU", 3, other)...)
		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, notes)
		got := parseMetadata(t, f, reeelf.DefaultLimits())
		if _, err := got.BuildID(); !errors.Is(err, reeelf.ErrInvalid) {
			t.Fatalf("BuildID() error = %v, want ErrInvalid", err)
		}
	})

	t.Run("empty descriptor", func(t *testing.T) {
		t.Parallel()

		order := byteOrderFor(reeelf.DataLittle)
		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, buildNote(order, "GNU", 3, nil))
		got := parseMetadata(t, f, reeelf.DefaultLimits())
		if _, err := got.BuildID(); !errors.Is(err, reeelf.ErrInvalid) {
			t.Fatalf("BuildID() error = %v, want ErrInvalid", err)
		}
	})
}

func TestComment(t *testing.T) {
	t.Parallel()

	f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
	got := parseMetadata(t, f, reeelf.DefaultLimits())
	entries, err := got.Comment()
	if err != nil {
		t.Fatalf("Comment() error = %v", err)
	}
	want := []string{"Go\tgo1.26.10", "gcc 13.2.0"}
	if len(entries) != len(want) {
		t.Fatalf("Comment() = %q, want %q", entries, want)
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Fatalf("Comment()[%d] = %q, want %q", i, entries[i], want[i])
		}
	}

	base := buildFixture(reeelf.Class64, reeelf.DataLittle)
	plain := parseMetadata(t, base, reeelf.DefaultLimits())
	if _, err := plain.Comment(); !errors.Is(err, reeelf.ErrNotFound) {
		t.Fatalf("Comment() error = %v, want ErrNotFound", err)
	}
}

func TestCommentErrors(t *testing.T) {
	t.Parallel()

	t.Run("invalid UTF-8", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		f.data[f.commentOffset+3] = 0xff
		got := parseMetadata(t, f, reeelf.DefaultLimits())
		if _, err := got.Comment(); !errors.Is(err, reeelf.ErrInvalid) {
			t.Fatalf("Comment() error = %v, want ErrInvalid", err)
		}
	})

	t.Run("entry limit", func(t *testing.T) {
		t.Parallel()

		longEntry := []byte("a comment entry longer than the name limit\x00")
		f := buildMetadataFixtureWithComment(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle), longEntry)
		limits := reeelf.DefaultLimits()
		limits.NameBytes = 20
		got := parseMetadata(t, f, limits)
		if _, err := got.Comment(); !errors.Is(err, reeelf.ErrLimit) {
			t.Fatalf("Comment() error = %v, want ErrLimit", err)
		}
	})

	t.Run("count limit", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		limits := reeelf.DefaultLimits()
		limits.CommentStrings = 1
		got := parseMetadata(t, f, limits)
		if _, err := got.Comment(); !errors.Is(err, reeelf.ErrLimit) {
			t.Fatalf("Comment() error = %v, want ErrLimit", err)
		}
	})

	t.Run("section size limit", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		f.put64(f.sectionStart+3*f.sectionSize+32, 100)
		limits := reeelf.DefaultLimits()
		limits.StringTableBytes = 60
		got := parseMetadata(t, f, limits)
		if _, err := got.Comment(); !errors.Is(err, reeelf.ErrLimit) {
			t.Fatalf("Comment() error = %v, want ErrLimit", err)
		}
	})

	t.Run("data outside artifact", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		cut := f.commentOffset
		got, err := parse(t, f.data[:cut], int64(cut), reeelf.DefaultLimits())
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if _, err := got.Comment(); !errors.Is(err, reeelf.ErrUnavailable) {
			t.Fatalf("Comment() error = %v, want ErrUnavailable", err)
		}
	})
}

type limitedReader struct {
	data   []byte
	failAt int64
}

func (r *limitedReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.failAt {
		return 0, io.ErrClosedPipe
	}
	if off+int64(len(p)) > r.failAt {
		n := int(r.failAt - off)
		copy(p, r.data[off:off+int64(n)])
		return n, io.ErrClosedPipe
	}
	return copy(p, r.data[off:]), nil
}

func TestSectionNameDecoding(t *testing.T) {
	t.Parallel()

	t.Run("invalid UTF-8", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		f.data[f.nameTableOffset+int(metadataName(".text"))] = 0xff
		got := parseMetadata(t, f, reeelf.DefaultLimits())
		if _, err := got.SectionName(4); !errors.Is(err, reeelf.ErrInvalid) {
			t.Fatalf("SectionName(4) error = %v, want ErrInvalid", err)
		}
	})

	t.Run("unterminated name", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		// Remove the NUL that terminates the final name in the table.
		f.data[f.nameTableOffset+len(metadataNames)-1] = 'x'
		got := parseMetadata(t, f, reeelf.DefaultLimits())
		if _, err := got.SectionName(5); !errors.Is(err, reeelf.ErrInvalid) {
			t.Fatalf("SectionName(5) error = %v, want ErrInvalid", err)
		}
	})

	t.Run("name above limit", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		f.data[f.nameTableOffset+len(metadataNames)-1] = 'x'
		limits := reeelf.DefaultLimits()
		limits.NameBytes = 4
		got := parseMetadata(t, f, limits)
		if _, err := got.SectionName(5); !errors.Is(err, reeelf.ErrLimit) {
			t.Fatalf("SectionName(5) error = %v, want ErrLimit", err)
		}
	})

	t.Run("name table not loaded", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		f.put16(f.sectionNameIndexOffset(), 5)
		limits := reeelf.DefaultLimits()
		limits.SectionHeaders = 2
		got := parseMetadata(t, f, limits)
		if _, err := got.SectionName(1); !errors.Is(err, reeelf.ErrUnavailable) {
			t.Fatalf("SectionName(1) error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("reader failure", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		reader := &limitedReader{data: f.data, failAt: int64(f.nameTableOffset)}
		got, err := reeelf.Parse(reader, int64(len(f.data)))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if _, err := got.SectionName(4); !errors.Is(err, reeelf.ErrRead) {
			t.Fatalf("SectionName(4) error = %v, want ErrRead", err)
		}
	})
}

func TestCommentEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("final entry without NUL", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixtureWithComment(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle), []byte("no terminator"))
		got := parseMetadata(t, f, reeelf.DefaultLimits())
		entries, err := got.Comment()
		if err != nil {
			t.Fatalf("Comment() error = %v", err)
		}
		if len(entries) != 1 || entries[0] != "no terminator" {
			t.Fatalf("Comment() = %q, want [\"no terminator\"]", entries)
		}
	})

	t.Run("empty section", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixtureWithComment(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle), nil)
		got := parseMetadata(t, f, reeelf.DefaultLimits())
		entries, err := got.Comment()
		if err != nil {
			t.Fatalf("Comment() error = %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("Comment() = %q, want none", entries)
		}
	})

	t.Run("NOBITS with size", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		f.put32(f.sectionStart+3*f.sectionSize+4, 8)
		got := parseMetadata(t, f, reeelf.DefaultLimits())
		if _, err := got.Comment(); !errors.Is(err, reeelf.ErrUnavailable) {
			t.Fatalf("Comment() error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("NOBITS without size", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		f.put32(f.sectionStart+3*f.sectionSize+4, 8)
		if f.class == reeelf.Class64 {
			f.put64(f.sectionStart+3*f.sectionSize+32, 0)
		} else {
			f.put32(f.sectionStart+3*f.sectionSize+20, 0)
		}
		got := parseMetadata(t, f, reeelf.DefaultLimits())
		entries, err := got.Comment()
		if err != nil {
			t.Fatalf("Comment() error = %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("Comment() = %q, want none", entries)
		}
	})

	t.Run("absent with partial table", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		limits := reeelf.DefaultLimits()
		limits.SectionHeaders = 2
		got := parseMetadata(t, f, limits)
		if _, err := got.Comment(); !errors.Is(err, reeelf.ErrUnavailable) {
			t.Fatalf("Comment() error = %v, want ErrUnavailable", err)
		}
	})
}

func TestNotesReaderFailureAndMultipleSections(t *testing.T) {
	t.Parallel()

	t.Run("reader failure", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		reader := &limitedReader{data: f.data, failAt: int64(f.noteOffset)}
		got, err := reeelf.Parse(reader, int64(len(f.data)))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if _, err := got.Notes(); !errors.Is(err, reeelf.ErrRead) {
			t.Fatalf("Notes() error = %v, want ErrRead", err)
		}
		if _, err := got.BuildID(); !errors.Is(err, reeelf.ErrRead) {
			t.Fatalf("BuildID() error = %v, want ErrRead", err)
		}
	})

	t.Run("incomplete section table", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		limits := reeelf.DefaultLimits()
		limits.SectionHeaders = 2
		got := parseMetadata(t, f, limits)
		set, err := got.Notes()
		if err != nil {
			t.Fatalf("Notes() error = %v", err)
		}
		if !set.Truncated || len(set.Notes) != 0 {
			t.Fatalf("Notes() = %d notes, truncated %t", len(set.Notes), set.Truncated)
		}
		if len(set.Limitations) == 0 || !strings.Contains(set.Limitations[0], "incomplete") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("note name above limit is skipped", func(t *testing.T) {
		t.Parallel()

		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle))
		limits := reeelf.DefaultLimits()
		limits.NameBytes = 4
		got := parseMetadata(t, f, limits)
		set, err := got.Notes()
		if err != nil {
			t.Fatalf("Notes() error = %v", err)
		}
		if !set.Truncated || len(set.Notes) != 1 || set.Notes[0].Name != "GNU" {
			t.Fatalf("Notes() = %+v, truncated %t", set.Notes, set.Truncated)
		}
		if len(set.Limitations) == 0 || !strings.Contains(set.Limitations[0], "name exceeds limit") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("limitation list is capped", func(t *testing.T) {
		t.Parallel()

		order := byteOrderFor(reeelf.DataLittle)
		noteData := make([]byte, 0, 65*16)
		for range 65 {
			noteData = append(noteData, buildNote(order, "GNU!", 3, nil)...)
		}
		f := buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, noteData)
		limits := reeelf.DefaultLimits()
		limits.NameBytes = 4
		got := parseMetadata(t, f, limits)
		set, err := got.Notes()
		if err != nil {
			t.Fatalf("Notes() error = %v", err)
		}
		if !set.Truncated {
			t.Fatal("Notes() did not report truncation")
		}
		// Mirror of the package cap; the test package cannot read the
		// unexported constant.
		const wantLimitations = 64
		if len(set.Limitations) != wantLimitations {
			t.Fatalf("limitations = %d, want %d", len(set.Limitations), wantLimitations)
		}
		if set.Limitations[len(set.Limitations)-1] != "additional note limitations omitted" {
			t.Fatalf("last limitation = %q", set.Limitations[len(set.Limitations)-1])
		}
	})
}
