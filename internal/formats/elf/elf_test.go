package elf_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	reeelf "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/elf"
)

const (
	elfTypeExec       = 2
	programTypeLoad   = 1
	sectionTypeStrtab = 3
)

var sectionNames = []byte("\x00.shstrtab\x00")

type fixture struct {
	data []byte

	class        reeelf.Class
	order        binary.ByteOrder
	headerSize   int
	sectionSize  int
	programSize  int
	programStart int
	sectionStart int
}

func buildFixture(class reeelf.Class, data reeelf.Data) fixture {
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
	f.sectionStart = f.programStart + f.programSize
	stringsStart := f.sectionStart + 2*f.sectionSize
	f.data = make([]byte, stringsStart+len(sectionNames))

	buf := f.data
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = byte(class)
	buf[5] = byte(data)
	buf[6] = 1

	machine := uint16(62)
	entry := uint64(0x401000)
	virtual := uint64(0x400000)
	if class == reeelf.Class32 {
		machine = 3
		entry = 0x8049000
		virtual = 0x8048000
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
	f.put16(f.programCountOffset(), 1)
	f.put16(f.sectionEntrySizeOffset(), uint16(f.sectionSize))
	f.put16(f.sectionCountOffset(), 2)
	f.put16(f.sectionNameIndexOffset(), 1)

	f.writeProgram(0, programTypeLoad, 5, 0, virtual, virtual, uint64(len(buf)), uint64(len(buf))+0x1000, 0x1000)
	f.writeSection(1, 1, sectionTypeStrtab, 0, 0, uint64(stringsStart), uint64(len(sectionNames)), 0, 0, 1, 0)
	copy(buf[stringsStart:], sectionNames)

	return f
}

func (f *fixture) put16(offset int, value uint16) {
	f.order.PutUint16(f.data[offset:offset+2], value)
}

func (f *fixture) put32(offset int, value uint32) {
	f.order.PutUint32(f.data[offset:offset+4], value)
}

func (f *fixture) put64(offset int, value uint64) {
	f.order.PutUint64(f.data[offset:offset+8], value)
}

func (f *fixture) headerSizeOffset() int {
	if f.class == reeelf.Class64 {
		return 52
	}
	return 40
}

func (f *fixture) programOffsetOffset() int {
	if f.class == reeelf.Class64 {
		return 32
	}
	return 28
}

func (f *fixture) sectionOffsetOffset() int {
	if f.class == reeelf.Class64 {
		return 40
	}
	return 32
}

func (f *fixture) programEntrySizeOffset() int {
	if f.class == reeelf.Class64 {
		return 54
	}
	return 42
}

func (f *fixture) programCountOffset() int {
	if f.class == reeelf.Class64 {
		return 56
	}
	return 44
}

func (f *fixture) sectionEntrySizeOffset() int {
	if f.class == reeelf.Class64 {
		return 58
	}
	return 46
}

func (f *fixture) sectionCountOffset() int {
	if f.class == reeelf.Class64 {
		return 60
	}
	return 48
}

func (f *fixture) sectionNameIndexOffset() int {
	if f.class == reeelf.Class64 {
		return 62
	}
	return 50
}

func (f *fixture) sectionZeroFieldOffset(field int) int {
	// field is the offset within a 64-bit section header.
	relative := field
	if f.class == reeelf.Class32 {
		switch field {
		case 8:
			relative = 8
		case 16:
			relative = 12
		case 24:
			relative = 16
		case 32:
			relative = 20
		case 40:
			relative = 24
		case 44:
			relative = 28
		case 48:
			relative = 32
		case 56:
			relative = 36
		}
	}
	return f.sectionStart + relative
}

func (f *fixture) putSectionZeroSize(value uint64) {
	if f.class == reeelf.Class64 {
		f.put64(f.sectionZeroFieldOffset(32), value)
		return
	}
	f.put32(f.sectionZeroFieldOffset(32), uint32(value))
}

func buildExtendedFixture(class reeelf.Class, data reeelf.Data) fixture {
	f := buildFixture(class, data)
	f.put16(f.sectionCountOffset(), 0)
	f.putSectionZeroSize(2)
	f.put16(f.programCountOffset(), 0xffff)
	f.put32(f.sectionZeroFieldOffset(44), 1)
	f.put16(f.sectionNameIndexOffset(), 0xffff)
	f.put32(f.sectionZeroFieldOffset(40), 1)
	return f
}

func (f *fixture) writeProgram(index int, typ, flags uint32, offset, virtual, physical, fileSize, memorySize, align uint64) {
	start := f.programStart + index*f.programSize
	f.order.PutUint32(f.data[start:start+4], typ)
	if f.class == reeelf.Class64 {
		f.order.PutUint32(f.data[start+4:start+8], flags)
		f.order.PutUint64(f.data[start+8:start+16], offset)
		f.order.PutUint64(f.data[start+16:start+24], virtual)
		f.order.PutUint64(f.data[start+24:start+32], physical)
		f.order.PutUint64(f.data[start+32:start+40], fileSize)
		f.order.PutUint64(f.data[start+40:start+48], memorySize)
		f.order.PutUint64(f.data[start+48:start+56], align)
		return
	}
	f.order.PutUint32(f.data[start+4:start+8], uint32(offset))
	f.order.PutUint32(f.data[start+8:start+12], uint32(virtual))
	f.order.PutUint32(f.data[start+12:start+16], uint32(physical))
	f.order.PutUint32(f.data[start+16:start+20], uint32(fileSize))
	f.order.PutUint32(f.data[start+20:start+24], uint32(memorySize))
	f.order.PutUint32(f.data[start+24:start+28], flags)
	f.order.PutUint32(f.data[start+28:start+32], uint32(align))
}

func (f *fixture) writeSection(index int, name uint32, typ uint32, flags, address, offset, size uint64, link, info uint32, addressAlign, entrySize uint64) {
	start := f.sectionStart + index*f.sectionSize
	f.order.PutUint32(f.data[start:start+4], name)
	f.order.PutUint32(f.data[start+4:start+8], typ)
	if f.class == reeelf.Class64 {
		f.order.PutUint64(f.data[start+8:start+16], flags)
		f.order.PutUint64(f.data[start+16:start+24], address)
		f.order.PutUint64(f.data[start+24:start+32], offset)
		f.order.PutUint64(f.data[start+32:start+40], size)
		f.order.PutUint32(f.data[start+40:start+44], link)
		f.order.PutUint32(f.data[start+44:start+48], info)
		f.order.PutUint64(f.data[start+48:start+56], addressAlign)
		f.order.PutUint64(f.data[start+56:start+64], entrySize)
		return
	}
	f.order.PutUint32(f.data[start+8:start+12], uint32(flags))
	f.order.PutUint32(f.data[start+12:start+16], uint32(address))
	f.order.PutUint32(f.data[start+16:start+20], uint32(offset))
	f.order.PutUint32(f.data[start+20:start+24], uint32(size))
	f.order.PutUint32(f.data[start+24:start+28], link)
	f.order.PutUint32(f.data[start+28:start+32], info)
	f.order.PutUint32(f.data[start+32:start+36], uint32(addressAlign))
	f.order.PutUint32(f.data[start+36:start+40], uint32(entrySize))
}

func parse(t *testing.T, data []byte, size int64, limits reeelf.Limits) (*reeelf.File, error) {
	t.Helper()
	return reeelf.ParseWithLimits(bytes.NewReader(data), size, limits)
}

func TestParseHeaderAndTables(t *testing.T) {
	t.Parallel()

	for _, class := range []reeelf.Class{reeelf.Class32, reeelf.Class64} {
		for _, data := range []reeelf.Data{reeelf.DataLittle, reeelf.DataBig} {
			name := fmt.Sprintf("%s/%s", class, data)
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				f := buildFixture(class, data)
				got, err := parse(t, f.data, int64(len(f.data)), reeelf.DefaultLimits())
				if err != nil {
					t.Fatalf("Parse() error = %v", err)
				}
				if got.Truncated {
					t.Fatalf("Parse() reported truncation: %v", got.Limitations)
				}
				if len(got.Limitations) != 0 {
					t.Fatalf("Parse() limitations = %v, want none", got.Limitations)
				}
				if got.Size() != int64(len(f.data)) {
					t.Fatalf("Size() = %d, want %d", got.Size(), len(f.data))
				}

				h := got.Header
				if h.Class != class || h.Data != data {
					t.Fatalf("identity = %s/%s, want %s/%s", h.Class, h.Data, class, data)
				}
				if h.IdentVersion != 1 || h.OSABI != 0 || h.ABIVersion != 0 {
					t.Fatalf("identifier metadata = version %d osabi %d abi %d", h.IdentVersion, h.OSABI, h.ABIVersion)
				}
				if h.Type != elfTypeExec || h.Version != 1 {
					t.Fatalf("type/version = %d/%d, want %d/1", h.Type, h.Version, elfTypeExec)
				}
				wantMachine := uint16(62)
				wantEntry := uint64(0x401000)
				if class == reeelf.Class32 {
					wantMachine = 3
					wantEntry = 0x8049000
				}
				if h.Machine != wantMachine || h.Entry != wantEntry {
					t.Fatalf("machine/entry = %d/%#x, want %d/%#x", h.Machine, h.Entry, wantMachine, wantEntry)
				}
				if h.HeaderSize != uint16(f.headerSize) {
					t.Fatalf("header size = %d, want %d", h.HeaderSize, f.headerSize)
				}
				if h.ProgramHeaderOffset != uint64(f.programStart) || h.SectionHeaderOffset != uint64(f.sectionStart) {
					t.Fatalf("table offsets = %d/%d, want %d/%d",
						h.ProgramHeaderOffset, h.SectionHeaderOffset, f.programStart, f.sectionStart)
				}
				if h.ProgramHeaderEntrySize != uint16(f.programSize) || h.SectionHeaderEntrySize != uint16(f.sectionSize) {
					t.Fatalf("entry sizes = %d/%d, want %d/%d",
						h.ProgramHeaderEntrySize, h.SectionHeaderEntrySize, f.programSize, f.sectionSize)
				}
				if h.ProgramHeaderCount != 1 || h.SectionHeaderCount != 2 || h.SectionNameIndex != 1 {
					t.Fatalf("counts = %d/%d/%d, want 1/2/1",
						h.ProgramHeaderCount, h.SectionHeaderCount, h.SectionNameIndex)
				}
				if h.ExtendedProgramHeaderCount || h.ExtendedSectionHeaderCount || h.ExtendedSectionNameIndex {
					t.Fatal("unexpected extended-numbering flags")
				}

				if len(got.SectionHeaders) != 2 {
					t.Fatalf("section count = %d, want 2", len(got.SectionHeaders))
				}
				if got.SectionHeaders[0] != (reeelf.SectionHeader{}) {
					t.Fatalf("section 0 = %+v, want zero value", got.SectionHeaders[0])
				}
				sh := got.SectionHeaders[1]
				wantSectionOffset := uint64(f.sectionStart + 2*f.sectionSize)
				if sh.Index != 1 || sh.NameOffset != 1 || sh.Type != sectionTypeStrtab {
					t.Fatalf("section 1 identity = %+v", sh)
				}
				if sh.Offset != wantSectionOffset || sh.Size != uint64(len(sectionNames)) {
					t.Fatalf("section 1 offset/size = %d/%d, want %d/%d",
						sh.Offset, sh.Size, wantSectionOffset, len(sectionNames))
				}
				if sh.AddressAlign != 1 || sh.EntrySize != 0 {
					t.Fatalf("section 1 alignment = %d/%d", sh.AddressAlign, sh.EntrySize)
				}

				if len(got.ProgramHeaders) != 1 {
					t.Fatalf("program count = %d, want 1", len(got.ProgramHeaders))
				}
				ph := got.ProgramHeaders[0]
				if ph.Index != 0 || ph.Type != programTypeLoad || ph.Flags != 5 {
					t.Fatalf("program 0 identity = %+v", ph)
				}
				if ph.Offset != 0 || ph.VirtualAddress != ph.PhysicalAddress {
					t.Fatalf("program 0 addresses = %d/%#x/%#x", ph.Offset, ph.VirtualAddress, ph.PhysicalAddress)
				}
				if ph.FileSize != uint64(len(f.data)) || ph.MemorySize != uint64(len(f.data))+0x1000 || ph.Align != 0x1000 {
					t.Fatalf("program 0 sizes/alignment = %d/%d/%#x", ph.FileSize, ph.MemorySize, ph.Align)
				}
			})
		}
	}
}

func TestParseWithoutTables(t *testing.T) {
	t.Parallel()

	f := buildFixture(reeelf.Class64, reeelf.DataLittle)
	f.put64(f.programOffsetOffset(), 0)
	f.put64(f.sectionOffsetOffset(), 0)
	f.put16(f.programCountOffset(), 0)
	f.put16(f.sectionCountOffset(), 0)
	f.put16(f.sectionNameIndexOffset(), 0)

	got, err := parse(t, f.data, int64(len(f.data)), reeelf.DefaultLimits())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(got.SectionHeaders) != 0 || len(got.ProgramHeaders) != 0 {
		t.Fatalf("tables = %d/%d, want 0/0", len(got.SectionHeaders), len(got.ProgramHeaders))
	}
	if got.Truncated {
		t.Fatalf("Parse() reported truncation: %v", got.Limitations)
	}
}

func TestParseExtendedNumbering(t *testing.T) {
	t.Parallel()

	for _, class := range []reeelf.Class{reeelf.Class32, reeelf.Class64} {
		for _, data := range []reeelf.Data{reeelf.DataLittle, reeelf.DataBig} {
			t.Run(class.String()+"/"+data.String(), func(t *testing.T) {
				t.Parallel()

				f := buildExtendedFixture(class, data)

				got, err := parse(t, f.data, int64(len(f.data)), reeelf.DefaultLimits())
				if err != nil {
					t.Fatalf("Parse() error = %v", err)
				}
				h := got.Header
				if !h.ExtendedSectionHeaderCount || !h.ExtendedProgramHeaderCount || !h.ExtendedSectionNameIndex {
					t.Fatalf("extended flags = %t/%t/%t, want all true",
						h.ExtendedSectionHeaderCount, h.ExtendedProgramHeaderCount, h.ExtendedSectionNameIndex)
				}
				if h.SectionHeaderCount != 2 || h.ProgramHeaderCount != 1 || h.SectionNameIndex != 1 {
					t.Fatalf("resolved counts = %d/%d/%d, want 2/1/1",
						h.SectionHeaderCount, h.ProgramHeaderCount, h.SectionNameIndex)
				}
				if len(got.SectionHeaders) != 2 || len(got.ProgramHeaders) != 1 {
					t.Fatalf("tables = %d/%d, want 2/1", len(got.SectionHeaders), len(got.ProgramHeaders))
				}
				if got.Truncated {
					t.Fatalf("Parse() reported truncation: %v", got.Limitations)
				}
			})
		}
	}
}

func TestParseRejectsInvalidHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(f *fixture)
	}{
		{name: "bad magic", mutate: func(f *fixture) { f.data[0] = 0 }},
		{name: "bad class", mutate: func(f *fixture) { f.data[4] = 3 }},
		{name: "bad data encoding", mutate: func(f *fixture) { f.data[5] = 3 }},
		{name: "bad identifier version", mutate: func(f *fixture) { f.data[6] = 2 }},
		{name: "bad file version", mutate: func(f *fixture) { f.put32(20, 2) }},
		{name: "bad header size", mutate: func(f *fixture) { f.put16(f.headerSizeOffset(), 0) }},
		{name: "bad section entry size", mutate: func(f *fixture) { f.put16(f.sectionEntrySizeOffset(), 1) }},
		{name: "bad program entry size", mutate: func(f *fixture) { f.put16(f.programEntrySizeOffset(), 1) }},
		{name: "section table missing", mutate: func(f *fixture) { f.put64(f.sectionOffsetOffset(), 0) }},
		{name: "section name index outside table", mutate: func(f *fixture) { f.put16(f.sectionNameIndexOffset(), 5) }},
		{name: "program table missing", mutate: func(f *fixture) { f.put64(f.programOffsetOffset(), 0) }},
		{
			name: "section name extension without sections",
			mutate: func(f *fixture) {
				f.put64(f.sectionOffsetOffset(), 0)
				f.put16(f.sectionCountOffset(), 0)
				f.put16(f.sectionNameIndexOffset(), 0xffff)
			},
		},
		{
			name: "program extension without sections",
			mutate: func(f *fixture) {
				f.put64(f.sectionOffsetOffset(), 0)
				f.put16(f.sectionCountOffset(), 0)
				f.put16(f.sectionNameIndexOffset(), 0)
				f.put16(f.programCountOffset(), 0xffff)
			},
		},
		{
			name: "zero extended section count",
			mutate: func(f *fixture) {
				f.put16(f.sectionCountOffset(), 0)
				f.putSectionZeroSize(0)
			},
		},
		{
			name: "extended section name index outside table",
			mutate: func(f *fixture) {
				f.put16(f.sectionNameIndexOffset(), 0xffff)
				f.put32(f.sectionZeroFieldOffset(40), 5)
			},
		},
	}

	for _, class := range []reeelf.Class{reeelf.Class32, reeelf.Class64} {
		for _, tt := range tests {
			t.Run(class.String()+"/"+tt.name, func(t *testing.T) {
				t.Parallel()

				f := buildFixture(class, reeelf.DataLittle)
				tt.mutate(&f)
				got, err := parse(t, f.data, int64(len(f.data)), reeelf.DefaultLimits())
				if err == nil {
					t.Fatalf("Parse() = %+v, want error", got)
				}
				if !errors.Is(err, reeelf.ErrInvalid) {
					t.Fatalf("Parse() error = %v, want ErrInvalid", err)
				}
			})
		}
	}
}

func TestParseRejectsInvalidSizeOrReader(t *testing.T) {
	t.Parallel()

	f := buildFixture(reeelf.Class64, reeelf.DataLittle)

	tests := []struct {
		name    string
		reader  io.ReaderAt
		size    int64
		wantErr error
	}{
		{name: "nil reader", reader: nil, size: int64(len(f.data)), wantErr: reeelf.ErrInvalid},
		{name: "negative size", reader: bytes.NewReader(f.data), size: -1, wantErr: reeelf.ErrInvalid},
		{name: "size above limit", reader: bytes.NewReader(f.data), size: reeelf.MaxArtifactBytes + 1, wantErr: reeelf.ErrLimit},
		{name: "short identifier", reader: bytes.NewReader(f.data), size: 10, wantErr: reeelf.ErrTruncated},
		{name: "short header", reader: bytes.NewReader(f.data), size: 40, wantErr: reeelf.ErrTruncated},
		{name: "reader failure", reader: errorReader{err: io.ErrClosedPipe}, size: int64(len(f.data)), wantErr: reeelf.ErrRead},
		{name: "short reader", reader: shortReader{}, size: int64(len(f.data)), wantErr: reeelf.ErrRead},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := reeelf.ParseWithLimits(tt.reader, tt.size, reeelf.DefaultLimits())
			if err == nil {
				t.Fatalf("Parse() = %+v, want error", got)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Parse() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseTruncatedTables(t *testing.T) {
	t.Parallel()

	t.Run("section table ends early", func(t *testing.T) {
		t.Parallel()

		f := buildFixture(reeelf.Class64, reeelf.DataLittle)
		cut := f.sectionStart + f.sectionSize
		got, err := parse(t, f.data[:cut], int64(cut), reeelf.DefaultLimits())
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if !got.Truncated || len(got.Limitations) == 0 {
			t.Fatalf("truncation = %t, limitations = %v", got.Truncated, got.Limitations)
		}
		if len(got.SectionHeaders) != 1 || got.SectionHeaders[0].Index != 0 {
			t.Fatalf("sections = %+v, want only section 0", got.SectionHeaders)
		}
		if len(got.ProgramHeaders) != 1 {
			t.Fatalf("programs = %d, want 1", len(got.ProgramHeaders))
		}
		if !strings.Contains(got.Limitations[0], "1 of 2 entries available") {
			t.Fatalf("limitation = %q, want availability detail", got.Limitations[0])
		}
	})

	t.Run("section table offset beyond artifact", func(t *testing.T) {
		t.Parallel()

		f := buildFixture(reeelf.Class64, reeelf.DataLittle)
		f.put64(f.sectionOffsetOffset(), uint64(len(f.data)+64))
		got, err := parse(t, f.data, int64(len(f.data)), reeelf.DefaultLimits())
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if !got.Truncated || len(got.SectionHeaders) != 0 {
			t.Fatalf("truncation = %t, sections = %d", got.Truncated, len(got.SectionHeaders))
		}
		if len(got.Limitations) == 0 {
			t.Fatal("missing limitation")
		}
	})

	t.Run("extended count needs missing section zero", func(t *testing.T) {
		t.Parallel()

		f := buildFixture(reeelf.Class64, reeelf.DataLittle)
		f.put16(f.sectionCountOffset(), 0)
		f.putSectionZeroSize(2)
		cut := f.sectionStart
		got, err := parse(t, f.data[:cut], int64(cut), reeelf.DefaultLimits())
		if err == nil {
			t.Fatalf("Parse() = %+v, want error", got)
		}
		if !errors.Is(err, reeelf.ErrTruncated) {
			t.Fatalf("Parse() error = %v, want ErrTruncated", err)
		}
	})
}

func TestParseCountLimits(t *testing.T) {
	t.Parallel()

	t.Run("section headers", func(t *testing.T) {
		t.Parallel()

		f := buildFixture(reeelf.Class64, reeelf.DataLittle)
		f.put16(f.sectionCountOffset(), 0)
		f.putSectionZeroSize(1000)
		limits := reeelf.DefaultLimits()
		limits.SectionHeaders = 1

		got, err := parse(t, f.data, int64(len(f.data)), limits)
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if !got.Truncated {
			t.Fatal("Parse() did not report truncation")
		}
		if got.Header.SectionHeaderCount != 1000 {
			t.Fatalf("declared section count = %d, want 1000", got.Header.SectionHeaderCount)
		}
		if len(got.SectionHeaders) != 1 {
			t.Fatalf("loaded section count = %d, want 1", len(got.SectionHeaders))
		}
		if len(got.Limitations) != 1 || !strings.Contains(got.Limitations[0], "exceeds limit 1") {
			t.Fatalf("limitations = %v", got.Limitations)
		}
	})

	t.Run("program headers", func(t *testing.T) {
		t.Parallel()

		f := buildFixture(reeelf.Class64, reeelf.DataLittle)
		f.put16(f.programCountOffset(), 0xffff)
		f.put32(f.sectionZeroFieldOffset(44), 100)
		limits := reeelf.DefaultLimits()
		limits.ProgramHeaders = 1

		got, err := parse(t, f.data, int64(len(f.data)), limits)
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if !got.Truncated {
			t.Fatal("Parse() did not report truncation")
		}
		if got.Header.ProgramHeaderCount != 100 {
			t.Fatalf("declared program count = %d, want 100", got.Header.ProgramHeaderCount)
		}
		if len(got.ProgramHeaders) != 1 {
			t.Fatalf("loaded program count = %d, want 1", len(got.ProgramHeaders))
		}
		if len(got.Limitations) != 1 || !strings.Contains(got.Limitations[0], "exceeds limit 1") {
			t.Fatalf("limitations = %v", got.Limitations)
		}
	})
}

func TestLimitsClampToPackageMaximum(t *testing.T) {
	t.Parallel()

	limits := reeelf.Limits{
		ArtifactBytes:  reeelf.MaxArtifactBytes * 2,
		SectionHeaders: reeelf.MaxSectionHeaders + 1,
		ProgramHeaders: reeelf.MaxProgramHeaders + 1,
	}
	f := buildFixture(reeelf.Class64, reeelf.DataLittle)
	if _, err := parse(t, f.data, int64(len(f.data)), limits); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
}

type errorReader struct {
	err error
}

func (r errorReader) ReadAt([]byte, int64) (int, error) {
	return 0, r.err
}

type shortReader struct{}

func (shortReader) ReadAt([]byte, int64) (int, error) {
	return 0, nil
}

func FuzzParse(f *testing.F) {
	fixture64 := buildFixture(reeelf.Class64, reeelf.DataLittle)
	f.Add(fixture64.data)
	fixture32 := buildFixture(reeelf.Class32, reeelf.DataBig)
	f.Add(fixture32.data)
	f.Add([]byte{})
	f.Add([]byte{0x7f, 'E', 'L', 'F'})

	limits := reeelf.Limits{
		ArtifactBytes:  1 << 20,
		SectionHeaders: 8,
		ProgramHeaders: 8,
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := reeelf.ParseWithLimits(bytes.NewReader(data), int64(len(data)), limits)
		if err != nil {
			if got != nil {
				t.Fatalf("Parse() returned file %+v with error %v", got, err)
			}
			return
		}
		if got == nil {
			t.Fatal("Parse() returned nil file without error")
		}
		if got.Truncated != (len(got.Limitations) > 0) {
			t.Fatalf("truncation = %t, limitations = %v", got.Truncated, got.Limitations)
		}
		if len(got.SectionHeaders) > limits.SectionHeaders {
			t.Fatalf("loaded %d section headers above limit %d", len(got.SectionHeaders), limits.SectionHeaders)
		}
		if len(got.ProgramHeaders) > limits.ProgramHeaders {
			t.Fatalf("loaded %d program headers above limit %d", len(got.ProgramHeaders), limits.ProgramHeaders)
		}
		if uint64(len(got.SectionHeaders)) > got.Header.SectionHeaderCount {
			t.Fatalf("loaded %d section headers above declared count %d",
				len(got.SectionHeaders), got.Header.SectionHeaderCount)
		}
		if uint64(len(got.ProgramHeaders)) > got.Header.ProgramHeaderCount {
			t.Fatalf("loaded %d program headers above declared count %d",
				len(got.ProgramHeaders), got.Header.ProgramHeaderCount)
		}
		if !got.Truncated {
			if uint64(len(got.SectionHeaders)) != got.Header.SectionHeaderCount {
				t.Fatalf("complete section table has %d of %d entries",
					len(got.SectionHeaders), got.Header.SectionHeaderCount)
			}
			if uint64(len(got.ProgramHeaders)) != got.Header.ProgramHeaderCount {
				t.Fatalf("complete program table has %d of %d entries",
					len(got.ProgramHeaders), got.Header.ProgramHeaderCount)
			}
		}
		for i, sh := range got.SectionHeaders {
			if sh.Index != i {
				t.Fatalf("section index = %d at position %d", sh.Index, i)
			}
		}
		for i, ph := range got.ProgramHeaders {
			if ph.Index != i {
				t.Fatalf("program index = %d at position %d", ph.Index, i)
			}
		}
	})
}
