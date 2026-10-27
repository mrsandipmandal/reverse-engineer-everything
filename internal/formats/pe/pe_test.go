package pe_test

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	repe "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/pe"
)

const (
	fixturePEHeaderOffset = 0x80
	fixtureHeadersSize    = 0x200
	fixtureTextOffset     = 0x200
	fixtureDataOffset     = 0x210
	fixtureOverlayOffset  = 0x218
	fixtureSectionCount   = 3
)

var (
	fixtureText    = []byte{0x55, 0x48, 0x89, 0xe5, 0x90, 0x90, 0x90, 0x90, 0xc3, 0x0f, 0x1f, 0x40, 0x00, 0x00, 0x00, 0x00}
	fixtureData    = []byte("DATA\x00\x00\x00\x00")
	fixtureOverlay = []byte("OVLY")
)

// peFixture is a crafted PE32 or PE32+ image with three sections and an
// overlay.
type peFixture struct {
	data         []byte
	magic        uint16
	optionalSize int
	optionalOff  int
	sectionTable int
}

func buildFixture(t testing.TB, magic uint16) *peFixture {
	t.Helper()

	optionalSize := 224
	machine := uint16(0x14c)
	characteristics := uint16(0x0102)
	if magic == repe.MagicPE32P {
		optionalSize = 240
		machine = 0x8664
		characteristics = 0x0022
	}

	data := make([]byte, fixtureHeadersSize, fixtureHeadersSize+len(fixtureText)+len(fixtureData)+len(fixtureOverlay))
	copy(data[0:], "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], fixturePEHeaderOffset)
	copy(data[fixturePEHeaderOffset:], "PE\x00\x00")

	coff := fixturePEHeaderOffset + 4
	binary.LittleEndian.PutUint16(data[coff:], machine)
	binary.LittleEndian.PutUint16(data[coff+2:], fixtureSectionCount)
	binary.LittleEndian.PutUint32(data[coff+4:], 0x5f5e1000)
	binary.LittleEndian.PutUint32(data[coff+8:], 0)
	binary.LittleEndian.PutUint32(data[coff+12:], 0)
	binary.LittleEndian.PutUint16(data[coff+16:], uint16(optionalSize))
	binary.LittleEndian.PutUint16(data[coff+18:], characteristics)

	f := &peFixture{
		magic:        magic,
		optionalSize: optionalSize,
		optionalOff:  coff + 20,
	}
	f.sectionTable = f.optionalOff + optionalSize
	f.writeOptional(data)

	f.writeSection(data, 0, ".text", 0x10, 0x1000, 0x10, fixtureTextOffset, 0x60000020)
	f.writeSection(data, 1, ".data", 0x8, 0x2000, 0x8, fixtureDataOffset, 0xc0000040)
	f.writeSection(data, 2, ".bss", 0x100, 0x3000, 0, 0, 0xc0000080)

	data = append(data, fixtureText...)
	data = append(data, fixtureData...)
	data = append(data, fixtureOverlay...)
	f.data = data
	return f
}

func (f *peFixture) writeOptional(data []byte) {
	base := f.optionalOff
	order := binary.LittleEndian
	order.PutUint16(data[base:], f.magic)
	data[base+2] = 14
	data[base+3] = 0
	order.PutUint32(data[base+4:], 0x10)
	order.PutUint32(data[base+8:], 0x8)
	order.PutUint32(data[base+12:], 0x100)
	order.PutUint32(data[base+16:], 0x1000)
	order.PutUint32(data[base+20:], 0x1000)
	order.PutUint32(data[base+32:], 0x1000)
	order.PutUint32(data[base+36:], 0x200)
	order.PutUint16(data[base+40:], 6)
	order.PutUint16(data[base+44:], 0)
	order.PutUint16(data[base+48:], 6)
	order.PutUint32(data[base+56:], 0x4000)
	order.PutUint32(data[base+60:], fixtureHeadersSize)
	order.PutUint16(data[base+68:], 3)
	order.PutUint16(data[base+70:], 0x8160)

	if f.magic == repe.MagicPE32 {
		order.PutUint32(data[base+24:], 0x2000)
		order.PutUint32(data[base+28:], 0x400000)
		order.PutUint32(data[base+72:], 0x100000)
		order.PutUint32(data[base+76:], 0x1000)
		order.PutUint32(data[base+80:], 0x100000)
		order.PutUint32(data[base+84:], 0x1000)
		order.PutUint32(data[base+92:], 16)
	} else {
		order.PutUint64(data[base+24:], 0x140000000)
		order.PutUint64(data[base+72:], 0x100000)
		order.PutUint64(data[base+80:], 0x1000)
		order.PutUint64(data[base+88:], 0x100000)
		order.PutUint64(data[base+96:], 0x1000)
		order.PutUint32(data[base+108:], 16)
	}

	fixedSize := 96
	if f.magic == repe.MagicPE32P {
		fixedSize = 112
	}
	directories := base + fixedSize
	order.PutUint32(data[directories+1*8:], 0x2000)
	order.PutUint32(data[directories+1*8+4:], 0x8)
	order.PutUint32(data[directories+2*8:], 0x2000)
	order.PutUint32(data[directories+2*8+4:], 0x4)
	order.PutUint32(data[directories+4*8:], fixtureOverlayOffset)
	order.PutUint32(data[directories+4*8+4:], uint32(len(fixtureOverlay)))
}

func (f *peFixture) writeSection(data []byte, index int, name string, virtualSize, virtualAddress, rawSize, rawOffset uint32, characteristics uint32) {
	base := f.sectionTable + index*40
	copy(data[base:base+8], name)
	order := binary.LittleEndian
	order.PutUint32(data[base+8:], virtualSize)
	order.PutUint32(data[base+12:], virtualAddress)
	order.PutUint32(data[base+16:], rawSize)
	order.PutUint32(data[base+20:], rawOffset)
	order.PutUint32(data[base+24:], 0)
	order.PutUint32(data[base+28:], 0)
	order.PutUint16(data[base+32:], 0)
	order.PutUint16(data[base+34:], 0)
	order.PutUint32(data[base+36:], characteristics)
}

func (f *peFixture) sectionOffset(index, field int) int {
	return f.sectionTable + index*40 + field
}

func (f *peFixture) optionalField(field int) int {
	return f.optionalOff + field
}

func (f *peFixture) parse(t testing.TB) *repe.File {
	t.Helper()

	file, err := repe.Parse(bytes.NewReader(f.data), int64(len(f.data)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return file
}

func magicName(t *testing.T, magic uint16) string {
	t.Helper()
	if magic == repe.MagicPE32 {
		return "PE32"
	}
	return "PE32+"
}

func TestParseFixture(t *testing.T) {
	t.Parallel()

	for _, magic := range []uint16{repe.MagicPE32, repe.MagicPE32P} {
		magic := magic
		t.Run(magicName(t, magic), func(t *testing.T) {
			t.Parallel()

			fixture := buildFixture(t, magic)
			file := fixture.parse(t)

			if file.Truncated || len(file.Limitations) != 0 {
				t.Fatalf("Truncated = %t, limitations = %v", file.Truncated, file.Limitations)
			}
			if file.Size() != int64(len(fixture.data)) {
				t.Fatalf("Size() = %d", file.Size())
			}
			header := file.Header
			if header.DOSMagic != 0x5a4d || header.PEHeaderOffset != fixturePEHeaderOffset {
				t.Fatalf("DOS header = %+v", header)
			}
			if header.NumberOfSections != fixtureSectionCount || header.SizeOfOptionalHeader != uint16(fixture.optionalSize) {
				t.Fatalf("COFF header = %+v", header)
			}
			if header.Machine != 0x14c && header.Machine != 0x8664 {
				t.Fatalf("machine = %#x", header.Machine)
			}
			if header.Optional.Magic != magic {
				t.Fatalf("optional magic = %#x", header.Optional.Magic)
			}
			if header.Optional.AddressOfEntryPoint != 0x1000 || header.Optional.Subsystem != 3 {
				t.Fatalf("optional identity = %+v", header.Optional)
			}
			if header.Optional.SizeOfImage != 0x4000 || header.Optional.SizeOfHeaders != fixtureHeadersSize {
				t.Fatalf("image sizes = %+v", header.Optional)
			}
			if header.Optional.NumberOfRvaAndSizes != 16 {
				t.Fatalf("directory count = %d", header.Optional.NumberOfRvaAndSizes)
			}
			if magic == repe.MagicPE32 {
				if header.Optional.BaseOfData != 0x2000 || header.Optional.ImageBase != 0x400000 {
					t.Fatalf("PE32 addresses = %+v", header.Optional)
				}
			} else {
				if header.Optional.BaseOfData != 0 || header.Optional.ImageBase != 0x140000000 {
					t.Fatalf("PE32+ addresses = %+v", header.Optional)
				}
			}

			if len(file.DataDirectories) != 16 {
				t.Fatalf("directory count = %d", len(file.DataDirectories))
			}
			if got := file.DataDirectories[1]; got.VirtualAddress != 0x2000 || got.Size != 8 {
				t.Fatalf("import directory = %+v", got)
			}

			if len(file.Sections) != fixtureSectionCount {
				t.Fatalf("section count = %d", len(file.Sections))
			}
			for i, want := range []struct {
				name string
				size uint32
			}{{".text", 0x10}, {".data", 0x8}, {".bss", 0x100}} {
				section := file.Sections[i]
				if section.Index != i || section.Name != want.name || !section.NameAvailable {
					t.Fatalf("section %d = %+v", i, section)
				}
				if section.VirtualSize != want.size {
					t.Fatalf("section %d virtual size = %#x", i, section.VirtualSize)
				}
			}

			text, err := file.SectionData(0)
			if err != nil || !bytes.Equal(text, fixtureText) {
				t.Fatalf("SectionData(0) = %x, %v", text, err)
			}
			dataSection, err := file.SectionData(1)
			if err != nil || !bytes.Equal(dataSection, fixtureData) {
				t.Fatalf("SectionData(1) = %x, %v", dataSection, err)
			}
			bss, err := file.SectionData(2)
			if err != nil || len(bss) != 0 {
				t.Fatalf("SectionData(2) = %x, %v", bss, err)
			}

			if file.OverlayOffset != fixtureOverlayOffset || file.OverlaySize != uint64(len(fixtureOverlay)) {
				t.Fatalf("overlay = %d/%d", file.OverlayOffset, file.OverlaySize)
			}

			checkMapping(t, file, 0x10, repe.RVAMapping{Offset: 0x10, SectionIndex: -1, FileBacked: true})
			checkMapping(t, file, 0x1000, repe.RVAMapping{Offset: fixtureTextOffset, SectionIndex: 0, FileBacked: true})
			checkMapping(t, file, 0x100f, repe.RVAMapping{Offset: fixtureTextOffset + 15, SectionIndex: 0, FileBacked: true})
			checkMapping(t, file, 0x2004, repe.RVAMapping{Offset: fixtureDataOffset + 4, SectionIndex: 1, FileBacked: true})
			checkMapping(t, file, 0x3000, repe.RVAMapping{SectionIndex: 2, FileBacked: false})
			checkMapping(t, file, 0x200, repe.RVAMapping{SectionIndex: -1, FileBacked: false})
			checkMapping(t, file, 0x4000, repe.RVAMapping{SectionIndex: -1, FileBacked: false})
		})
	}
}

func checkMapping(t *testing.T, file *repe.File, rva uint32, want repe.RVAMapping) {
	t.Helper()

	got := file.MapRVA(rva)
	if got.Offset != want.Offset || got.SectionIndex != want.SectionIndex ||
		got.FileBacked != want.FileBacked || got.Ambiguous != want.Ambiguous {
		t.Fatalf("MapRVA(%#x) = %+v, want %+v", rva, got, want)
	}
}

func TestMapRVAHeadersWin(t *testing.T) {
	t.Parallel()

	fixture := buildFixture(t, repe.MagicPE32)
	binary.LittleEndian.PutUint32(fixture.data[fixture.sectionOffset(0, 12):], 0x100)

	file := fixture.parse(t)
	mapping := file.MapRVA(0x104)
	if mapping.SectionIndex != -1 || !mapping.FileBacked || mapping.Offset != 0x104 || !mapping.Ambiguous {
		t.Fatalf("MapRVA(0x104) = %+v", mapping)
	}
}

func TestMapRVAOverlappingSections(t *testing.T) {
	t.Parallel()

	fixture := buildFixture(t, repe.MagicPE32)
	data := fixture.data
	binary.LittleEndian.PutUint32(data[fixture.sectionOffset(1, 12):], 0x1000)

	file := fixture.parse(t)
	mapping := file.MapRVA(0x1004)
	if !mapping.Ambiguous || mapping.SectionIndex != 0 || mapping.Offset != fixtureTextOffset+4 {
		t.Fatalf("MapRVA(0x1004) = %+v", mapping)
	}
}

func TestParseTruncation(t *testing.T) {
	t.Parallel()

	fixture := buildFixture(t, repe.MagicPE32)

	t.Run("section table partial entry", func(t *testing.T) {
		t.Parallel()

		cut := fixture.sectionTable + 40 + 10
		file, err := repe.Parse(bytes.NewReader(fixture.data[:cut]), int64(cut))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if !file.Truncated || len(file.Sections) != 1 {
			t.Fatalf("Truncated = %t, sections = %d", file.Truncated, len(file.Sections))
		}
		if !hasLimitation(file.Limitations, "section table truncated") {
			t.Fatalf("limitations = %v", file.Limitations)
		}
		if _, err := file.SectionData(1); !errors.Is(err, repe.ErrUnavailable) {
			t.Fatalf("SectionData(1) error = %v, want ErrUnavailable", err)
		}
		if _, err := file.SectionData(3); !errors.Is(err, repe.ErrOutOfRange) {
			t.Fatalf("SectionData(3) error = %v, want ErrOutOfRange", err)
		}
	})

	t.Run("section table absent", func(t *testing.T) {
		t.Parallel()

		cut := fixture.sectionTable
		file, err := repe.Parse(bytes.NewReader(fixture.data[:cut]), int64(cut))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if !file.Truncated || len(file.Sections) != 0 {
			t.Fatalf("Truncated = %t, sections = %d", file.Truncated, len(file.Sections))
		}
	})
}

func TestParseInvalid(t *testing.T) {
	t.Parallel()

	fixture := buildFixture(t, repe.MagicPE32)

	tests := []struct {
		name   string
		size   int64
		mutate func([]byte)
		want   error
	}{
		{name: "too small", size: 10, want: repe.ErrTruncated},
		{name: "bad DOS magic", mutate: func(data []byte) { data[0] = 'X' }, want: repe.ErrInvalid},
		{name: "PE offset overlaps DOS header", mutate: func(data []byte) {
			binary.LittleEndian.PutUint32(data[0x3c:], 0x20)
		}, want: repe.ErrInvalid},
		{name: "PE signature missing", mutate: func(data []byte) {
			copy(data[fixturePEHeaderOffset:], "PX\x00\x00")
		}, want: repe.ErrInvalid},
		{name: "optional header truncated", size: int64(fixture.optionalOff + 8), want: repe.ErrTruncated},
		{name: "unsupported optional magic", mutate: func(data []byte) {
			binary.LittleEndian.PutUint16(data[fixture.optionalField(0):], 0x999)
		}, want: repe.ErrInvalid},
		{name: "optional header too small", mutate: func(data []byte) {
			binary.LittleEndian.PutUint16(data[fixturePEHeaderOffset+4+16:], 80)
		}, want: repe.ErrInvalid},
		{name: "optional header size zero", mutate: func(data []byte) {
			binary.LittleEndian.PutUint16(data[fixturePEHeaderOffset+4+16:], 0)
		}, want: repe.ErrInvalid},
		{name: "PE32+ optional header too small", mutate: func(data []byte) {
			binary.LittleEndian.PutUint16(data[fixture.optionalField(0):], repe.MagicPE32P)
			binary.LittleEndian.PutUint16(data[fixturePEHeaderOffset+4+16:], 100)
		}, want: repe.ErrInvalid},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			data := append([]byte(nil), fixture.data...)
			if test.mutate != nil {
				test.mutate(data)
			}
			size := test.size
			if size == 0 {
				size = int64(len(data))
			}
			if _, err := repe.Parse(bytes.NewReader(data), size); !errors.Is(err, test.want) {
				t.Fatalf("Parse() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseOptionsAndLimits(t *testing.T) {
	t.Parallel()

	fixture := buildFixture(t, repe.MagicPE32)

	if _, err := repe.Parse(nil, int64(len(fixture.data))); !errors.Is(err, repe.ErrInvalid) {
		t.Fatalf("Parse(nil) error = %v", err)
	}
	if _, err := repe.Parse(bytes.NewReader(fixture.data), -1); !errors.Is(err, repe.ErrInvalid) {
		t.Fatalf("Parse(negative) error = %v", err)
	}
	limits := repe.DefaultLimits()
	limits.ArtifactBytes = 16
	if _, err := repe.ParseWithLimits(bytes.NewReader(fixture.data), int64(len(fixture.data)), limits); !errors.Is(err, repe.ErrLimit) {
		t.Fatalf("ParseWithLimits(over limit) error = %v", err)
	}

	limits = repe.DefaultLimits()
	limits.Sections = 2
	file, err := repe.ParseWithLimits(bytes.NewReader(fixture.data), int64(len(fixture.data)), limits)
	if err != nil {
		t.Fatalf("ParseWithLimits() error = %v", err)
	}
	if !file.Truncated || len(file.Sections) != 2 {
		t.Fatalf("sections = %d, truncated = %t", len(file.Sections), file.Truncated)
	}
	if !hasLimitation(file.Limitations, "section count 3 exceeds limit 2") {
		t.Fatalf("limitations = %v", file.Limitations)
	}

	limits = repe.DefaultLimits()
	limits.DataDirectories = 4
	file, err = repe.ParseWithLimits(bytes.NewReader(fixture.data), int64(len(fixture.data)), limits)
	if err != nil {
		t.Fatalf("ParseWithLimits() error = %v", err)
	}
	if len(file.DataDirectories) != 4 {
		t.Fatalf("directory count = %d", len(file.DataDirectories))
	}
	if !hasLimitation(file.Limitations, "data directory count 16 exceeds limit 4") {
		t.Fatalf("limitations = %v", file.Limitations)
	}
	if _, err := file.DataDirectory(5); !errors.Is(err, repe.ErrUnavailable) {
		t.Fatalf("DataDirectory(5) error = %v", err)
	}

	limits = repe.DefaultLimits()
	limits.SectionDataBytes = 4
	file, err = repe.ParseWithLimits(bytes.NewReader(fixture.data), int64(len(fixture.data)), limits)
	if err != nil {
		t.Fatalf("ParseWithLimits() error = %v", err)
	}
	if _, err := file.SectionData(0); !errors.Is(err, repe.ErrLimit) {
		t.Fatalf("SectionData(0) error = %v", err)
	}
}

func TestParseDataDirectoryCounts(t *testing.T) {
	t.Parallel()

	fixture := buildFixture(t, repe.MagicPE32)
	binary.LittleEndian.PutUint32(fixture.data[fixture.optionalField(92):], 20)
	file := fixture.parse(t)
	if len(file.DataDirectories) != 16 {
		t.Fatalf("directory count = %d", len(file.DataDirectories))
	}
	if !hasLimitation(file.Limitations, "data directory count 20 exceeds the 16 supported entries") {
		t.Fatalf("limitations = %v", file.Limitations)
	}

	// A smaller optional header can hold fewer directories than it declares.
	binary.LittleEndian.PutUint16(fixture.data[fixturePEHeaderOffset+4+16:], 96+16)
	binary.LittleEndian.PutUint32(fixture.data[fixture.optionalField(92):], 16)
	file = fixture.parse(t)
	if len(file.DataDirectories) != 2 {
		t.Fatalf("directory count = %d", len(file.DataDirectories))
	}
	if !hasLimitation(file.Limitations, "exceeds the 2 entries present") {
		t.Fatalf("limitations = %v", file.Limitations)
	}
}

func TestParseHugeDirectoryCount(t *testing.T) {
	t.Parallel()

	fixture := buildFixture(t, repe.MagicPE32)
	binary.LittleEndian.PutUint32(fixture.data[fixture.optionalField(92):], 0xffffffff)
	file := fixture.parse(t)
	if len(file.DataDirectories) != 16 {
		t.Fatalf("directory count = %d", len(file.DataDirectories))
	}
	if file.Header.Optional.NumberOfRvaAndSizes != 0xffffffff {
		t.Fatalf("declared directory count = %#x", file.Header.Optional.NumberOfRvaAndSizes)
	}
	if !hasLimitation(file.Limitations, "data directory count 4294967295 exceeds the 16 supported entries") {
		t.Fatalf("limitations = %v", file.Limitations)
	}
}

func TestLimitsClamp(t *testing.T) {
	t.Parallel()

	fixture := buildFixture(t, repe.MagicPE32)
	binary.LittleEndian.PutUint16(fixture.data[fixturePEHeaderOffset+4+2:], 200)
	tableEnd := fixture.sectionTable + 200*40
	for len(fixture.data) < tableEnd {
		fixture.data = append(fixture.data, 0)
	}

	limits := repe.Limits{
		ArtifactBytes:    repe.MaxArtifactBytes * 2,
		Sections:         repe.MaxSections * 2,
		DataDirectories:  repe.MaxDataDirectories * 2,
		SectionDataBytes: repe.MaxSectionDataBytes * 2,
	}
	file, err := repe.ParseWithLimits(bytes.NewReader(fixture.data), int64(len(fixture.data)), limits)
	if err != nil {
		t.Fatalf("ParseWithLimits() error = %v", err)
	}
	if len(file.Sections) != repe.MaxSections {
		t.Fatalf("loaded %d sections, want %d", len(file.Sections), repe.MaxSections)
	}
	if !file.Truncated || !hasLimitation(file.Limitations, "section count 200 exceeds limit 96") {
		t.Fatalf("truncation = %t, limitations = %v", file.Truncated, file.Limitations)
	}
	if len(file.DataDirectories) != repe.MaxDataDirectories {
		t.Fatalf("loaded %d directories, want %d", len(file.DataDirectories), repe.MaxDataDirectories)
	}
}

func TestSectionNameAndOverlayEdges(t *testing.T) {
	t.Parallel()

	fixture := buildFixture(t, repe.MagicPE32)
	copy(fixture.data[fixture.sectionOffset(0, 0):], []byte{0xff, 0xfe, 0xfd, 0xfc, 0, 0, 0, 0})
	copy(fixture.data[fixture.sectionOffset(1, 0):], []byte{0, 0, 0, 0, 0, 0, 0, 0})
	binary.LittleEndian.PutUint32(fixture.data[fixture.sectionOffset(2, 16):], 0x10)
	binary.LittleEndian.PutUint32(fixture.data[fixture.sectionOffset(2, 20):], uint32(len(fixture.data)+0x10))
	file := fixture.parse(t)

	if file.Sections[0].NameAvailable || file.Sections[0].Name != "" {
		t.Fatalf("invalid name section = %+v", file.Sections[0])
	}
	if file.Sections[1].NameAvailable || file.Sections[1].Name != "" {
		t.Fatalf("empty name section = %+v", file.Sections[1])
	}
	if !hasLimitation(file.Limitations, "1 section names are not valid UTF-8") {
		t.Fatalf("limitations = %v", file.Limitations)
	}
	if file.OverlaySize != 0 || file.OverlayOffset != 0 {
		t.Fatalf("overlay reported with out-of-range section = %d/%d", file.OverlayOffset, file.OverlaySize)
	}
	if !hasLimitation(file.Limitations, "overlay is not reported") {
		t.Fatalf("limitations = %v", file.Limitations)
	}
	if _, err := file.SectionData(2); !errors.Is(err, repe.ErrUnavailable) {
		t.Fatalf("SectionData(2) error = %v", err)
	}
}

func TestSizeOfHeadersBeyondArtifact(t *testing.T) {
	t.Parallel()

	fixture := buildFixture(t, repe.MagicPE32)
	binary.LittleEndian.PutUint32(fixture.data[fixture.optionalField(60):], 0x1000)
	file := fixture.parse(t)
	if !hasLimitation(file.Limitations, "SizeOfHeaders 4096 exceeds artifact size") {
		t.Fatalf("limitations = %v", file.Limitations)
	}
	if file.OverlayOffset != 0 || file.OverlaySize != 0 {
		t.Fatalf("overlay = %d/%d, want unreported", file.OverlayOffset, file.OverlaySize)
	}
}

func TestSectionDataReaderFailure(t *testing.T) {
	t.Parallel()

	fixture := buildFixture(t, repe.MagicPE32)
	reader := failingReader{data: fixture.data, off: int64(fixtureTextOffset)}
	file, err := repe.Parse(reader, int64(len(fixture.data)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if _, err := file.SectionData(0); !errors.Is(err, repe.ErrRead) {
		t.Fatalf("SectionData(0) error = %v, want ErrRead", err)
	}
}

type failingReader struct {
	data []byte
	off  int64
}

func (r failingReader) ReadAt(p []byte, off int64) (int, error) {
	if off == r.off {
		return 0, io.ErrUnexpectedEOF
	}
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	return copy(p, r.data[off:]), nil
}

func hasLimitation(limitations []string, fragment string) bool {
	for _, limitation := range limitations {
		if bytes.Contains([]byte(limitation), []byte(fragment)) {
			return true
		}
	}
	return false
}

func TestDataDirectoryAccessor(t *testing.T) {
	t.Parallel()

	fixture := buildFixture(t, repe.MagicPE32)
	file := fixture.parse(t)
	directory, err := file.DataDirectory(4)
	if err != nil || directory.VirtualAddress != fixtureOverlayOffset || directory.Size != uint32(len(fixtureOverlay)) {
		t.Fatalf("DataDirectory(4) = %+v, %v", directory, err)
	}
	if _, err := file.DataDirectory(-1); !errors.Is(err, repe.ErrOutOfRange) {
		t.Fatalf("DataDirectory(-1) error = %v", err)
	}
	if _, err := file.DataDirectory(16); !errors.Is(err, repe.ErrOutOfRange) {
		t.Fatalf("DataDirectory(16) error = %v", err)
	}
}

func TestDifferentialAgainstDebugPE(t *testing.T) {
	t.Parallel()

	for _, magic := range []uint16{repe.MagicPE32, repe.MagicPE32P} {
		magic := magic
		t.Run(magicName(t, magic), func(t *testing.T) {
			t.Parallel()

			fixture := buildFixture(t, magic)
			got := fixture.parse(t)
			want, err := pe.NewFile(bytes.NewReader(fixture.data))
			if err != nil {
				t.Fatalf("debug/pe.NewFile() error = %v", err)
			}
			t.Cleanup(func() { _ = want.Close() })

			compareFileHeader(t, got, want.FileHeader)
			compareOptionalHeader(t, got, want)
			compareSections(t, got, want.Sections)
		})
	}
}

func compareFileHeader(t *testing.T, got *repe.File, want pe.FileHeader) {
	t.Helper()

	if got.Header.Machine != want.Machine ||
		got.Header.NumberOfSections != want.NumberOfSections ||
		got.Header.TimeDateStamp != want.TimeDateStamp ||
		got.Header.PointerToSymbolTable != want.PointerToSymbolTable ||
		got.Header.NumberOfSymbols != want.NumberOfSymbols ||
		got.Header.SizeOfOptionalHeader != want.SizeOfOptionalHeader ||
		got.Header.Characteristics != want.Characteristics {
		t.Fatalf("file header = %+v, want %+v", got.Header, want)
	}
}

func compareOptionalHeader(t *testing.T, got *repe.File, want *pe.File) {
	t.Helper()

	switch optional := want.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		checkOptional(t, got.Header.Optional, optional.Magic, optional.AddressOfEntryPoint,
			uint64(optional.ImageBase), optional.SectionAlignment, optional.FileAlignment,
			optional.SizeOfImage, optional.SizeOfHeaders, optional.Subsystem,
			optional.DllCharacteristics, optional.NumberOfRvaAndSizes)
		checkDirectories(t, got.DataDirectories, optional.DataDirectory[:])
	case *pe.OptionalHeader64:
		checkOptional(t, got.Header.Optional, optional.Magic, optional.AddressOfEntryPoint,
			optional.ImageBase, optional.SectionAlignment, optional.FileAlignment,
			optional.SizeOfImage, optional.SizeOfHeaders, optional.Subsystem,
			optional.DllCharacteristics, optional.NumberOfRvaAndSizes)
		checkDirectories(t, got.DataDirectories, optional.DataDirectory[:])
	default:
		t.Fatalf("unexpected optional header type %T", optional)
	}
}

func checkOptional(t *testing.T, got repe.OptionalHeader, magic uint16, entry uint32, imageBase uint64,
	sectionAlignment, fileAlignment, imageSize, headersSize uint32, subsystem, dllCharacteristics uint16,
	directories uint32) {
	t.Helper()

	if got.Magic != magic || got.AddressOfEntryPoint != entry || got.ImageBase != imageBase ||
		got.SectionAlignment != sectionAlignment || got.FileAlignment != fileAlignment ||
		got.SizeOfImage != imageSize || got.SizeOfHeaders != headersSize ||
		got.Subsystem != subsystem || got.DllCharacteristics != dllCharacteristics ||
		got.NumberOfRvaAndSizes != directories {
		t.Fatalf("optional header = %+v", got)
	}
}

func checkDirectories(t *testing.T, got []repe.DataDirectory, want []pe.DataDirectory) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("directory count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].VirtualAddress != want[i].VirtualAddress || got[i].Size != want[i].Size {
			t.Fatalf("directory %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func compareSections(t *testing.T, got *repe.File, want []*pe.Section) {
	t.Helper()

	if len(got.Sections) != len(want) {
		t.Fatalf("section count = %d, want %d", len(got.Sections), len(want))
	}
	for i, section := range want {
		header := got.Sections[i]
		if header.Name != section.Name {
			t.Fatalf("section %d name = %q, want %q", i, header.Name, section.Name)
		}
		if header.VirtualSize != section.VirtualSize ||
			header.VirtualAddress != section.VirtualAddress ||
			header.SizeOfRawData != section.Size ||
			header.PointerToRawData != section.Offset ||
			header.Characteristics != section.Characteristics {
			t.Fatalf("section %d = %+v, want %+v", i, header, section.SectionHeader)
		}
		own, err := got.SectionData(i)
		if err != nil {
			t.Fatalf("SectionData(%d) error = %v", i, err)
		}
		oracle, err := section.Data()
		if err != nil {
			t.Fatalf("debug/pe section %d data error = %v", i, err)
		}
		if !bytes.Equal(own, oracle) {
			t.Fatalf("section %d data = %x, want %x", i, own, oracle)
		}
	}
}

func FuzzParse(f *testing.F) {
	fixture32 := buildFixture(f, repe.MagicPE32)
	f.Add(fixture32.data)
	fixture64 := buildFixture(f, repe.MagicPE32P)
	f.Add(fixture64.data)
	f.Add([]byte{})
	f.Add([]byte("MZ"))

	limits := repe.Limits{
		ArtifactBytes:       1 << 20,
		Sections:            8,
		DataDirectories:     8,
		SectionDataBytes:    16 << 10,
		ImportModules:       8,
		ImportThunks:        32,
		Exports:             32,
		StringBytes:         256,
		ImportStringBytes:   4 << 10,
		ExportStringBytes:   4 << 10,
		ResourceDepth:       4,
		ResourceEntries:     16,
		ResourceStringBytes: 4 << 10,
		Certificates:        4,
		CertificateBytes:    64 << 10,
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := repe.ParseWithLimits(bytes.NewReader(data), int64(len(data)), limits)
		if err != nil {
			if file != nil {
				t.Fatalf("Parse() returned file %+v with error %v", file, err)
			}
			return
		}
		if file == nil {
			t.Fatal("Parse() returned nil file without error")
		}

		sections := len(file.Sections)
		if sections > int(file.Header.NumberOfSections) {
			t.Fatalf("loaded %d section headers above declared count %d",
				sections, file.Header.NumberOfSections)
		}
		if sections > limits.Sections {
			t.Fatalf("loaded %d section headers above limit %d", sections, limits.Sections)
		}
		if file.Truncated == (sections == int(file.Header.NumberOfSections)) {
			t.Fatalf("truncation = %t with %d of %d sections",
				file.Truncated, sections, file.Header.NumberOfSections)
		}

		directories := len(file.DataDirectories)
		if directories > int(file.Header.Optional.NumberOfRvaAndSizes) {
			t.Fatalf("loaded %d directories above declared count %d",
				directories, file.Header.Optional.NumberOfRvaAndSizes)
		}
		if directories > limits.DataDirectories {
			t.Fatalf("loaded %d directories above limit %d", directories, limits.DataDirectories)
		}

		for i, section := range file.Sections {
			if section.Index != i {
				t.Fatalf("section index = %d at position %d", section.Index, i)
			}
			content, err := file.SectionData(i)
			if err == nil && uint64(len(content)) != uint64(section.SizeOfRawData) {
				t.Fatalf("section %d read %d bytes, declared %d",
					i, len(content), section.SizeOfRawData)
			}
		}
		for i := range file.DataDirectories {
			if _, err := file.DataDirectory(i); err != nil {
				t.Fatalf("DataDirectory(%d) error = %v", i, err)
			}
		}
		for _, rva := range []uint32{0, 1, 0x1000, 0x2000, 0x7fffffff, 0xffffffff} {
			mapping := file.MapRVA(rva)
			if mapping.SectionIndex < -1 || mapping.SectionIndex >= sections {
				t.Fatalf("MapRVA(%#x) section index = %d", rva, mapping.SectionIndex)
			}
		}

		imports, err := file.Imports()
		if err == nil {
			if imports == nil {
				t.Fatal("Imports() returned nil table without error")
			}
			if len(imports.Modules) > limits.ImportModules {
				t.Fatalf("loaded %d import modules above limit %d", len(imports.Modules), limits.ImportModules)
			}
			thunks := 0
			for i, module := range imports.Modules {
				if module.Index != i {
					t.Fatalf("import module index = %d at position %d", module.Index, i)
				}
				thunks += len(module.Thunks)
				for j, thunk := range module.Thunks {
					if thunk.Index != j {
						t.Fatalf("import thunk index = %d at position %d", thunk.Index, j)
					}
				}
			}
			if thunks > limits.ImportThunks {
				t.Fatalf("loaded %d import thunks above limit %d", thunks, limits.ImportThunks)
			}
		}

		exports, err := file.Exports()
		if err == nil {
			if exports == nil {
				t.Fatal("Exports() returned nil table without error")
			}
			if len(exports.Exports) > limits.Exports {
				t.Fatalf("loaded %d exports above limit %d", len(exports.Exports), limits.Exports)
			}
			for i, entry := range exports.Exports {
				if entry.Index != i {
					t.Fatalf("export index = %d at position %d", entry.Index, i)
				}
			}
		}

		resources, err := file.Resources()
		if err == nil {
			if resources == nil {
				t.Fatal("Resources() returned nil table without error")
			}
			if len(resources.Resources) > limits.ResourceEntries {
				t.Fatalf("loaded %d resources above limit %d", len(resources.Resources), limits.ResourceEntries)
			}
			for _, resource := range resources.Resources {
				if len(resource.Path) == 0 || len(resource.Path) > limits.ResourceDepth+1 {
					t.Fatalf("resource path depth = %d", len(resource.Path))
				}
			}
		}

		certificates, err := file.Certificates()
		if err == nil {
			if certificates == nil {
				t.Fatal("Certificates() returned nil table without error")
			}
			if len(certificates.Certificates) > limits.Certificates {
				t.Fatalf("loaded %d certificates above limit %d", len(certificates.Certificates), limits.Certificates)
			}
			for i, certificate := range certificates.Certificates {
				if certificate.Index != i {
					t.Fatalf("certificate index = %d at position %d", certificate.Index, i)
				}
				if certificate.DataOffset <= certificate.Offset || certificate.DataSize+8 != certificate.Length {
					t.Fatalf("certificate %d = %+v", i, certificate)
				}
			}
		}
	})
}
