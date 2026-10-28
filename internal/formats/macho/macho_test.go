package macho

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func parseImageBytes(t *testing.T, image []byte) *Artifact {
	t.Helper()
	artifact, err := Parse(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return artifact
}

func onlyFile(t *testing.T, artifact *Artifact) *File {
	t.Helper()
	if artifact == nil || len(artifact.Slices) != 1 {
		t.Fatalf("expected one slice, got %#v", artifact)
	}
	if artifact.Slices[0].File == nil {
		t.Fatalf("slice error: %v", artifact.Slices[0].Err)
	}
	return artifact.Slices[0].File
}

func TestParseThin64(t *testing.T) {
	image := buildImage(t, defaultImage())
	artifact := parseImageBytes(t, image)
	file := onlyFile(t, artifact)

	if artifact.Fat {
		t.Fatal("thin image reported as fat")
	}
	if artifact.Magic != Magic64 || file.Header.Magic != Magic64 {
		t.Fatalf("magic = %#x / %#x, want %#x", artifact.Magic, file.Header.Magic, Magic64)
	}
	if !file.Header.Is64 || file.Header.Data != DataLittle {
		t.Fatalf("is64=%v data=%v", file.Header.Is64, file.Header.Data)
	}
	if file.Header.CPUType != fixtureCPUAMD64 || file.Header.CPUSubtype != 3 {
		t.Fatalf("cpu = %#x/%#x", file.Header.CPUType, file.Header.CPUSubtype)
	}
	if file.Header.FileType != fixtureFileDylib || file.Header.Flags != 0x00200085 {
		t.Fatalf("file type or flags wrong: %#v", file.Header)
	}
	if file.Header.NumberOfCommands != 2 || file.Header.LoadedCommandCount != 2 {
		t.Fatalf("commands = %d/%d", file.Header.NumberOfCommands, file.Header.LoadedCommandCount)
	}
	if len(file.Commands) != 2 || file.Commands[1].Command != 0x1b || file.Commands[1].Size != 24 {
		t.Fatalf("commands = %#v", file.Commands)
	}
	if len(file.Segments) != 1 {
		t.Fatalf("segments = %d", len(file.Segments))
	}
	segment := file.Segments[0]
	if segment.Name != "__TEXT" || !segment.NameAvailable {
		t.Fatalf("segment name = %q available=%v", segment.Name, segment.NameAvailable)
	}
	if segment.VMAddress != 0x100000000 || segment.InitProtection != 5 || segment.MaxProtection != 5 {
		t.Fatalf("segment fields = %#v", segment)
	}
	if segment.DeclaredSectionCount != 2 || segment.SectionCount != 2 || segment.FirstSection != 0 {
		t.Fatalf("segment sections = %#v", segment)
	}
	if file.Header.LoadedSectionCount != 2 || len(file.Sections) != 2 {
		t.Fatalf("loaded sections = %d", len(file.Sections))
	}

	text := file.Sections[0]
	if text.Name != "__text" || !text.NameAvailable || text.SegmentIndex != 0 {
		t.Fatalf("section = %#v", text)
	}
	if text.Address != 0x100001000 || text.Size != 10 || text.Flags != 0x80000400 {
		t.Fatalf("section fields = %#v", text)
	}
	if file.Sections[1].Name != "__const" || file.Sections[1].Size != 11 {
		t.Fatalf("second section = %#v", file.Sections[1])
	}
	if file.Truncated {
		t.Fatal("unexpected truncation")
	}
	if len(file.Limitations) != 0 {
		t.Fatalf("limitations = %v", file.Limitations)
	}
	if file.Size() != int64(len(image)) || artifact.Size() != int64(len(image)) {
		t.Fatalf("sizes = %d/%d/%d", file.Size(), artifact.Size(), len(image))
	}

	data, err := file.SectionData(0)
	if err != nil || string(data) != "text-bytes" {
		t.Fatalf("SectionData(0) = %q, %v", data, err)
	}
	data, err = file.SectionData(1)
	if err != nil || string(data) != "const-bytes" {
		t.Fatalf("SectionData(1) = %q, %v", data, err)
	}
}

func TestParseThin32(t *testing.T) {
	opt := defaultImage()
	opt.is64 = false
	opt.cpuType = fixtureCPUI386
	opt.segments[0].vmaddr = 0x1000
	opt.segments[0].sections[0].addr = 0x2000
	image := buildImage(t, opt)
	file := onlyFile(t, parseImageBytes(t, image))

	if file.Header.Magic != Magic32 || file.Header.Is64 {
		t.Fatalf("header = %#v", file.Header)
	}
	if file.Header.Reserved != 0 {
		t.Fatal("32-bit header has a reserved field")
	}
	if len(file.Sections) != 2 || file.Sections[0].Address != 0x2000 {
		t.Fatalf("sections = %#v", file.Sections)
	}
	data, err := file.SectionData(0)
	if err != nil || string(data) != "text-bytes" {
		t.Fatalf("SectionData(0) = %q, %v", data, err)
	}
	if file.Truncated || len(file.Limitations) != 0 {
		t.Fatalf("truncated=%v limitations=%v", file.Truncated, file.Limitations)
	}
}

func TestParseBigEndian(t *testing.T) {
	opt := defaultImage()
	opt.is64 = false
	opt.data = DataBig
	opt.cpuType = 18
	image := buildImage(t, opt)
	if got := image[:4]; !bytes.Equal(got, []byte{0xfe, 0xed, 0xfa, 0xce}) {
		t.Fatalf("magic bytes = %x", got)
	}
	file := onlyFile(t, parseImageBytes(t, image))
	if file.Header.Data != DataBig || file.Header.Magic != Magic32 {
		t.Fatalf("header = %#v", file.Header)
	}
	if file.Sections[0].Name != "__text" || file.Segments[0].Name != "__TEXT" {
		t.Fatalf("names not decoded: %#v %#v", file.Segments[0], file.Sections[0])
	}
	data, err := file.SectionData(0)
	if err != nil || string(data) != "text-bytes" {
		t.Fatalf("SectionData(0) = %q, %v", data, err)
	}
}

func TestParseNoCommands(t *testing.T) {
	opt := defaultImage()
	opt.segments = nil
	opt.extra = nil
	image := buildImage(t, opt)
	file := onlyFile(t, parseImageBytes(t, image))
	if file.Truncated || len(file.Limitations) != 0 {
		t.Fatalf("truncated=%v limitations=%v", file.Truncated, file.Limitations)
	}
	if len(file.Commands) != 0 || len(file.Segments) != 0 {
		t.Fatalf("commands=%d segments=%d", len(file.Commands), len(file.Segments))
	}
}

func TestParseFat(t *testing.T) {
	first := buildImage(t, defaultImage())
	secondOpt := defaultImage()
	secondOpt.is64 = false
	secondOpt.cpuType = fixtureCPUI386
	second := buildImage(t, secondOpt)
	fat := buildFat(t, false, false, []fixtureFatSlice{
		{cpuType: fixtureCPUAMD64, cpuSubtype: 3, data: first},
		{cpuType: fixtureCPUI386, cpuSubtype: 3, data: second},
	})

	artifact := parseImageBytes(t, fat)
	if !artifact.Fat || artifact.Magic != FatMagic || artifact.Data != DataBig {
		t.Fatalf("artifact = %#v", artifact)
	}
	if len(artifact.Slices) != 2 {
		t.Fatalf("slices = %d", len(artifact.Slices))
	}
	if artifact.Limitations != nil {
		t.Fatalf("limitations = %v", artifact.Limitations)
	}
	for i, want := range []uint32{fixtureCPUAMD64, fixtureCPUI386} {
		slice := artifact.Slices[i]
		if slice.Index != i || slice.CPUType != want {
			t.Fatalf("slice %d = %#v", i, slice)
		}
		if slice.File == nil {
			t.Fatalf("slice %d error: %v", i, slice.Err)
		}
		if slice.Offset < int64(fatHeaderSize) || slice.Size <= 0 {
			t.Fatalf("slice %d bounds = %d/%d", i, slice.Offset, slice.Size)
		}
		if slice.Offset+slice.Size > int64(len(fat)) {
			t.Fatalf("slice %d range escapes the artifact", i)
		}
	}
	if artifact.Slices[0].File.Header.Is64 != true || artifact.Slices[1].File.Header.Is64 != false {
		t.Fatal("slice headers mixed up")
	}
	if artifact.Slices[0].Alignment != 12 {
		t.Fatalf("alignment = %d", artifact.Slices[0].Alignment)
	}
	data, err := artifact.Slices[0].File.SectionData(0)
	if err != nil || string(data) != "text-bytes" {
		t.Fatalf("fat slice SectionData = %q, %v", data, err)
	}
}

func TestParseFat64Swapped(t *testing.T) {
	first := buildImage(t, defaultImage())
	fat := buildFat(t, true, true, []fixtureFatSlice{
		{cpuType: fixtureCPUAMD64, cpuSubtype: 3, data: first, align: 14},
	})
	artifact := parseImageBytes(t, fat)
	if artifact.Magic != FatMagic64 || artifact.Data != DataLittle {
		t.Fatalf("artifact = %#v", artifact)
	}
	if len(artifact.Slices) != 1 || artifact.Slices[0].File == nil {
		t.Fatalf("slices = %#v", artifact.Slices)
	}
	if artifact.Slices[0].Alignment != 14 {
		t.Fatalf("alignment = %d", artifact.Slices[0].Alignment)
	}
}

func TestParseFatBadSlice(t *testing.T) {
	good := buildImage(t, defaultImage())
	fat := buildFat(t, false, false, []fixtureFatSlice{
		{cpuType: fixtureCPUAMD64, data: good},
		{cpuType: fixtureCPUI386, data: []byte("this is not a mach-o image")},
	})
	artifact := parseImageBytes(t, fat)
	if len(artifact.Slices) != 2 {
		t.Fatalf("slices = %d", len(artifact.Slices))
	}
	if artifact.Slices[0].File == nil {
		t.Fatalf("good slice failed: %v", artifact.Slices[0].Err)
	}
	if artifact.Slices[1].File != nil || artifact.Slices[1].Err == nil {
		t.Fatalf("bad slice = %#v", artifact.Slices[1])
	}
	if !errors.Is(artifact.Slices[1].Err, ErrInvalid) {
		t.Fatalf("bad slice error = %v", artifact.Slices[1].Err)
	}
	if len(artifact.Limitations) != 1 {
		t.Fatalf("limitations = %v", artifact.Limitations)
	}
	if !bytes.Contains([]byte(artifact.Limitations[0]), []byte("slice 1 could not be parsed")) {
		t.Fatalf("limitation = %q", artifact.Limitations[0])
	}
}

func TestParseFatAllSlicesBad(t *testing.T) {
	fat := buildFat(t, false, false, []fixtureFatSlice{
		{cpuType: fixtureCPUAMD64, data: []byte("not-a-macho")},
	})
	_, err := Parse(bytes.NewReader(fat), int64(len(fat)))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v", err)
	}
}

func TestParseFatSliceLimits(t *testing.T) {
	first := buildImage(t, defaultImage())
	fat := buildFat(t, false, false, []fixtureFatSlice{
		{cpuType: fixtureCPUAMD64, data: first},
		{cpuType: fixtureCPUI386, data: first},
	})
	_, err := ParseWithLimits(bytes.NewReader(fat), int64(len(fat)), Limits{FatSlices: 1})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("error = %v", err)
	}
}

func TestParseFatSliceOutOfRange(t *testing.T) {
	first := buildImage(t, defaultImage())
	fat := buildFat(t, false, false, []fixtureFatSlice{
		{cpuType: fixtureCPUAMD64, data: first},
		{cpuType: fixtureCPUI386, data: first},
	})
	// Point the second entry past the artifact end.
	putUint32(t, DataBig, fat, fatHeaderSize+fatEntry32Size+8, 0x7fffffff)
	artifact := parseImageBytes(t, fat)
	if artifact.Slices[1].Err == nil {
		t.Fatal("out-of-range slice parsed")
	}
	if !errors.Is(artifact.Slices[1].Err, ErrTruncated) {
		t.Fatalf("error = %v", artifact.Slices[1].Err)
	}
	if artifact.Slices[0].File == nil {
		t.Fatal("first slice lost")
	}
}

func TestParseErrors(t *testing.T) {
	valid := buildImage(t, defaultImage())
	inconsistent := append([]byte(nil), valid...)
	putUint32(t, DataLittle, inconsistent, 20, 8) // two commands cannot fit in eight bytes

	tests := []struct {
		name   string
		reader *bytes.Reader
		size   int64
		want   error
	}{
		{name: "negative size", reader: bytes.NewReader(nil), size: -1, want: ErrInvalid},
		{name: "empty", reader: bytes.NewReader(nil), size: 0, want: ErrTruncated},
		{name: "short magic", reader: bytes.NewReader([]byte{0xcf, 0xfa, 0xed}), size: 3, want: ErrTruncated},
		{name: "bad magic", reader: bytes.NewReader([]byte("NOPE")), size: 4, want: ErrInvalid},
		{name: "magic only", reader: bytes.NewReader(valid[:4]), size: 4, want: ErrTruncated},
		{name: "short header", reader: bytes.NewReader(valid[:20]), size: 20, want: ErrTruncated},
		{name: "commands do not fit", reader: bytes.NewReader(inconsistent), size: int64(len(inconsistent)), want: ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.reader, test.size)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseNilReader(t *testing.T) {
	_, err := Parse(nil, 0)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v", err)
	}
}

func TestParseArtifactLimit(t *testing.T) {
	image := buildImage(t, defaultImage())
	_, err := ParseWithLimits(bytes.NewReader(image), int64(len(image)), Limits{ArtifactBytes: 64})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("error = %v", err)
	}
}

func TestParseFatHeaderErrors(t *testing.T) {
	t.Run("no slices", func(t *testing.T) {
		header := make([]byte, fatHeaderSize)
		writeMagic(header, DataBig, FatMagic)
		_, err := Parse(bytes.NewReader(header), int64(len(header)))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("table beyond artifact", func(t *testing.T) {
		header := make([]byte, fatHeaderSize)
		writeMagic(header, DataBig, FatMagic)
		fixtureOrder(DataBig).PutUint32(header[4:], 2)
		_, err := Parse(bytes.NewReader(header), int64(len(header)))
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestParseLoadCommandDefects(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func([]byte)
		wantSub string
	}{
		{
			name: "zero size",
			mutate: func(image []byte) {
				putUint32(t, DataLittle, image, header64Size+4, 0)
			},
			wantSub: "invalid size 0",
		},
		{
			name: "unaligned size",
			mutate: func(image []byte) {
				putUint32(t, DataLittle, image, header64Size+4, 10)
			},
			wantSub: "not 4-byte aligned",
		},
		{
			name: "beyond table",
			mutate: func(image []byte) {
				putUint32(t, DataLittle, image, header64Size+4, 0x1000)
			},
			wantSub: "extends beyond the load command table",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := buildImage(t, defaultImage())
			test.mutate(image)
			file := onlyFile(t, parseImageBytes(t, image))
			if !file.Truncated {
				t.Fatal("defect did not set Truncated")
			}
			if len(file.Limitations) == 0 {
				t.Fatal("defect produced no limitation")
			}
			if !bytes.Contains([]byte(file.Limitations[0]), []byte(test.wantSub)) {
				t.Fatalf("limitation = %q, want substring %q", file.Limitations[0], test.wantSub)
			}
			if len(file.Commands) != 0 {
				t.Fatalf("commands = %#v", file.Commands)
			}
		})
	}
}

func TestParseTrailingCommandBytes(t *testing.T) {
	// One eight-byte command followed by eight unclaimed bytes.
	header := make([]byte, header64Size+16)
	writeMagic(header, DataLittle, Magic64)
	order := fixtureOrder(DataLittle)
	order.PutUint32(header[4:], fixtureCPUAMD64)
	order.PutUint32(header[12:], fixtureFileExec)
	order.PutUint32(header[16:], 1)
	order.PutUint32(header[20:], 16)
	order.PutUint32(header[header64Size:], 0x1b)
	order.PutUint32(header[header64Size+4:], 8)

	file := onlyFile(t, parseImageBytes(t, header))
	if !file.Truncated {
		t.Fatal("trailing bytes did not set Truncated")
	}
	want := "load command table has 8 trailing bytes"
	if len(file.Limitations) != 1 || file.Limitations[0] != want {
		t.Fatalf("limitations = %v", file.Limitations)
	}
}

func TestParseLoadCommandTableTruncated(t *testing.T) {
	image := buildImage(t, defaultImage())
	putUint32(t, DataLittle, image, 20, 4096)
	file := onlyFile(t, parseImageBytes(t, image))
	if !file.Truncated {
		t.Fatal("declared size beyond artifact did not set Truncated")
	}
	if !bytes.Contains([]byte(file.Limitations[0]), []byte("load command table truncated at")) {
		t.Fatalf("limitations = %v", file.Limitations)
	}
	if len(file.Commands) != 2 || len(file.Segments) != 1 {
		t.Fatalf("commands=%d segments=%d", len(file.Commands), len(file.Segments))
	}
}

func TestParseCommandCountLimit(t *testing.T) {
	image := buildImage(t, defaultImage())
	artifact, err := ParseWithLimits(bytes.NewReader(image), int64(len(image)), Limits{LoadCommands: 1})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	file := onlyFile(t, artifact)
	if !file.Truncated || len(file.Commands) != 1 {
		t.Fatalf("truncated=%v commands=%d", file.Truncated, len(file.Commands))
	}
	want := "load command count 2 exceeds limit 1"
	if file.Limitations[0] != want {
		t.Fatalf("limitations = %v", file.Limitations)
	}
	if len(file.Segments) != 1 || len(file.Sections) != 2 {
		t.Fatal("segment command lost to the command limit")
	}
}

func twoSegmentImage() fixtureImage {
	opt := defaultImage()
	opt.segments = []fixtureSegment{
		{
			name: "__TEXT", vmaddr: 0x100000000,
			sections: []fixtureSection{{name: "__text", addr: 0x100001000, data: []byte("first")}},
		},
		{
			name: "__DATA", vmaddr: 0x100004000,
			sections: []fixtureSection{{name: "__data", addr: 0x100005000, data: []byte("second")}},
		},
	}
	return opt
}

func TestParseSegmentLimit(t *testing.T) {
	image := buildImage(t, twoSegmentImage())
	artifact, err := ParseWithLimits(bytes.NewReader(image), int64(len(image)), Limits{Segments: 1})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	file := onlyFile(t, artifact)
	if !file.Truncated || len(file.Segments) != 1 {
		t.Fatalf("truncated=%v segments=%d", file.Truncated, len(file.Segments))
	}
	if !bytes.Contains([]byte(file.Limitations[0]), []byte("segment count 2 exceeds limit 1")) {
		t.Fatalf("limitations = %v", file.Limitations)
	}
}

func TestParseSectionLimit(t *testing.T) {
	image := buildImage(t, twoSegmentImage())
	artifact, err := ParseWithLimits(bytes.NewReader(image), int64(len(image)), Limits{Sections: 1})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	file := onlyFile(t, artifact)
	if !file.Truncated || len(file.Sections) != 1 {
		t.Fatalf("truncated=%v sections=%d", file.Truncated, len(file.Sections))
	}
	limitations := 0
	for _, limitation := range file.Limitations {
		if bytes.Contains([]byte(limitation), []byte("section count")) {
			limitations++
		}
	}
	if limitations != 1 {
		t.Fatalf("section limitations = %d in %v", limitations, file.Limitations)
	}
	if file.Segments[0].SectionCount != 1 || file.Segments[1].SectionCount != 0 {
		t.Fatalf("segment section counts = %d/%d",
			file.Segments[0].SectionCount, file.Segments[1].SectionCount)
	}
}

func TestParseSegmentHeaderTooShort(t *testing.T) {
	image := buildImage(t, defaultImage())
	// Shrink the segment command below its fixed header, keeping the chain
	// consistent by leaving the table size unchanged.
	putUint32(t, DataLittle, image, header64Size+4, 40)
	image = image[:header64Size+40+24]
	putUint32(t, DataLittle, image, 20, 64)

	file := onlyFile(t, parseImageBytes(t, image))
	if len(file.Segments) != 0 {
		t.Fatalf("segments = %#v", file.Segments)
	}
	if !bytes.Contains([]byte(file.Limitations[0]), []byte("shorter than its fixed header")) {
		t.Fatalf("limitations = %v", file.Limitations)
	}
}

func TestParseNames(t *testing.T) {
	t.Run("invalid utf8", func(t *testing.T) {
		image := buildImage(t, defaultImage())
		image[header64Size+72] = 0xff
		file := onlyFile(t, parseImageBytes(t, image))
		section := file.Sections[0]
		if section.NameAvailable || section.Name != "" {
			t.Fatalf("section = %#v", section)
		}
		want := "1 segment or section names are not valid UTF-8"
		if file.Limitations[len(file.Limitations)-1] != want {
			t.Fatalf("limitations = %v", file.Limitations)
		}
	})
	t.Run("empty", func(t *testing.T) {
		image := buildImage(t, defaultImage())
		for i := 0; i < fixedNameSize; i++ {
			image[header64Size+72+i] = 0
		}
		file := onlyFile(t, parseImageBytes(t, image))
		if file.Sections[0].NameAvailable {
			t.Fatal("empty name reported as available")
		}
		for _, limitation := range file.Limitations {
			if bytes.Contains([]byte(limitation), []byte("UTF-8")) {
				t.Fatalf("empty name produced a limitation: %v", file.Limitations)
			}
		}
	})
	t.Run("full width", func(t *testing.T) {
		image := buildImage(t, defaultImage())
		copy(image[header64Size+72:header64Size+88], "__sixteen_chars_")
		file := onlyFile(t, parseImageBytes(t, image))
		if file.Sections[0].Name != "__sixteen_chars_" || !file.Sections[0].NameAvailable {
			t.Fatalf("section = %#v", file.Sections[0])
		}
	})
}

func TestParseOutsideRanges(t *testing.T) {
	t.Run("section", func(t *testing.T) {
		image := buildImage(t, defaultImage())
		putUint32(t, DataLittle, image, header64Size+72+48, 0x7fffffff)
		file := onlyFile(t, parseImageBytes(t, image))
		want := "1 section ranges extend beyond the slice"
		if file.Limitations[len(file.Limitations)-1] != want {
			t.Fatalf("limitations = %v", file.Limitations)
		}
	})
	t.Run("segment", func(t *testing.T) {
		image := buildImage(t, defaultImage())
		putUint64(t, DataLittle, image, header64Size+40, 0x7fffffff)
		file := onlyFile(t, parseImageBytes(t, image))
		want := "1 segment file ranges extend beyond the slice"
		if file.Limitations[len(file.Limitations)-1] != want {
			t.Fatalf("limitations = %v", file.Limitations)
		}
	})
}

func TestSectionData(t *testing.T) {
	image := buildImage(t, defaultImage())
	file := onlyFile(t, parseImageBytes(t, image))

	if _, err := file.SectionData(-1); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("negative index error = %v", err)
	}
	if _, err := file.SectionData(2); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("large index error = %v", err)
	}

	artifact, err := ParseWithLimits(bytes.NewReader(image), int64(len(image)), Limits{SectionDataBytes: 5})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	limited := onlyFile(t, artifact)
	if _, err := limited.SectionData(0); !errors.Is(err, ErrLimit) {
		t.Fatalf("limit error = %v", err)
	}

	broken := buildImage(t, defaultImage())
	putUint32(t, DataLittle, broken, header64Size+72+48, 0x7fffffff)
	brokenFile := onlyFile(t, parseImageBytes(t, broken))
	if _, err := brokenFile.SectionData(0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unavailable error = %v", err)
	}

	empty := defaultImage()
	empty.segments[0].sections = []fixtureSection{{name: "__bss", addr: 0x100003000}}
	emptyFile := onlyFile(t, parseImageBytes(t, buildImage(t, empty)))
	data, err := emptyFile.SectionData(0)
	if err != nil || len(data) != 0 {
		t.Fatalf("empty section = %q, %v", data, err)
	}

	var nilFile *File
	if _, err := nilFile.SectionData(0); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("nil file error = %v", err)
	}
	if nilFile.Size() != 0 {
		t.Fatal("nil file size")
	}
	var nilArtifact *Artifact
	if nilArtifact.Size() != 0 {
		t.Fatal("nil artifact size")
	}
}

func TestLimitsDefaultsAndClamping(t *testing.T) {
	defaults := DefaultLimits()
	if got := (Limits{}).withDefaults(); got != defaults {
		t.Fatalf("zero limits = %#v, want %#v", got, defaults)
	}
	high := Limits{
		ArtifactBytes:    1 << 40,
		FatSlices:        1 << 20,
		LoadCommands:     1 << 20,
		LoadCommandBytes: 1 << 40,
		Segments:         1 << 20,
		Sections:         1 << 20,
		SectionDataBytes: 1 << 40,
	}.withDefaults()
	if high != defaults {
		t.Fatalf("clamped limits = %#v, want %#v", high, defaults)
	}
	low := Limits{
		ArtifactBytes:    1024,
		FatSlices:        2,
		LoadCommands:     3,
		LoadCommandBytes: 4096,
		Segments:         4,
		Sections:         5,
		SectionDataBytes: 6,
	}
	if got := low.withDefaults(); got != low {
		t.Fatalf("lowered limits changed: %#v", got)
	}
}

func TestParseAllCommandSizes(t *testing.T) {
	// A command table made only of unknown, well-sized commands must load in
	// order without touching segments.
	extra := make([][]byte, 0, 3)
	for i, size := range []int{8, 16, 24} {
		command := make([]byte, size)
		fixtureOrder(DataLittle).PutUint32(command, uint32(0x30+i))
		fixtureOrder(DataLittle).PutUint32(command[4:], uint32(size))
		extra = append(extra, command)
	}
	opt := defaultImage()
	opt.segments = nil
	opt.extra = extra
	file := onlyFile(t, parseImageBytes(t, buildImage(t, opt)))
	if len(file.Commands) != 3 || file.Truncated {
		t.Fatalf("commands=%v truncated=%v", file.Commands, file.Truncated)
	}
	for i, command := range file.Commands {
		if command.Index != i || command.Command != uint32(0x30+i) {
			t.Fatalf("command %d = %#v", i, command)
		}
	}
}

func TestReadAtShortRead(t *testing.T) {
	image := buildImage(t, defaultImage())
	short := image[:16]
	err := readAt(bytes.NewReader(short), 0, make([]byte, 32), 32)
	if !errors.Is(err, ErrRead) {
		t.Fatalf("error = %v", err)
	}
	if !bytes.Contains([]byte(fmt.Sprint(err)), []byte("short read")) {
		t.Fatalf("error = %v", err)
	}
}

func TestReadAtBounds(t *testing.T) {
	image := buildImage(t, defaultImage())
	if err := readAt(bytes.NewReader(image), -1, make([]byte, 4), int64(len(image))); !errors.Is(err, ErrTruncated) {
		t.Fatalf("negative offset error = %v", err)
	}
	if err := readAt(bytes.NewReader(image), 0, make([]byte, 4), 2); !errors.Is(err, ErrTruncated) {
		t.Fatalf("oversized range error = %v", err)
	}
}

func TestReadAtReaderFailure(t *testing.T) {
	err := readAt(failingReader{}, 0, make([]byte, 4), 4)
	if !errors.Is(err, ErrRead) {
		t.Fatalf("error = %v", err)
	}
	if !bytes.Contains([]byte(fmt.Sprint(err)), []byte("boom")) {
		t.Fatalf("cause lost: %v", err)
	}
}

type failingReader struct{}

func (failingReader) ReadAt([]byte, int64) (int, error) {
	return 0, errors.New("boom")
}
