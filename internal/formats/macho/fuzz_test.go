package macho

import (
	"bytes"
	"testing"
)

// FuzzParse checks that no input can make the reader panic or return an
// inconsistent view. Limits are lowered so a fuzz corpus cannot spend its time
// allocating.
func FuzzParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xcf, 0xfa, 0xed, 0xfe})
	f.Add(buildImage(f, defaultImage()))
	f.Add(buildImage(f, twoSegmentImage()))
	opt32 := defaultImage()
	opt32.is64 = false
	f.Add(buildImage(f, opt32))
	f.Add(buildFat(f, false, false, []fixtureFatSlice{
		{cpuType: fixtureCPUAMD64, data: buildImage(f, defaultImage())},
		{cpuType: fixtureCPUI386, data: buildImage(f, opt32)},
	}))

	limits := Limits{
		FatSlices:        4,
		LoadCommands:     64,
		LoadCommandBytes: 64 << 10,
		Segments:         16,
		Sections:         64,
		SectionDataBytes: 4 << 10,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		artifact, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), limits)
		if err != nil {
			if artifact != nil {
				t.Fatal("artifact returned with an error")
			}
			return
		}
		if artifact == nil {
			t.Fatal("nil artifact without an error")
		}
		if len(artifact.Slices) == 0 {
			t.Fatal("artifact has no slices")
		}
		if artifact.Fat && artifact.Magic != FatMagic && artifact.Magic != FatMagic64 {
			t.Fatalf("fat artifact magic = %#x", artifact.Magic)
		}
		for _, slice := range artifact.Slices {
			if slice.Offset < 0 || slice.Size < 0 {
				t.Fatalf("slice %d has negative bounds", slice.Index)
			}
			if slice.Offset > int64(len(data)) || slice.Size > int64(len(data))-slice.Offset {
				t.Fatalf("slice %d escapes the artifact", slice.Index)
			}
			file := slice.File
			if file == nil {
				if slice.Err == nil {
					t.Fatalf("slice %d has no file and no error", slice.Index)
				}
				continue
			}
			if file.Size() != slice.Size {
				t.Fatalf("slice %d file size = %d, want %d", slice.Index, file.Size(), slice.Size)
			}
			if file.Truncated && len(file.Limitations) == 0 {
				t.Fatalf("slice %d is truncated without a limitation", slice.Index)
			}
			if len(file.Commands) > limits.LoadCommands || len(file.Segments) > limits.Segments ||
				len(file.Sections) > limits.Sections {
				t.Fatalf("slice %d exceeds a count limit", slice.Index)
			}
			for _, section := range file.Sections {
				if section.Index < 0 || section.Index >= len(file.Sections) {
					t.Fatalf("section index %d outside %d entries", section.Index, len(file.Sections))
				}
				if _, err := file.SectionData(section.Index); err != nil {
					// Any error is acceptable here; the point is that the read is
					// bounded and does not panic.
					continue
				}
			}
		}
	})
}
