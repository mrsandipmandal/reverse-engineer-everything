package macho

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzMetadata asserts that the metadata decoders never panic on a crafted
// image and that every returned table respects the configured limit.
func FuzzMetadata(f *testing.F) {
	f.Add([]byte{})
	f.Add(buildMetadata(f, metadataFixture{is64: true}))
	f.Add(buildMetadata(f, defaultMetadataFixture()))
	invalid := defaultMetadataFixture()
	invalid.dylibs = []metadataDylib{{command: CommandLoadDylib, name: "\xff\xfe"}}
	f.Add(buildMetadata(f, invalid))

	f.Fuzz(func(t *testing.T, data []byte) {
		limits := Limits{
			FatSlices:         4,
			LoadCommands:      64,
			LoadCommandBytes:  64 << 10,
			Segments:          16,
			Sections:          64,
			SectionDataBytes:  4 << 10,
			Dylibs:            8,
			StringBytes:       64,
			BuildTools:        4,
			Symbols:           64,
			SymbolStringBytes: 1024,
			CodeSignBlobs:     8,
			CodeSignBytes:     1024,
		}
		artifact, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), limits)
		if err != nil {
			if !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrTruncated) && !errors.Is(err, ErrLimit) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		for _, slice := range artifact.Slices {
			file := slice.File
			if file == nil {
				continue
			}
			if table, err := file.Dylibs(); err == nil {
				if len(table.Dylibs) > limits.Dylibs {
					t.Fatalf("dylibs %d exceeds limit %d", len(table.Dylibs), limits.Dylibs)
				}
			}
			if _, err := file.UUID(); err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrInvalid) {
				t.Fatalf("UUID error: %v", err)
			}
			if version, err := file.BuildVersion(); err == nil {
				if len(version.Tools) > limits.BuildTools {
					t.Fatalf("tools %d exceeds limit %d", len(version.Tools), limits.BuildTools)
				}
			}
			if _, err := file.EntryPoint(); err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrInvalid) {
				t.Fatalf("EntryPoint error: %v", err)
			}
			if table, err := file.Symbols(); err == nil {
				if len(table.Symbols) > limits.Symbols {
					t.Fatalf("symbols %d exceeds limit %d", len(table.Symbols), limits.Symbols)
				}
				if table.StringBytes > limits.SymbolStringBytes {
					t.Fatalf("string bytes %d exceeds limit %d", table.StringBytes, limits.SymbolStringBytes)
				}
			}
			if signature, err := file.CodeSignature(); err == nil {
				if len(signature.Blobs) > limits.CodeSignBlobs {
					t.Fatalf("blobs %d exceeds limit %d", len(signature.Blobs), limits.CodeSignBlobs)
				}
			}
		}
	})
}
