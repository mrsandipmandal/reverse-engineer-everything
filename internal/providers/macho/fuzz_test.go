package macho

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	remacho "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/macho"
)

// FuzzObserve asserts that no artifact can make the adapter panic, emit an
// invalid record, or produce a payload that exceeds its budget contract.
func FuzzObserve(f *testing.F) {
	f.Add([]byte{})
	f.Add(buildFixture(f, defaultFixture()))
	f.Add(metadataImage(f, defaultMetadataFixture()))
	f.Add(buildFatFixture(f, [][]byte{buildFixture(f, defaultFixture()), []byte("bad")}))

	f.Fuzz(func(t *testing.T, data []byte) {
		opts := Options{
			ProviderVersion: "fuzz",
			Limits: remacho.Limits{
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
			},
			PayloadBytes: MinPayloadBytes,
			ContentBytes: 4096,
		}
		record, err := Observe(bytes.NewReader(data), int64(len(data)), opts)
		if err != nil {
			return
		}
		sealed, err := evidence.Encode(record)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if len(sealed) == 0 {
			t.Fatal("empty record")
		}
		var payload Payload
		if err := json.Unmarshal(record.Payload, &payload); err != nil {
			t.Fatalf("payload decode: %v", err)
		}
		if payload.Schema != PayloadSchema {
			t.Fatalf("schema = %q", payload.Schema)
		}
		if len(payload.Slices) != payload.Artifact.SliceCount {
			t.Fatalf("slices = %d, count = %d", len(payload.Slices), payload.Artifact.SliceCount)
		}
		loaded := 0
		for _, slice := range payload.Slices {
			if slice.Header != nil {
				loaded++
			}
			if slice.Status == "" {
				t.Fatal("slice has no status")
			}
		}
		if loaded != payload.Artifact.LoadedSliceCount {
			t.Fatalf("loaded slices = %d, count = %d", loaded, payload.Artifact.LoadedSliceCount)
		}
	})
}
