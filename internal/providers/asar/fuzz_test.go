package asar

import (
	"bytes"
	"encoding/json"
	"testing"

	reasar "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/asar"
)

// FuzzObserve checks that no input can make the provider panic or emit a
// payload that contradicts its own counts. Limits are lowered so a fuzz corpus
// cannot spend its time allocating.
func FuzzObserve(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("PK\x03\x04"))
	f.Add(buildASAR(f, `{"files":{}}`, nil))
	f.Add(buildASAR(f, inventoryJSON, []byte("helloworld!")))
	f.Add(buildASAR(f, manyFiles(4), []byte("x")))

	limits := reasar.Limits{
		HeaderBytes:    64 << 10,
		Entries:        32,
		PathBytes:      64,
		Depth:          4,
		EntryDataBytes: 4 << 10,
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		record, err := Observe(bytes.NewReader(data), int64(len(data)), Options{
			ProviderVersion: "fuzz",
			Limits:          limits,
			PayloadBytes:    MinPayloadBytes,
		})
		if err != nil {
			return
		}
		var payload Payload
		if err := json.Unmarshal(record.Payload, &payload); err != nil {
			t.Fatalf("payload: %v", err)
		}
		if payload.Schema != PayloadSchema {
			t.Fatalf("schema = %q", payload.Schema)
		}
		if payload.Artifact.EntryCount != len(payload.Entries) && payload.Artifact.LoadedEntryCount == payload.Artifact.EntryCount {
			t.Fatalf("entry count %d, entries %d, loaded %d",
				payload.Artifact.EntryCount, len(payload.Entries), payload.Artifact.LoadedEntryCount)
		}
		if payload.Artifact.LoadedEntryCount != len(payload.Entries) {
			t.Fatalf("loaded %d, entries %d", payload.Artifact.LoadedEntryCount, len(payload.Entries))
		}
		for index, entry := range payload.Entries {
			if entry.Index != index {
				t.Fatalf("entry %d index %d", index, entry.Index)
			}
		}
	})
}
