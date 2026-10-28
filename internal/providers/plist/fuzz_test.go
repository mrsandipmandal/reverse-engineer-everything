package plist

import (
	"bytes"
	"encoding/json"
	"testing"

	replist "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/plist"
)

// FuzzObserve checks that no input can make the provider panic or emit a
// payload that contradicts its own counts. Limits are lowered so a fuzz corpus
// cannot spend its time allocating.
func FuzzObserve(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("bplist00"))
	f.Add([]byte(xmlDocument(`<string>a</string>`)))
	f.Add(buildBinary(f, [][]byte{bdict(1, 2), bstr("k"), bint(1)}))
	f.Add(buildBinary(f, [][]byte{barray(1, 2), bstr("a"), buid(7, 2)}))

	limits := replist.Limits{
		ArtifactBytes: 64 << 10,
		Objects:       32,
		Depth:         4,
		StringBytes:   64,
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
		if payload.Artifact.LoadedObjectCount != len(payload.Objects) {
			t.Fatalf("loaded %d, objects %d", payload.Artifact.LoadedObjectCount, len(payload.Objects))
		}
		if payload.Artifact.LoadedObjectCount < payload.Artifact.ObjectCount && len(record.Limitations) == 0 {
			t.Fatal("abridged payload without a limitation")
		}
		for index, object := range payload.Objects {
			if object.Index != index {
				t.Fatalf("object %d index %d", index, object.Index)
			}
			for _, ref := range append(append(append([]int(nil), object.Keys...), object.Values...), object.Refs...) {
				if ref < 0 || ref >= payload.Artifact.ObjectCount {
					t.Fatalf("object %d references %d outside %d objects",
						index, ref, payload.Artifact.ObjectCount)
				}
			}
		}
	})
}
