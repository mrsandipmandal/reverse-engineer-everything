package archive

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	rearchive "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/archive"
)

// FuzzObserve checks that no input can make the adapter panic, emit an invalid
// record, or claim more nesting than it was allowed to inspect.
func FuzzObserve(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not an archive"))
	f.Add(buildZIP(f, []zipFixture{{name: "a.txt", data: []byte("hello")}}))
	f.Add(buildTar(f, []tarFixture{{name: "a.txt", data: []byte("hello")}}))
	f.Add(buildGzip(f, "a.txt", "note", []byte("hello")))
	f.Add(buildTar(f, []tarFixture{{
		name: "inner.zip",
		data: buildZIP(f, []zipFixture{{name: "b.txt", data: []byte("b")}}),
	}}))

	opts := Options{
		ProviderVersion: "fuzz",
		Limits: rearchive.Limits{
			Entries:          32,
			NameBytes:        128,
			DirectoryBytes:   64 << 10,
			EntryDataBytes:   64 << 10,
			ExtraBytes:       8 << 10,
			PaxBytes:         16 << 10,
			GzipCommentBytes: 128,
		},
		PayloadBytes:  MinPayloadBytes,
		NestedDepth:   MaxNestedDepth,
		NestedBytes:   MinNestedBytes,
		NestedMembers: 4,
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		record, err := Observe(bytes.NewReader(data), int64(len(data)), opts)
		if err != nil {
			return
		}
		encoded, err := evidence.Encode(record)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		sealed, err := evidence.Decode(encoded)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if err := sealed.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		var payload Payload
		if err := json.Unmarshal(sealed.Payload, &payload); err != nil {
			t.Fatalf("payload decode: %v", err)
		}
		if payload.Schema != PayloadSchema {
			t.Fatalf("schema = %q", payload.Schema)
		}
		checkDepth(t, payload.Artifact, payload.Entries, 0)
	})
}

// checkDepth fails when a payload reports a container deeper than the adapter
// allows, or a loaded count larger than the entry count.
func checkDepth(t *testing.T, container PayloadArchive, entries []PayloadEntry, depth int) {
	t.Helper()
	if container.Depth != depth {
		t.Fatalf("container depth = %d, want %d", container.Depth, depth)
	}
	if depth > MaxNestedDepth {
		t.Fatalf("container depth %d exceeds the limit", depth)
	}
	if container.LoadedEntryCount > container.EntryCount {
		t.Fatalf("loaded count %d exceeds entry count %d", container.LoadedEntryCount, container.EntryCount)
	}
	if len(entries) != container.LoadedEntryCount {
		t.Fatalf("entries = %d, loaded = %d", len(entries), container.LoadedEntryCount)
	}
	for _, entry := range entries {
		if entry.Nested != nil {
			checkDepth(t, *entry.Nested, entry.Nested.Entries, depth+1)
		}
	}
}
