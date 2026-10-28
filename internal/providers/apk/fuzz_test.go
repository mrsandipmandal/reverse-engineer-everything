package apk

import (
	"bytes"
	"encoding/json"
	"testing"

	reapk "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/apk"
)

func FuzzObserve(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("PK\x05\x06"))
	f.Add(buildZIP(f, []string{"AndroidManifest.xml"}, [][]byte{[]byte("m")}))
	f.Add(buildAPK(f, []string{"AndroidManifest.xml", "classes.dex"},
		[][]byte{[]byte("m"), []byte("d")},
		signBlock(pair(0x7109871a, []byte("value")))))

	opts := Options{
		ProviderVersion: "1.0.0",
		PayloadBytes:    MinPayloadBytes,
		Limits: reapk.Limits{
			ArtifactBytes:    64 << 10,
			Entries:          32,
			SigningBytes:     4 << 10,
			SigningPairs:     8,
			DigestBytes:      4 << 10,
			TotalDigestBytes: 8 << 10,
		},
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		record, err := Observe(bytes.NewReader(data), int64(len(data)), opts)
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
		if len(payload.Entries) != payload.Artifact.LoadedEntryCount {
			t.Fatalf("loaded = %d, entries = %d",
				payload.Artifact.LoadedEntryCount, len(payload.Entries))
		}
		if payload.Artifact.LoadedEntryCount > payload.Artifact.EntryCount {
			t.Fatalf("loaded = %d above count = %d",
				payload.Artifact.LoadedEntryCount, payload.Artifact.EntryCount)
		}
		if payload.Artifact.Signing.PairCount != len(payload.Artifact.Signing.Pairs) {
			t.Fatalf("pair count = %d, pairs = %d",
				payload.Artifact.Signing.PairCount, len(payload.Artifact.Signing.Pairs))
		}
		for index, entry := range payload.Entries {
			if entry.Index != index {
				t.Fatalf("entry %d index = %d", index, entry.Index)
			}
			if entry.DigestAvailable != (entry.Digest != nil) {
				t.Fatalf("entry %d digest availability disagrees", index)
			}
		}
		if payload.Artifact.Signing.Present {
			if payload.Artifact.Signing.Offset == nil || payload.Artifact.Signing.Size == nil {
				t.Fatal("present signing block has no offset or size")
			}
		}
	})
}
