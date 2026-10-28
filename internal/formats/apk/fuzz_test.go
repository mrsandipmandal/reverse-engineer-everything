package apk

import (
	"bytes"
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("PK\x05\x06"))
	f.Add(buildZIP(f, []string{"AndroidManifest.xml"}, [][]byte{[]byte("m")}))
	f.Add(buildAPK(f, []string{"AndroidManifest.xml", "classes.dex"},
		[][]byte{[]byte("m"), []byte("d")},
		signBlock(pair(idV2, []byte("value")))))

	limits := Limits{
		ArtifactBytes:    64 << 10,
		Entries:          32,
		SigningBytes:     4 << 10,
		SigningPairs:     8,
		DigestBytes:      4 << 10,
		TotalDigestBytes: 8 << 10,
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), limits)
		if err != nil {
			if parsed != nil {
				t.Fatalf("APK returned with error %v", err)
			}
			return
		}
		if parsed == nil {
			t.Fatal("nil APK without an error")
		}
		if len(parsed.Entries) != len(parsed.ZIP.Entries) {
			t.Fatalf("classifications = %d, ZIP entries = %d",
				len(parsed.Entries), len(parsed.ZIP.Entries))
		}
		if len(parsed.ZIP.Entries) > limits.Entries {
			t.Fatalf("entries = %d above limit %d", len(parsed.ZIP.Entries), limits.Entries)
		}
		for index, entry := range parsed.Entries {
			if entry.DigestAvailable && entry.Digest == "" {
				t.Fatalf("entry %d digest is available but empty", index)
			}
			if !entry.DigestAvailable && entry.Digest != "" {
				t.Fatalf("entry %d digest is unavailable but set", index)
			}
		}
		if len(parsed.Signing.Pairs) > limits.SigningPairs {
			t.Fatalf("signing pairs = %d above limit %d",
				len(parsed.Signing.Pairs), limits.SigningPairs)
		}
		for index, pair := range parsed.Signing.Pairs {
			if !pair.DigestAvailable || pair.Digest == "" {
				t.Fatalf("signing pair %d has no digest", index)
			}
		}
		if parsed.Truncated && len(parsed.Limitations) == 0 {
			t.Fatal("truncated package has no limitation")
		}
	})
}
