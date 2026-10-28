package plist

import (
	"bytes"
	"testing"
)

// FuzzParse checks that no input can make the reader panic or return an
// inconsistent inventory. Limits are lowered so a fuzz corpus cannot spend its
// time allocating.
func FuzzParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("bplist00"))
	f.Add([]byte(xmlDocument(`<dict><key>a</key><string>b</string></dict>`)))
	f.Add(buildBinary(f, [][]byte{bdict(1, 2), bstr("k"), bint(1)}))
	f.Add(buildBinary(f, [][]byte{barray(1, 2), bstr("a"), buid(7, 2)}))

	limits := Limits{
		ArtifactBytes: 64 << 10,
		Objects:       16,
		Depth:         4,
		StringBytes:   64,
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), limits)
		if err != nil {
			if parsed != nil {
				t.Fatal("plist returned with an error")
			}
			return
		}
		if parsed == nil {
			t.Fatal("nil plist without an error")
		}
		if parsed.Truncated && len(parsed.Limitations) == 0 {
			t.Fatal("truncated plist without a limitation")
		}
		if len(parsed.Objects) > limits.Objects {
			t.Fatalf("objects = %d, limit %d", len(parsed.Objects), limits.Objects)
		}
		if parsed.TopObject < 0 || parsed.TopObject >= len(parsed.Objects) {
			t.Fatalf("top object %d outside %d objects", parsed.TopObject, len(parsed.Objects))
		}
		for index := range parsed.Objects {
			object := parsed.Objects[index]
			if object.Index != index {
				t.Fatalf("object %d has index %d", index, object.Index)
			}
			if len(object.TextBytes) > limits.StringBytes {
				t.Fatalf("object %d text is %d bytes", index, len(object.TextBytes))
			}
			for _, ref := range append(append(append([]uint64(nil), object.Keys...), object.Values...), object.Refs...) {
				if ref >= uint64(len(parsed.Objects)) {
					t.Fatalf("object %d references %d outside the inventory", index, ref)
				}
			}
			if _, err := parsed.ObjectAt(index); err != nil {
				t.Fatalf("object %d: %v", index, err)
			}
		}
	})
}
