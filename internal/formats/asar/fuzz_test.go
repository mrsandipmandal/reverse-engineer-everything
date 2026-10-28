package asar

import (
	"bytes"
	"testing"
)

// FuzzParse checks that no input can make the reader panic or return an
// inconsistent inventory. Limits are lowered so a fuzz corpus cannot spend its
// time allocating.
func FuzzParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("PK\x03\x04"))
	f.Add(buildASAR(f, `{"files":{}}`, nil))
	f.Add(buildASAR(f, `{"files":{"a.txt":{"size":5,"offset":"0"}}}`, []byte("hello")))
	f.Add(buildASAR(f, `{"files":{"dir":{"files":{"b":{"size":1,"offset":"0"}}},"link":{"link":"a"}}}`, []byte("x")))

	limits := Limits{
		HeaderBytes:    64 << 10,
		Entries:        16,
		PathBytes:      64,
		Depth:          4,
		EntryDataBytes: 4 << 10,
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), limits)
		if err != nil {
			if parsed != nil {
				t.Fatal("archive returned with an error")
			}
			return
		}
		if parsed == nil {
			t.Fatal("nil archive without an error")
		}
		if parsed.Truncated && len(parsed.Limitations) == 0 {
			t.Fatal("truncated archive without a limitation")
		}
		if len(parsed.Entries) > limits.Entries {
			t.Fatalf("entries = %d, limit %d", len(parsed.Entries), limits.Entries)
		}
		for index := range parsed.Entries {
			entry := parsed.Entries[index]
			if entry.Index != index {
				t.Fatalf("entry %d has index %d", index, entry.Index)
			}
			if len(entry.PathBytes) > limits.PathBytes {
				t.Fatalf("entry %d path is %d bytes", index, len(entry.PathBytes))
			}
			if entry.DataKnown && (entry.DataOffset < 0 || entry.DataOffset > parsed.Size()) {
				t.Fatalf("entry %d data offset %d outside artifact", index, entry.DataOffset)
			}
			if entry.DataKnown && entry.Size > uint64(parsed.Size()-entry.DataOffset) {
				t.Fatalf("entry %d size %d exceeds the remaining artifact", index, entry.Size)
			}
			data, err := parsed.EntryData(index)
			if err != nil {
				continue
			}
			if uint64(len(data)) != entry.Size {
				t.Fatalf("entry %d data is %d bytes, size field is %d", index, len(data), entry.Size)
			}
			if _, err := parsed.EntryPrefix(index, 16); err != nil {
				t.Fatalf("entry %d prefix: %v", index, err)
			}
		}
	})
}
