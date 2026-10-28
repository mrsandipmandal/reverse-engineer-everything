package archive

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
	f.Add([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff})
	f.Add(buildZIP(f, []zipEntryFixture{
		{name: []byte("hello.txt"), data: []byte("hello world"), method: fixtureStored},
		{name: []byte("packed"), data: bytes.Repeat([]byte("abcd"), 32), method: fixtureDeflate},
	}))
	f.Add(buildTar(f, []tarEntryFixture{
		{name: "a.txt", data: []byte("abc")},
		{name: "link", typeflag: tarTypeSymlink, linkname: "a.txt"},
	}))
	f.Add(buildGzip(f, gzipMember{data: []byte("hello"), name: "hello.txt"}))

	limits := Limits{
		Entries:          32,
		NameBytes:        128,
		DirectoryBytes:   64 << 10,
		EntryDataBytes:   64 << 10,
		ExtraBytes:       8 << 10,
		PaxBytes:         16 << 10,
		GzipCommentBytes: 128,
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
			if entry.HeaderOffset < 0 || entry.DataOffset < 0 {
				t.Fatalf("entry %d has negative offsets", index)
			}
			if len(entry.NameBytes) > limits.NameBytes {
				t.Fatalf("entry %d name is %d bytes", index, len(entry.NameBytes))
			}
			if _, err := parsed.EntryData(index); err != nil {
				continue
			}
			if _, err := parsed.EntryPrefix(index, 32); err != nil {
				t.Fatalf("entry %d prefix: %v", index, err)
			}
		}
	})
}
