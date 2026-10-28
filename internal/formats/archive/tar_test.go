package archive

import (
	"bytes"
	"errors"
	"testing"
)

// int64Ptr returns a pointer to value for fixture overrides.
func int64Ptr(value int64) *int64 { return &value }

func TestParseTarUSTAR(t *testing.T) {
	data := buildTar(t, []tarEntryFixture{
		{name: "a.txt", data: []byte("abc"), mode: 0o644, mtime: 1700000000},
		{name: "dir/", typeflag: tarTypeDirectory, mode: 0o755},
		{name: "link", typeflag: tarTypeSymlink, linkname: "a.txt"},
		{name: "b.txt", prefix: "p", data: []byte("b")},
	})
	parsed := parseBytes(t, data)
	if parsed.Container != ContainerTar {
		t.Fatalf("container = %v", parsed.Container)
	}
	if parsed.Truncated || len(parsed.Limitations) != 0 {
		t.Fatalf("truncated=%v limitations=%v", parsed.Truncated, parsed.Limitations)
	}
	if len(parsed.Entries) != 4 {
		t.Fatalf("entries = %d", len(parsed.Entries))
	}

	file := parsed.Entries[0]
	if file.Name != "a.txt" || !file.NameAvailable || file.NameUnsafe != "" {
		t.Fatalf("file = %#v", file)
	}
	if file.Type != EntryFile || file.Method != MethodStored {
		t.Fatalf("type or method = %#v", file)
	}
	if !file.ModeAvailable || file.Mode != 0o644 {
		t.Fatalf("mode = %#v", file)
	}
	if !file.ModifiedAvailable || file.ModifiedUnix != 1700000000 {
		t.Fatalf("mtime = %#v", file)
	}
	if file.CompressedSize != 3 || file.UncompressedSize != 3 {
		t.Fatalf("sizes = %#v", file)
	}
	if got := entryData(t, parsed, 0); string(got) != "abc" {
		t.Fatalf("data = %q", got)
	}
	if prefix, err := parsed.EntryPrefix(0, 2); err != nil || string(prefix) != "ab" {
		t.Fatalf("prefix = %q, %v", prefix, err)
	}

	if dir := parsed.Entries[1]; dir.Type != EntryDirectory {
		t.Fatalf("directory type = %v", dir.Type)
	}
	link := parsed.Entries[2]
	if link.Type != EntrySymlink || !link.LinkTargetAvailable || link.LinkTarget != "a.txt" {
		t.Fatalf("symlink = %#v", link)
	}
	if _, err := parsed.EntryData(2); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("symlink EntryData error = %v", err)
	}
	if prefixed := parsed.Entries[3]; prefixed.Name != "p/b.txt" {
		t.Fatalf("prefixed name = %q", prefixed.Name)
	}
}

func TestParseTarPAX(t *testing.T) {
	pax := paxRecords(t, map[string]string{"path": "deep/name.txt", "linkpath": "target"})
	data := buildTar(t, []tarEntryFixture{
		{name: "pax", typeflag: tarTypePax, data: pax},
		{name: "short", data: []byte("hello")},
	})
	parsed := parseBytes(t, data)
	if len(parsed.Entries) != 1 {
		t.Fatalf("entries = %d", len(parsed.Entries))
	}
	entry := parsed.Entries[0]
	if entry.Name != "deep/name.txt" || !entry.NameAvailable {
		t.Fatalf("name = %#v", entry)
	}
	if entry.LinkTarget != "target" || !entry.LinkTargetAvailable {
		t.Fatalf("link target = %#v", entry)
	}
	if got := entryData(t, parsed, 0); string(got) != "hello" {
		t.Fatalf("data = %q", got)
	}
}

func TestParseTarPAXSizeOverride(t *testing.T) {
	pax := paxRecords(t, map[string]string{"size": "7"})
	data := buildTar(t, []tarEntryFixture{
		{name: "pax", typeflag: tarTypePax, data: pax},
		{name: "file", size: int64Ptr(0), data: []byte("1234567")},
	})
	parsed := parseBytes(t, data)
	if len(parsed.Entries) != 1 {
		t.Fatalf("entries = %d", len(parsed.Entries))
	}
	if parsed.Entries[0].UncompressedSize != 7 {
		t.Fatalf("size = %d", parsed.Entries[0].UncompressedSize)
	}
	if got := entryData(t, parsed, 0); string(got) != "1234567" {
		t.Fatalf("data = %q", got)
	}
}

func TestParseTarGNULongName(t *testing.T) {
	longName := append([]byte("very/long/path/name.txt"), 0)
	longLink := append([]byte("target/file.txt"), 0)
	data := buildTar(t, []tarEntryFixture{
		{name: "././@LongLink", typeflag: tarTypeGNULongName, data: longName},
		{name: "short", data: []byte("x")},
		{name: "././@LongLink", typeflag: tarTypeGNULongLink, data: longLink},
		{name: "link2", typeflag: tarTypeSymlink},
	})
	parsed := parseBytes(t, data)
	if len(parsed.Entries) != 2 {
		t.Fatalf("entries = %d", len(parsed.Entries))
	}
	if parsed.Entries[0].Name != "very/long/path/name.txt" {
		t.Fatalf("name = %q", parsed.Entries[0].Name)
	}
	if parsed.Entries[1].LinkTarget != "target/file.txt" {
		t.Fatalf("link = %q", parsed.Entries[1].LinkTarget)
	}
}

func TestParseTarTypes(t *testing.T) {
	data := buildTar(t, []tarEntryFixture{
		{name: "hard", typeflag: tarTypeHardlink, linkname: "a.txt"},
		{name: "char", typeflag: tarTypeCharacter},
		{name: "block", typeflag: tarTypeBlock},
		{name: "fifo", typeflag: tarTypeFIFO},
		{name: "unknown", typeflag: 'Z'},
	})
	parsed := parseBytes(t, data)
	want := []EntryType{EntryHardlink, EntryCharacterDevice, EntryBlockDevice, EntryFIFO, EntryOther}
	if len(parsed.Entries) != len(want) {
		t.Fatalf("entries = %d", len(parsed.Entries))
	}
	for i, entryType := range want {
		if got := parsed.Entries[i].Type; got != entryType {
			t.Fatalf("entry %d type = %v, want %v", i, got, entryType)
		}
		if _, err := parsed.EntryData(i); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("entry %d EntryData error = %v", i, err)
		}
	}
}

func TestParseTarBase256Size(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 300)
	data := buildTar(t, []tarEntryFixture{{name: "big", data: payload, base256: true}})
	parsed := parseBytes(t, data)
	entry := parsed.Entries[0]
	if !entry.UncompressedSizeKnown || entry.UncompressedSize != 300 {
		t.Fatalf("size = %#v", entry)
	}
	if got := entryData(t, parsed, 0); len(got) != 300 {
		t.Fatalf("data length = %d", len(got))
	}
}

func TestParseTarErrors(t *testing.T) {
	t.Run("bad checksum", func(t *testing.T) {
		data := buildTar(t, []tarEntryFixture{{name: "a", data: []byte("a"), badChecksum: true}})
		if _, err := Parse(bytes.NewReader(data), int64(len(data))); !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v, want ErrInvalid", err)
		}
	})
	t.Run("bad size", func(t *testing.T) {
		data := buildTar(t, []tarEntryFixture{{name: "a", data: []byte("a"), badSize: true}})
		if _, err := Parse(bytes.NewReader(data), int64(len(data))); !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v, want ErrInvalid", err)
		}
	})
	t.Run("truncated header", func(t *testing.T) {
		data := buildTar(t, []tarEntryFixture{{name: "a", data: []byte("a")}})
		parsed, err := Parse(bytes.NewReader(data[:300]), 300)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if !parsed.Truncated || len(parsed.Entries) != 0 || len(parsed.Limitations) == 0 {
			t.Fatalf("truncated=%v entries=%d limitations=%v", parsed.Truncated, len(parsed.Entries), parsed.Limitations)
		}
	})
}

func TestParseTarTruncatedData(t *testing.T) {
	data := buildTar(t, []tarEntryFixture{{name: "a", data: []byte("abc"), size: int64Ptr(1024)}})
	data = data[:tarBlockSize*2]
	parsed := parseBytes(t, data)
	if len(parsed.Entries) != 1 || !parsed.Truncated {
		t.Fatalf("entries=%d truncated=%v", len(parsed.Entries), parsed.Truncated)
	}
	if len(parsed.Entries[0].Limitations) == 0 {
		t.Fatal("entry has no limitation")
	}
	if _, err := parsed.EntryData(0); !errors.Is(err, ErrTruncated) {
		t.Fatalf("EntryData error = %v, want ErrTruncated", err)
	}
}

func TestParseTarSparse(t *testing.T) {
	data := buildTar(t, []tarEntryFixture{{name: "sparse", typeflag: tarTypeGNUSparse}})
	parsed := parseBytes(t, data)
	if len(parsed.Entries) != 1 || !parsed.Entries[0].Sparse || !parsed.Truncated {
		t.Fatalf("archive = %#v", parsed)
	}
}

func TestParseTarGlobalPax(t *testing.T) {
	pax := paxRecords(t, map[string]string{"path": "ignored"})
	data := buildTar(t, []tarEntryFixture{
		{name: "global", typeflag: tarTypePaxGlobal, data: pax},
		{name: "file", data: []byte("x")},
	})
	parsed := parseBytes(t, data)
	if len(parsed.Entries) != 1 || parsed.Entries[0].Name != "file" {
		t.Fatalf("entries = %#v", parsed.Entries)
	}
	if len(parsed.Limitations) == 0 || parsed.Limitations[0] != "global PAX attributes are not applied" {
		t.Fatalf("limitations = %v", parsed.Limitations)
	}
}

func TestParseTarLongNameLimit(t *testing.T) {
	longName := append(bytes.Repeat([]byte("n"), 100), 0)
	data := buildTar(t, []tarEntryFixture{
		{name: "././@LongLink", typeflag: tarTypeGNULongName, data: longName},
		{name: "short", data: []byte("x")},
	})
	parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{NameBytes: 16})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(parsed.Entries) != 1 || parsed.Entries[0].Name != "short" {
		t.Fatalf("entries = %#v", parsed.Entries)
	}
	if len(parsed.Limitations) == 0 {
		t.Fatal("missing long name limitation")
	}
}

func TestParseTarLimits(t *testing.T) {
	data := buildTar(t, []tarEntryFixture{
		{name: "a", data: []byte("a")},
		{name: "b", data: []byte("b")},
	})
	parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{Entries: 1})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(parsed.Entries) != 1 || !parsed.Truncated {
		t.Fatalf("entries=%d truncated=%v", len(parsed.Entries), parsed.Truncated)
	}
}
