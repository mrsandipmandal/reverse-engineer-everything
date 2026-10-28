package archive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func TestDecodeText(t *testing.T) {
	tests := []struct {
		name      string
		raw       []byte
		limit     int
		available bool
		stored    int
	}{
		{"valid", []byte("hello"), 10, true, 5},
		{"empty", nil, 10, false, 0},
		{"nul", []byte("a\x00b"), 10, false, 3},
		{"invalid utf8", []byte{0xff, 0xfe}, 10, false, 2},
		{"too long", []byte("abcdef"), 4, false, 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			text, available, stored := decodeText(test.raw, test.limit)
			if available != test.available || len(stored) != test.stored {
				t.Fatalf("available=%v stored=%d", available, len(stored))
			}
			if available && text != string(test.raw) {
				t.Fatalf("text = %q", text)
			}
		})
	}
}

func TestTarString(t *testing.T) {
	if got := string(tarString([]byte("abc\x00def"))); got != "abc" {
		t.Fatalf("string = %q", got)
	}
	if got := string(tarString([]byte("abcdef"))); got != "abcdef" {
		t.Fatalf("string = %q", got)
	}
}

func TestTarNumber(t *testing.T) {
	base256 := make([]byte, 12)
	putTarBase256(base256, 300)
	overflow := make([]byte, 12)
	overflow[0] = 0x80
	for i := 1; i < len(overflow); i++ {
		overflow[i] = 0xff
	}
	tests := []struct {
		name string
		raw  []byte
		want int64
		ok   bool
	}{
		{"octal", []byte("00000000144\x00"), 100, true},
		{"empty", []byte("00000000000\x00"), 0, true},
		{"invalid digit", []byte("0000000x000\x00"), 0, false},
		{"base256", base256, 300, true},
		{"negative", []byte{0xc0, 0, 0, 0}, 0, false},
		{"overflow", overflow, 0, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := tarNumber(test.raw)
			if got != test.want || ok != test.ok {
				t.Fatalf("tarNumber = %d, %v; want %d, %v", got, ok, test.want, test.ok)
			}
		})
	}
}

func TestTarNext(t *testing.T) {
	tests := []struct {
		name     string
		offset   int64
		size     int64
		artifact int64
		want     int64
		ok       bool
	}{
		{"small", 0, 512, 4096, 1024, true},
		{"no header space", 0, 0, 0, 0, false},
		{"negative size", 0, -1, 1000, 0, false},
		{"overflow", 0, math.MaxInt64, math.MaxInt64, 0, false},
		{"offset past end", 100, 10, 512, 0, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := tarNext(test.offset, test.size, test.artifact)
			if got != test.want || ok != test.ok {
				t.Fatalf("tarNext = %d, %v; want %d, %v", got, ok, test.want, test.ok)
			}
		})
	}
}

func TestZIP64MissingValues(t *testing.T) {
	data := buildZIP(t, []zipEntryFixture{{name: []byte("a"), data: []byte("abc")}})
	end := eocdOffset(t, data)
	cdOffset := int(binary.LittleEndian.Uint32(data[end+16:]))
	data = patch(data, cdOffset+24, []byte{0xff, 0xff, 0xff, 0xff})
	parsed := parseBytes(t, data)
	entry := parsed.Entries[0]
	if entry.UncompressedSizeKnown {
		t.Fatalf("size is known: %#v", entry)
	}
	if len(entry.Limitations) == 0 {
		t.Fatal("missing limitation")
	}
	if _, err := parsed.EntryData(0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("EntryData error = %v, want ErrUnavailable", err)
	}
}

func TestZIP64MalformedExtra(t *testing.T) {
	data := buildZIP(t, []zipEntryFixture{{
		name:  []byte("a"),
		data:  []byte("abc"),
		extra: []byte{1, 0, 100, 0},
	}})
	parsed := parseBytes(t, data)
	if len(parsed.Entries) != 1 {
		t.Fatalf("entries = %d", len(parsed.Entries))
	}
	if len(parsed.Entries[0].Limitations) == 0 {
		t.Fatal("missing extra limitation")
	}
}

func TestZIPExtraLimit(t *testing.T) {
	data := buildZIP(t, []zipEntryFixture{{
		name:  []byte("a"),
		data:  []byte("abc"),
		extra: []byte{1, 0, 0, 0},
	}})
	parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{ExtraBytes: 2})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(parsed.Entries[0].Limitations) == 0 {
		t.Fatal("missing extra limit limitation")
	}
}

func TestZIP64DiskStart(t *testing.T) {
	data := buildZIP(t, []zipEntryFixture{{
		name:      []byte("a"),
		data:      []byte("abc"),
		diskStart: zipMaxUint16,
		extra:     []byte{1, 0, 4, 0, 1, 0, 0, 0},
	}})
	parsed := parseBytes(t, data)
	entry := parsed.Entries[0]
	if len(entry.Limitations) == 0 || entry.UncompressedSizeKnown {
		t.Fatalf("entry = %#v", entry)
	}
	if _, err := parsed.EntryData(0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("EntryData error = %v, want ErrUnavailable", err)
	}
}

func TestZIPSpecialTypes(t *testing.T) {
	data := buildZIP(t, []zipEntryFixture{
		{name: []byte("char"), data: []byte("c"), versionMadeBy: 3 << 8, external: 0x21ff0000},
		{name: []byte("block"), data: []byte("b"), versionMadeBy: 3 << 8, external: 0x61ff0000},
		{name: []byte("fifo"), data: []byte("f"), versionMadeBy: 3 << 8, external: 0x11ff0000},
		{name: []byte("plain"), data: []byte("p"), versionMadeBy: 3 << 8, external: 0x81ff0000},
	})
	parsed := parseBytes(t, data)
	want := []EntryType{EntryCharacterDevice, EntryBlockDevice, EntryFIFO, EntryFile}
	for i, entryType := range want {
		if got := parsed.Entries[i].Type; got != entryType {
			t.Fatalf("entry %d type = %v, want %v", i, got, entryType)
		}
		if entryType != EntryFile {
			if _, err := parsed.EntryData(i); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("entry %d EntryData error = %v", i, err)
			}
		}
	}
}

func TestZIPContentLimits(t *testing.T) {
	t.Run("size limit", func(t *testing.T) {
		data := buildZIP(t, []zipEntryFixture{{name: []byte("a"), data: []byte("abc")}})
		parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{EntryDataBytes: 2})
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if _, err := parsed.EntryData(0); !errors.Is(err, ErrLimit) {
			t.Fatalf("EntryData error = %v, want ErrLimit", err)
		}
	})
	t.Run("zero length", func(t *testing.T) {
		parsed := parseBytes(t, buildZIP(t, []zipEntryFixture{{name: []byte("empty")}}))
		if got := entryData(t, parsed, 0); len(got) != 0 {
			t.Fatalf("data = %q", got)
		}
		if prefix, err := parsed.EntryPrefix(0, 4); err != nil || len(prefix) != 0 {
			t.Fatalf("prefix = %q, %v", prefix, err)
		}
	})
	t.Run("local header outside", func(t *testing.T) {
		data := buildZIP(t, []zipEntryFixture{{name: []byte("a"), data: []byte("abc")}})
		end := eocdOffset(t, data)
		cdOffset := int(binary.LittleEndian.Uint32(data[end+16:]))
		data = patch(data, cdOffset+42, []byte{0x00, 0x00, 0x00, 0x10})
		parsed := parseBytes(t, data)
		if len(parsed.Entries[0].Limitations) == 0 {
			t.Fatal("missing local offset limitation")
		}
		if _, err := parsed.EntryData(0); !errors.Is(err, ErrTruncated) {
			t.Fatalf("EntryData error = %v, want ErrTruncated", err)
		}
	})
}

func TestEntryPrefixEncrypted(t *testing.T) {
	parsed := parseBytes(t, buildZIP(t, []zipEntryFixture{{name: []byte("a"), data: []byte("x"), flags: zipFlagEncrypt}}))
	if _, err := parsed.EntryPrefix(0, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
}

func TestParseTarMalformedPAX(t *testing.T) {
	data := buildTar(t, []tarEntryFixture{
		{name: "pax", typeflag: tarTypePax, data: []byte("garbage")},
		{name: "file", data: []byte("x")},
	})
	parsed := parseBytes(t, data)
	if len(parsed.Entries) != 1 || parsed.Entries[0].Name != "file" {
		t.Fatalf("entries = %#v", parsed.Entries)
	}
	if len(parsed.Limitations) == 0 {
		t.Fatal("missing malformed PAX limitation")
	}
}

func TestParseTarPAXLimit(t *testing.T) {
	pax := paxRecords(t, map[string]string{"path": "ignored"})
	data := buildTar(t, []tarEntryFixture{
		{name: "pax", typeflag: tarTypePax, data: pax},
		{name: "file", data: []byte("x")},
	})
	parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{PaxBytes: 4})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(parsed.Entries) != 1 || parsed.Entries[0].Name != "file" {
		t.Fatalf("entries = %#v", parsed.Entries)
	}
	if len(parsed.Limitations) == 0 {
		t.Fatal("missing PAX limit limitation")
	}
}

func TestReadLongValueUnavailable(t *testing.T) {
	parsed := &Archive{reader: failingReader{}, size: 1000, limits: DefaultLimits()}
	if got := parsed.readLongValue(0, 10, parsed.limits); got != nil {
		t.Fatalf("value = %q", got)
	}
	if len(parsed.Limitations) == 0 {
		t.Fatal("missing limitation")
	}
}

func TestContainerReadersRejectNonFiles(t *testing.T) {
	parsed := &Archive{reader: bytes.NewReader(nil), limits: DefaultLimits()}
	if _, err := parsed.zipData(&Entry{Type: EntryFIFO}, -1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("zipData error = %v", err)
	}
	if _, err := parsed.tarData(&Entry{Type: EntryDirectory}, -1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("tarData error = %v", err)
	}
	if _, err := parsed.tarData(&Entry{Type: EntryFile}, -1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("tarData unknown size error = %v", err)
	}
	if _, err := parsed.gzipData(&Entry{Type: EntryDirectory}, -1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("gzipData error = %v", err)
	}
}

func TestZIP64DirectoryErrors(t *testing.T) {
	valid := buildZIP64(t, []byte("a"), []byte("abc"))
	locator := bytes.Index(valid, []byte("PK\x06\x07"))
	if locator < 0 {
		t.Fatal("locator not found")
	}
	recordOffset := int(binary.LittleEndian.Uint64(valid[locator+8:]))

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"locator multi disk", patch(valid, locator+4, []byte{1, 0, 0, 0}), ErrInvalid},
		{"record too small", patch(valid, recordOffset+4, []byte{0, 0, 0, 0, 0, 0, 0, 0}), ErrInvalid},
		{"record misplaced", patch(valid, recordOffset+4, []byte{44 + 1, 0, 0, 0, 0, 0, 0, 0}), ErrInvalid},
		{"record outside", patch(valid, locator+8, []byte{0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0}), ErrTruncated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse(bytes.NewReader(test.data), int64(len(test.data))); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}
