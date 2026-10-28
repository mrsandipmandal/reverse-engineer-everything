package asar

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

const inventoryJSON = `{"files":{
	"a.txt":{"size":5,"offset":"0"},
	"dir":{"files":{"b.txt":{"size":6,"offset":"5"}}},
	"empty":{"size":0,"offset":"11"},
	"link":{"link":"a.txt"},
	"out":{"size":4,"offset":"0","unpacked":true},
	"packed":{"size":0,"offset":"11","executable":true,"integrity":{"algorithm":"SHA256","hash":"ABCD","blockSize":4,"blocks":[{"offset":"0","size":4}]}},
	"run.sh":{"size":0,"offset":"11","executable":true}
}}`

func TestParseInventory(t *testing.T) {
	data := []byte("helloworld!")
	parsed := parseBytes(t, buildASAR(t, inventoryJSON, data))

	if parsed.Truncated || len(parsed.Limitations) != 0 {
		t.Fatalf("truncated=%v limitations=%v", parsed.Truncated, parsed.Limitations)
	}
	if parsed.DataOffset != int64(asarHeaderSize(inventoryJSON)) {
		t.Fatalf("data offset = %d, want %d", parsed.DataOffset, asarHeaderSize(inventoryJSON))
	}
	if parsed.HeaderBytes != parsed.DataOffset-8 {
		t.Fatalf("header bytes = %d, data offset = %d", parsed.HeaderBytes, parsed.DataOffset)
	}
	wantPaths := []string{"a.txt", "dir", "dir/b.txt", "empty", "link", "out", "packed", "run.sh"}
	if len(parsed.Entries) != len(wantPaths) {
		t.Fatalf("entries = %d, want %d", len(parsed.Entries), len(wantPaths))
	}
	for i, want := range wantPaths {
		if parsed.Entries[i].Path != want {
			t.Fatalf("entry %d path = %q, want %q", i, parsed.Entries[i].Path, want)
		}
		if parsed.Entries[i].Index != i {
			t.Fatalf("entry %d index = %d", i, parsed.Entries[i].Index)
		}
	}

	file := parsed.Entries[findPath(t, parsed, "a.txt")]
	if file.Type != EntryFile || !file.SizeKnown || file.Size != 5 || !file.OffsetKnown || !file.DataKnown {
		t.Fatalf("file = %#v", file)
	}
	if !file.PathAvailable || file.PathUnsafe != "" {
		t.Fatalf("path state = %#v", file)
	}
	if got := entryData(t, parsed, file.Index); string(got) != "hello" {
		t.Fatalf("data = %q", got)
	}
	if prefix, err := parsed.EntryPrefix(file.Index, 2); err != nil || string(prefix) != "he" {
		t.Fatalf("prefix = %q, %v", prefix, err)
	}

	dir := parsed.Entries[findPath(t, parsed, "dir")]
	if dir.Type != EntryDirectory || dir.SizeKnown {
		t.Fatalf("directory = %#v", dir)
	}
	if _, err := parsed.EntryData(dir.Index); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("directory EntryData error = %v", err)
	}

	nested := parsed.Entries[findPath(t, parsed, "dir/b.txt")]
	if got := entryData(t, parsed, nested.Index); string(got) != "world!" {
		t.Fatalf("nested data = %q", got)
	}

	empty := parsed.Entries[findPath(t, parsed, "empty")]
	if got := entryData(t, parsed, empty.Index); len(got) != 0 {
		t.Fatalf("empty data = %q", got)
	}
	if prefix, err := parsed.EntryPrefix(empty.Index, 4); err != nil || len(prefix) != 0 {
		t.Fatalf("empty prefix = %q, %v", prefix, err)
	}

	link := parsed.Entries[findPath(t, parsed, "link")]
	if link.Type != EntryLink || !link.LinkTargetAvailable || link.LinkTarget != "a.txt" {
		t.Fatalf("link = %#v", link)
	}
	if _, err := parsed.EntryData(link.Index); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("link EntryData error = %v", err)
	}

	unpacked := parsed.Entries[findPath(t, parsed, "out")]
	if !unpacked.Unpacked || unpacked.DataKnown {
		t.Fatalf("unpacked = %#v", unpacked)
	}
	if len(unpacked.Limitations) != 1 || unpacked.Limitations[0] != "file content is unpacked" {
		t.Fatalf("limitations = %v", unpacked.Limitations)
	}
	if _, err := parsed.EntryData(unpacked.Index); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unpacked EntryData error = %v", err)
	}

	packed := parsed.Entries[findPath(t, parsed, "packed")]
	if !packed.Executable {
		t.Fatal("packed entry is not executable")
	}
	if packed.Integrity == nil {
		t.Fatal("integrity metadata is missing")
	}
	if packed.Integrity.Algorithm != "SHA256" || !packed.Integrity.AlgorithmAvailable {
		t.Fatalf("algorithm = %#v", packed.Integrity)
	}
	if packed.Integrity.Hash != "abcd" || !packed.Integrity.HashAvailable {
		t.Fatalf("hash = %#v", packed.Integrity)
	}
	if packed.Integrity.BlockCount != 1 {
		t.Fatalf("blocks = %d", packed.Integrity.BlockCount)
	}

	if parsed.Entries[findPath(t, parsed, "run.sh")].Executable != true {
		t.Fatal("run.sh is not executable")
	}
}

func TestParseEmptyArchive(t *testing.T) {
	parsed := parseBytes(t, buildASAR(t, `{"files":{}}`, nil))
	if len(parsed.Entries) != 0 || parsed.Truncated || len(parsed.Limitations) != 0 {
		t.Fatalf("archive = %#v", parsed)
	}
}

func TestParseHeaderErrors(t *testing.T) {
	valid := buildASAR(t, inventoryJSON, []byte("helloworld!"))
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"first pickle size", patch(valid, 0, binary.LittleEndian.AppendUint32(nil, 5)), ErrInvalid},
		{"header too small", patch(valid, 4, binary.LittleEndian.AppendUint32(nil, 7)), ErrInvalid},
		{"header beyond artifact", patch(valid, 4, binary.LittleEndian.AppendUint32(nil, uint32(len(valid)))), ErrTruncated},
		{"json larger than header", patch(valid, 8, binary.LittleEndian.AppendUint32(nil, 1<<20)), ErrInvalid},
		{"json length above json size", patch(valid, 12, binary.LittleEndian.AppendUint32(nil, 1<<20)), ErrInvalid},
		{"empty json length", patch(valid, 12, binary.LittleEndian.AppendUint32(nil, 0)), ErrInvalid},
		{"json is a list", buildASAR(t, `[]`, nil), ErrInvalid},
		{"json is truncated", buildASAR(t, `{"files":`, nil), ErrInvalid},
		{"header without files", buildASAR(t, `{"x":1}`, nil), ErrInvalid},
		{"short artifact", valid[:3], ErrTruncated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := Parse(bytes.NewReader(test.data), int64(len(test.data)))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if parsed != nil {
				t.Fatal("archive returned with an error")
			}
		})
	}
}

func patch(data []byte, offset int, value []byte) []byte {
	out := append([]byte(nil), data...)
	copy(out[offset:], value)
	return out
}

func TestParseLimits(t *testing.T) {
	valid := buildASAR(t, inventoryJSON, []byte("helloworld!"))

	t.Run("artifact bytes", func(t *testing.T) {
		_, err := ParseWithLimits(bytes.NewReader(valid), int64(len(valid)), Limits{ArtifactBytes: 4})
		if !errors.Is(err, ErrLimit) {
			t.Fatalf("error = %v, want ErrLimit", err)
		}
	})
	t.Run("header bytes", func(t *testing.T) {
		_, err := ParseWithLimits(bytes.NewReader(valid), int64(len(valid)), Limits{HeaderBytes: 4})
		if !errors.Is(err, ErrLimit) {
			t.Fatalf("error = %v, want ErrLimit", err)
		}
	})
	t.Run("entries", func(t *testing.T) {
		parsed, err := ParseWithLimits(bytes.NewReader(valid), int64(len(valid)), Limits{Entries: 2})
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(parsed.Entries) != 2 || !parsed.Truncated || len(parsed.Limitations) == 0 {
			t.Fatalf("entries=%d truncated=%v limitations=%v", len(parsed.Entries), parsed.Truncated, parsed.Limitations)
		}
	})
	t.Run("path bytes", func(t *testing.T) {
		parsed, err := ParseWithLimits(bytes.NewReader(valid), int64(len(valid)), Limits{PathBytes: 6})
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(parsed.Entries) != len(parseBytes(t, valid).Entries) {
			t.Fatalf("entries = %d", len(parsed.Entries))
		}
		entry := parsed.Entries[2]
		if entry.PathAvailable || len(entry.PathBytes) != 6 {
			t.Fatalf("over-limit path = %#v", entry)
		}
		if entry.PathUnsafe != "path exceeds 6 bytes" {
			t.Fatalf("unsafe reason = %q", entry.PathUnsafe)
		}
	})
	t.Run("entry data bytes", func(t *testing.T) {
		parsed, err := ParseWithLimits(bytes.NewReader(valid), int64(len(valid)), Limits{EntryDataBytes: 2})
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		index := findPath(t, parsed, "a.txt")
		if _, err := parsed.EntryData(index); !errors.Is(err, ErrLimit) {
			t.Fatalf("EntryData error = %v, want ErrLimit", err)
		}
		if _, err := parsed.EntryPrefix(index, 2); !errors.Is(err, ErrLimit) {
			t.Fatalf("EntryPrefix error = %v, want ErrLimit", err)
		}
	})
}

func TestParseDepthLimit(t *testing.T) {
	directory := `{"files":{"a":{"files":{"b":{"files":{"c":{"size":0,"offset":"0"}}}}}}}`
	data := buildASAR(t, directory, nil)

	shallow, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{Depth: 1})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(shallow.Entries) != 1 || shallow.Entries[0].Path != "a" || !shallow.Truncated {
		t.Fatalf("entries=%#v truncated=%v", shallow.Entries, shallow.Truncated)
	}

	deep, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{Depth: 2})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(deep.Entries) != 2 || deep.Entries[1].Path != "a/b" || !deep.Truncated {
		t.Fatalf("entries=%#v truncated=%v", deep.Entries, deep.Truncated)
	}
}

func TestParsePathSafety(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		available bool
		unsafe    string
	}{
		{"parent", "../escape", true, "parent-directory segment"},
		{"absolute", "/abs", true, "absolute path"},
		{"drive", "C:/x", true, "drive-letter path"},
		{"backslash", `a\\b`, true, "backslash separator"},
		{"root", ".", true, "name resolves to the archive root"},
		{"empty", "", false, "empty name"},
		{"nul", "bad\u0000name", false, "path contains a NUL byte"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := `{"files":{` + quoteKey(test.key) + `:{"size":1,"offset":"0"}}}`
			parsed := parseBytes(t, buildASAR(t, directory, []byte("x")))
			entry := parsed.Entries[0]
			if entry.PathAvailable != test.available || entry.PathUnsafe != test.unsafe {
				t.Fatalf("entry = %#v", entry)
			}
			if _, err := parsed.EntryData(0); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("EntryData error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestParseUnsafeDirectory(t *testing.T) {
	directory := `{"files":{"..":{"files":{"x":{"size":1,"offset":"0"}}}}}`
	parsed := parseBytes(t, buildASAR(t, directory, []byte("x")))
	if len(parsed.Entries) != 2 {
		t.Fatalf("entries = %d", len(parsed.Entries))
	}
	if parsed.Entries[0].Type != EntryDirectory || parsed.Entries[0].PathUnsafe != "parent-directory segment" {
		t.Fatalf("directory = %#v", parsed.Entries[0])
	}
	if parsed.Entries[1].Path != "../x" || parsed.Entries[1].PathUnsafe != "parent-directory segment" {
		t.Fatalf("file = %#v", parsed.Entries[1])
	}
	if _, err := parsed.EntryData(1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("EntryData error = %v", err)
	}
}

func quoteKey(key string) string {
	encoded, err := json.Marshal(key)
	if err != nil {
		return `""`
	}
	return string(encoded)
}

func TestParseRangeOutside(t *testing.T) {
	tests := []struct {
		name   string
		record string
	}{
		{"size past data", `{"size":100,"offset":"0"}`},
		{"offset past artifact", `{"size":1,"offset":"999999"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := `{"files":{"a":` + test.record + `}}`
			parsed := parseBytes(t, buildASAR(t, directory, []byte("x")))
			entry := parsed.Entries[0]
			if !entry.RangeOutside || entry.DataKnown {
				t.Fatalf("entry = %#v", entry)
			}
			if _, err := parsed.EntryData(0); !errors.Is(err, ErrTruncated) {
				t.Fatalf("EntryData error = %v, want ErrTruncated", err)
			}
		})
	}
}

func TestParseInvalidNumbers(t *testing.T) {
	tests := []string{
		`{"size":"abc","offset":"0"}`,
		`{"size":-1,"offset":"0"}`,
		`{"size":1.5,"offset":"0"}`,
		`{"size":1,"offset":"1e3"}`,
	}
	for _, record := range tests {
		t.Run(record, func(t *testing.T) {
			directory := `{"files":{"a":` + record + `}}`
			data := buildASAR(t, directory, []byte("x"))
			if _, err := Parse(bytes.NewReader(data), int64(len(data))); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestParseMissingFields(t *testing.T) {
	tests := []struct {
		name       string
		record     string
		limitation string
	}{
		{"missing size", `{"offset":"0"}`, "node declares no type"},
		{"missing offset", `{"size":1}`, "file offset is missing"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := `{"files":{"a":` + test.record + `}}`
			parsed := parseBytes(t, buildASAR(t, directory, []byte("x")))
			entry := parsed.Entries[0]
			if len(entry.Limitations) == 0 || entry.Limitations[0] != test.limitation {
				t.Fatalf("limitations = %v, want %q", entry.Limitations, test.limitation)
			}
			if _, err := parsed.EntryData(0); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("EntryData error = %v", err)
			}
		})
	}
}

func TestParseIntegrityMalformed(t *testing.T) {
	directory := `{"files":{"a":{"size":1,"offset":"0","integrity":"nope"}}}`
	parsed := parseBytes(t, buildASAR(t, directory, []byte("x")))
	entry := parsed.Entries[0]
	if entry.Integrity == nil || len(entry.Limitations) != 1 {
		t.Fatalf("entry = %#v", entry)
	}
	if entry.Limitations[0] != "integrity metadata is malformed" {
		t.Fatalf("limitations = %v", entry.Limitations)
	}
}

func TestEntryBounds(t *testing.T) {
	parsed := parseBytes(t, buildASAR(t, `{"files":{"a":{"size":1,"offset":"0"}}}`, []byte("x")))
	for _, index := range []int{-1, 1, 99} {
		if _, err := parsed.EntryData(index); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("EntryData(%d) error = %v, want ErrOutOfRange", index, err)
		}
		if _, err := parsed.EntryPrefix(index, 1); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("EntryPrefix(%d) error = %v, want ErrOutOfRange", index, err)
		}
	}
	var nilArchive *Archive
	if _, err := nilArchive.EntryData(0); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("nil EntryData error = %v", err)
	}
	if nilArchive.Size() != 0 {
		t.Fatal("nil Size is not zero")
	}
	if parsed.Size() != int64(len(buildASAR(t, `{"files":{"a":{"size":1,"offset":"0"}}}`, []byte("x")))) {
		t.Fatal("Size does not report the artifact size")
	}
	if _, err := parsed.EntryPrefix(0, -1); !errors.Is(err, ErrLimit) {
		t.Fatalf("negative prefix error = %v", err)
	}
	if _, err := parsed.EntryPrefix(0, int(MaxEntryDataBytes)+1); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversized prefix error = %v", err)
	}
}

func TestParseNilReader(t *testing.T) {
	if _, err := Parse(nil, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Parse(nil) error = %v", err)
	}
	if _, err := Parse(bytes.NewReader(nil), -1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative size error = %v", err)
	}
}

func TestLimitsDefaultsAndClamping(t *testing.T) {
	defaults := DefaultLimits()
	if defaults.ArtifactBytes != MaxArtifactBytes || defaults.HeaderBytes != MaxHeaderBytes ||
		defaults.Entries != MaxEntries || defaults.PathBytes != MaxPathBytes ||
		defaults.Depth != MaxDepth || defaults.EntryDataBytes != MaxEntryDataBytes {
		t.Fatalf("defaults do not match the package limits: %#v", defaults)
	}
	clamped := Limits{
		ArtifactBytes:  MaxArtifactBytes + 1,
		HeaderBytes:    MaxHeaderBytes + 1,
		Entries:        MaxEntries + 1,
		PathBytes:      MaxPathBytes + 1,
		Depth:          MaxDepth + 1,
		EntryDataBytes: MaxEntryDataBytes + 1,
	}.withDefaults()
	if clamped != defaults {
		t.Fatalf("clamped limits = %#v, want %#v", clamped, defaults)
	}
	if zero := (Limits{}).withDefaults(); zero != defaults {
		t.Fatalf("zero limits = %#v, want %#v", zero, defaults)
	}
}

func TestParseUintField(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		want  uint64
		known bool
		ok    bool
	}{
		{"number", `5`, 5, true, true},
		{"string", `"42"`, 42, true, true},
		{"zero", `0`, 0, true, true},
		{"absent", ``, 0, false, true},
		{"null", `null`, 0, false, true},
		{"negative", `-1`, 0, false, false},
		{"float", `1.5`, 0, false, false},
		{"exponent", `1e3`, 0, false, false},
		{"text", `"abc"`, 0, false, false},
		{"empty string", `""`, 0, false, false},
		{"long", strings.Repeat("9", 21), 0, false, false},
		{"overflow", "18446744073709551616", 0, false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, known, err := parseUintField([]byte(test.raw))
			if (err == nil) != test.ok || value != test.want || known != test.known {
				t.Fatalf("parseUintField(%q) = %d, %v, %v", test.raw, value, known, err)
			}
		})
	}
}

func TestDecodeText(t *testing.T) {
	tests := []struct {
		name      string
		raw       []byte
		limit     int
		available bool
		stored    int
	}{
		{"valid", []byte("target"), 10, true, 6},
		{"empty", nil, 10, false, 0},
		{"nul", []byte("a\x00b"), 10, false, 3},
		{"invalid utf8", []byte{0xff, 0xfe}, 10, false, 2},
		{"too long", []byte("abcdef"), 4, false, 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, available, stored := decodeText(test.raw, test.limit)
			if available != test.available || len(stored) != test.stored {
				t.Fatalf("available=%v stored=%d", available, len(stored))
			}
		})
	}
}

func TestJoinPath(t *testing.T) {
	if got := joinPath("", "a"); got != "a" {
		t.Fatalf("joinPath root = %q", got)
	}
	if got := joinPath("a", "b"); got != "a/b" {
		t.Fatalf("joinPath = %q", got)
	}
	if got := displayPath(""); got != "<root>" {
		t.Fatalf("displayPath = %q", got)
	}
}

// failingReader always fails.
type failingReader struct{}

func (failingReader) ReadAt([]byte, int64) (int, error) {
	return 0, io.ErrClosedPipe
}

// shortReader claims fewer bytes than requested without an error.
type shortReader struct{ data []byte }

func (r shortReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	if n == len(p) && n > 0 {
		n--
	}
	return n, nil
}

func TestReaderFailures(t *testing.T) {
	data := buildASAR(t, `{"files":{"a":{"size":1,"offset":"0"}}}`, []byte("x"))
	if _, err := Parse(failingReader{}, int64(len(data))); !errors.Is(err, ErrRead) {
		t.Fatalf("failing reader error = %v, want ErrRead", err)
	}
	if _, err := Parse(shortReader{data: data}, int64(len(data))); !errors.Is(err, ErrRead) {
		t.Fatalf("short reader error = %v, want ErrRead", err)
	}
	buf := make([]byte, 4)
	if err := readAt(bytes.NewReader(data), int64(len(data)), buf, int64(len(data))); !errors.Is(err, ErrTruncated) {
		t.Fatalf("out-of-range read error = %v", err)
	}
	if err := readAt(bytes.NewReader(data), -1, buf, int64(len(data))); !errors.Is(err, ErrTruncated) {
		t.Fatalf("negative offset read error = %v", err)
	}
}

func TestEntryTypeString(t *testing.T) {
	tests := map[EntryType]string{
		EntryFile:      "file",
		EntryDirectory: "directory",
		EntryLink:      "link",
		EntryOther:     "other",
		EntryUnknown:   "unknown",
	}
	for entryType, want := range tests {
		if got := entryType.String(); got != want {
			t.Fatalf("%d.String() = %q, want %q", entryType, got, want)
		}
	}
}
