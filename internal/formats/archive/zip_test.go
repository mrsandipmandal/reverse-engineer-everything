package archive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// patch returns a copy of data with value written at offset.
func patch(data []byte, offset int, value []byte) []byte {
	out := append([]byte(nil), data...)
	copy(out[offset:], value)
	return out
}

// eocdOffset returns the offset of the ZIP end record.
func eocdOffset(t testing.TB, data []byte) int {
	t.Helper()
	offset := bytes.LastIndex(data, []byte("PK\x05\x06"))
	if offset < 0 {
		t.Fatal("end of central directory record not found")
	}
	return offset
}

func TestParseZIPStoredAndDeflated(t *testing.T) {
	data := buildZIP(t, []zipEntryFixture{
		{name: []byte("hello.txt"), data: []byte("hello world"), method: fixtureStored},
		{name: []byte("dir/"), method: fixtureStored},
		{name: []byte("deflated.bin"), data: bytes.Repeat([]byte("abcd"), 100), method: fixtureDeflate},
	})
	parsed := parseBytes(t, data)
	if parsed.Container != ContainerZIP {
		t.Fatalf("container = %v", parsed.Container)
	}
	if parsed.Truncated || len(parsed.Limitations) != 0 {
		t.Fatalf("truncated=%v limitations=%v", parsed.Truncated, parsed.Limitations)
	}
	if len(parsed.Entries) != 3 {
		t.Fatalf("entries = %d", len(parsed.Entries))
	}

	file := parsed.Entries[0]
	if file.Name != "hello.txt" || !file.NameAvailable || file.NameUnsafe != "" {
		t.Fatalf("name = %#v", file)
	}
	if file.Type != EntryFile || file.Method != MethodStored {
		t.Fatalf("type or method = %#v", file)
	}
	if !file.CompressedSizeKnown || file.CompressedSize != 11 ||
		!file.UncompressedSizeKnown || file.UncompressedSize != 11 {
		t.Fatalf("sizes = %#v", file)
	}
	if !file.CRC32Available || !file.ModifiedAvailable || file.ModifiedUnix != 315532800 {
		t.Fatalf("crc or time = %#v", file)
	}
	if got := entryData(t, parsed, 0); string(got) != "hello world" {
		t.Fatalf("data = %q", got)
	}
	if prefix, err := parsed.EntryPrefix(0, 5); err != nil || string(prefix) != "hello" {
		t.Fatalf("prefix = %q, %v", prefix, err)
	}

	dir := parsed.Entries[1]
	if dir.Type != EntryDirectory || dir.UncompressedSize != 0 {
		t.Fatalf("directory = %#v", dir)
	}
	if got := entryData(t, parsed, 1); len(got) != 0 {
		t.Fatalf("directory data = %q", got)
	}

	deflated := parsed.Entries[2]
	if deflated.Method != MethodDeflate {
		t.Fatalf("method = %v", deflated.Method)
	}
	if got := entryData(t, parsed, 2); !bytes.Equal(got, bytes.Repeat([]byte("abcd"), 100)) {
		t.Fatalf("deflated data = %d bytes", len(got))
	}
	if prefix, err := parsed.EntryPrefix(2, 6); err != nil || string(prefix) != "abcdab" {
		t.Fatalf("deflated prefix = %q, %v", prefix, err)
	}
}

func TestParseZIPDirectorySymlinkAndMode(t *testing.T) {
	data := buildZIP(t, []zipEntryFixture{
		{name: []byte("dir/"), versionMadeBy: 3 << 8, external: 0x41ed0000},
		{name: []byte("link"), data: []byte("target.txt"), versionMadeBy: 3 << 8, external: 0xa1ff0000},
		{name: []byte("script.sh"), data: []byte("#!/bin/sh\n"), versionMadeBy: 3 << 8, external: 0x81ed0000},
	})
	parsed := parseBytes(t, data)
	if parsed.Entries[0].Type != EntryDirectory {
		t.Fatalf("directory type = %v", parsed.Entries[0].Type)
	}
	link := parsed.Entries[1]
	if link.Type != EntrySymlink || !link.ModeAvailable || link.Mode != 0xa1ff {
		t.Fatalf("symlink = %#v", link)
	}
	if got := entryData(t, parsed, 1); string(got) != "target.txt" {
		t.Fatalf("symlink data = %q", got)
	}
	if parsed.Entries[2].Type != EntryFile || parsed.Entries[2].Mode != 0x81ed {
		t.Fatalf("file = %#v", parsed.Entries[2])
	}
}

func TestParseZIPUnsafeNames(t *testing.T) {
	tests := []struct {
		name      []byte
		available bool
		unsafe    string
	}{
		{[]byte("../escape"), true, "parent-directory segment"},
		{[]byte("/abs"), true, "absolute path"},
		{[]byte("C:/x"), true, "drive-letter path"},
		{[]byte(`a\b`), true, "backslash separator"},
		{[]byte("."), true, "name resolves to the archive root"},
		{[]byte{}, false, "empty name"},
		{[]byte("a\x00b"), false, "name contains a NUL byte"},
		{[]byte{0xff, 0xfe}, false, "name is not valid UTF-8"},
		{[]byte(strings.Repeat("a", MaxNameBytes+1)), false, "name exceeds 4096 bytes"},
	}
	for _, test := range tests {
		t.Run(string(test.name), func(t *testing.T) {
			parsed := parseBytes(t, buildZIP(t, []zipEntryFixture{{name: test.name, data: []byte("x")}}))
			entry := parsed.Entries[0]
			if entry.NameAvailable != test.available || entry.NameUnsafe != test.unsafe {
				t.Fatalf("entry = %#v", entry)
			}
			if _, err := parsed.EntryData(0); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("EntryData error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestParseZIPSafeUncleanName(t *testing.T) {
	parsed := parseBytes(t, buildZIP(t, []zipEntryFixture{{name: []byte("a//b"), data: []byte("x")}}))
	if entry := parsed.Entries[0]; !entry.NameAvailable || entry.NameUnsafe != "" {
		t.Fatalf("entry = %#v", entry)
	}
}

func TestParseZIPEncryptedAndUnsupported(t *testing.T) {
	data := buildZIP(t, []zipEntryFixture{
		{name: []byte("secret"), data: []byte("x"), flags: zipFlagEncrypt},
		{name: []byte("packed"), data: []byte("x"), method: uint16(MethodBzip2)},
	})
	parsed := parseBytes(t, data)
	if !parsed.Entries[0].Encrypted {
		t.Fatal("entry is not encrypted")
	}
	if _, err := parsed.EntryData(0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("encrypted EntryData error = %v", err)
	}
	if parsed.Entries[1].Method != MethodBzip2 {
		t.Fatalf("method = %v", parsed.Entries[1].Method)
	}
	if _, err := parsed.EntryData(1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unsupported EntryData error = %v", err)
	}
}

func TestParseZIPDataDescriptor(t *testing.T) {
	parsed := parseBytes(t, buildZIP(t, []zipEntryFixture{{
		name:   []byte("descriptor.txt"),
		data:   []byte("hello descriptor"),
		method: fixtureDeflate,
		flags:  fixtureDescriptor,
	}}))
	if got := entryData(t, parsed, 0); string(got) != "hello descriptor" {
		t.Fatalf("data = %q", got)
	}
}

func TestParseZIP64(t *testing.T) {
	data := buildZIP64(t, []byte("z64.txt"), []byte("hello zip64"))
	parsed := parseBytes(t, data)
	if len(parsed.Entries) != 1 {
		t.Fatalf("entries = %d", len(parsed.Entries))
	}
	entry := parsed.Entries[0]
	if !entry.UncompressedSizeKnown || entry.UncompressedSize != 11 ||
		!entry.CompressedSizeKnown || entry.CompressedSize == 0 {
		t.Fatalf("sizes = %#v", entry)
	}
	if got := entryData(t, parsed, 0); string(got) != "hello zip64" {
		t.Fatalf("data = %q", got)
	}
}

func TestParseZIP64BrokenLocator(t *testing.T) {
	data := buildZIP64(t, []byte("z64.txt"), []byte("hello"))
	locator := bytes.Index(data, []byte("PK\x06\x07"))
	if locator < 0 {
		t.Fatal("locator not found")
	}
	broken := patch(data, locator, []byte("PK\x06\x08"))
	if _, err := Parse(bytes.NewReader(broken), int64(len(broken))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

func TestParseZIPLocalHeaderDefects(t *testing.T) {
	tests := []struct {
		name string
		edit func([]byte) []byte
		want error
	}{
		{
			name: "bad local signature",
			edit: func([]byte) []byte {
				data := buildZIP(t, []zipEntryFixture{
					{name: []byte("a"), data: []byte("a")},
					{name: []byte("b"), data: []byte("b")},
				})
				second := bytes.Index(data[4:], []byte("PK\x03\x04"))
				if second < 0 {
					t.Fatal("second local header not found")
				}
				return patch(data, 4+second, []byte("XXXX"))
			},
			want: ErrInvalid,
		},
		{
			name: "local name mismatch",
			edit: func([]byte) []byte {
				return buildZIP(t, []zipEntryFixture{{
					name: []byte("central.txt"), localName: []byte("local.txt"), data: []byte("x"),
				}})
			},
			want: ErrInvalid,
		},
		{
			name: "stored sizes disagree",
			edit: func([]byte) []byte {
				uncompressed := uint32(4)
				return buildZIP(t, []zipEntryFixture{{
					name: []byte("a"), data: []byte("abc"), uncompressed: &uncompressed,
				}})
			},
			want: ErrInvalid,
		},
		{
			name: "crc mismatch",
			edit: func([]byte) []byte {
				bad := uint32(1)
				return buildZIP(t, []zipEntryFixture{{
					name: []byte("a"), data: []byte("abc"), crc: &bad,
				}})
			},
			want: ErrInvalid,
		},
		{
			name: "compressed range outside",
			edit: func([]byte) []byte {
				compressed := uint32(1 << 20)
				return buildZIP(t, []zipEntryFixture{{
					name: []byte("a"), data: []byte("abc"), compressed: &compressed,
				}})
			},
			want: ErrTruncated,
		},
		{
			name: "truncated deflate",
			edit: func([]byte) []byte {
				payload := deflateBytes(t, []byte("hello world hello world"))
				compressed := uint32(len(payload) - 1)
				return buildZIP(t, []zipEntryFixture{{
					name: []byte("a"), data: []byte("hello world hello world"),
					method: fixtureDeflate, compressed: &compressed,
				}})
			},
			want: ErrTruncated,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := test.edit(buildZIP(t, []zipEntryFixture{{name: []byte("a"), data: []byte("abc")}}))
			parsed := parseBytes(t, data)
			index := 0
			if test.name == "bad local signature" {
				index = 1
			}
			if _, err := parsed.EntryData(index); !errors.Is(err, test.want) {
				t.Fatalf("EntryData error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseZIPErrors(t *testing.T) {
	valid := buildZIP(t, []zipEntryFixture{{name: []byte("a"), data: []byte("abc")}})
	end := eocdOffset(t, valid)
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"missing end record", patch(valid, end, []byte("XXXX")), ErrTruncated},
		{"multi disk", patch(valid, end+4, []byte{1, 0}), ErrInvalid},
		{"directory outside", patch(valid, end+16, []byte{0xff, 0xff, 0xff, 0x7f}), ErrTruncated},
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

func TestParseZIPCentralDirectoryDefects(t *testing.T) {
	valid := buildZIP(t, []zipEntryFixture{{name: []byte("a"), data: []byte("abc")}})
	end := eocdOffset(t, valid)
	cdOffset := int(binary.LittleEndian.Uint32(valid[end+16:]))

	badSignature := patch(valid, cdOffset, []byte("XXXX"))
	if _, err := Parse(bytes.NewReader(badSignature), int64(len(badSignature))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad signature error = %v, want ErrInvalid", err)
	}

	badNameLength := patch(valid, cdOffset+28, []byte{0xff, 0xff})
	parsed, err := Parse(bytes.NewReader(badNameLength), int64(len(badNameLength)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !parsed.Truncated || len(parsed.Entries) != 0 || len(parsed.Limitations) == 0 {
		t.Fatalf("truncated=%v entries=%d limitations=%v", parsed.Truncated, len(parsed.Entries), parsed.Limitations)
	}
}

func TestParseZIPEmpty(t *testing.T) {
	parsed := parseBytes(t, buildZIP(t, nil))
	if len(parsed.Entries) != 0 || parsed.Truncated || len(parsed.Limitations) != 0 {
		t.Fatalf("archive = %#v", parsed)
	}
}

func TestParseZIPLimits(t *testing.T) {
	t.Run("entries", func(t *testing.T) {
		data := buildZIP(t, []zipEntryFixture{
			{name: []byte("a"), data: []byte("a")},
			{name: []byte("b"), data: []byte("b")},
			{name: []byte("c"), data: []byte("c")},
		})
		parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{Entries: 2})
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(parsed.Entries) != 2 || !parsed.Truncated {
			t.Fatalf("entries=%d truncated=%v", len(parsed.Entries), parsed.Truncated)
		}
	})

	t.Run("directory bytes", func(t *testing.T) {
		data := buildZIP(t, []zipEntryFixture{{name: []byte("a"), data: []byte("a")}})
		parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{DirectoryBytes: 10})
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(parsed.Entries) != 0 || !parsed.Truncated || len(parsed.Limitations) == 0 {
			t.Fatalf("entries=%d truncated=%v limitations=%v", len(parsed.Entries), parsed.Truncated, parsed.Limitations)
		}
	})

	t.Run("name bytes", func(t *testing.T) {
		data := buildZIP(t, []zipEntryFixture{{name: []byte("abcdef"), data: []byte("a")}})
		parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{NameBytes: 4})
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		entry := parsed.Entries[0]
		if entry.NameAvailable || entry.NameUnsafe != "name exceeds 4 bytes" || len(entry.NameBytes) != 4 {
			t.Fatalf("entry = %#v", entry)
		}
	})
}
