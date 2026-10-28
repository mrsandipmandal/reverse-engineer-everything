package archive

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// parseBytes parses an in-memory archive with the package limits.
func parseBytes(t testing.TB, data []byte) *Archive {
	t.Helper()
	parsed, err := Parse(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed == nil {
		t.Fatal("Parse returned a nil archive without an error")
	}
	return parsed
}

// entryData returns entry data and fails the test on error.
func entryData(t testing.TB, parsed *Archive, index int) []byte {
	t.Helper()
	data, err := parsed.EntryData(index)
	if err != nil {
		t.Fatalf("EntryData(%d): %v", index, err)
	}
	return data
}

func TestDetect(t *testing.T) {
	tarLike := make([]byte, tarMagicOffset+5)
	copy(tarLike[tarMagicOffset:], "ustar")
	tests := []struct {
		name   string
		prefix []byte
		want   Container
	}{
		{"zip local", []byte("PK\x03\x04rest"), ContainerZIP},
		{"zip empty", []byte("PK\x05\x06"), ContainerZIP},
		{"gzip", []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff}, ContainerGZIP},
		{"tar", tarLike, ContainerTar},
		{"unknown", []byte("not an archive"), ContainerUnknown},
		{"short gzip", []byte{0x1f, 0x8b, 8}, ContainerUnknown},
		{"empty", nil, ContainerUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Detect(test.prefix); got != test.want {
				t.Fatalf("Detect = %v, want %v", got, test.want)
			}
		})
	}
}

func TestContainerString(t *testing.T) {
	tests := map[Container]string{
		ContainerZIP:     "zip",
		ContainerTar:     "tar",
		ContainerGZIP:    "gzip",
		ContainerUnknown: "unknown",
	}
	for container, want := range tests {
		if got := container.String(); got != want {
			t.Fatalf("%d.String() = %q, want %q", container, got, want)
		}
	}
}

func TestMethodString(t *testing.T) {
	tests := map[Method]string{
		MethodStored:    "stored",
		MethodDeflate:   "deflate",
		MethodDeflate64: "deflate64",
		MethodBzip2:     "bzip2",
		MethodLZMA:      "lzma",
		MethodZstandard: "zstandard",
		Method(0x1234):  "method-4660",
	}
	for method, want := range tests {
		if got := method.String(); got != want {
			t.Fatalf("%d.String() = %q, want %q", method, got, want)
		}
	}
}

func TestEntryTypeString(t *testing.T) {
	tests := map[EntryType]string{
		EntryFile:            "file",
		EntryDirectory:       "directory",
		EntrySymlink:         "symlink",
		EntryHardlink:        "hardlink",
		EntryFIFO:            "fifo",
		EntryCharacterDevice: "character-device",
		EntryBlockDevice:     "block-device",
		EntryOther:           "other",
		EntryUnknown:         "unknown",
	}
	for entryType, want := range tests {
		if got := entryType.String(); got != want {
			t.Fatalf("%d.String() = %q, want %q", entryType, got, want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, ErrTruncated},
		{"short", []byte("PK"), ErrInvalid},
		{"unknown", []byte("this is not an archive"), ErrInvalid},
		{"truncated gzip header", []byte{0x1f, 0x8b, 8}, ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := Parse(bytes.NewReader(test.data), int64(len(test.data)))
			if !errors.Is(err, test.want) {
				t.Fatalf("Parse error = %v, want %v", err, test.want)
			}
			if parsed != nil {
				t.Fatal("archive returned with an error")
			}
		})
	}
}

func TestParseNilReader(t *testing.T) {
	if _, err := Parse(nil, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Parse(nil) error = %v, want ErrInvalid", err)
	}
	if _, err := Parse(nil, -1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Parse negative size error = %v, want ErrInvalid", err)
	}
}

func TestParseArtifactLimit(t *testing.T) {
	data := buildZIP(t, []zipEntryFixture{{name: []byte("a"), data: []byte("a")}})
	_, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{ArtifactBytes: 4})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("error = %v, want ErrLimit", err)
	}
}

func TestLimitsDefaultsAndClamping(t *testing.T) {
	defaults := DefaultLimits()
	if defaults.ArtifactBytes != MaxArtifactBytes || defaults.Entries != MaxEntries ||
		defaults.NameBytes != MaxNameBytes || defaults.DirectoryBytes != MaxDirectoryBytes ||
		defaults.EntryDataBytes != MaxEntryDataBytes || defaults.ExtraBytes != MaxExtraBytes ||
		defaults.PaxBytes != MaxPaxBytes || defaults.GzipCommentBytes != MaxGzipCommentBytes {
		t.Fatalf("defaults do not match the package limits: %#v", defaults)
	}
	clamped := Limits{
		ArtifactBytes:    MaxArtifactBytes + 1,
		Entries:          MaxEntries + 1,
		NameBytes:        MaxNameBytes + 1,
		DirectoryBytes:   MaxDirectoryBytes + 1,
		EntryDataBytes:   MaxEntryDataBytes + 1,
		ExtraBytes:       MaxExtraBytes + 1,
		PaxBytes:         MaxPaxBytes + 1,
		GzipCommentBytes: MaxGzipCommentBytes + 1,
	}.withDefaults()
	if clamped != defaults {
		t.Fatalf("clamped limits = %#v, want %#v", clamped, defaults)
	}
	zero := Limits{}.withDefaults()
	if zero != defaults {
		t.Fatalf("zero limits = %#v, want %#v", zero, defaults)
	}
}

func TestEntryIndexBounds(t *testing.T) {
	parsed := parseBytes(t, buildZIP(t, []zipEntryFixture{{name: []byte("a"), data: []byte("a")}}))
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
		t.Fatalf("nil EntryData error = %v, want ErrOutOfRange", err)
	}
}

func TestEntryPrefixLimit(t *testing.T) {
	parsed := parseBytes(t, buildZIP(t, []zipEntryFixture{{name: []byte("a"), data: []byte("hello")}}))
	if _, err := parsed.EntryPrefix(0, -1); !errors.Is(err, ErrLimit) {
		t.Fatalf("negative prefix error = %v, want ErrLimit", err)
	}
	if _, err := parsed.EntryPrefix(0, int(MaxEntryDataBytes)+1); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversized prefix error = %v, want ErrLimit", err)
	}
	prefix, err := parsed.EntryPrefix(0, 2)
	if err != nil || string(prefix) != "he" {
		t.Fatalf("prefix = %q, %v", prefix, err)
	}
}

func TestSize(t *testing.T) {
	data := buildZIP(t, nil)
	parsed := parseBytes(t, data)
	if parsed.Size() != int64(len(data)) {
		t.Fatalf("Size = %d, want %d", parsed.Size(), len(data))
	}
	var nilArchive *Archive
	if nilArchive.Size() != 0 {
		t.Fatal("nil Size is not zero")
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

func TestReadAtFailures(t *testing.T) {
	data := buildZIP(t, []zipEntryFixture{{name: []byte("a"), data: []byte("abc")}})
	if _, err := Parse(failingReader{}, int64(len(data))); !errors.Is(err, ErrRead) {
		t.Fatalf("failing reader error = %v, want ErrRead", err)
	}
	if _, err := Parse(shortReader{data: data}, int64(len(data))); !errors.Is(err, ErrRead) {
		t.Fatalf("short reader error = %v, want ErrRead", err)
	}
	buf := make([]byte, 4)
	if err := readAt(bytes.NewReader(data), int64(len(data)), buf, int64(len(data))); !errors.Is(err, ErrTruncated) {
		t.Fatalf("out-of-range read error = %v, want ErrTruncated", err)
	}
	if err := readAt(bytes.NewReader(data), -1, buf, int64(len(data))); !errors.Is(err, ErrTruncated) {
		t.Fatalf("negative offset read error = %v, want ErrTruncated", err)
	}
}
