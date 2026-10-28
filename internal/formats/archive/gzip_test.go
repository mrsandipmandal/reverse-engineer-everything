package archive

import (
	"bytes"
	"errors"
	"hash/crc32"
	"testing"
)

func TestParseGzip(t *testing.T) {
	data := buildGzip(t, gzipMember{
		data:    []byte("hello gzip"),
		name:    "hello.txt",
		comment: "note",
		extra:   []byte{1, 2, 3, 4},
		mtime:   1700000000,
	})
	parsed := parseBytes(t, data)
	if parsed.Container != ContainerGZIP {
		t.Fatalf("container = %v", parsed.Container)
	}
	if parsed.GZIP == nil {
		t.Fatal("gzip header is nil")
	}
	if !parsed.GZIP.NameAvailable || parsed.GZIP.Name != "hello.txt" {
		t.Fatalf("header = %#v", parsed.GZIP)
	}
	if !parsed.GZIP.CommentAvailable || parsed.GZIP.Comment != "note" {
		t.Fatalf("comment = %#v", parsed.GZIP)
	}
	if parsed.GZIP.ExtraBytes != 4 {
		t.Fatalf("extra bytes = %d", parsed.GZIP.ExtraBytes)
	}
	if !parsed.GZIP.ModifiedAvailable || parsed.GZIP.ModifiedUnix != 1700000000 {
		t.Fatalf("mtime = %#v", parsed.GZIP)
	}

	if len(parsed.Entries) != 1 {
		t.Fatalf("entries = %d", len(parsed.Entries))
	}
	entry := parsed.Entries[0]
	if entry.Type != EntryFile || entry.Method != MethodDeflate {
		t.Fatalf("entry = %#v", entry)
	}
	if !entry.CompressedSizeKnown || entry.CompressedSize != uint64(len(data)) {
		t.Fatalf("compressed size = %#v", entry)
	}
	if entry.UncompressedSizeKnown || entry.CRC32Available {
		t.Fatalf("gzip sizes or CRC claim to be known: %#v", entry)
	}
	if entry.Name != "hello.txt" || !entry.NameAvailable || entry.NameUnsafe != "" {
		t.Fatalf("name = %#v", entry)
	}
	if got := entryData(t, parsed, 0); string(got) != "hello gzip" {
		t.Fatalf("data = %q", got)
	}
	if prefix, err := parsed.EntryPrefix(0, 5); err != nil || string(prefix) != "hello" {
		t.Fatalf("prefix = %q, %v", prefix, err)
	}
}

func TestParseGzipMultiStream(t *testing.T) {
	data := buildGzip(t,
		gzipMember{data: []byte("abc"), name: "one"},
		gzipMember{data: []byte("def"), name: "two"},
	)
	parsed := parseBytes(t, data)
	if len(parsed.Entries) != 1 {
		t.Fatalf("entries = %d", len(parsed.Entries))
	}
	if got := entryData(t, parsed, 0); string(got) != "abcdef" {
		t.Fatalf("data = %q", got)
	}
}

func TestParseGzipNoName(t *testing.T) {
	parsed := parseBytes(t, buildGzip(t, gzipMember{data: []byte("x")}))
	entry := parsed.Entries[0]
	if entry.NameAvailable || len(entry.NameBytes) != 0 || entry.NameUnsafe != "" {
		t.Fatalf("entry = %#v", entry)
	}
	if got := entryData(t, parsed, 0); string(got) != "x" {
		t.Fatalf("data = %q", got)
	}
}

// gzipWithHeaderCRC returns a member with the FHCRC flag set and a valid
// header CRC.
func gzipWithHeaderCRC(t testing.TB, data []byte) []byte {
	t.Helper()
	base := buildGzip(t, gzipMember{data: data})
	header := append([]byte(nil), base[:gzipHeaderSize]...)
	header[3] |= gzipFlagHeaderCRC
	checksum := crc32.ChecksumIEEE(header)
	out := make([]byte, 0, len(header)+2+len(base)-gzipHeaderSize)
	out = append(out, header...)
	out = append(out, byte(checksum), byte(checksum>>8))
	out = append(out, base[gzipHeaderSize:]...)
	return out
}

func TestParseGzipHeaderCRC(t *testing.T) {
	valid := gzipWithHeaderCRC(t, []byte("payload"))
	parsed := parseBytes(t, valid)
	if got := entryData(t, parsed, 0); string(got) != "payload" {
		t.Fatalf("data = %q", got)
	}

	broken := append([]byte(nil), valid...)
	broken[gzipHeaderSize] ^= 0xff
	if _, err := Parse(bytes.NewReader(broken), int64(len(broken))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

func TestParseGzipReservedFlags(t *testing.T) {
	data := buildGzip(t, gzipMember{data: []byte("x")})
	data[3] |= 0x20
	if _, err := Parse(bytes.NewReader(data), int64(len(data))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

func TestParseGzipErrors(t *testing.T) {
	tests := []struct {
		name string
		data func(t testing.TB) []byte
		want error
	}{
		{
			name: "truncated trailer",
			data: func(t testing.TB) []byte {
				data := buildGzip(t, gzipMember{data: []byte("hello")})
				return data[:len(data)-4]
			},
			want: ErrTruncated,
		},
		{
			name: "crc mismatch",
			data: func(t testing.TB) []byte {
				data := buildGzip(t, gzipMember{data: []byte("hello")})
				data[len(data)-8] ^= 0xff
				return data
			},
			want: ErrInvalid,
		},
		{
			name: "corrupt deflate",
			data: func(t testing.TB) []byte {
				data := buildGzip(t, gzipMember{data: bytes.Repeat([]byte("abcd"), 32)})
				data[gzipHeaderSize] ^= 0xff
				data[gzipHeaderSize+1] ^= 0xff
				return data
			},
			want: ErrInvalid,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed := parseBytes(t, test.data(t))
			if _, err := parsed.EntryData(0); !errors.Is(err, test.want) {
				t.Fatalf("EntryData error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseGzipLimits(t *testing.T) {
	t.Run("name bytes", func(t *testing.T) {
		data := buildGzip(t, gzipMember{data: []byte("x"), name: "long-name.txt"})
		if _, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{NameBytes: 4}); !errors.Is(err, ErrLimit) {
			t.Fatalf("error = %v, want ErrLimit", err)
		}
	})
	t.Run("comment bytes", func(t *testing.T) {
		data := buildGzip(t, gzipMember{data: []byte("x"), comment: "long comment"})
		if _, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{GzipCommentBytes: 4}); !errors.Is(err, ErrLimit) {
			t.Fatalf("error = %v, want ErrLimit", err)
		}
	})
	t.Run("entry data bytes", func(t *testing.T) {
		data := buildGzip(t, gzipMember{data: bytes.Repeat([]byte("x"), 100)})
		parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{EntryDataBytes: 10})
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if _, err := parsed.EntryData(0); !errors.Is(err, ErrLimit) {
			t.Fatalf("EntryData error = %v, want ErrLimit", err)
		}
	})
}
