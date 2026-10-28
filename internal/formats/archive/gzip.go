package archive

import (
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// Gzip header layout and flags.
const (
	gzipHeaderSize    = 10
	gzipFlagHeaderCRC = 1 << 1
	gzipFlagExtra     = 1 << 2
	gzipFlagName      = 1 << 3
	gzipFlagComment   = 1 << 4
	gzipFlagReserved  = 0xe0
)

// parseGZIP inventories a gzip stream as one entry. Member boundaries and the
// uncompressed size are not enumerated; EntryData decodes the members on
// demand.
func parseGZIP(r io.ReaderAt, size int64, limits Limits) (*Archive, error) {
	header, err := parseGZIPHeader(r, size, limits)
	if err != nil {
		return nil, err
	}
	entry := Entry{
		Index:                 0,
		Type:                  EntryFile,
		Method:                MethodDeflate,
		CompressedSize:        uint64(size),
		CompressedSizeKnown:   true,
		UncompressedSizeKnown: false,
		ModifiedUnix:          header.ModifiedUnix,
		ModifiedAvailable:     header.ModifiedAvailable,
		HeaderOffset:          0,
		DataOffset:            header.HeaderBytes,
	}
	if header.NameAvailable {
		entry.Name = header.Name
		entry.NameBytes = header.NameBytes
		entry.NameAvailable = true
	}
	return &Archive{
		Container: ContainerGZIP,
		Entries:   []Entry{entry},
		GZIP:      &header,
		reader:    r,
		size:      size,
		limits:    limits,
	}, nil
}

// parseGZIPHeader reads the optional gzip fields and verifies the header CRC
// when one is present.
func parseGZIPHeader(r io.ReaderAt, size int64, limits Limits) (GZIPHeader, error) {
	var header GZIPHeader
	maxPrefix := int64(gzipHeaderSize+2) + limits.ExtraBytes +
		int64(limits.NameBytes) + int64(limits.GzipCommentBytes) + 2
	prefixSize := size
	if prefixSize > maxPrefix {
		prefixSize = maxPrefix
	}
	buf := make([]byte, prefixSize)
	if err := readAt(r, 0, buf, size); err != nil {
		return header, err
	}
	if len(buf) < gzipHeaderSize {
		return header, fmt.Errorf("%w: gzip header is %d bytes", ErrTruncated, len(buf))
	}
	if buf[0] != 0x1f || buf[1] != 0x8b || buf[2] != 8 {
		return header, fmt.Errorf("%w: gzip magic or compression method is invalid", ErrInvalid)
	}
	flags := buf[3]
	if flags&gzipFlagReserved != 0 {
		return header, fmt.Errorf("%w: gzip reserved flags are set", ErrInvalid)
	}
	mtime := binary.LittleEndian.Uint32(buf[4:])
	header.OS = buf[9]
	if mtime != 0 {
		header.ModifiedUnix = int64(mtime)
		header.ModifiedAvailable = true
	}

	pos := gzipHeaderSize
	var err error
	if flags&gzipFlagExtra != 0 {
		if len(buf)-pos < 2 {
			return header, fmt.Errorf("%w: gzip extra field length runs past the artifact", ErrTruncated)
		}
		header.ExtraBytes = binary.LittleEndian.Uint16(buf[pos:])
		pos += 2
		if int64(header.ExtraBytes) > limits.ExtraBytes {
			return header, fmt.Errorf("%w: gzip extra field %d exceeds limit %d",
				ErrLimit, header.ExtraBytes, limits.ExtraBytes)
		}
		if len(buf)-pos < int(header.ExtraBytes) {
			return header, fmt.Errorf("%w: gzip extra field runs past the artifact", ErrTruncated)
		}
		pos += int(header.ExtraBytes)
	}
	if flags&gzipFlagName != 0 {
		header.Name, header.NameAvailable, header.NameBytes, pos, err = gzipField(buf, pos, limits.NameBytes, "name")
		if err != nil {
			return header, err
		}
	}
	if flags&gzipFlagComment != 0 {
		header.Comment, header.CommentAvailable, _, pos, err = gzipField(buf, pos, limits.GzipCommentBytes, "comment")
		if err != nil {
			return header, err
		}
	}
	if flags&gzipFlagHeaderCRC != 0 {
		if len(buf)-pos < 2 {
			return header, fmt.Errorf("%w: gzip header CRC runs past the artifact", ErrTruncated)
		}
		want := uint16(crc32.ChecksumIEEE(buf[:pos]))
		if binary.LittleEndian.Uint16(buf[pos:]) != want {
			return header, fmt.Errorf("%w: gzip header CRC mismatch", ErrInvalid)
		}
		pos += 2
	}
	header.HeaderBytes = int64(pos)
	return header, nil
}

// gzipField reads one NUL-terminated gzip name or comment field and returns the
// decoded value and the position after its terminator.
func gzipField(buf []byte, pos, limit int, field string) (string, bool, []byte, int, error) {
	end := -1
	search := buf[pos:]
	if len(search) > limit {
		search = search[:limit]
	}
	for i, b := range search {
		if b == 0 {
			end = i
			break
		}
	}
	if end < 0 {
		if pos+len(search) < len(buf) || len(search) == limit {
			return "", false, nil, pos, fmt.Errorf("%w: gzip %s exceeds limit %d", ErrLimit, field, limit)
		}
		return "", false, nil, pos, fmt.Errorf("%w: gzip %s has no terminator", ErrTruncated, field)
	}
	raw := buf[pos : pos+end]
	name, available, stored := decodeText(raw, limit)
	return name, available, stored, pos + end + 1, nil
}

// gzipData decodes the concatenated gzip members, or a prefix of the decoded
// bytes when prefix is non-negative.
func (a *Archive) gzipData(entry *Entry, prefix int64) ([]byte, error) {
	if entry.Type != EntryFile {
		return nil, fmt.Errorf("%w: entry %d is a %s", ErrUnavailable, entry.Index, entry.Type)
	}
	reader, err := gzip.NewReader(io.NewSectionReader(a.reader, 0, a.size))
	if err != nil {
		return nil, gzipError(err)
	}
	defer reader.Close()

	want := a.limits.EntryDataBytes
	if prefix >= 0 {
		want = prefix
	} else {
		want++
	}
	buf, err := io.ReadAll(io.LimitReader(reader, want))
	if err != nil {
		return nil, gzipError(err)
	}
	if int64(len(buf)) > a.limits.EntryDataBytes {
		return nil, fmt.Errorf("%w: entry %d decoded size exceeds limit %d",
			ErrLimit, entry.Index, a.limits.EntryDataBytes)
	}
	return buf, nil
}

// gzipError classifies a gzip reader error.
func gzipError(err error) error {
	var corrupt flate.CorruptInputError
	switch {
	case errors.Is(err, gzip.ErrHeader):
		return fmt.Errorf("%w: gzip header is invalid", ErrInvalid)
	case errors.Is(err, gzip.ErrChecksum):
		return fmt.Errorf("%w: gzip CRC-32 or size does not match the data", ErrInvalid)
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return fmt.Errorf("%w: gzip stream ended early", ErrTruncated)
	case errors.As(err, &corrupt):
		return fmt.Errorf("%w: gzip DEFLATE stream is corrupt: %w", ErrInvalid, err)
	default:
		return fmt.Errorf("%w: gzip read failed: %w", ErrRead, err)
	}
}
