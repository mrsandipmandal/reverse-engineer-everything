package archive

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"time"
)

// ZIP record signatures and fixed sizes. All ZIP fields are little-endian.
const (
	zipLocalSignature         uint32 = 0x04034b50
	zipCentralSignature       uint32 = 0x02014b50
	zipEOCDSignature          uint32 = 0x06054b50
	zipEOCD64Signature        uint32 = 0x06064b50
	zipEOCD64LocatorSignature uint32 = 0x07064b50

	zipLocalSize   = 30
	zipCentralSize = 46
	zipEOCDSize    = 22
	zipEOCD64Size  = 56
	zipLocatorSize = 20
	zip64ExtraID   = 0x0001
	zipMaxComment  = 0xffff
	zipMaxUint32   = 0xffffffff
	zipMaxUint16   = 0xffff
	zipFlagEncrypt = 1 << 0
)

// zipDirectory is the end-of-central-directory summary.
type zipDirectory struct {
	entries uint64
	offset  int64
	size    int64
}

// parseZIP reads the central directory and inventories its entries.
func parseZIP(r io.ReaderAt, size int64, limits Limits) (*Archive, error) {
	eocd, eocdOffset, err := findEOCD(r, size)
	if err != nil {
		return nil, err
	}
	dir, err := readZIPDirectory(r, size, eocd, eocdOffset)
	if err != nil {
		return nil, err
	}
	archive := &Archive{Container: ContainerZIP, reader: r, size: size, limits: limits}

	declared := dir.entries
	load := declared
	if load > uint64(limits.Entries) {
		load = uint64(limits.Entries)
		archive.Truncated = true
		archive.note("central directory declares %d entries, limit is %d", declared, limits.Entries)
	}
	dirBytes := dir.size
	if dirBytes > limits.DirectoryBytes {
		dirBytes = limits.DirectoryBytes
		archive.Truncated = true
		archive.note("central directory size %d exceeds limit %d", dir.size, limits.DirectoryBytes)
	}
	if dirBytes > 0 {
		buf := make([]byte, dirBytes)
		if err := readAt(r, dir.offset, buf, size); err != nil {
			return nil, err
		}
		pos := 0
		for index := uint64(0); index < load; index++ {
			if len(buf)-pos < zipCentralSize {
				archive.Truncated = true
				archive.note("central directory ended after %d of %d entries", index, declared)
				break
			}
			entry, n, err := decodeZIPCentral(buf[pos:], size, limits, int(index))
			if err != nil {
				if errors.Is(err, ErrTruncated) {
					archive.Truncated = true
					archive.note("central directory ended after %d of %d entries", index, declared)
					break
				}
				return nil, err
			}
			archive.Entries = append(archive.Entries, entry)
			pos += n
		}
	}
	if uint64(len(archive.Entries)) < declared && !archive.Truncated {
		archive.Truncated = true
		archive.note("central directory declares %d entries but %d were read", declared, len(archive.Entries))
	}
	return archive, nil
}

// findEOCD locates the end-of-central-directory record. The record must end at
// the artifact end, including its declared comment, so a signature inside a
// comment is not mistaken for the record.
func findEOCD(r io.ReaderAt, size int64) ([]byte, int64, error) {
	if size < zipEOCDSize {
		return nil, 0, fmt.Errorf("%w: artifact size %d is smaller than the ZIP end record", ErrTruncated, size)
	}
	scan := int64(zipEOCDSize) + zipMaxComment
	if scan > size {
		scan = size
	}
	buf := make([]byte, scan)
	if err := readAt(r, size-scan, buf, size); err != nil {
		return nil, 0, err
	}
	order := binary.LittleEndian
	for i := len(buf) - zipEOCDSize; i >= 0; i-- {
		if order.Uint32(buf[i:]) != zipEOCDSignature {
			continue
		}
		comment := int(order.Uint16(buf[i+20:]))
		if i+zipEOCDSize+comment != len(buf) {
			continue
		}
		return buf[i:], size - scan + int64(i), nil
	}
	return nil, 0, fmt.Errorf("%w: ZIP end of central directory record not found", ErrTruncated)
}

// readZIPDirectory reads the central directory location from the end record,
// including the ZIP64 end record and locator when the base record is saturated.
func readZIPDirectory(r io.ReaderAt, size int64, eocd []byte, eocdOffset int64) (zipDirectory, error) {
	order := binary.LittleEndian
	disk := order.Uint16(eocd[4:])
	cdDisk := order.Uint16(eocd[6:])
	entriesDisk := uint64(order.Uint16(eocd[8:]))
	entries := uint64(order.Uint16(eocd[10:]))
	cdSize := uint64(order.Uint32(eocd[12:]))
	cdOffset := uint64(order.Uint32(eocd[16:]))
	if disk != 0 || cdDisk != 0 {
		return zipDirectory{}, fmt.Errorf("%w: multi-disk ZIP archives are not supported", ErrInvalid)
	}
	// The ZIP64 locator sits between the central directory and this record, so
	// the directory may not reach the base record.
	end := eocdOffset
	zip64 := entries == zipMaxUint16 || cdSize == zipMaxUint32 || cdOffset == zipMaxUint32
	if zip64 {
		var err error
		entries, entriesDisk, cdSize, cdOffset, end, err = readZIP64Directory(r, size, eocdOffset)
		if err != nil {
			return zipDirectory{}, err
		}
	}
	if entriesDisk != entries {
		return zipDirectory{}, fmt.Errorf("%w: central directory entry counts disagree", ErrInvalid)
	}
	if cdOffset > uint64(size) || cdSize > uint64(size)-cdOffset {
		return zipDirectory{}, fmt.Errorf("%w: central directory range %d bytes at offset %d is outside artifact size %d",
			ErrTruncated, cdSize, cdOffset, size)
	}
	if cdOffset+cdSize > uint64(end) {
		return zipDirectory{}, fmt.Errorf("%w: central directory ends beyond the end record", ErrInvalid)
	}
	return zipDirectory{
		entries: entries,
		offset:  int64(cdOffset),
		size:    int64(cdSize),
	}, nil
}

// readZIP64Directory reads the ZIP64 end record and locator.
func readZIP64Directory(r io.ReaderAt, size, eocdOffset int64) (entries, entriesDisk, cdSize, cdOffset uint64, end int64, err error) {
	if eocdOffset < zipLocatorSize {
		return 0, 0, 0, 0, 0, fmt.Errorf("%w: ZIP64 locator does not fit before the end record", ErrTruncated)
	}
	var locator [zipLocatorSize]byte
	if err := readAt(r, eocdOffset-zipLocatorSize, locator[:], size); err != nil {
		return 0, 0, 0, 0, 0, err
	}
	order := binary.LittleEndian
	if order.Uint32(locator[0:]) != zipEOCD64LocatorSignature {
		return 0, 0, 0, 0, 0, fmt.Errorf("%w: ZIP64 locator signature is missing", ErrInvalid)
	}
	if order.Uint32(locator[4:]) != 0 || order.Uint32(locator[16:]) != 1 {
		return 0, 0, 0, 0, 0, fmt.Errorf("%w: multi-disk ZIP archives are not supported", ErrInvalid)
	}
	offset := order.Uint64(locator[8:])
	if offset > uint64(size) || zipEOCD64Size > uint64(size)-offset {
		return 0, 0, 0, 0, 0, fmt.Errorf("%w: ZIP64 end record at offset %d is outside artifact size %d",
			ErrTruncated, offset, size)
	}
	var record [zipEOCD64Size]byte
	if err := readAt(r, int64(offset), record[:], size); err != nil {
		return 0, 0, 0, 0, 0, err
	}
	if order.Uint32(record[0:]) != zipEOCD64Signature {
		return 0, 0, 0, 0, 0, fmt.Errorf("%w: ZIP64 end record signature is missing", ErrInvalid)
	}
	recordSize := order.Uint64(record[4:])
	if recordSize < zipEOCD64Size-12 {
		return 0, 0, 0, 0, 0, fmt.Errorf("%w: ZIP64 end record size %d is too small", ErrInvalid, recordSize)
	}
	if offset+12+recordSize != uint64(eocdOffset-zipLocatorSize) {
		return 0, 0, 0, 0, 0, fmt.Errorf("%w: ZIP64 end record does not end at its locator", ErrInvalid)
	}
	if order.Uint32(record[16:]) != 0 || order.Uint32(record[20:]) != 0 {
		return 0, 0, 0, 0, 0, fmt.Errorf("%w: multi-disk ZIP archives are not supported", ErrInvalid)
	}
	entriesDisk = order.Uint64(record[24:])
	entries = order.Uint64(record[32:])
	cdSize = order.Uint64(record[40:])
	cdOffset = order.Uint64(record[48:])
	return entries, entriesDisk, cdSize, cdOffset, int64(offset), nil
}

// decodeZIPCentral decodes one central directory record and returns it with the
// number of bytes consumed.
func decodeZIPCentral(raw []byte, size int64, limits Limits, index int) (Entry, int, error) {
	if len(raw) < zipCentralSize {
		return Entry{}, 0, fmt.Errorf("%w: central directory entry %d is short", ErrTruncated, index)
	}
	order := binary.LittleEndian
	if order.Uint32(raw[0:]) != zipCentralSignature {
		return Entry{}, 0, fmt.Errorf("%w: bad central directory signature at entry %d", ErrInvalid, index)
	}
	nameLen := int(order.Uint16(raw[28:]))
	extraLen := int(order.Uint16(raw[30:]))
	commentLen := int(order.Uint16(raw[32:]))
	total := zipCentralSize + nameLen + extraLen + commentLen
	if total > len(raw) {
		return Entry{}, 0, fmt.Errorf("%w: central directory entry %d extends beyond the directory", ErrTruncated, index)
	}
	versionMadeBy := order.Uint16(raw[4:])
	flags := order.Uint16(raw[8:])
	method := Method(order.Uint16(raw[10:]))
	modified, modifiedOK := dosTime(order.Uint16(raw[14:]), order.Uint16(raw[12:]))
	crc := order.Uint32(raw[16:])
	compressed := uint64(order.Uint32(raw[20:]))
	uncompressed := uint64(order.Uint32(raw[24:]))
	diskStart := order.Uint16(raw[34:])
	external := order.Uint32(raw[38:])
	localOffset := order.Uint32(raw[42:])

	nameBytes := raw[zipCentralSize : zipCentralSize+nameLen]
	extra := raw[zipCentralSize+nameLen : zipCentralSize+nameLen+extraLen]
	name, available, unsafe, stored := decodeEntryName(nameBytes, limits.NameBytes)

	entry := Entry{
		Index:                 index,
		Name:                  name,
		NameAvailable:         available,
		NameBytes:             stored,
		NameUnsafe:            unsafe,
		Type:                  EntryFile,
		Method:                method,
		Flags:                 flags,
		Encrypted:             flags&zipFlagEncrypt != 0,
		CRC32:                 crc,
		CRC32Available:        true,
		CompressedSize:        compressed,
		CompressedSizeKnown:   true,
		UncompressedSize:      uncompressed,
		UncompressedSizeKnown: true,
		ModifiedUnix:          modified,
		ModifiedAvailable:     modifiedOK,
		HeaderOffset:          int64(localOffset),
	}

	if extraLen > int(limits.ExtraBytes) {
		entry.Limitations = append(entry.Limitations,
			fmt.Sprintf("extra field of %d bytes exceeds limit %d", extraLen, limits.ExtraBytes))
		if uncompressed == zipMaxUint32 {
			entry.UncompressedSizeKnown = false
		}
		if compressed == zipMaxUint32 {
			entry.CompressedSizeKnown = false
		}
	} else {
		values, malformed := readZIP64Extra(extra, uncompressed == zipMaxUint32,
			compressed == zipMaxUint32, localOffset == zipMaxUint32, diskStart == zipMaxUint16)
		if malformed {
			entry.Limitations = append(entry.Limitations, "ZIP64 extra field is truncated")
		}
		if uncompressed == zipMaxUint32 {
			if values.haveUncompressed {
				entry.UncompressedSize = values.uncompressed
			} else {
				entry.UncompressedSizeKnown = false
				if !malformed {
					entry.Limitations = append(entry.Limitations, "ZIP64 uncompressed size is missing")
				}
			}
		}
		if compressed == zipMaxUint32 {
			if values.haveCompressed {
				entry.CompressedSize = values.compressed
			} else {
				entry.CompressedSizeKnown = false
				if !malformed {
					entry.Limitations = append(entry.Limitations, "ZIP64 compressed size is missing")
				}
			}
		}
		if localOffset == zipMaxUint32 {
			if values.haveOffset {
				entry.HeaderOffset = int64(values.offset)
			} else {
				if !malformed {
					entry.Limitations = append(entry.Limitations, "ZIP64 local header offset is missing")
				}
				entry.Limitations = append(entry.Limitations, "local header is outside the artifact")
			}
		}
		if values.haveDisk && values.disk != 0 {
			entry.Limitations = append(entry.Limitations,
				fmt.Sprintf("entry is on disk %d of a split archive", values.disk))
			entry.CompressedSizeKnown = false
			entry.UncompressedSizeKnown = false
		}
	}

	if versionMadeBy>>8 == 3 {
		mode := external >> 16
		entry.Mode = mode
		entry.ModeAvailable = true
		switch mode & 0xf000 {
		case 0x4000:
			entry.Type = EntryDirectory
		case 0xa000:
			entry.Type = EntrySymlink
		case 0x2000:
			entry.Type = EntryCharacterDevice
		case 0x6000:
			entry.Type = EntryBlockDevice
		case 0x1000:
			entry.Type = EntryFIFO
		}
	}
	if strings.HasSuffix(string(nameBytes), "/") {
		entry.Type = EntryDirectory
	}
	if entry.HeaderOffset < 0 || entry.HeaderOffset > size-zipLocalSize {
		entry.Limitations = append(entry.Limitations,
			"local header is outside the artifact")
	}
	return entry, total, nil
}

// zip64Values holds the ZIP64 extra values that were present.
type zip64Values struct {
	uncompressed     uint64
	compressed       uint64
	offset           uint64
	disk             uint32
	haveUncompressed bool
	haveCompressed   bool
	haveOffset       bool
	haveDisk         bool
}

// readZIP64Extra returns the ZIP64 values present in an entry's extra fields
// and reports whether a field block is malformed.
func readZIP64Extra(extra []byte, needUncompressed, needCompressed, needOffset, needDisk bool) (zip64Values, bool) {
	var out zip64Values
	order := binary.LittleEndian
	for pos := 0; pos < len(extra); {
		if len(extra)-pos < 4 {
			return out, true
		}
		id := order.Uint16(extra[pos:])
		length := int(order.Uint16(extra[pos+2:]))
		pos += 4
		if length > len(extra)-pos {
			return out, true
		}
		if id != zip64ExtraID {
			pos += length
			continue
		}
		values := extra[pos : pos+length]
		width := 0
		if needUncompressed {
			width += 8
		}
		if needCompressed {
			width += 8
		}
		if needOffset {
			width += 8
		}
		if needDisk {
			width += 4
		}
		if len(values) < width {
			return out, true
		}
		at := 0
		if needUncompressed {
			out.uncompressed = order.Uint64(values[at:])
			out.haveUncompressed = true
			at += 8
		}
		if needCompressed {
			out.compressed = order.Uint64(values[at:])
			out.haveCompressed = true
			at += 8
		}
		if needOffset {
			out.offset = order.Uint64(values[at:])
			out.haveOffset = true
			at += 8
		}
		if needDisk {
			out.disk = order.Uint32(values[at:])
			out.haveDisk = true
		}
		return out, false
	}
	return out, false
}

// dosTime converts a ZIP DOS date and time to Unix seconds in UTC. It reports
// false for an absent or impossible value.
func dosTime(date, clock uint16) (int64, bool) {
	if date == 0 && clock == 0 {
		return 0, false
	}
	year := int(date>>9) + 1980
	month := int(date>>5) & 0x0f
	day := int(date) & 0x1f
	hour := int(clock>>11) & 0x1f
	minute := int(clock>>5) & 0x3f
	second := int(clock&0x1f) * 2
	if month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59 {
		return 0, false
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
	if t.Year() != year || int(t.Month()) != month || t.Day() != day {
		return 0, false
	}
	return t.Unix(), true
}

// zipData returns the stored bytes of one ZIP entry, or a prefix of them when
// prefix is non-negative. A full read verifies the CRC-32.
func (a *Archive) zipData(entry *Entry, prefix int64) ([]byte, error) {
	if entry.Type != EntryFile && entry.Type != EntryDirectory && entry.Type != EntrySymlink {
		return nil, fmt.Errorf("%w: entry %d is a %s", ErrUnavailable, entry.Index, entry.Type)
	}
	if !entry.CompressedSizeKnown || !entry.UncompressedSizeKnown {
		return nil, fmt.Errorf("%w: entry %d has no usable size", ErrUnavailable, entry.Index)
	}
	if entry.UncompressedSize > uint64(a.limits.EntryDataBytes) {
		return nil, fmt.Errorf("%w: entry %d size %d exceeds limit %d",
			ErrLimit, entry.Index, entry.UncompressedSize, a.limits.EntryDataBytes)
	}
	if entry.UncompressedSize == 0 {
		return []byte{}, nil
	}

	dataOffset, err := a.zipDataOffset(entry)
	if err != nil {
		return nil, err
	}
	if entry.CompressedSize > uint64(a.size-dataOffset) {
		return nil, fmt.Errorf("%w: entry %d compressed range is outside the artifact", ErrTruncated, entry.Index)
	}

	switch entry.Method {
	case MethodStored:
		return a.zipStored(entry, dataOffset, prefix)
	case MethodDeflate:
		return a.zipDeflate(entry, dataOffset, prefix)
	default:
		return nil, fmt.Errorf("%w: entry %d uses compression method %s", ErrUnavailable, entry.Index, entry.Method)
	}
}

// zipDataOffset validates the local header and returns the start of entry data.
func (a *Archive) zipDataOffset(entry *Entry) (int64, error) {
	if entry.HeaderOffset < 0 || entry.HeaderOffset > a.size-zipLocalSize {
		return 0, fmt.Errorf("%w: entry %d local header is outside the artifact", ErrTruncated, entry.Index)
	}
	var local [zipLocalSize]byte
	if err := readAt(a.reader, entry.HeaderOffset, local[:], a.size); err != nil {
		return 0, err
	}
	order := binary.LittleEndian
	if order.Uint32(local[0:]) != zipLocalSignature {
		return 0, fmt.Errorf("%w: entry %d local header signature is missing", ErrInvalid, entry.Index)
	}
	nameLen := int64(order.Uint16(local[26:]))
	extraLen := int64(order.Uint16(local[28:]))
	dataOffset := int64(zipLocalSize) + nameLen + extraLen
	if dataOffset > a.size-entry.HeaderOffset {
		return 0, fmt.Errorf("%w: entry %d local header is outside the artifact", ErrTruncated, entry.Index)
	}
	dataOffset += entry.HeaderOffset

	name := make([]byte, nameLen)
	if err := readAt(a.reader, entry.HeaderOffset+zipLocalSize, name, a.size); err != nil {
		return 0, err
	}
	if !bytes.Equal(name, entry.NameBytes) {
		return 0, fmt.Errorf("%w: entry %d local name differs from the central directory", ErrInvalid, entry.Index)
	}
	return dataOffset, nil
}

// zipStored returns stored bytes, which must be uncompressed.
func (a *Archive) zipStored(entry *Entry, dataOffset, prefix int64) ([]byte, error) {
	if entry.CompressedSize != entry.UncompressedSize {
		return nil, fmt.Errorf("%w: entry %d stored sizes disagree", ErrInvalid, entry.Index)
	}
	want := int64(entry.UncompressedSize)
	full := prefix < 0
	if !full && prefix < want {
		want = prefix
	}
	buf := make([]byte, want)
	if want > 0 {
		if err := readAt(a.reader, dataOffset, buf, a.size); err != nil {
			return nil, err
		}
	}
	if full {
		if err := verifyCRC(entry, buf); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// zipDeflate returns deflated bytes, verifying the declared size and CRC-32 on
// a full read.
func (a *Archive) zipDeflate(entry *Entry, dataOffset, prefix int64) ([]byte, error) {
	section := io.NewSectionReader(a.reader, dataOffset, int64(entry.CompressedSize))
	reader := flate.NewReader(section)
	defer reader.Close()

	full := prefix < 0
	if full {
		limit := int64(entry.UncompressedSize)
		buf, err := io.ReadAll(io.LimitReader(reader, limit+1))
		if err != nil {
			return nil, deflateError(entry.Index, err)
		}
		if int64(len(buf)) > limit {
			return nil, fmt.Errorf("%w: entry %d decompressed size exceeds the declared size", ErrInvalid, entry.Index)
		}
		if int64(len(buf)) != limit {
			return nil, fmt.Errorf("%w: entry %d decompressed size %d does not match declared size %d",
				ErrInvalid, entry.Index, len(buf), limit)
		}
		if err := verifyCRC(entry, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	buf, err := io.ReadAll(io.LimitReader(reader, prefix))
	if err != nil {
		return nil, deflateError(entry.Index, err)
	}
	return buf, nil
}

// deflateError classifies a DEFLATE reader error.
func deflateError(index int, err error) error {
	var corrupt flate.CorruptInputError
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return fmt.Errorf("%w: entry %d DEFLATE stream ended early", ErrTruncated, index)
	case errors.As(err, &corrupt):
		return fmt.Errorf("%w: entry %d DEFLATE stream is corrupt: %w", ErrInvalid, index, err)
	default:
		return fmt.Errorf("%w: entry %d DEFLATE read failed: %w", ErrRead, index, err)
	}
}

// verifyCRC checks an entry's declared CRC-32 against its bytes.
func verifyCRC(entry *Entry, data []byte) error {
	if !entry.CRC32Available {
		return nil
	}
	if crc32.ChecksumIEEE(data) != entry.CRC32 {
		return fmt.Errorf("%w: entry %d CRC-32 mismatch", ErrInvalid, entry.Index)
	}
	return nil
}
