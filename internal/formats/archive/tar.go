package archive

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
)

// tar fixed layout. A tar archive is a chain of 512-byte header blocks, each
// followed by the entry's data padded to a block boundary.
const (
	tarBlockSize     = 512
	tarMagicOffset   = 257
	tarChecksumStart = 148
	tarChecksumEnd   = 156
	tarTypeOffset    = 156
	tarNameSize      = 100
	tarPrefixStart   = 345
	tarPrefixEnd     = 500
)

// Tar type flags.
const (
	tarTypeFile        = '0'
	tarTypeHardlink    = '1'
	tarTypeSymlink     = '2'
	tarTypeCharacter   = '3'
	tarTypeBlock       = '4'
	tarTypeDirectory   = '5'
	tarTypeFIFO        = '6'
	tarTypeContiguous  = '7'
	tarTypePax         = 'x'
	tarTypePaxGlobal   = 'g'
	tarTypeGNULongName = 'L'
	tarTypeGNULongLink = 'K'
	tarTypeGNUSparse   = 'S'
)

// paxValues holds the extended attributes that apply to the next entry.
type paxValues struct {
	path     []byte
	linkpath []byte
	size     int64
	havePath bool
	haveLink bool
	haveSize bool
}

// parseTar walks the header chain and inventories each entry.
func parseTar(r io.ReaderAt, size int64, limits Limits) (*Archive, error) {
	archive := &Archive{Container: ContainerTar, reader: r, size: size, limits: limits}
	offset := int64(0)
	headers := 0
	var pending paxValues
	var longName, longLink []byte
	notedGlobalPax := false

	for offset < size {
		if headers >= limits.Entries {
			archive.Truncated = true
			archive.note("tar header count reached limit %d at offset %d", limits.Entries, offset)
			break
		}
		var block [tarBlockSize]byte
		if err := readAt(r, offset, block[:], size); err != nil {
			if errors.Is(err, ErrTruncated) {
				archive.Truncated = true
				archive.note("tar header at offset %d extends beyond the artifact", offset)
				break
			}
			return nil, err
		}
		if isZeroBlock(block[:]) {
			break
		}
		if !tarChecksumValid(block[:]) {
			return nil, fmt.Errorf("%w: tar header checksum at offset %d is invalid", ErrInvalid, offset)
		}
		headers++

		declaredSize, sizeOK := tarNumber(block[124:136])
		if !sizeOK || declaredSize < 0 {
			return nil, fmt.Errorf("%w: tar entry at offset %d has an invalid size field", ErrInvalid, offset)
		}
		next, nextOK := tarNext(offset, declaredSize, size)

		typeflag := block[tarTypeOffset]
		switch typeflag {
		case tarTypePax:
			values, malformed := archive.readPax(offset, declaredSize, limits)
			if malformed {
				archive.note("PAX header at offset %d is malformed", offset)
			}
			if !nextOK {
				archive.Truncated = true
				archive.note("PAX data at offset %d extends beyond the artifact", offset)
				return archive, nil
			}
			pending = mergePax(pending, values)
			offset = next
			continue
		case tarTypePaxGlobal:
			if !notedGlobalPax {
				archive.note("global PAX attributes are not applied")
				notedGlobalPax = true
			}
			if !nextOK {
				archive.Truncated = true
				archive.note("global PAX data at offset %d extends beyond the artifact", offset)
				return archive, nil
			}
			offset = next
			continue
		case tarTypeGNULongName:
			longName = archive.readLongValue(offset, declaredSize, limits)
			if !nextOK {
				archive.Truncated = true
				archive.note("GNU long name at offset %d extends beyond the artifact", offset)
				return archive, nil
			}
			offset = next
			continue
		case tarTypeGNULongLink:
			longLink = archive.readLongValue(offset, declaredSize, limits)
			if !nextOK {
				archive.Truncated = true
				archive.note("GNU long link at offset %d extends beyond the artifact", offset)
				return archive, nil
			}
			offset = next
			continue
		}

		effectiveSize := declaredSize
		if pending.haveSize {
			effectiveSize = pending.size
		}
		next, nextOK = tarNext(offset, effectiveSize, size)

		entry := archive.tarEntry(block[:], offset, typeflag, effectiveSize, pending, longName, longLink)
		pending = paxValues{}
		longName, longLink = nil, nil

		if !nextOK {
			entry.Limitations = append(entry.Limitations, "entry data extends beyond the artifact")
			archive.Entries = append(archive.Entries, entry)
			archive.Truncated = true
			archive.note("tar entry data at offset %d extends beyond the artifact", offset)
			break
		}
		archive.Entries = append(archive.Entries, entry)
		if entry.Sparse {
			archive.Truncated = true
			archive.note("GNU sparse entry at offset %d stops the header chain", offset)
			break
		}
		offset = next
	}
	return archive, nil
}

// tarEntry builds one inventory entry from a validated header block.
func (a *Archive) tarEntry(block []byte, offset int64, typeflag byte, size int64, pax paxValues, longName, longLink []byte) Entry {
	rawName := tarName(block, longName)
	if pax.havePath {
		rawName = pax.path
	}
	name, available, unsafe, stored := decodeEntryName(rawName, a.limits.NameBytes)
	entry := Entry{
		Index:                 len(a.Entries),
		Name:                  name,
		NameAvailable:         available,
		NameBytes:             stored,
		NameUnsafe:            unsafe,
		Type:                  tarEntryType(typeflag),
		Method:                MethodStored,
		CompressedSize:        uint64(size),
		CompressedSizeKnown:   true,
		UncompressedSize:      uint64(size),
		UncompressedSizeKnown: true,
		HeaderOffset:          offset,
		DataOffset:            offset + tarBlockSize,
	}
	if mode, ok := tarNumber(block[100:108]); ok && mode >= 0 && mode <= math.MaxUint32 {
		entry.Mode = uint32(mode)
		entry.ModeAvailable = true
	}
	if modified, ok := tarNumber(block[136:148]); ok {
		entry.ModifiedUnix = modified
		entry.ModifiedAvailable = true
	}

	link := tarString(block[157:257])
	if longLink != nil {
		link = longLink
	}
	if pax.haveLink {
		link = pax.linkpath
	}
	if len(link) > 0 {
		entry.LinkTarget, entry.LinkTargetAvailable, _ = decodeText(link, a.limits.NameBytes)
	}

	switch typeflag {
	case tarTypeGNUSparse:
		entry.Sparse = true
		entry.Limitations = append(entry.Limitations, "GNU sparse layout is not decoded")
	case tarTypeDirectory:
		entry.Type = EntryDirectory
	}
	return entry
}

// tarEntryType maps a tar type flag to the inventory type.
func tarEntryType(typeflag byte) EntryType {
	switch typeflag {
	case 0, tarTypeFile, tarTypeContiguous:
		return EntryFile
	case tarTypeHardlink:
		return EntryHardlink
	case tarTypeSymlink:
		return EntrySymlink
	case tarTypeCharacter:
		return EntryCharacterDevice
	case tarTypeBlock:
		return EntryBlockDevice
	case tarTypeDirectory:
		return EntryDirectory
	case tarTypeFIFO:
		return EntryFIFO
	default:
		return EntryOther
	}
}

// tarName joins the ustar prefix and name fields, or returns the GNU long name
// when one was read.
func tarName(block, longName []byte) []byte {
	if longName != nil {
		return longName
	}
	name := tarString(block[0:tarNameSize])
	if string(block[tarMagicOffset:tarMagicOffset+5]) != "ustar" {
		return name
	}
	prefix := tarString(block[tarPrefixStart:tarPrefixEnd])
	if len(prefix) == 0 {
		return name
	}
	joined := make([]byte, 0, len(prefix)+1+len(name))
	joined = append(joined, prefix...)
	joined = append(joined, '/')
	joined = append(joined, name...)
	return joined
}

// tarString returns a fixed-width field up to its first NUL.
func tarString(field []byte) []byte {
	if index := bytes.IndexByte(field, 0); index >= 0 {
		return field[:index]
	}
	return field
}

// tarChecksumValid reports whether either the unsigned or the signed header
// checksum matches the stored value.
func tarChecksumValid(block []byte) bool {
	declared, ok := tarOctal(block[tarChecksumStart:tarChecksumEnd])
	if !ok {
		return false
	}
	var unsigned, signed int64
	for i, b := range block {
		value := b
		if i >= tarChecksumStart && i < tarChecksumEnd {
			value = ' '
		}
		unsigned += int64(value)
		signed += int64(int8(value))
	}
	return declared == unsigned || declared == signed
}

func isZeroBlock(block []byte) bool {
	for _, b := range block {
		if b != 0 {
			return false
		}
	}
	return true
}

// tarOctal parses an octal checksum or numeric field.
func tarOctal(field []byte) (int64, bool) {
	raw := bytes.TrimRight(field, "\x00 ")
	raw = bytes.TrimLeft(raw, " ")
	if len(raw) == 0 {
		return 0, true
	}
	for _, b := range raw {
		if b < '0' || b > '7' {
			return 0, false
		}
	}
	value, err := strconv.ParseInt(string(raw), 8, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// tarNumber parses an octal or GNU base-256 numeric field. A negative value is
// reported as invalid; no field this package decodes is meaningfully negative.
func tarNumber(field []byte) (int64, bool) {
	if len(field) == 0 {
		return 0, false
	}
	if field[0]&0x80 != 0 {
		if field[0]&0x40 != 0 {
			return 0, false
		}
		var value int64
		for i, b := range field {
			if i == 0 {
				b &= 0x7f
			}
			if value > (math.MaxInt64-int64(b))/256 {
				return 0, false
			}
			value = value*256 + int64(b)
		}
		return value, true
	}
	return tarOctal(field)
}

// tarNext returns the offset after an entry's data, and false when the padded
// data would overflow or extend beyond the artifact.
func tarNext(offset, size, artifact int64) (int64, bool) {
	if offset < 0 || size < 0 || offset > artifact-tarBlockSize {
		return 0, false
	}
	if size > math.MaxInt64-tarBlockSize {
		return 0, false
	}
	padded := (size + tarBlockSize - 1) / tarBlockSize * tarBlockSize
	if padded > artifact-offset-tarBlockSize {
		return 0, false
	}
	return offset + tarBlockSize + padded, true
}

// readPax reads and decodes one PAX extended header. It returns the values it
// could decode and whether a record was malformed.
func (a *Archive) readPax(offset, size int64, limits Limits) (paxValues, bool) {
	var values paxValues
	if size <= 0 || size > limits.PaxBytes {
		if size > limits.PaxBytes {
			a.note("PAX header at offset %d exceeds limit %d", offset, limits.PaxBytes)
			return values, false
		}
		return values, false
	}
	data := make([]byte, size)
	if err := readAt(a.reader, offset+tarBlockSize, data, a.size); err != nil {
		return values, true
	}
	for len(data) > 0 {
		space := bytes.IndexByte(data, ' ')
		if space <= 0 {
			return values, true
		}
		length, err := strconv.Atoi(string(data[:space]))
		if err != nil || length <= space+1 || length > len(data) {
			return values, true
		}
		record := data[space+1 : length]
		if len(record) == 0 || record[len(record)-1] != '\n' {
			return values, true
		}
		record = record[:len(record)-1]
		equals := bytes.IndexByte(record, '=')
		if equals <= 0 {
			return values, true
		}
		key, value := string(record[:equals]), record[equals+1:]
		switch key {
		case "path":
			values.path = append([]byte(nil), value...)
			values.havePath = true
		case "linkpath":
			values.linkpath = append([]byte(nil), value...)
			values.haveLink = true
		case "size":
			parsed, err := strconv.ParseInt(string(value), 10, 64)
			if err != nil || parsed < 0 {
				return values, true
			}
			values.size = parsed
			values.haveSize = true
		}
		data = data[length:]
	}
	return values, false
}

// mergePax applies a new PAX block to the values pending for the next entry.
func mergePax(current, next paxValues) paxValues {
	if next.havePath {
		current.path = next.path
		current.havePath = true
	}
	if next.haveLink {
		current.linkpath = next.linkpath
		current.haveLink = true
	}
	if next.haveSize {
		current.size = next.size
		current.haveSize = true
	}
	return current
}

// readLongValue reads a GNU long name or long link payload.
func (a *Archive) readLongValue(offset, size int64, limits Limits) []byte {
	if size <= 0 {
		return nil
	}
	if size > int64(limits.NameBytes) {
		a.note("GNU long name at offset %d exceeds limit %d", offset, limits.NameBytes)
		return nil
	}
	data := make([]byte, size)
	if err := readAt(a.reader, offset+tarBlockSize, data, a.size); err != nil {
		a.note("GNU long name at offset %d is unavailable", offset)
		return nil
	}
	return bytes.TrimRight(data, "\x00")
}

// tarData returns an entry's stored bytes, or a prefix of them when prefix is
// non-negative. Tar entry data is never compressed.
func (a *Archive) tarData(entry *Entry, prefix int64) ([]byte, error) {
	if entry.Type != EntryFile {
		return nil, fmt.Errorf("%w: entry %d is a %s", ErrUnavailable, entry.Index, entry.Type)
	}
	if !entry.UncompressedSizeKnown {
		return nil, fmt.Errorf("%w: entry %d has no usable size", ErrUnavailable, entry.Index)
	}
	want := int64(entry.UncompressedSize)
	if prefix >= 0 && prefix < want {
		want = prefix
	}
	buf := make([]byte, want)
	if want > 0 {
		if err := readAt(a.reader, entry.DataOffset, buf, a.size); err != nil {
			return nil, err
		}
	}
	return buf, nil
}
