package archive

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"sort"
	"strconv"
	"testing"
	"time"
)

// ZIP methods used by the fixtures.
const (
	fixtureStored     uint16 = 0
	fixtureDeflate    uint16 = 8
	fixtureDescriptor uint16 = 1 << 3
)

// zipEntryFixture describes one entry for buildZIP.
type zipEntryFixture struct {
	name          []byte
	data          []byte
	method        uint16
	flags         uint16
	crc           *uint32
	uncompressed  *uint32
	compressed    *uint32
	versionMadeBy uint16
	external      uint32
	extra         []byte
	localName     []byte
	localExtra    []byte
	diskStart     uint16
}

// buildZIP builds a ZIP archive with a central directory and end record.
func buildZIP(t testing.TB, entries []zipEntryFixture) []byte {
	t.Helper()
	var body bytes.Buffer
	central := make([]byte, 0, 64*len(entries))
	for _, entry := range entries {
		payload := entry.data
		if entry.method == fixtureDeflate {
			payload = deflateBytes(t, entry.data)
		}
		crc := crc32.ChecksumIEEE(entry.data)
		if entry.crc != nil {
			crc = *entry.crc
		}
		uncompressed := uint32(len(entry.data))
		if entry.uncompressed != nil {
			uncompressed = *entry.uncompressed
		}
		compressed := uint32(len(payload))
		if entry.compressed != nil {
			compressed = *entry.compressed
		}
		localName := entry.name
		if entry.localName != nil {
			localName = entry.localName
		}
		localExtra := entry.extra
		if entry.localExtra != nil {
			localExtra = entry.localExtra
		}
		offset := uint32(body.Len())

		local := make([]byte, zipLocalSize)
		order := binary.LittleEndian
		order.PutUint32(local[0:], zipLocalSignature)
		order.PutUint16(local[4:], 20)
		order.PutUint16(local[6:], entry.flags)
		order.PutUint16(local[8:], entry.method)
		order.PutUint16(local[10:], 0)
		order.PutUint16(local[12:], 0x21) // 1980-01-01
		if entry.flags&fixtureDescriptor == 0 {
			order.PutUint32(local[14:], crc)
			order.PutUint32(local[18:], compressed)
			order.PutUint32(local[22:], uncompressed)
		}
		order.PutUint16(local[26:], uint16(len(localName)))
		order.PutUint16(local[28:], uint16(len(localExtra)))
		body.Write(local)
		body.Write(localName)
		body.Write(localExtra)
		body.Write(payload)
		if entry.flags&fixtureDescriptor != 0 {
			var descriptor [16]byte
			order.PutUint32(descriptor[0:], 0x08074b50)
			order.PutUint32(descriptor[4:], crc)
			order.PutUint32(descriptor[8:], compressed)
			order.PutUint32(descriptor[12:], uncompressed)
			body.Write(descriptor[:])
		}

		central = append(central, buildZIPCentral(entry, crc, compressed, uncompressed, offset)...)
	}

	cdOffset := uint32(body.Len())
	body.Write(central)
	var eocd [zipEOCDSize]byte
	order := binary.LittleEndian
	order.PutUint32(eocd[0:], zipEOCDSignature)
	order.PutUint16(eocd[8:], uint16(len(entries)))
	order.PutUint16(eocd[10:], uint16(len(entries)))
	order.PutUint32(eocd[12:], uint32(len(central)))
	order.PutUint32(eocd[16:], cdOffset)
	body.Write(eocd[:])
	return body.Bytes()
}

func buildZIPCentral(entry zipEntryFixture, crc, compressed, uncompressed, offset uint32) []byte {
	order := binary.LittleEndian
	name := entry.name
	record := make([]byte, zipCentralSize, zipCentralSize+len(name)+len(entry.extra))
	order.PutUint32(record[0:], zipCentralSignature)
	order.PutUint16(record[4:], entry.versionMadeBy)
	order.PutUint16(record[6:], 20)
	order.PutUint16(record[8:], entry.flags)
	order.PutUint16(record[10:], entry.method)
	order.PutUint16(record[12:], 0)
	order.PutUint16(record[14:], 0x21)
	order.PutUint32(record[16:], crc)
	order.PutUint32(record[20:], compressed)
	order.PutUint32(record[24:], uncompressed)
	order.PutUint16(record[28:], uint16(len(name)))
	order.PutUint16(record[30:], uint16(len(entry.extra)))
	order.PutUint16(record[34:], entry.diskStart)
	order.PutUint32(record[38:], entry.external)
	order.PutUint32(record[42:], offset)
	record = append(record, name...)
	record = append(record, entry.extra...)
	return record
}

func deflateBytes(t testing.TB, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

// buildZIP64 builds a ZIP64 archive with saturated base records and a ZIP64
// extra field on the single entry.
func buildZIP64(t testing.TB, name, data []byte) []byte {
	t.Helper()
	var body bytes.Buffer
	order := binary.LittleEndian
	offset := uint32(0)
	payload := deflateBytes(t, data)
	crc := crc32.ChecksumIEEE(data)

	local := make([]byte, zipLocalSize)
	order.PutUint32(local[0:], zipLocalSignature)
	order.PutUint16(local[4:], 45)
	order.PutUint16(local[8:], fixtureDeflate)
	order.PutUint16(local[12:], 0x21)
	order.PutUint32(local[14:], crc)
	order.PutUint32(local[18:], uint32(len(payload)))
	order.PutUint32(local[22:], uint32(len(data)))
	order.PutUint16(local[26:], uint16(len(name)))
	body.Write(local)
	body.Write(name)
	body.Write(payload)

	extra := make([]byte, 4+8+8+8)
	order.PutUint16(extra[0:], zip64ExtraID)
	order.PutUint16(extra[2:], 24)
	order.PutUint64(extra[4:], uint64(len(data)))
	order.PutUint64(extra[12:], uint64(len(payload)))
	order.PutUint64(extra[20:], uint64(offset))

	central := make([]byte, zipCentralSize, zipCentralSize+len(name)+len(extra))
	order.PutUint32(central[0:], zipCentralSignature)
	order.PutUint16(central[4:], 45)
	order.PutUint16(central[6:], 45)
	order.PutUint16(central[10:], fixtureDeflate)
	order.PutUint32(central[16:], crc)
	order.PutUint32(central[20:], zipMaxUint32)
	order.PutUint32(central[24:], zipMaxUint32)
	order.PutUint16(central[28:], uint16(len(name)))
	order.PutUint16(central[30:], uint16(len(extra)))
	order.PutUint32(central[42:], zipMaxUint32)
	central = append(central, name...)
	central = append(central, extra...)

	cdOffset := uint32(body.Len())
	body.Write(central)
	cdSize := uint32(len(central))

	var record [zipEOCD64Size]byte
	order.PutUint32(record[0:], zipEOCD64Signature)
	order.PutUint64(record[4:], zipEOCD64Size-12)
	order.PutUint16(record[12:], 45)
	order.PutUint16(record[14:], 45)
	order.PutUint64(record[24:], 1)
	order.PutUint64(record[32:], 1)
	order.PutUint64(record[40:], uint64(cdSize))
	order.PutUint64(record[48:], uint64(cdOffset))
	body.Write(record[:])

	var locator [zipLocatorSize]byte
	order.PutUint32(locator[0:], zipEOCD64LocatorSignature)
	order.PutUint32(locator[4:], 0)
	order.PutUint64(locator[8:], uint64(cdOffset)+uint64(cdSize))
	order.PutUint32(locator[16:], 1)
	body.Write(locator[:])

	var eocd [zipEOCDSize]byte
	order.PutUint32(eocd[0:], zipEOCDSignature)
	order.PutUint16(eocd[8:], zipMaxUint16)
	order.PutUint16(eocd[10:], zipMaxUint16)
	order.PutUint32(eocd[12:], zipMaxUint32)
	order.PutUint32(eocd[16:], zipMaxUint32)
	body.Write(eocd[:])
	return body.Bytes()
}

// tarEntryFixture describes one entry for buildTar.
type tarEntryFixture struct {
	name        string
	prefix      string
	data        []byte
	typeflag    byte
	mode        int64
	mtime       int64
	linkname    string
	size        *int64
	badChecksum bool
	base256     bool
	badSize     bool
}

// buildTar builds a tar archive with two zero blocks at the end.
func buildTar(t testing.TB, entries []tarEntryFixture) []byte {
	t.Helper()
	var body bytes.Buffer
	for _, entry := range entries {
		body.Write(buildTarHeader(t, entry))
		body.Write(entry.data)
		if padding := (tarBlockSize - len(entry.data)%tarBlockSize) % tarBlockSize; padding > 0 {
			body.Write(make([]byte, padding))
		}
	}
	body.Write(make([]byte, 2*tarBlockSize))
	return body.Bytes()
}

func buildTarHeader(t testing.TB, entry tarEntryFixture) []byte {
	t.Helper()
	block := make([]byte, tarBlockSize)
	copy(block[0:tarNameSize], entry.name)
	copy(block[tarPrefixStart:tarPrefixEnd], entry.prefix)
	putTarOctal(block[100:108], entry.mode)
	size := int64(len(entry.data))
	if entry.size != nil {
		size = *entry.size
	}
	switch {
	case entry.badSize:
		copy(block[124:136], "0000000000x\x00")
	case entry.base256:
		putTarBase256(block[124:136], size)
	default:
		putTarOctal(block[124:136], size)
	}
	putTarOctal(block[136:148], entry.mtime)
	copy(block[257:263], "ustar\x00")
	copy(block[263:265], "00")
	if entry.typeflag != 0 {
		block[tarTypeOffset] = entry.typeflag
	}
	copy(block[157:257], entry.linkname)
	for i := tarChecksumStart; i < tarChecksumEnd; i++ {
		block[i] = ' '
	}
	var sum int64
	for _, b := range block {
		sum += int64(b)
	}
	if entry.badChecksum {
		sum++
	}
	putTarOctal(block[148:156], sum)
	return block
}

func putTarOctal(field []byte, value int64) {
	formatted := fmt.Sprintf("%0*o", len(field)-1, value)
	copy(field, formatted)
	field[len(field)-1] = 0
}

func putTarBase256(field []byte, value int64) {
	for i := len(field) - 1; i >= 0; i-- {
		field[i] = byte(value)
		value >>= 8
	}
	field[0] |= 0x80
}

// paxRecords encodes PAX extended header records.
func paxRecords(t testing.TB, values map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := values[key]
		record := fmt.Sprintf("%s=%s\n", key, value)
		length := len(record) + 2
		for {
			next := len(strconv.Itoa(length)) + 1 + len(record)
			if next == length {
				break
			}
			length = next
		}
		fmt.Fprintf(&buf, "%d %s", length, record)
	}
	return buf.Bytes()
}

// gzipMember describes one member for buildGzip.
type gzipMember struct {
	data    []byte
	name    string
	comment string
	extra   []byte
	mtime   int64
}

// buildGzip builds a concatenated gzip stream.
func buildGzip(t testing.TB, members ...gzipMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, member := range members {
		writer := gzip.NewWriter(&buf)
		writer.Name = member.name
		writer.Comment = member.comment
		writer.Extra = member.extra
		writer.OS = 255
		if member.mtime != 0 {
			writer.ModTime = time.Unix(member.mtime, 0)
		}
		if _, err := writer.Write(member.data); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
	}
	return buf.Bytes()
}
