package archive

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"testing"
)

// ZIP layout constants for the fixtures.
const (
	fixtureZIPLocal        = 30
	fixtureZIPCentral      = 46
	fixtureZIPEOCD         = 22
	fixtureZIPMagic        = 0x04034b50
	fixtureZIPCentralMagic = 0x02014b50
	fixtureZIPEOCDMagic    = 0x06054b50
)

// zipFixture describes one entry for buildZIP.
type zipFixture struct {
	name    string
	data    []byte
	deflate bool
}

// buildZIP builds a ZIP archive with one central directory record per entry.
func buildZIP(t testing.TB, entries []zipFixture) []byte {
	t.Helper()
	order := binary.LittleEndian
	var body bytes.Buffer
	central := make([]byte, 0, fixtureZIPCentral*len(entries))
	for _, entry := range entries {
		payload := entry.data
		method := uint16(0)
		if entry.deflate {
			method = 8
			payload = deflateBytes(t, entry.data)
		}
		crc := crc32.ChecksumIEEE(entry.data)
		offset := uint32(body.Len())

		local := make([]byte, fixtureZIPLocal)
		order.PutUint32(local[0:], fixtureZIPMagic)
		order.PutUint16(local[4:], 20)
		order.PutUint16(local[8:], method)
		order.PutUint16(local[12:], 0x21)
		order.PutUint32(local[14:], crc)
		order.PutUint32(local[18:], uint32(len(payload)))
		order.PutUint32(local[22:], uint32(len(entry.data)))
		order.PutUint16(local[26:], uint16(len(entry.name)))
		body.Write(local)
		body.WriteString(entry.name)
		body.Write(payload)

		record := make([]byte, fixtureZIPCentral, fixtureZIPCentral+len(entry.name))
		order.PutUint32(record[0:], fixtureZIPCentralMagic)
		order.PutUint16(record[4:], 20)
		order.PutUint16(record[6:], 20)
		order.PutUint16(record[10:], method)
		order.PutUint16(record[14:], 0x21)
		order.PutUint32(record[16:], crc)
		order.PutUint32(record[20:], uint32(len(payload)))
		order.PutUint32(record[24:], uint32(len(entry.data)))
		order.PutUint16(record[28:], uint16(len(entry.name)))
		order.PutUint32(record[42:], offset)
		record = append(record, entry.name...)
		central = append(central, record...)
	}

	cdOffset := uint32(body.Len())
	body.Write(central)
	eocd := make([]byte, fixtureZIPEOCD)
	order.PutUint32(eocd[0:], fixtureZIPEOCDMagic)
	order.PutUint16(eocd[8:], uint16(len(entries)))
	order.PutUint16(eocd[10:], uint16(len(entries)))
	order.PutUint32(eocd[12:], uint32(len(central)))
	order.PutUint32(eocd[16:], cdOffset)
	body.Write(eocd)
	return body.Bytes()
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

// tarFixture describes one entry for buildTar.
type tarFixture struct {
	name     string
	data     []byte
	typeflag byte
	link     string
	mode     int64
}

// buildTar builds a ustar archive with two trailing zero blocks.
func buildTar(t testing.TB, entries []tarFixture) []byte {
	t.Helper()
	var body bytes.Buffer
	for _, entry := range entries {
		block := make([]byte, 512)
		copy(block[0:100], entry.name)
		mode := entry.mode
		if mode == 0 {
			mode = 0o644
		}
		putOctal(block[100:108], mode)
		putOctal(block[124:136], int64(len(entry.data)))
		putOctal(block[136:148], 1700000000)
		copy(block[257:263], "ustar\x00")
		copy(block[263:265], "00")
		if entry.typeflag != 0 {
			block[156] = entry.typeflag
		}
		copy(block[157:257], entry.link)
		for i := 148; i < 156; i++ {
			block[i] = ' '
		}
		var sum int64
		for _, b := range block {
			sum += int64(b)
		}
		putOctal(block[148:156], sum)
		body.Write(block)
		body.Write(entry.data)
		if padding := (512 - len(entry.data)%512) % 512; padding > 0 {
			body.Write(make([]byte, padding))
		}
	}
	body.Write(make([]byte, 1024))
	return body.Bytes()
}

func putOctal(field []byte, value int64) {
	formatted := fmt.Sprintf("%0*o", len(field)-1, value)
	copy(field, formatted)
	field[len(field)-1] = 0
}

// buildGzip builds one gzip member with the optional header fields.
func buildGzip(t testing.TB, name, comment string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	writer.Name = name
	writer.Comment = comment
	writer.OS = 3
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// nestedZIP returns a ZIP archive that contains one stored file.
func nestedZIP(t testing.TB, name, data string) []byte {
	t.Helper()
	return buildZIP(t, []zipFixture{{name: name, data: []byte(data)}})
}
