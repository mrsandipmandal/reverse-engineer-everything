package plist

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
	"unicode/utf16"
)

// buildBinary assembles a binary plist from pre-encoded objects.
func buildBinary(t testing.TB, objects [][]byte) []byte {
	t.Helper()
	var body bytes.Buffer
	body.WriteString("bplist00")
	offsets := make([]int, len(objects))
	for i, object := range objects {
		offsets[i] = body.Len()
		body.Write(object)
	}
	tableOffset := body.Len()
	for _, offset := range offsets {
		if offset > math.MaxUint16 {
			t.Fatalf("fixture offset %d does not fit two bytes", offset)
		}
		var field [2]byte
		binary.BigEndian.PutUint16(field[:], uint16(offset))
		body.Write(field[:])
	}
	var trailer [32]byte
	trailer[6] = 2
	trailer[7] = 1
	binary.BigEndian.PutUint64(trailer[8:], uint64(len(objects)))
	binary.BigEndian.PutUint64(trailer[16:], 0)
	binary.BigEndian.PutUint64(trailer[24:], uint64(tableOffset))
	body.Write(trailer[:])
	return body.Bytes()
}

// bint encodes a one-byte integer.
func bint(value byte) []byte { return []byte{0x10, value} }

// blong encodes a 16-byte integer with the low 8 bytes set to value.
func blong(value uint64, high uint64) []byte {
	out := []byte{0x14}
	var field [8]byte
	binary.BigEndian.PutUint64(field[:], high)
	out = append(out, field[:]...)
	binary.BigEndian.PutUint64(field[:], value)
	return append(out, field[:]...)
}

// breal encodes a 64-bit real.
func breal(value float64) []byte {
	out := make([]byte, 0, 9)
	out = append(out, 0x23)
	var field [8]byte
	binary.BigEndian.PutUint64(field[:], math.Float64bits(value))
	return append(out, field[:]...)
}

// bdate encodes a date from Unix seconds.
func bdate(unix int64) []byte {
	return brealWithMarker(0x33, float64(unix-binaryDateEpoch))
}

func brealWithMarker(marker byte, value float64) []byte {
	out := make([]byte, 0, 9)
	out = append(out, marker)
	var field [8]byte
	binary.BigEndian.PutUint64(field[:], math.Float64bits(value))
	return append(out, field[:]...)
}

// bstr encodes a short ASCII string.
func bstr(text string) []byte {
	if len(text) > 14 {
		out := []byte{0x5F, 0x11}
		var field [2]byte
		binary.BigEndian.PutUint16(field[:], uint16(len(text)))
		out = append(out, field[:]...)
		return append(out, text...)
	}
	return append([]byte{0x50 | byte(len(text))}, text...)
}

// bstrLong encodes a long ASCII string with a count extension.
func bstrLong(text string) []byte {
	out := []byte{0x5F, 0x11}
	var field [2]byte
	binary.BigEndian.PutUint16(field[:], uint16(len(text)))
	out = append(out, field[:]...)
	return append(out, text...)
}

// bdata encodes a data object of n bytes.
func bdata(n int) []byte {
	if n > 14 {
		out := []byte{0x4F, 0x11}
		var field [2]byte
		binary.BigEndian.PutUint16(field[:], uint16(n))
		out = append(out, field[:]...)
		return append(out, make([]byte, n)...)
	}
	return append([]byte{0x40 | byte(n)}, make([]byte, n)...)
}

// barray encodes an array of references.
func barray(refs ...byte) []byte { return append([]byte{0xA0 | byte(len(refs))}, refs...) }

// bdict encodes a dictionary of key and value references.
func bdict(refs ...byte) []byte {
	out := make([]byte, 0, 1+len(refs))
	out = append(out, 0xD0|byte(len(refs)/2))
	return append(out, refs...)
}

// butf16 encodes a UTF-16BE string.
func butf16(text string) []byte {
	units := utf16.Encode([]rune(text))
	out := make([]byte, 0, 1+2*len(units))
	out = append(out, 0x60|byte(len(units)))
	for _, unit := range units {
		var field [2]byte
		binary.BigEndian.PutUint16(field[:], unit)
		out = append(out, field[:]...)
	}
	return out
}

// buid encodes a UID of width bytes.
func buid(value uint64, width int) []byte {
	out := []byte{0x80 | byte(width-1)}
	for i := width - 1; i >= 0; i-- {
		out = append(out, byte(value>>(8*uint(i))))
	}
	return out
}

// xmlDocument wraps values in a plist root.
func xmlDocument(body string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">` + body + `</plist>`
}

// parseBytes parses an in-memory property list with the package limits.
func parseBytes(t testing.TB, data []byte) *Plist {
	t.Helper()
	parsed, err := Parse(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed == nil {
		t.Fatal("Parse returned a nil plist without an error")
	}
	return parsed
}

// parseWith parses an in-memory property list with limits.
func parseWith(t testing.TB, data []byte, limits Limits) (*Plist, error) {
	t.Helper()
	return ParseWithLimits(bytes.NewReader(data), int64(len(data)), limits)
}

// patch returns a copy of data with value written at offset.
func patch(data []byte, offset int, value []byte) []byte {
	out := append([]byte(nil), data...)
	copy(out[offset:], value)
	return out
}
