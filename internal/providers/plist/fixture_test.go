package plist

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"
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
		var field [2]byte
		binary.BigEndian.PutUint16(field[:], uint16(offset))
		body.Write(field[:])
	}
	var trailer [32]byte
	trailer[6] = 2
	trailer[7] = 1
	binary.BigEndian.PutUint64(trailer[8:], uint64(len(objects)))
	binary.BigEndian.PutUint64(trailer[24:], uint64(tableOffset))
	body.Write(trailer[:])
	return body.Bytes()
}

// bstr encodes a short ASCII string.
func bstr(text string) []byte {
	return append([]byte{0x50 | byte(len(text))}, text...)
}

// bint encodes a one-byte integer.
func bint(value byte) []byte { return []byte{0x10, value} }

// bdict encodes a dictionary of key and value references.
func bdict(refs ...byte) []byte {
	out := make([]byte, 0, 1+len(refs))
	out = append(out, 0xD0|byte(len(refs)/2))
	return append(out, refs...)
}

// barray encodes an array of references.
func barray(refs ...byte) []byte {
	out := make([]byte, 0, 1+len(refs))
	out = append(out, 0xA0|byte(len(refs)))
	return append(out, refs...)
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
	out := make([]byte, 9)
	out[0] = 0x33
	binary.BigEndian.PutUint64(out[1:], math.Float64bits(float64(unix-978307200)))
	return out
}

// bdata encodes a data object of n bytes.
func bdata(n int) []byte {
	return append([]byte{0x40 | byte(n)}, make([]byte, n)...)
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
<plist version="1.0">` + body + `</plist>`
}

// manyStrings builds an array of count string values.
func manyStrings(count int) string {
	var builder strings.Builder
	builder.WriteString("<array>")
	for i := 0; i < count; i++ {
		fmt.Fprintf(&builder, "<string>value-%03d-padding</string>", i)
	}
	builder.WriteString("</array>")
	return xmlDocument(builder.String())
}
