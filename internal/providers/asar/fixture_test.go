package asar

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// headerFixedBytes mirrors the reader's fixed header.
const headerFixedBytes = 16

// buildASAR builds an artifact from a JSON directory and data section.
func buildASAR(t testing.TB, directory string, data []byte) []byte {
	t.Helper()
	raw := []byte(directory)
	aligned := (len(raw) + 3) / 4 * 4
	var buf bytes.Buffer
	var fixed [headerFixedBytes]byte
	order := binary.LittleEndian
	order.PutUint32(fixed[0:], 4)
	order.PutUint32(fixed[4:], uint32(8+aligned))
	order.PutUint32(fixed[8:], uint32(aligned))
	order.PutUint32(fixed[12:], uint32(len(raw)))
	buf.Write(fixed[:])
	buf.Write(raw)
	buf.Write(make([]byte, aligned-len(raw)))
	buf.Write(data)
	return buf.Bytes()
}

// manyFiles builds a directory with count one-byte files.
func manyFiles(count int) string {
	var builder strings.Builder
	builder.WriteString(`{"files":{`)
	for i := 0; i < count; i++ {
		if i > 0 {
			builder.WriteByte(',')
		}
		fmt.Fprintf(&builder, `"file-%03d.txt":{"size":1,"offset":"0"}`, i)
	}
	builder.WriteString(`}}`)
	return builder.String()
}
