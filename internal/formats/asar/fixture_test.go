package asar

import (
	"bytes"
	"encoding/binary"
	"testing"
)

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

// asarHeaderSize returns the artifact offset where the data section begins.
func asarHeaderSize(directory string) int {
	aligned := (len(directory) + 3) / 4 * 4
	return headerFixedBytes + aligned
}

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

// findPath returns the index of the first entry with a path.
func findPath(t testing.TB, parsed *Archive, path string) int {
	t.Helper()
	for i, entry := range parsed.Entries {
		if entry.Path == path {
			return i
		}
	}
	t.Fatalf("entry %q not found", path)
	return -1
}
