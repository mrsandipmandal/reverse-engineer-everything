package archive

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
)

// eocdCentral returns the central directory offset of a fixture ZIP.
func eocdCentral(t testing.TB, data []byte) int {
	t.Helper()
	offset := bytes.LastIndex(data, []byte("PK\x05\x06"))
	if offset < 0 {
		t.Fatal("end of central directory record not found")
	}
	return int(binary.LittleEndian.Uint32(data[offset+16:]))
}

// patch returns a copy of data with value written at offset.
func patch(data []byte, offset int, value []byte) []byte {
	out := append([]byte(nil), data...)
	copy(out[offset:], value)
	return out
}

func TestObserveTruncatedArtifact(t *testing.T) {
	full := buildTar(t, []tarFixture{{name: "big", data: make([]byte, 2048)}})
	record, payload := observe(t, full[:600], Options{})
	if !payload.Artifact.Truncated {
		t.Fatalf("artifact is not truncated: %#v", payload.Artifact)
	}
	if len(payload.Artifact.Limitations) == 0 {
		t.Fatalf("artifact limitations = %v", payload.Artifact.Limitations)
	}
	if !hasLimitation(record.Limitations, "artifact inventory is partial") {
		t.Fatalf("limitations = %v", record.Limitations)
	}
	if record.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %v", record.Coverage)
	}
}

func TestObserveNestedPrefixFailure(t *testing.T) {
	inner := nestedZIP(t, "a.txt", "a")
	data := buildZIP(t, []zipFixture{{name: "inner.zip", data: inner}})
	central := eocdCentral(t, data)
	data = patch(data, central+20, []byte{0x00, 0x00, 0x10, 0x00})
	record, payload := observe(t, data, Options{})
	if payload.Entries[0].Nested != nil {
		t.Fatalf("nested = %#v", payload.Entries[0].Nested)
	}
	if !hasLimitation(record.Limitations, "nested detection skipped: truncated") {
		t.Fatalf("limitations = %v", record.Limitations)
	}
}

func TestObserveNestedReadFailure(t *testing.T) {
	inner := nestedZIP(t, "a.txt", "a")
	data := buildZIP(t, []zipFixture{{name: "inner.zip", data: inner}})
	central := eocdCentral(t, data)
	data = patch(data, central+16, []byte{1, 0, 0, 0})
	record, payload := observe(t, data, Options{})
	nested := payload.Entries[0].Nested
	if nested == nil || nested.Status != "invalid" {
		t.Fatalf("nested = %#v", nested)
	}
	if !hasLimitation(record.Limitations, "nested zip is unavailable: invalid") {
		t.Fatalf("limitations = %v", record.Limitations)
	}
}

func TestObserveNestedDecodedBudget(t *testing.T) {
	inner := buildGzip(t, "inner.gz", "", incompressible(1_200_000))
	data := buildGzip(t, "outer.gz", "", inner)
	record, payload := observe(t, data, Options{NestedBytes: MinNestedBytes})
	nested := payload.Entries[0].Nested
	if nested == nil || nested.Status != "limit" {
		t.Fatalf("nested = %#v", nested)
	}
	if !hasLimitation(record.Limitations, "nested member exceeds the nested byte budget") {
		t.Fatalf("limitations = %v", record.Limitations)
	}
}

func TestObserveNestedTruncated(t *testing.T) {
	inner := buildTar(t, []tarFixture{{name: "big", data: make([]byte, 2048)}})
	data := buildTar(t, []tarFixture{{name: "inner.tar", data: inner[:600]}})
	record, payload := observe(t, data, Options{})
	nested := payload.Entries[0].Nested
	if nested == nil || !nested.Truncated {
		t.Fatalf("nested = %#v", nested)
	}
	if len(nested.Limitations) == 0 {
		t.Fatalf("nested limitations = %v", nested.Limitations)
	}
	if !hasLimitation(record.Limitations, "nested inventory is partial") {
		t.Fatalf("limitations = %v", record.Limitations)
	}
}

func TestObserveNestedEntryBudget(t *testing.T) {
	fixtures := make([]zipFixture, 0, 30)
	for i := 0; i < 30; i++ {
		fixtures = append(fixtures, zipFixture{
			name: "nested-entry-with-a-long-name-" + string(rune('a'+i)) + ".txt",
			data: bytes.Repeat([]byte("x"), 32),
		})
	}
	inner := buildZIP(t, fixtures)
	data := buildTar(t, []tarFixture{{name: "many.zip", data: inner}})
	record, payload := observe(t, data, Options{PayloadBytes: MinPayloadBytes})
	nested := payload.Entries[0].Nested
	if nested == nil {
		t.Fatal("nested container missing")
	}
	if nested.LoadedEntryCount >= nested.EntryCount {
		t.Fatalf("nested entries were not abridged: %#v", nested)
	}
	if !hasLimitation(record.Limitations, "payload budget omits nested entries") {
		t.Fatalf("limitations = %v", record.Limitations)
	}
}

func TestObserveGzipModified(t *testing.T) {
	data := buildGzip(t, "stamp.txt", "", []byte("x"))
	binary.LittleEndian.PutUint32(data[4:], 1700000000)
	_, payload := observe(t, data, Options{})
	header := payload.Artifact.GZIP
	if header == nil || header.ModifiedUnix == nil || *header.ModifiedUnix != "1700000000" {
		t.Fatalf("header = %#v", header)
	}
}

// incompressible returns deterministic bytes that DEFLATE cannot shrink.
func incompressible(n int) []byte {
	out := make([]byte, n)
	state := uint32(0x9e3779b9)
	for i := range out {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		out[i] = byte(state)
	}
	return out
}
