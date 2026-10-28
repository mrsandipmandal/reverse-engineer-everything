package asar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	reasar "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/asar"
)

const inventoryJSON = `{"files":{
	"a.txt":{"size":5,"offset":"0"},
	"dir":{"files":{"b.txt":{"size":6,"offset":"5"}}},
	"link":{"link":"a.txt"},
	"out":{"size":4,"offset":"0","unpacked":true},
	"packed":{"size":0,"offset":"11","executable":true,"integrity":{"algorithm":"SHA256","hash":"ABCD","blocks":[{"offset":"0","size":4}]}}
}}`

func observeBytes(t testing.TB, data []byte, opts Options) evidence.Evidence {
	t.Helper()
	if opts.ProviderVersion == "" {
		opts.ProviderVersion = "0.1.0"
	}
	record, err := Observe(bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	return record
}

func decodePayload(t testing.TB, record evidence.Evidence) Payload {
	t.Helper()
	var payload Payload
	if err := json.Unmarshal(record.Payload, &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	return payload
}

func TestObserveInventory(t *testing.T) {
	data := buildASAR(t, inventoryJSON, []byte("helloworld!"))
	record := observeBytes(t, data, Options{})

	if record.Schema != evidence.Schema {
		t.Fatalf("schema = %q", record.Schema)
	}
	digest := sha256.Sum256(data)
	if record.Subject.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("digest = %q", record.Subject.SHA256)
	}
	if record.Subject.Size != int64(len(data)) {
		t.Fatalf("size = %d", record.Subject.Size)
	}
	if record.Provider.ID != ProviderID || record.Provider.Profile != ProviderProfile || record.Provider.Version != "0.1.0" {
		t.Fatalf("provider = %#v", record.Provider)
	}
	if record.Authority != evidence.AuthorityObserved {
		t.Fatalf("authority = %q", record.Authority)
	}
	if record.Coverage != evidence.CoverageComplete {
		t.Fatalf("coverage = %q, limitations = %v", record.Coverage, record.Limitations)
	}
	if len(record.Limitations) != 0 || len(record.Unknowns) != 0 {
		t.Fatalf("limitations = %v unknowns = %v", record.Limitations, record.Unknowns)
	}

	payload := decodePayload(t, record)
	if payload.Schema != PayloadSchema {
		t.Fatalf("payload schema = %q", payload.Schema)
	}
	if payload.Artifact.Status != "parsed" || payload.Artifact.Truncated {
		t.Fatalf("artifact = %#v", payload.Artifact)
	}
	if payload.Artifact.EntryCount != 6 || payload.Artifact.LoadedEntryCount != 6 {
		t.Fatalf("counts = %d/%d", payload.Artifact.EntryCount, payload.Artifact.LoadedEntryCount)
	}
	if len(payload.Entries) != 6 {
		t.Fatalf("entries = %d", len(payload.Entries))
	}
	if payload.Entries[0].Path != "a.txt" || payload.Entries[2].Path != "dir/b.txt" {
		t.Fatalf("paths = %#v", payload.Entries)
	}

	file := payload.Entries[0]
	if file.Type != "file" || file.Size == nil || *file.Size != "5" || file.Offset == nil || *file.Offset != "0" {
		t.Fatalf("file = %#v", file)
	}
	if file.DataOffset == nil {
		t.Fatalf("data offset is null: %#v", file)
	}
	if file.PathHex != hex.EncodeToString([]byte("a.txt")) {
		t.Fatalf("path hex = %q", file.PathHex)
	}

	dir := payload.Entries[1]
	if dir.Type != "directory" || dir.Size != nil || dir.Offset != nil {
		t.Fatalf("directory = %#v", dir)
	}

	link := payload.Entries[3]
	if link.Type != "link" || link.LinkTarget != "a.txt" || !link.LinkTargetAvailable {
		t.Fatalf("link = %#v", link)
	}

	unpacked := payload.Entries[4]
	if !unpacked.Unpacked || len(unpacked.Limitations) != 1 {
		t.Fatalf("unpacked = %#v", unpacked)
	}

	packed := payload.Entries[5]
	if !packed.Executable || packed.Integrity == nil {
		t.Fatalf("packed = %#v", packed)
	}
	if packed.Integrity.Hash != "abcd" || packed.Integrity.BlockCount != 1 || !packed.Integrity.HashAvailable {
		t.Fatalf("integrity = %#v", packed.Integrity)
	}
}

func TestObserveTruncated(t *testing.T) {
	data := buildASAR(t, inventoryJSON, []byte("helloworld!"))
	record := observeBytes(t, data, Options{Limits: reasar.Limits{Entries: 2}})
	if record.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q", record.Coverage)
	}
	if len(record.Limitations) == 0 {
		t.Fatal("missing limitations")
	}
	payload := decodePayload(t, record)
	if !payload.Artifact.Truncated || payload.Artifact.LoadedEntryCount != 2 {
		t.Fatalf("artifact = %#v", payload.Artifact)
	}
}

func TestObserveUnsafePath(t *testing.T) {
	directory := `{"files":{"../escape":{"size":1,"offset":"0"}}}`
	record := observeBytes(t, buildASAR(t, directory, []byte("x")), Options{})
	payload := decodePayload(t, record)
	entry := payload.Entries[0]
	if entry.Unsafe != "parent-directory segment" || !entry.PathAvailable {
		t.Fatalf("entry = %#v", entry)
	}
	if entry.PathHex != hex.EncodeToString([]byte("../escape")) {
		t.Fatalf("path hex = %q", entry.PathHex)
	}
}

func TestObserveRangeOutside(t *testing.T) {
	directory := `{"files":{"a":{"size":100,"offset":"0"}}}`
	record := observeBytes(t, buildASAR(t, directory, []byte("x")), Options{})
	payload := decodePayload(t, record)
	entry := payload.Entries[0]
	if !entry.RangeOutside || entry.DataOffset != nil {
		t.Fatalf("entry = %#v", entry)
	}
	if len(entry.Limitations) == 0 {
		t.Fatal("missing limitation")
	}
}

func TestObservePayloadBudget(t *testing.T) {
	data := buildASAR(t, manyFiles(300), []byte("x"))
	record := observeBytes(t, data, Options{PayloadBytes: MinPayloadBytes})
	payload := decodePayload(t, record)
	if payload.Artifact.LoadedEntryCount >= payload.Artifact.EntryCount {
		t.Fatalf("loaded = %d of %d", payload.Artifact.LoadedEntryCount, payload.Artifact.EntryCount)
	}
	if len(payload.Entries) != payload.Artifact.LoadedEntryCount {
		t.Fatalf("entries = %d, loaded = %d", len(payload.Entries), payload.Artifact.LoadedEntryCount)
	}
	found := false
	for _, limitation := range record.Limitations {
		if strings.HasPrefix(limitation, "payload budget omits ") {
			found = true
		}
	}
	if !found {
		t.Fatalf("limitations = %v", record.Limitations)
	}
	if record.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q", record.Coverage)
	}
}

func TestObserveDeterministic(t *testing.T) {
	data := buildASAR(t, inventoryJSON, []byte("helloworld!"))
	first := observeBytes(t, data, Options{})
	second := observeBytes(t, data, Options{})
	firstRaw, err := evidence.Encode(first)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	secondRaw, err := evidence.Encode(second)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(firstRaw, secondRaw) {
		t.Fatal("encoding is not deterministic")
	}
}

func TestObserveOptions(t *testing.T) {
	if _, err := Observe(bytes.NewReader(nil), 0, Options{}); !errors.Is(err, ErrOptions) {
		t.Fatalf("missing version error = %v", err)
	}
	defaults := Options{}.withDefaults()
	if defaults.PayloadBytes != DefaultPayloadBytes {
		t.Fatalf("payload bytes = %d", defaults.PayloadBytes)
	}
	small := Options{PayloadBytes: 1}.withDefaults()
	if small.PayloadBytes != MinPayloadBytes {
		t.Fatalf("small payload = %d", small.PayloadBytes)
	}
	large := Options{PayloadBytes: MaxPayloadBytes + 1}.withDefaults()
	if large.PayloadBytes != MaxPayloadBytes {
		t.Fatalf("large payload = %d", large.PayloadBytes)
	}
}

func TestObserveInvalidArtifact(t *testing.T) {
	data := buildASAR(t, `{"files":{}}`, nil)
	truncated := data[:4]
	_, err := Observe(bytes.NewReader(truncated), int64(len(truncated)), Options{ProviderVersion: "0.1.0"})
	if !errors.Is(err, reasar.ErrTruncated) {
		t.Fatalf("error = %v, want ErrTruncated", err)
	}
	broken := append([]byte(nil), data...)
	broken[0] = 5
	_, err = Observe(bytes.NewReader(broken), int64(len(broken)), Options{ProviderVersion: "0.1.0"})
	if !errors.Is(err, reasar.ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

// failingReader always fails.
type failingReader struct{}

func (failingReader) ReadAt([]byte, int64) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestObserveReaderFailure(t *testing.T) {
	_, err := Observe(failingReader{}, 16, Options{ProviderVersion: "0.1.0"})
	if !errors.Is(err, reasar.ErrRead) {
		t.Fatalf("error = %v, want ErrRead", err)
	}
}

func TestCollectorBounds(t *testing.T) {
	notes := &collector{}
	for i := 0; i < maxRecordLimitations+10; i++ {
		notes.addLimitation(fmt.Sprintf("limitation %d", i))
	}
	for i := 0; i < maxRecordUnknowns+10; i++ {
		notes.addUnknown(fmt.Sprintf("unknown %d", i))
	}
	notes.addLimitation("limitation 0")
	notes.addUnknown("unknown 0")
	limitations, unknowns := notes.finish()
	if len(limitations) != maxRecordLimitations {
		t.Fatalf("limitations = %d", len(limitations))
	}
	if len(unknowns) != maxRecordUnknowns {
		t.Fatalf("unknowns = %d", len(unknowns))
	}
	if limitations[len(limitations)-1] != "additional limitations omitted" {
		t.Fatalf("last limitation = %q", limitations[len(limitations)-1])
	}
	if unknowns[len(unknowns)-1] != "additional unknowns omitted" {
		t.Fatalf("last unknown = %q", unknowns[len(unknowns)-1])
	}
}

func TestValueHelpers(t *testing.T) {
	if got := uint64String(1 << 63); got != "9223372036854775808" {
		t.Fatalf("uint64String = %q", got)
	}
	if got := int64String(-5); got != "-5" {
		t.Fatalf("int64String = %q", got)
	}
	if got := jsonSize(make(chan int)); got != 0 {
		t.Fatalf("jsonSize = %d", got)
	}
}

func TestPayloadBudget(t *testing.T) {
	budget := newPayloadBudget(-1)
	if budget.remaining != 0 {
		t.Fatalf("remaining = %d", budget.remaining)
	}
	budget.reserve(10)
	if budget.remaining != 0 {
		t.Fatalf("reserve did not clamp: %d", budget.remaining)
	}
	budget = newPayloadBudget(1000)
	budget.reserve(200)
	budget.start(50)
	if budget.allowance != 400 {
		t.Fatalf("allowance = %d", budget.allowance)
	}
	if !budget.fits(400) || budget.fits(401) {
		t.Fatal("fits does not respect the allowance")
	}
	budget.add(400)
	budget.finish()
	if budget.remaining != 400 {
		t.Fatalf("remaining after finish = %d", budget.remaining)
	}
	budget.add(1000)
	budget.finish()
	if budget.remaining != 0 {
		t.Fatalf("finish did not clamp: %d", budget.remaining)
	}
}

// failAfterReader succeeds for a fixed number of reads, then fails.
type failAfterReader struct {
	data  []byte
	reads int
}

func (r *failAfterReader) ReadAt(p []byte, off int64) (int, error) {
	if r.reads <= 0 {
		return 0, io.ErrClosedPipe
	}
	r.reads--
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	return copy(p, r.data[off:]), nil
}

// shortReader withholds the last byte of its data.
type shortReader struct{ data []byte }

func (r shortReader) ReadAt(p []byte, off int64) (int, error) {
	limit := int64(len(r.data) - 1)
	if off >= limit {
		return 0, io.EOF
	}
	return copy(p, r.data[off:limit]), nil
}

func TestHashArtifactFailures(t *testing.T) {
	data := buildASAR(t, `{"files":{"a":{"size":1,"offset":"0"}}}`, []byte("x"))
	reader := &failAfterReader{data: data, reads: 2}
	_, err := Observe(reader, int64(len(data)), Options{ProviderVersion: "0.1.0"})
	if !errors.Is(err, reasar.ErrRead) {
		t.Fatalf("error = %v, want ErrRead", err)
	}
	if _, err := hashArtifact(shortReader{data: data}, int64(len(data))); !errors.Is(err, reasar.ErrRead) {
		t.Fatalf("short hash error = %v, want ErrRead", err)
	}
}
