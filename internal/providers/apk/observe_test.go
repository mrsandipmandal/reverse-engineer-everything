package apk

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	reapk "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/apk"
)

func TestObservePackage(t *testing.T) {
	names, contents := standardFiles()
	record := observeBytes(t, buildZIP(t, names, contents))
	payload := decodePayload(t, record)

	if payload.Schema != PayloadSchema {
		t.Fatalf("schema = %q", payload.Schema)
	}
	if record.Provider.ID != ProviderID || record.Provider.Profile != ProviderProfile {
		t.Fatalf("provider = %#v", record.Provider)
	}
	if record.Coverage != evidence.CoverageComplete {
		t.Fatalf("coverage = %v, limitations = %v", record.Coverage, record.Limitations)
	}
	artifact := payload.Artifact
	if artifact.EntryCount != len(names) || artifact.LoadedEntryCount != len(names) {
		t.Fatalf("entry counts = %d/%d", artifact.EntryCount, artifact.LoadedEntryCount)
	}
	if artifact.Truncated || artifact.Status != "parsed" {
		t.Fatalf("artifact = %#v", artifact)
	}
	if artifact.Counts.Manifest != 1 || artifact.Counts.DEX != 1 || artifact.Counts.Resources != 1 ||
		artifact.Counts.NativeLibrary != 1 || artifact.Counts.ResourceEntry != 1 ||
		artifact.Counts.SignatureFile != 1 || artifact.Counts.Asset != 0 {
		t.Fatalf("counts = %#v", artifact.Counts)
	}
	if artifact.Signing.Present || artifact.Signing.PairCount != 0 || artifact.Signing.Pairs == nil {
		t.Fatalf("signing = %#v", artifact.Signing)
	}
	if artifact.Signing.Offset != nil || artifact.Signing.Size != nil {
		t.Fatal("absent signing block has offset or size")
	}
	if len(payload.Entries) != len(names) {
		t.Fatalf("entries = %d", len(payload.Entries))
	}
	for index, entry := range payload.Entries {
		if entry.Index != index {
			t.Fatalf("entry %d index = %d", index, entry.Index)
		}
		if !entry.NameAvailable || entry.Name != names[index] {
			t.Fatalf("entry %d name = %q", index, entry.Name)
		}
	}
	manifest := payload.Entries[0]
	if manifest.Kind != "manifest" || !manifest.DigestAvailable {
		t.Fatalf("manifest = %#v", manifest)
	}
	if manifest.Digest == nil || *manifest.Digest != digest(contents[0]) {
		t.Fatalf("manifest digest = %v", manifest.Digest)
	}
	if manifest.CompressedSize == nil || manifest.UncompressedSize == nil {
		t.Fatalf("sizes = %#v", manifest)
	}
	library := payload.Entries[3]
	if library.Kind != "native_library" || library.ABI != "arm64-v8a" || library.Digest != nil {
		t.Fatalf("library = %#v", library)
	}
}

func TestObserveSigningBlock(t *testing.T) {
	names, contents := standardFiles()
	value2 := []byte("v2-signature")
	value3 := []byte("v3-signature")
	block := signBlock(pair(0x7109871a, value2), pair(0xf05368c0, value3), pair(0x12345678, []byte("x")))
	record := observeBytes(t, buildAPK(t, names, contents, block))
	payload := decodePayload(t, record)
	signing := payload.Artifact.Signing

	if !signing.Present || signing.Truncated || signing.PairCount != 3 {
		t.Fatalf("signing = %#v", signing)
	}
	if signing.Offset == nil || signing.Size == nil {
		t.Fatal("present signing block has no offset or size")
	}
	if *signing.Size != uint64String(uint64(len(block))) {
		t.Fatalf("size = %q", *signing.Size)
	}
	schemes := []string{"v2", "v3", ""}
	for i, want := range schemes {
		pair := signing.Pairs[i]
		if pair.Scheme != want {
			t.Fatalf("pair %d scheme = %q", i, pair.Scheme)
		}
		if pair.Digest == nil || *pair.Digest == "" || !pair.DigestAvailable {
			t.Fatalf("pair %d digest = %#v", i, pair)
		}
	}
	if signing.Pairs[0].ID != "0x7109871a" {
		t.Fatalf("v2 id = %q", signing.Pairs[0].ID)
	}
	if *signing.Pairs[0].Digest != digest(value2) {
		t.Fatalf("v2 digest = %q", *signing.Pairs[0].Digest)
	}
	if signing.Pairs[2].ID != "0x12345678" || signing.Pairs[2].Scheme != "" {
		t.Fatalf("unknown pair = %#v", signing.Pairs[2])
	}
	if record.Coverage != evidence.CoverageComplete {
		t.Fatalf("coverage = %v, limitations = %v", record.Coverage, record.Limitations)
	}
}

func TestObserveTruncated(t *testing.T) {
	names, contents := standardFiles()
	data := buildZIP(t, names, contents)
	record, err := Observe(bytes.NewReader(data), int64(len(data)), Options{
		ProviderVersion: "1.0.0",
		Limits:          reapk.Limits{Entries: 2},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	payload := decodePayload(t, record)
	if !payload.Artifact.Truncated {
		t.Fatal("artifact is not truncated")
	}
	if payload.Artifact.EntryCount != 2 || payload.Artifact.LoadedEntryCount != 2 {
		t.Fatalf("counts = %d/%d", payload.Artifact.EntryCount, payload.Artifact.LoadedEntryCount)
	}
	if record.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %v", record.Coverage)
	}
	if !hasString(record.Limitations, "artifact inventory is partial") {
		t.Fatalf("limitations = %v", record.Limitations)
	}
	if len(payload.Artifact.Limitations) == 0 {
		t.Fatal("payload artifact has no limitation")
	}
}

func TestObservePayloadBudget(t *testing.T) {
	names, contents := assetFiles(t, 200)
	data := buildZIP(t, names, contents)
	record, err := Observe(bytes.NewReader(data), int64(len(data)), Options{
		ProviderVersion: "1.0.0",
		PayloadBytes:    MinPayloadBytes,
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	payload := decodePayload(t, record)
	artifact := payload.Artifact
	if artifact.LoadedEntryCount >= artifact.EntryCount {
		t.Fatalf("payload holds every entry: %d", artifact.LoadedEntryCount)
	}
	if len(payload.Entries) != artifact.LoadedEntryCount {
		t.Fatalf("loaded = %d, entries = %d", artifact.LoadedEntryCount, len(payload.Entries))
	}
	found := false
	for _, limitation := range record.Limitations {
		if strings.HasPrefix(limitation, "payload budget omits entries after ") {
			found = true
		}
	}
	if !found {
		t.Fatalf("limitations = %v", record.Limitations)
	}
	if record.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %v", record.Coverage)
	}
	for index, entry := range payload.Entries {
		if entry.Index != index {
			t.Fatalf("entry %d index = %d", index, entry.Index)
		}
	}
}

func TestObserveErrors(t *testing.T) {
	names, contents := standardFiles()
	data := buildZIP(t, names, contents)

	if _, err := Observe(bytes.NewReader(data), int64(len(data)), Options{}); !errors.Is(err, ErrOptions) {
		t.Fatalf("missing version error = %v", err)
	}
	if _, err := Observe(bytes.NewReader([]byte("junk")), 4, Options{ProviderVersion: "1.0.0"}); err == nil {
		t.Fatal("invalid artifact was observed")
	}
	if _, err := Observe(nil, int64(len(data)), Options{ProviderVersion: "1.0.0"}); err == nil {
		t.Fatal("nil reader was observed")
	}
	noManifest := buildZIP(t, []string{"classes.dex"}, [][]byte{[]byte("dex")})
	if _, err := Observe(bytes.NewReader(noManifest), int64(len(noManifest)), Options{ProviderVersion: "1.0.0"}); err == nil {
		t.Fatal("package without a manifest was observed")
	}
}

func TestObserveOptionsClamping(t *testing.T) {
	defaults := (Options{}).withDefaults()
	if defaults.PayloadBytes != DefaultPayloadBytes {
		t.Fatalf("default = %d", defaults.PayloadBytes)
	}
	if got := (Options{PayloadBytes: 1}).withDefaults().PayloadBytes; got != MinPayloadBytes {
		t.Fatalf("minimum = %d", got)
	}
	if got := (Options{PayloadBytes: MaxPayloadBytes + 1}).withDefaults().PayloadBytes; got != MaxPayloadBytes {
		t.Fatalf("maximum = %d", got)
	}
	if got := (Options{PayloadBytes: 100_000}).withDefaults().PayloadBytes; got != 100_000 {
		t.Fatalf("kept = %d", got)
	}
}

func TestObserveRecordValidates(t *testing.T) {
	names, contents := standardFiles()
	record := observeBytes(t, buildZIP(t, names, contents))
	raw, err := evidence.Encode(record)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := evidence.Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestObserveDeterministic(t *testing.T) {
	names, contents := standardFiles()
	data := buildAPK(t, names, contents, signBlock(pair(0x7109871a, []byte("value"))))
	first, err := Observe(bytes.NewReader(data), int64(len(data)), Options{ProviderVersion: "1.0.0"})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	second, err := Observe(bytes.NewReader(data), int64(len(data)), Options{ProviderVersion: "1.0.0"})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	firstRaw, err := evidence.Encode(first)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	secondRaw, err := evidence.Encode(second)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(firstRaw, secondRaw) {
		t.Fatal("two observations of one package differ")
	}
}

func TestCollectorBounds(t *testing.T) {
	c := &collector{}
	c.addLimitation("")
	c.addLimitation("one")
	c.addLimitation("one")
	if len(c.limitations) != 1 {
		t.Fatalf("limitations = %v", c.limitations)
	}
	for i := 0; i < maxRecordLimitations+10; i++ {
		c.addLimitation(strings.Repeat("x", i+1))
	}
	got := c.finish()
	if len(got) != maxRecordLimitations {
		t.Fatalf("finished = %d", len(got))
	}
	if got[len(got)-1] != "additional limitations omitted" {
		t.Fatalf("last = %q", got[len(got)-1])
	}
}

func TestHashArtifactShortRead(t *testing.T) {
	names, contents := standardFiles()
	data := buildZIP(t, names, contents)
	if _, err := hashArtifact(failingReader{}, int64(len(data))); !errors.Is(err, reapk.ErrRead) {
		t.Fatalf("error = %v", err)
	}
	if _, err := hashArtifact(bytes.NewReader(data), int64(len(data))+4); !errors.Is(err, reapk.ErrRead) {
		t.Fatalf("short error = %v", err)
	}
}

func TestPayloadBudgetEdges(t *testing.T) {
	budget := newPayloadBudget(-1)
	if budget.remaining != 0 {
		t.Fatalf("remaining = %d", budget.remaining)
	}
	budget.reserve(10)
	if budget.remaining != 0 {
		t.Fatalf("remaining after reserve = %d", budget.remaining)
	}
	budget.start(100)
	if budget.fits(1) {
		t.Fatal("empty budget fits an entry")
	}
	budget.add(5)
	budget.finish()
	if jsonSize(make(chan int)) != 0 {
		t.Fatal("jsonSize of an unencodable value is not zero")
	}
}

// failingReader always fails.
type failingReader struct{}

func (failingReader) ReadAt([]byte, int64) (int, error) {
	return 0, io.ErrClosedPipe
}

func hasString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
