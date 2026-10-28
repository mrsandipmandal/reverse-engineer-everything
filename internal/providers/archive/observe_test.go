package archive

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	rearchive "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/archive"
)

// observe runs the adapter and returns the validated record and its payload.
func observe(t testing.TB, data []byte, opts Options) (evidence.Evidence, Payload) {
	t.Helper()
	if opts.ProviderVersion == "" {
		opts.ProviderVersion = "test"
	}
	record, err := Observe(bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	encoded, err := evidence.Encode(record)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	record, err = evidence.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if err := record.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	var payload Payload
	if err := json.Unmarshal(record.Payload, &payload); err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	if payload.Schema != PayloadSchema {
		t.Fatalf("payload schema = %q", payload.Schema)
	}
	if record.Provider.ID != ProviderID || record.Provider.Profile != ProviderProfile {
		t.Fatalf("provider = %#v", record.Provider)
	}
	return record, payload
}

func TestObserveZIP(t *testing.T) {
	data := buildZIP(t, []zipFixture{
		{name: "hello.txt", data: []byte("hello world")},
		{name: "dir/"},
		{name: "packed.bin", data: bytes.Repeat([]byte("abcd"), 100), deflate: true},
	})
	record, payload := observe(t, data, Options{})

	if record.Provider.ID != "builtin.archive" {
		t.Fatalf("provider id = %q", record.Provider.ID)
	}
	if record.Subject.SHA256 == "" || record.Subject.Size != int64(len(data)) {
		t.Fatalf("subject = %#v", record.Subject)
	}
	if payload.Artifact.Container != "zip" || payload.Artifact.Depth != 0 || payload.Artifact.Status != statusParsed {
		t.Fatalf("artifact = %#v", payload.Artifact)
	}
	if payload.Artifact.Size == nil || *payload.Artifact.Size != fmt.Sprint(len(data)) {
		t.Fatalf("size = %#v", payload.Artifact.Size)
	}
	if payload.Artifact.EntryCount != 3 || payload.Artifact.LoadedEntryCount != 3 || payload.Artifact.Truncated {
		t.Fatalf("artifact counts = %#v", payload.Artifact)
	}
	if payload.Artifact.GZIP != nil {
		t.Fatalf("zip payload has a gzip header: %#v", payload.Artifact.GZIP)
	}
	if len(payload.Entries) != 3 {
		t.Fatalf("entries = %d", len(payload.Entries))
	}

	file := payload.Entries[0]
	if file.Name != "hello.txt" || !file.NameAvailable || file.Unsafe != "" || file.NameHex != "68656c6c6f2e747874" {
		t.Fatalf("entry = %#v", file)
	}
	if file.Type != "file" || file.Method != "stored" || file.Encrypted {
		t.Fatalf("entry = %#v", file)
	}
	if file.CompressedSize == nil || *file.CompressedSize != "11" ||
		file.UncompressedSize == nil || *file.UncompressedSize != "11" {
		t.Fatalf("sizes = %#v", file)
	}
	if file.CRC32 == nil || file.ModifiedUnix == nil {
		t.Fatalf("crc or time = %#v", file)
	}
	if file.Nested != nil {
		t.Fatalf("plain entry has a nested container: %#v", file.Nested)
	}

	if dir := payload.Entries[1]; dir.Type != "directory" || *dir.UncompressedSize != "0" {
		t.Fatalf("directory = %#v", dir)
	}
	if packed := payload.Entries[2]; packed.Method != "deflate" || *packed.UncompressedSize != "400" {
		t.Fatalf("packed = %#v", packed)
	}
	if record.Coverage != evidence.CoverageComplete || len(record.Limitations) != 0 {
		t.Fatalf("coverage = %v limitations = %v", record.Coverage, record.Limitations)
	}
}

func TestObserveUnsafeName(t *testing.T) {
	record, payload := observe(t, buildZIP(t, []zipFixture{
		{name: "../escape", data: []byte("x")},
		{name: "/abs", data: []byte("x")},
	}), Options{})
	if got := payload.Entries[0].Unsafe; got != "parent-directory segment" {
		t.Fatalf("unsafe = %q", got)
	}
	if !payload.Entries[1].NameAvailable || payload.Entries[1].Unsafe != "absolute path" {
		t.Fatalf("entry = %#v", payload.Entries[1])
	}
	if record.Coverage != evidence.CoverageComplete {
		t.Fatalf("coverage = %v", record.Coverage)
	}
}

func TestObserveTar(t *testing.T) {
	data := buildTar(t, []tarFixture{
		{name: "a.txt", data: []byte("abc"), mode: 0o750},
		{name: "dir/", typeflag: '5'},
		{name: "link", typeflag: '2', link: "a.txt"},
	})
	_, payload := observe(t, data, Options{})

	if payload.Artifact.Container != "tar" {
		t.Fatalf("container = %q", payload.Artifact.Container)
	}
	file := payload.Entries[0]
	if file.Type != "file" || file.Method != "stored" {
		t.Fatalf("entry = %#v", file)
	}
	if file.Mode == nil || *file.Mode != 0o750 {
		t.Fatalf("mode = %#v", file.Mode)
	}
	if file.ModifiedUnix == nil || *file.ModifiedUnix != "1700000000" {
		t.Fatalf("mtime = %#v", file.ModifiedUnix)
	}
	if dir := payload.Entries[1]; dir.Type != "directory" {
		t.Fatalf("directory = %#v", dir)
	}
	link := payload.Entries[2]
	if link.Type != "symlink" || !link.LinkTargetAvailable || link.LinkTarget != "a.txt" {
		t.Fatalf("link = %#v", link)
	}
}

func TestObserveGzip(t *testing.T) {
	data := buildGzip(t, "hello.txt", "note", []byte("hello gzip"))
	_, payload := observe(t, data, Options{})

	artifact := payload.Artifact
	if artifact.Container != "gzip" || artifact.GZIP == nil {
		t.Fatalf("artifact = %#v", artifact)
	}
	header := artifact.GZIP
	if header.Name != "hello.txt" || !header.NameAvailable || header.NameHex != "68656c6c6f2e747874" {
		t.Fatalf("header = %#v", header)
	}
	if header.Comment != "note" || !header.CommentAvailable || header.OS != 3 {
		t.Fatalf("header = %#v", header)
	}
	if header.ModifiedUnix != nil {
		t.Fatalf("mtime = %#v", header.ModifiedUnix)
	}
	entry := payload.Entries[0]
	if entry.CompressedSize == nil || *entry.CompressedSize != fmt.Sprint(len(data)) {
		t.Fatalf("compressed size = %#v", entry.CompressedSize)
	}
	if entry.UncompressedSize != nil || entry.CRC32 != nil {
		t.Fatalf("gzip entry claims known sizes: %#v", entry)
	}
	if entry.Nested != nil {
		t.Fatalf("gzip stream of text has a nested container: %#v", entry.Nested)
	}
}

// nestedFixture returns a tar archive that contains a ZIP archive that contains
// a tar archive with one leaf file.
func nestedFixture(t testing.TB) []byte {
	t.Helper()
	leaf := buildTar(t, []tarFixture{{name: "leaf.txt", data: []byte("leaf")}})
	inner := buildZIP(t, []zipFixture{{name: "deep.tar", data: leaf}})
	return buildTar(t, []tarFixture{{name: "inner.zip", data: inner}})
}

func TestObserveNestedDepthOne(t *testing.T) {
	record, payload := observe(t, nestedFixture(t), Options{})
	entry := payload.Entries[0]
	if entry.Nested == nil {
		t.Fatal("nested container was not detected")
	}
	nested := entry.Nested
	if nested.Container != "zip" || nested.Depth != 1 || nested.Status != statusParsed {
		t.Fatalf("nested = %#v", nested)
	}
	if nested.Size != nil {
		t.Fatalf("nested size = %#v", nested.Size)
	}
	if nested.EntryCount != 1 || nested.LoadedEntryCount != 1 {
		t.Fatalf("nested counts = %#v", nested)
	}
	if nested.Entries[0].Name != "deep.tar" || nested.Entries[0].Nested != nil {
		t.Fatalf("nested entry = %#v", nested.Entries[0])
	}
	if record.Coverage != evidence.CoverageComplete {
		t.Fatalf("coverage = %v limitations = %v", record.Coverage, record.Limitations)
	}
}

func TestObserveNestedDepthTwo(t *testing.T) {
	_, payload := observe(t, nestedFixture(t), Options{NestedDepth: 2})
	nested := payload.Entries[0].Nested
	if nested == nil || nested.Entries[0].Nested == nil {
		t.Fatalf("second nesting level missing: %#v", nested)
	}
	deepest := nested.Entries[0].Nested
	if deepest.Container != "tar" || deepest.Depth != 2 || deepest.Entries[0].Name != "leaf.txt" {
		t.Fatalf("deepest = %#v", deepest)
	}
	if deepest.Entries[0].Nested != nil {
		t.Fatal("third nesting level was inspected")
	}
}

func TestObserveNestedDisabled(t *testing.T) {
	_, payload := observe(t, nestedFixture(t), Options{NestedDepth: -1})
	if payload.Entries[0].Nested != nil {
		t.Fatalf("nested = %#v", payload.Entries[0].Nested)
	}
}

func TestObserveNestedMemberLimit(t *testing.T) {
	data := buildTar(t, []tarFixture{
		{name: "a.zip", data: nestedZIP(t, "a.txt", "a")},
		{name: "b.zip", data: nestedZIP(t, "b.txt", "b")},
	})
	record, payload := observe(t, data, Options{NestedMembers: 1})
	if payload.Entries[0].Nested == nil {
		t.Fatal("first nested container missing")
	}
	if payload.Entries[1].Nested != nil {
		t.Fatalf("second nested container = %#v", payload.Entries[1].Nested)
	}
	if !hasLimitation(record.Limitations, "nested member limit 1 reached") {
		t.Fatalf("limitations = %v", record.Limitations)
	}
}

func TestObserveNestedByteBudget(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 1_200_000)
	data := buildTar(t, []tarFixture{{
		name: "big.zip",
		data: buildZIP(t, []zipFixture{{name: "big.bin", data: big}}),
	}})
	record, payload := observe(t, data, Options{NestedBytes: MinNestedBytes})
	if payload.Entries[0].Nested != nil {
		t.Fatalf("nested = %#v", payload.Entries[0].Nested)
	}
	if !hasLimitation(record.Limitations, "nested byte budget 1048576 is exhausted") {
		t.Fatalf("limitations = %v", record.Limitations)
	}
	if record.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %v", record.Coverage)
	}
}

func TestObserveNestedInvalid(t *testing.T) {
	data := buildTar(t, []tarFixture{{
		name: "bad.zip",
		data: []byte("PK\x03\x04not a real archive"),
	}})
	record, payload := observe(t, data, Options{})
	nested := payload.Entries[0].Nested
	if nested == nil || nested.Status == statusParsed {
		t.Fatalf("nested = %#v", nested)
	}
	if len(nested.Limitations) == 0 {
		t.Fatalf("nested limitations = %v", nested.Limitations)
	}
	if !hasLimitation(record.Limitations, "nested zip is") {
		t.Fatalf("limitations = %v", record.Limitations)
	}
}

func TestObserveNestedGzip(t *testing.T) {
	data := buildTar(t, []tarFixture{{
		name: "data.gz",
		data: buildGzip(t, "payload.txt", "", []byte("nested gzip")),
	}})
	_, payload := observe(t, data, Options{})
	nested := payload.Entries[0].Nested
	if nested == nil || nested.Container != "gzip" || nested.GZIP == nil {
		t.Fatalf("nested = %#v", nested)
	}
	if nested.GZIP.Name != "payload.txt" {
		t.Fatalf("nested header = %#v", nested.GZIP)
	}
}

func TestObserveNestedUnsafeEntry(t *testing.T) {
	data := buildTar(t, []tarFixture{{
		name: "../escape.zip",
		data: nestedZIP(t, "a.txt", "a"),
	}})
	_, payload := observe(t, data, Options{})
	if payload.Entries[0].Unsafe == "" {
		t.Fatalf("entry = %#v", payload.Entries[0])
	}
	if payload.Entries[0].Nested != nil {
		t.Fatal("nested detection read an unsafe entry")
	}
}

func TestObservePayloadBudget(t *testing.T) {
	fixtures := make([]zipFixture, 0, 40)
	for i := 0; i < 40; i++ {
		fixtures = append(fixtures, zipFixture{
			name: fmt.Sprintf("file-%02d-with-a-long-name.txt", i),
			data: []byte(strings.Repeat("x", 32)),
		})
	}
	record, payload := observe(t, buildZIP(t, fixtures), Options{PayloadBytes: MinPayloadBytes})
	if payload.Artifact.EntryCount != 40 {
		t.Fatalf("entry count = %d", payload.Artifact.EntryCount)
	}
	if payload.Artifact.LoadedEntryCount >= payload.Artifact.EntryCount {
		t.Fatalf("payload was not truncated: %#v", payload.Artifact)
	}
	if payload.Artifact.LoadedEntryCount != len(payload.Entries) {
		t.Fatalf("loaded count = %d, entries = %d", payload.Artifact.LoadedEntryCount, len(payload.Entries))
	}
	if !hasLimitation(record.Limitations, "payload budget omits entries") {
		t.Fatalf("limitations = %v", record.Limitations)
	}
}

func TestObserveDeterministic(t *testing.T) {
	data := nestedFixture(t)
	first, _ := observe(t, data, Options{NestedDepth: 2})
	second, _ := observe(t, data, Options{NestedDepth: 2})
	if !bytes.Equal(first.Payload, second.Payload) {
		t.Fatal("payload is not deterministic")
	}
	firstEncoded, err := evidence.Encode(first)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	secondEncoded, err := evidence.Encode(second)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(firstEncoded, secondEncoded) {
		t.Fatal("record is not deterministic")
	}
}

func TestObserveOptions(t *testing.T) {
	defaults := Options{}.withDefaults()
	if defaults.PayloadBytes != DefaultPayloadBytes || defaults.NestedDepth != DefaultNestedDepth ||
		defaults.NestedBytes != DefaultNestedBytes || defaults.NestedMembers != DefaultNestedMembers {
		t.Fatalf("defaults = %#v", defaults)
	}
	disabled := Options{NestedDepth: -1}.withDefaults()
	if disabled.NestedDepth != -1 {
		t.Fatalf("disabled depth = %d", disabled.NestedDepth)
	}
	clamped := Options{
		PayloadBytes:  MaxPayloadBytes + 1,
		NestedDepth:   MaxNestedDepth + 1,
		NestedBytes:   MaxNestedBytes + 1,
		NestedMembers: MaxNestedMembers + 1,
	}.withDefaults()
	if clamped.PayloadBytes != MaxPayloadBytes || clamped.NestedDepth != MaxNestedDepth ||
		clamped.NestedBytes != MaxNestedBytes || clamped.NestedMembers != MaxNestedMembers {
		t.Fatalf("clamped = %#v", clamped)
	}
	tiny := Options{PayloadBytes: 1, NestedBytes: 1, NestedMembers: 1}.withDefaults()
	if tiny.PayloadBytes != MinPayloadBytes || tiny.NestedBytes != MinNestedBytes || tiny.NestedMembers != 1 {
		t.Fatalf("tiny = %#v", tiny)
	}
	if _, err := Observe(bytes.NewReader(nil), 0, Options{}); !errors.Is(err, ErrOptions) {
		t.Fatalf("error = %v, want ErrOptions", err)
	}
}

// failingReader always fails.
type failingReader struct{}

func (failingReader) ReadAt([]byte, int64) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestObserveReaderFailure(t *testing.T) {
	data := buildZIP(t, []zipFixture{{name: "a", data: []byte("a")}})
	_, err := Observe(failingReader{}, int64(len(data)), Options{ProviderVersion: "test"})
	if !errors.Is(err, rearchive.ErrRead) {
		t.Fatalf("error = %v, want ErrRead", err)
	}
}

func TestObserveInvalidArtifact(t *testing.T) {
	_, err := Observe(bytes.NewReader([]byte("not an archive")), 14, Options{ProviderVersion: "test"})
	if !errors.Is(err, rearchive.ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

func TestCollectorBounds(t *testing.T) {
	c := &collector{}
	for i := 0; i < maxRecordLimitations+20; i++ {
		c.addLimitation(fmt.Sprintf("limitation %d", i))
	}
	for i := 0; i < maxRecordUnknowns+20; i++ {
		c.addUnknown(fmt.Sprintf("unknown %d", i))
	}
	c.addLimitation("limitation 0")
	c.addUnknown("unknown 0")
	limitations, unknowns := c.finish()
	if len(limitations) != maxRecordLimitations {
		t.Fatalf("limitations = %d", len(limitations))
	}
	if limitations[len(limitations)-1] != "additional limitations omitted" {
		t.Fatalf("last limitation = %q", limitations[len(limitations)-1])
	}
	if len(unknowns) != maxRecordUnknowns {
		t.Fatalf("unknowns = %d", len(unknowns))
	}
	if unknowns[len(unknowns)-1] != "additional unknowns omitted" {
		t.Fatalf("last unknown = %q", unknowns[len(unknowns)-1])
	}
	empty := &collector{}
	if limitations, unknowns := empty.finish(); limitations != nil || unknowns != nil {
		t.Fatalf("empty finish = %v / %v", limitations, unknowns)
	}
	empty.addLimitation("")
	empty.addUnknown("")
	if limitations, unknowns := empty.finish(); len(limitations) != 0 || len(unknowns) != 0 {
		t.Fatalf("empty string was recorded")
	}
}

func TestSentinelStatus(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("%w: x", rearchive.ErrInvalid), "invalid"},
		{fmt.Errorf("%w: x", rearchive.ErrTruncated), "truncated"},
		{fmt.Errorf("%w: x", rearchive.ErrLimit), "limit"},
		{fmt.Errorf("%w: x", rearchive.ErrUnavailable), "unavailable"},
		{fmt.Errorf("%w: x", rearchive.ErrRead), "read"},
		{errors.New("other"), "unknown"},
	}
	for _, test := range tests {
		if got := sentinelStatus(test.err); got != test.want {
			t.Fatalf("sentinelStatus = %q, want %q", got, test.want)
		}
	}
}

func TestPayloadBudget(t *testing.T) {
	budget := newPayloadBudget(-1)
	if budget.remaining != 0 {
		t.Fatalf("negative remaining = %d", budget.remaining)
	}
	budget = newPayloadBudget(1000)
	budget.reserve(100)
	budget.start(50)
	if budget.allowance != 450 {
		t.Fatalf("allowance = %d", budget.allowance)
	}
	if !budget.fits(450) || budget.fits(451) {
		t.Fatal("fits boundary wrong")
	}
	budget.add(200)
	budget.finish()
	if budget.remaining != 700 {
		t.Fatalf("remaining = %d", budget.remaining)
	}
	budget.take(1000)
	budget.reserve(1000)
	if budget.remaining != 0 {
		t.Fatalf("remaining = %d", budget.remaining)
	}
}

func TestValueHelpers(t *testing.T) {
	if got := uint64String(1<<63 + 1); got != "9223372036854775809" {
		t.Fatalf("uint64String = %q", got)
	}
	if got := int64String(-42); got != "-42" {
		t.Fatalf("int64String = %q", got)
	}
	if got := jsonSize("abc"); got != 5 {
		t.Fatalf("jsonSize = %d", got)
	}
	if got := jsonSize(func() {}); got != 0 {
		t.Fatalf("jsonSize = %d", got)
	}
}

// hasLimitation reports whether any limitation contains fragment.
func hasLimitation(limitations []string, fragment string) bool {
	for _, limitation := range limitations {
		if strings.Contains(limitation, fragment) {
			return true
		}
	}
	return false
}
