package plist

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	replist "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/plist"
)

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

func TestObserveXMLInventory(t *testing.T) {
	document := xmlDocument(`<dict>
	<key>name</key><string>demo</string>
	<key>count</key><integer>7</integer>
	<key>ratio</key><real>1.5</real>
	<key>enabled</key><true/>
	<key>when</key><date>2020-01-02T03:04:05Z</date>
	<key>blob</key><data>AAAA</data>
	<key>uid</key><uid>42</uid>
	<key>list</key><array><string>a</string><string>b</string></array>
</dict>`)
	data := []byte(document)
	record := observeBytes(t, data, Options{})

	if record.Schema != evidence.Schema {
		t.Fatalf("schema = %q", record.Schema)
	}
	digest := sha256.Sum256(data)
	if record.Subject.SHA256 != hex.EncodeToString(digest[:]) || record.Subject.Size != int64(len(data)) {
		t.Fatalf("subject = %#v", record.Subject)
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
	if payload.Artifact.Format != "xml" || payload.Artifact.Version != "" {
		t.Fatalf("artifact = %#v", payload.Artifact)
	}
	if payload.Artifact.Status != "parsed" || payload.Artifact.Truncated {
		t.Fatalf("artifact = %#v", payload.Artifact)
	}
	if payload.Artifact.ObjectCount != 19 || payload.Artifact.LoadedObjectCount != 19 {
		t.Fatalf("counts = %d/%d", payload.Artifact.ObjectCount, payload.Artifact.LoadedObjectCount)
	}
	if payload.Artifact.TopObject != 0 || len(payload.Objects) != 19 {
		t.Fatalf("top = %d objects = %d", payload.Artifact.TopObject, len(payload.Objects))
	}

	root := payload.Objects[0]
	if root.Type != "dictionary" || !root.Reachable || root.Depth != 0 || len(root.Keys) != 8 {
		t.Fatalf("root = %#v", root)
	}
	byKey := map[string]PayloadObject{}
	for i, key := range root.Keys {
		byKey[payload.Objects[key].Text] = payload.Objects[root.Values[i]]
	}
	if got := byKey["name"]; got.Type != "string" || !got.TextAvailable || got.Text != "demo" {
		t.Fatalf("name = %#v", got)
	}
	if got := byKey["name"]; got.TextHex != hex.EncodeToString([]byte("demo")) {
		t.Fatalf("name hex = %q", got.TextHex)
	}
	if got := byKey["count"]; got.Type != "integer" || got.Integer != "7" {
		t.Fatalf("count = %#v", got)
	}
	if got := byKey["ratio"]; got.Type != "real" || got.Real == nil || *got.Real != 1.5 {
		t.Fatalf("ratio = %#v", got)
	}
	if got := byKey["enabled"]; got.Type != "boolean" || !got.Boolean {
		t.Fatalf("enabled = %#v", got)
	}
	if got := byKey["when"]; got.Type != "date" || got.DateUnix == nil || *got.DateUnix != "1577934245" {
		t.Fatalf("when = %#v", got)
	}
	if got := byKey["blob"]; got.Type != "data" || got.DataBytes == nil || *got.DataBytes != "3" {
		t.Fatalf("blob = %#v", got)
	}
	if got := byKey["uid"]; got.Type != "uid" || got.UID == nil || *got.UID != "42" {
		t.Fatalf("uid = %#v", got)
	}
	if got := byKey["list"]; got.Type != "array" || len(got.Refs) != 2 {
		t.Fatalf("list = %#v", got)
	}
}

func TestObserveBinaryInventory(t *testing.T) {
	data := buildBinary(t, [][]byte{
		bdict(1, 2, 3, 4),
		bstr("name"),
		bstr("version"),
		bstr("demo"),
		bint(3),
	})
	record := observeBytes(t, data, Options{})
	payload := decodePayload(t, record)

	if payload.Artifact.Format != "binary" || payload.Artifact.Version != "00" {
		t.Fatalf("artifact = %#v", payload.Artifact)
	}
	if payload.Artifact.ObjectCount != 5 || payload.Artifact.LoadedObjectCount != 5 {
		t.Fatalf("counts = %d/%d", payload.Artifact.ObjectCount, payload.Artifact.LoadedObjectCount)
	}
	if got := payload.Objects[0]; got.Type != "dictionary" || len(got.Keys) != 2 {
		t.Fatalf("root = %#v", got)
	}
	if got := payload.Objects[3]; got.Type != "string" || got.Text != "demo" || !got.TextAvailable {
		t.Fatalf("value = %#v", got)
	}
	if got := payload.Objects[4]; got.Type != "integer" || got.Integer != "3" {
		t.Fatalf("integer = %#v", got)
	}
	if got := payload.Objects[4].Depth; got != 1 {
		t.Fatalf("integer depth = %d", got)
	}
}

func TestObserveTruncatedAndUnreachable(t *testing.T) {
	data := buildBinary(t, [][]byte{
		barray(1),
		barray(2),
		barray(3),
		{0x00},
		{0x00},
	})
	record := observeBytes(t, data, Options{Limits: replist.Limits{Depth: 1}})
	if record.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q", record.Coverage)
	}
	payload := decodePayload(t, record)
	if !payload.Artifact.Truncated {
		t.Fatalf("artifact = %#v", payload.Artifact)
	}
	foundDepth := false
	foundUnreachable := false
	for _, limitation := range record.Limitations {
		if strings.Contains(limitation, "depth limit") {
			foundDepth = true
		}
		if strings.Contains(limitation, "not reachable") {
			foundUnreachable = true
		}
	}
	if !foundDepth || !foundUnreachable {
		t.Fatalf("limitations = %v", record.Limitations)
	}
	if got := payload.Objects[1]; len(got.Limitations) == 0 {
		t.Fatalf("object 1 = %#v", got)
	}
	if got := payload.Objects[4]; got.Reachable || got.Depth != -1 {
		t.Fatalf("unreachable object = %#v", got)
	}
}

func TestObservePayloadBudget(t *testing.T) {
	document := manyStrings(200)
	record := observeBytes(t, []byte(document), Options{PayloadBytes: MinPayloadBytes})
	payload := decodePayload(t, record)
	if payload.Artifact.ObjectCount != 201 {
		t.Fatalf("object count = %d", payload.Artifact.ObjectCount)
	}
	if payload.Artifact.LoadedObjectCount != len(payload.Objects) {
		t.Fatalf("loaded = %d objects = %d", payload.Artifact.LoadedObjectCount, len(payload.Objects))
	}
	if payload.Artifact.LoadedObjectCount >= payload.Artifact.ObjectCount {
		t.Fatalf("budget did not omit objects: %d", payload.Artifact.LoadedObjectCount)
	}
	if record.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q", record.Coverage)
	}
	found := false
	for _, limitation := range record.Limitations {
		if strings.Contains(limitation, "payload budget") {
			found = true
		}
	}
	if !found {
		t.Fatalf("limitations = %v", record.Limitations)
	}
	for index, object := range payload.Objects {
		if object.Index != index {
			t.Fatalf("object %d index %d", index, object.Index)
		}
	}
}

func TestObserveErrors(t *testing.T) {
	valid := []byte(xmlDocument(`<string>a</string>`))
	if _, err := Observe(bytes.NewReader(valid), int64(len(valid)), Options{}); !errors.Is(err, ErrOptions) {
		t.Fatalf("missing version error = %v", err)
	}
	if _, err := Observe(bytes.NewReader([]byte("not a plist")), 11, Options{ProviderVersion: "x"}); err == nil {
		t.Fatal("invalid artifact did not fail")
	}
	if _, err := Observe(nil, 0, Options{ProviderVersion: "x"}); err == nil {
		t.Fatal("nil reader did not fail")
	}
}

func TestObserveOptionsClamping(t *testing.T) {
	if got := (Options{}).withDefaults().PayloadBytes; got != DefaultPayloadBytes {
		t.Fatalf("default = %d", got)
	}
	if got := (Options{PayloadBytes: 1}).withDefaults().PayloadBytes; got != MinPayloadBytes {
		t.Fatalf("minimum = %d", got)
	}
	if got := (Options{PayloadBytes: MaxPayloadBytes + 1}).withDefaults().PayloadBytes; got != MaxPayloadBytes {
		t.Fatalf("maximum = %d", got)
	}
}

func TestObserveRecordValidates(t *testing.T) {
	data := []byte(xmlDocument(`<array><string>a</string></array>`))
	record := observeBytes(t, data, Options{})
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

func TestObserveNonFiniteReal(t *testing.T) {
	data := buildBinary(t, [][]byte{breal(math.NaN())})
	record := observeBytes(t, data, Options{})
	payload := decodePayload(t, record)
	object := payload.Objects[0]
	if object.Type != "real" || object.Real != nil {
		t.Fatalf("object = %#v", object)
	}
	if len(object.Limitations) != 1 || record.Coverage != evidence.CoverageComplete {
		t.Fatalf("limitations = %v coverage = %q", object.Limitations, record.Coverage)
	}
}

func TestObserveNonFiniteDate(t *testing.T) {
	data := buildBinary(t, [][]byte{{0x33, 0x7F, 0xF8, 0, 0, 0, 0, 0, 0}})
	record := observeBytes(t, data, Options{})
	payload := decodePayload(t, record)
	object := payload.Objects[0]
	if object.DateUnix != nil || len(object.Limitations) != 1 {
		t.Fatalf("object = %#v", object)
	}
}

func TestCollectorBounds(t *testing.T) {
	var collector collector
	collector.addLimitation("")
	collector.addLimitation("same")
	collector.addLimitation("same")
	if got := collector.finish(); len(got) != 1 || got[0] != "same" {
		t.Fatalf("limitations = %v", got)
	}
	for i := 0; i < 200; i++ {
		collector.addLimitation(strings.Repeat("x", i+1))
	}
	got := collector.finish()
	if len(got) != maxRecordLimitations {
		t.Fatalf("limitations = %d", len(got))
	}
	if got[len(got)-1] != "additional limitations omitted" {
		t.Fatalf("last limitation = %q", got[len(got)-1])
	}
}

func TestHashArtifactShortRead(t *testing.T) {
	reader := bytes.NewReader([]byte("short"))
	if _, err := hashArtifact(reader, 10); err == nil {
		t.Fatal("short read did not fail")
	}
	if _, err := hashArtifact(failingReader{}, 4); err == nil {
		t.Fatal("failing reader did not fail")
	}
}

func TestPayloadBudgetEdges(t *testing.T) {
	budget := newPayloadBudget(-1)
	if budget.remaining != 0 {
		t.Fatalf("remaining = %d", budget.remaining)
	}
	budget.start(100)
	if budget.fits(1) {
		t.Fatal("empty budget fits an object")
	}
	budget.finish()
	if budget.remaining != 0 {
		t.Fatalf("remaining = %d", budget.remaining)
	}
	if jsonSize(make(chan int)) != 0 {
		t.Fatal("unencodable value has a size")
	}
}

// failingReader always fails.
type failingReader struct{}

func (failingReader) ReadAt([]byte, int64) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestObserveBinaryDateAndData(t *testing.T) {
	data := buildBinary(t, [][]byte{
		barray(1, 2),
		bdate(1_600_000_000),
		bdata(4),
	})
	payload := decodePayload(t, observeBytes(t, data, Options{}))
	if got := payload.Objects[1]; got.Type != "date" || got.DateUnix == nil || *got.DateUnix != "1600000000" {
		t.Fatalf("date = %#v", got)
	}
	if got := payload.Objects[2]; got.Type != "data" || got.DataBytes == nil || *got.DataBytes != "4" {
		t.Fatalf("data = %#v", got)
	}
}

func TestObserveDeterministic(t *testing.T) {
	document := xmlDocument(`<dict>
	<key>name</key><string>demo</string>
	<key>count</key><integer>7</integer>
	<key>list</key><array><real>1.5</real><true/></array>
</dict>`)
	first, err := evidence.Encode(observeBytes(t, []byte(document), Options{}))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	second, err := evidence.Encode(observeBytes(t, []byte(document), Options{}))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("encoding is not deterministic")
	}
}
