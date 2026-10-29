package inventory

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
)

func record(t *testing.T, payload string, limitations ...string) evidence.Evidence {
	t.Helper()
	if !json.Valid([]byte(payload)) {
		t.Fatalf("payload is not valid JSON: %s", payload)
	}
	return evidence.Evidence{
		Payload:     json.RawMessage(payload),
		Limitations: limitations,
	}
}

func TestBuildArchive(t *testing.T) {
	payload := `{
		"schema": "ree.payload.archive/1",
		"artifact": {"container": "zip"},
		"entries": [
			{"index": 0, "name": "a.txt", "name_available": true, "type": "file",
			 "compressed_size": "3", "uncompressed_size": "5", "limitations": []},
			{"index": 1, "name": "dir", "name_available": true, "type": "directory",
			 "limitations": ["nested entry omitted"]},
			{"index": 2, "name": "inner.txt", "name_available": true, "type": "file",
			 "compressed_size": "2",
			 "nested": {"schema": "ree.payload.archive/1",
			            "entries": [{"index": 0, "name": "inner.txt", "name_available": true,
			                         "type": "file", "compressed_size": "2"}]}},
			{"index": 3, "type": "file", "limitations": []}
		]
	}`
	collection, err := Build(record(t, payload, "artifact inventory is partial"))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if collection.Schema != SchemaArchive || collection.Format != "zip" {
		t.Fatalf("schema = %q format = %q", collection.Schema, collection.Format)
	}
	if len(collection.Limitations) != 1 || collection.Limitations[0] != "artifact inventory is partial" {
		t.Fatalf("limitations = %v", collection.Limitations)
	}
	if len(collection.Items) != 5 {
		t.Fatalf("items = %d, want 5", len(collection.Items))
	}
	first := collection.Items[0]
	if first.Name != "a.txt" || first.Kind != "file" || first.Size == nil || *first.Size != 5 {
		t.Fatalf("first = %#v", first)
	}
	if collection.Items[1].Unsafe != "" || collection.Items[1].Kind != "directory" {
		t.Fatalf("directory = %#v", collection.Items[1])
	}
	if collection.Items[2].Depth != 0 || collection.Items[3].Depth != 1 || collection.Items[3].Name != "inner.txt" {
		t.Fatalf("nested = %#v / %#v", collection.Items[2], collection.Items[3])
	}
	if collection.Items[3].Size == nil || *collection.Items[3].Size != 2 {
		t.Fatalf("nested size = %#v", collection.Items[3].Size)
	}
	unnamed := collection.Items[4]
	if unnamed.NameAvailable || unnamed.Depth != 0 {
		t.Fatalf("unnamed = %#v", unnamed)
	}
}

func TestBuildASAR(t *testing.T) {
	payload := `{
		"schema": "ree.payload.asar/1",
		"artifact": {"entry_count": 2},
		"entries": [
			{"index": 0, "path": "index.js", "path_available": true, "type": "file",
			 "size": "12", "unsafe": "", "limitations": []},
			{"index": 1, "path": "../escape", "path_available": true, "type": "file",
			 "size": "4", "unsafe": "parent-directory segment", "limitations": []}
		]
	}`
	collection, err := Build(record(t, payload))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if collection.Format != "asar" || len(collection.Items) != 2 {
		t.Fatalf("format = %q items = %d", collection.Format, len(collection.Items))
	}
	if got := collection.Items[1]; got.Unsafe != "parent-directory segment" || got.Size == nil || *got.Size != 4 {
		t.Fatalf("unsafe item = %#v", got)
	}
}

func TestBuildAPK(t *testing.T) {
	payload := `{
		"schema": "ree.payload.apk/1",
		"artifact": {"entry_count": 2},
		"entries": [
			{"index": 0, "name": "AndroidManifest.xml", "name_available": true,
			 "kind": "manifest", "compressed_size": "4", "uncompressed_size": "8",
			 "digest": "abcd", "digest_available": true, "limitations": []},
			{"index": 1, "name": "classes.dex", "name_available": true, "kind": "dex",
			 "compressed_size": "9", "digest": null, "digest_available": false,
			 "limitations": ["content digest is unavailable"]}
		]
	}`
	collection, err := Build(record(t, payload))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if collection.Format != "apk" || len(collection.Items) != 2 {
		t.Fatalf("format = %q items = %d", collection.Format, len(collection.Items))
	}
	manifest := collection.Items[0]
	if manifest.Kind != "manifest" || manifest.Size == nil || *manifest.Size != 8 ||
		manifest.Digest != "abcd" || !manifest.DigestAvailable {
		t.Fatalf("manifest = %#v", manifest)
	}
	dex := collection.Items[1]
	if dex.Size == nil || *dex.Size != 9 || dex.DigestAvailable || dex.Digest != "" {
		t.Fatalf("dex = %#v", dex)
	}
}

func TestBuildPlist(t *testing.T) {
	payload := `{
		"schema": "ree.payload.plist/1",
		"artifact": {"object_count": 3},
		"objects": [
			{"index": 0, "type": "dictionary", "text": "", "text_available": false, "depth": 0},
			{"index": 1, "type": "string", "text": "name", "text_available": true, "depth": 1},
			{"index": 2, "type": "integer", "text": "", "text_available": false, "depth": 1,
			 "limitations": ["integer exceeds 64 bits"]}
		]
	}`
	collection, err := Build(record(t, payload))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if collection.Format != "plist" || len(collection.Items) != 3 {
		t.Fatalf("format = %q items = %d", collection.Format, len(collection.Items))
	}
	if got := collection.Items[1]; got.Name != "name" || !got.NameAvailable || got.Depth != 1 {
		t.Fatalf("string = %#v", got)
	}
	if got := collection.Items[2]; got.NameAvailable || len(got.Limitations) != 1 {
		t.Fatalf("integer = %#v", got)
	}
}

func TestBuildRejectsUnsupported(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{name: "elf", payload: `{"schema":"ree.payload.elf/1"}`},
		{name: "missing schema", payload: `{}`},
		{name: "not json", payload: `"text"`},
		{name: "malformed member", payload: `{"schema":"ree.payload.archive/1","entries":"no"}`},
		{name: "malformed plist", payload: `{"schema":"ree.payload.plist/1","objects":7}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Build(record(t, test.payload)); err == nil {
				t.Fatal("Build succeeded, want an error")
			}
		})
	}
	if _, err := Build(evidence.Evidence{Payload: json.RawMessage(`{"schema":"ree.payload.macho/1"}`)}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
}

func TestPage(t *testing.T) {
	collection := &Collection{Items: []Item{{Index: 0}, {Index: 1}, {Index: 2}}}
	page, err := collection.Page(0, 2)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if page.Total != 3 || len(page.Items) != 2 || page.NextOffset == nil || *page.NextOffset != 2 {
		t.Fatalf("page = %+v", page)
	}
	page, err = collection.Page(2, 2)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if len(page.Items) != 1 || page.NextOffset != nil {
		t.Fatalf("last page = %+v", page)
	}
	page, err = collection.Page(9, 2)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if len(page.Items) != 0 || page.Items == nil || page.NextOffset != nil {
		t.Fatalf("past-end page = %+v", page)
	}
	for _, test := range []struct{ offset, limit int }{{-1, 10}, {0, 0}, {0, -1}, {0, MaxPageLimit + 1}} {
		if _, err := collection.Page(test.offset, test.limit); !errors.Is(err, ErrPage) {
			t.Fatalf("Page(%d, %d) error = %v", test.offset, test.limit, err)
		}
	}
	var nilCollection *Collection
	if _, err := nilCollection.Page(0, 1); !errors.Is(err, ErrPage) {
		t.Fatalf("nil Page error = %v", err)
	}
}

func TestSearch(t *testing.T) {
	collection := &Collection{
		Schema:      SchemaAPK,
		Format:      "apk",
		Limitations: []string{"artifact inventory is partial"},
		Items: []Item{
			{Index: 0, Name: "AndroidManifest.xml", NameAvailable: true},
			{Index: 1, Name: "classes.dex", NameAvailable: true},
			{Index: 2, Name: "assets/Logo.PNG", NameAvailable: true},
			{Index: 3},
		},
	}
	result, err := collection.Search("logo")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(result.Items) != 1 || result.Items[0].Name != "assets/Logo.PNG" {
		t.Fatalf("items = %+v", result.Items)
	}
	if result.Schema != SchemaAPK || len(result.Limitations) != 1 {
		t.Fatalf("result = %+v", result)
	}
	if _, err := collection.Search("   "); !errors.Is(err, ErrQuery) {
		t.Fatalf("empty query error = %v", err)
	}
	empty, err := collection.Search("absent")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if empty.Items == nil || len(empty.Items) != 0 {
		t.Fatalf("empty result = %#v", empty.Items)
	}
}

func TestCompare(t *testing.T) {
	size := int64(5)
	other := int64(6)
	left := &Collection{Items: []Item{
		{Index: 0, Name: "same.txt", NameAvailable: true, Kind: "file", Size: &size},
		{Index: 1, Name: "gone.txt", NameAvailable: true, Kind: "file"},
		{Index: 2, Name: "changed.txt", NameAvailable: true, Kind: "file", Size: &size},
	}}
	right := &Collection{Items: []Item{
		{Index: 0, Name: "same.txt", NameAvailable: true, Kind: "file", Size: &size},
		{Index: 1, Name: "new.txt", NameAvailable: true, Kind: "file"},
		{Index: 2, Name: "changed.txt", NameAvailable: true, Kind: "file", Size: &other},
	}}
	result := Compare(left, right)
	if len(result.Added) != 1 || result.Added[0].Name != "new.txt" {
		t.Fatalf("added = %+v", result.Added)
	}
	if len(result.Removed) != 1 || result.Removed[0].Name != "gone.txt" {
		t.Fatalf("removed = %+v", result.Removed)
	}
	if len(result.Changed) != 1 || result.Changed[0].Name != "changed.txt" {
		t.Fatalf("changed = %+v", result.Changed)
	}
	if result.Changed[0].Left.Size == nil || *result.Changed[0].Left.Size != 5 ||
		result.Changed[0].Right.Size == nil || *result.Changed[0].Right.Size != 6 {
		t.Fatalf("change = %+v", result.Changed[0])
	}

	empty := Compare(nil, nil)
	if empty.Added == nil || empty.Removed == nil || empty.Changed == nil {
		t.Fatalf("nil compare = %+v", empty)
	}
}

func TestCompareKeys(t *testing.T) {
	digestLeft := &Collection{Items: []Item{
		{Index: 0, Name: "a.bin", NameAvailable: true, Digest: "aa", DigestAvailable: true},
		{Index: 1, NameAvailable: false},
	}}
	digestRight := &Collection{Items: []Item{
		{Index: 0, Name: "a.bin", NameAvailable: true, Digest: "bb", DigestAvailable: true},
		{Index: 1, NameAvailable: false},
		{Index: 2, DigestAvailable: true},
	}}
	result := Compare(digestLeft, digestRight)
	if len(result.Changed) != 1 || len(result.Added) != 1 {
		t.Fatalf("result = %+v", result)
	}
	if result.Added[0].Index != 2 {
		t.Fatalf("added = %+v", result.Added)
	}
	if keyOf(Item{Index: 4}) != "#4" {
		t.Fatalf("keyOf unnamed = %q", keyOf(Item{Index: 4}))
	}
}

func TestSizeOf(t *testing.T) {
	text := func(s string) *string { return &s }
	if got := sizeOf(text("12"), text("5")); got == nil || *got != 12 {
		t.Fatalf("sizeOf = %v", got)
	}
	if got := sizeOf(text("bad"), text("5")); got == nil || *got != 5 {
		t.Fatalf("sizeOf fallback = %v", got)
	}
	if got := sizeOf(text("-1"), nil); got != nil {
		t.Fatalf("negative size = %v", *got)
	}
	if got := sizeOf(nil, nil); got != nil {
		t.Fatalf("absent size = %v", *got)
	}
}

func TestSearchKeepsOrder(t *testing.T) {
	collection := &Collection{Items: []Item{
		{Index: 0, Name: "z.log", NameAvailable: true},
		{Index: 1, Name: "a.log", NameAvailable: true},
	}}
	result, err := collection.Search("LOG")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	names := make([]string, 0, len(result.Items))
	for _, item := range result.Items {
		names = append(names, item.Name)
	}
	if got := strings.Join(names, ","); got != "z.log,a.log" {
		t.Fatalf("names = %q", got)
	}
}
