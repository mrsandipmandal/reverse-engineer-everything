package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInventoryText(t *testing.T) {
	t.Parallel()

	path := writeCLIFixture(t, "bundle.zip", cliZIP(t, "a.txt", "hi", "lib/b.so", "xx"))

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"inventory", path}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"REE Inventory",
		"artifact: bundle.zip",
		"format: zip",
		"schema: ree.payload.archive/1",
		"total: 2",
		"page: offset=0 limit=50 returned=2",
		"[0] a.txt kind=file size=2",
		"[1] lib/b.so kind=file size=2",
		"limitations: none",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRunInventoryJSON(t *testing.T) {
	t.Parallel()

	path := writeCLIFixture(t, "bundle.zip", cliZIP(t, "a.txt", "hi"))

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"inventory", "--json", path}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	var view inventoryView
	if err := json.Unmarshal(stdout.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v; output=%q", err, stdout.String())
	}
	if view.Artifact != "bundle.zip" || view.Format != "zip" || view.Schema != "ree.payload.archive/1" {
		t.Fatalf("view = %+v", view)
	}
	if view.Page.Total != 1 || len(view.Page.Items) != 1 || view.Page.NextOffset != nil {
		t.Fatalf("page = %+v", view.Page)
	}
	item := view.Page.Items[0]
	if item.Name != "a.txt" || !item.NameAvailable || item.Kind != "file" {
		t.Fatalf("item = %+v", item)
	}
	if item.Size == nil || *item.Size != 2 {
		t.Fatalf("size = %v, want 2", item.Size)
	}
}

func TestRunInventoryPagination(t *testing.T) {
	t.Parallel()

	path := writeCLIFixture(t, "bundle.zip", cliZIP(t,
		"a.txt", "a", "b.txt", "b", "c.txt", "c", "d.txt", "d", "e.txt", "e"))

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(),
		[]string{"inventory", path, "--offset", "2", "--limit", "2"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"total: 5", "page: offset=2 limit=2 returned=2", "next: --offset 4 --limit 2", "[2] c.txt"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}

	stdout.Reset()
	code = Run(context.Background(),
		[]string{"inventory", path, "--json", "--offset", "4", "--limit", "2"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	var view inventoryView
	if err := json.Unmarshal(stdout.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	if len(view.Page.Items) != 1 || view.Page.NextOffset != nil {
		t.Fatalf("page = %+v", view.Page)
	}
	if view.Page.Items[0].Name != "e.txt" {
		t.Fatalf("item = %+v", view.Page.Items[0])
	}
}

func TestRunInventoryAPK(t *testing.T) {
	t.Parallel()

	path := writeCLIFixture(t, "app.apk", cliAPK(t))

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"inventory", path}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"format: apk", "schema: ree.payload.apk/1", "kind=manifest", "kind=dex"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "sha256=") {
		t.Fatalf("manifest digest missing:\n%s", out)
	}
}

func TestRunInventoryASARAndPlist(t *testing.T) {
	t.Parallel()

	asarPath := writeCLIFixture(t, "app.asar", cliASAR(t))
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"inventory", asarPath}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("asar Run() = %d; stderr=%q", code, stderr.String())
	}
	for _, want := range []string{"format: asar", "a.txt", "kind=file size=2"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("asar output missing %q:\n%s", want, stdout.String())
		}
	}

	plistPath := writeCLIFixture(t, "Info.plist", cliPlist())
	stdout.Reset()
	if code := Run(context.Background(), []string{"inventory", plistPath}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("plist Run() = %d; stderr=%q", code, stderr.String())
	}
	for _, want := range []string{"format: plist", "example.test", "total: 5"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("plist output missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestRunInventoryDeterministic(t *testing.T) {
	t.Parallel()

	path := writeCLIFixture(t, "bundle.zip", cliZIP(t, "b.txt", "b", "a.txt", "a"))

	var first, second, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"inventory", path, "--json"}, &first, &stderr); code != ExitOK {
		t.Fatalf("first Run() = %d; stderr=%q", code, stderr.String())
	}
	if code := Run(context.Background(), []string{"inventory", path, "--json"}, &second, &stderr); code != ExitOK {
		t.Fatalf("second Run() = %d; stderr=%q", code, stderr.String())
	}
	if first.String() != second.String() {
		t.Fatalf("inventory is not deterministic:\n%s\n%s", first.String(), second.String())
	}
}

func TestRunInventoryUnsupported(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"inventory", path}, &stdout, &stderr)
	if code != ExitUsage {
		t.Fatalf("Run() = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr.String(), "no inventory view") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "ree analyze") {
		t.Fatalf("stderr does not point at ree analyze: %q", stderr.String())
	}
}

func TestRunSearch(t *testing.T) {
	t.Parallel()

	path := writeCLIFixture(t, "bundle.zip", cliZIP(t,
		"lib/a.so", "a", "lib/b.so", "b", "README.md", "c"))

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(),
		[]string{"search", path, "--query", "LIB"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"REE Search", "query: LIB", "total: 2", "lib/a.so", "lib/b.so"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "README.md") {
		t.Fatalf("search kept a non-matching name:\n%s", out)
	}

	stdout.Reset()
	code = Run(context.Background(),
		[]string{"search", path, "--query", "nothing-here", "--json"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("empty Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	var view searchView
	if err := json.Unmarshal(stdout.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	if view.Query != "nothing-here" || view.Page.Total != 0 || len(view.Page.Items) != 0 {
		t.Fatalf("view = %+v", view)
	}
}

func TestRunCompare(t *testing.T) {
	t.Parallel()

	left := writeCLIFixture(t, "left.zip", cliZIP(t,
		"keep.txt", "aaa", "drop.txt", "x"))
	right := writeCLIFixture(t, "right.zip", cliZIP(t,
		"keep.txt", "bbbb", "new.txt", "y"))

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"compare", left, right}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"REE Compare",
		"left: left.zip (zip)",
		"right: right.zip (zip)",
		"added: 1",
		"removed: 1",
		"changed: 1",
		"new.txt",
		"drop.txt",
		"keep.txt",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}

	stdout.Reset()
	code = Run(context.Background(),
		[]string{"compare", left, right, "--json"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("json Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	var view compareView
	if err := json.Unmarshal(stdout.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v; output=%q", err, stdout.String())
	}
	if view.Left.Artifact != "left.zip" || view.Right.Artifact != "right.zip" {
		t.Fatalf("sides = %+v / %+v", view.Left, view.Right)
	}
	if view.Added.Total != 1 || view.Removed.Total != 1 || view.Changed.Total != 1 {
		t.Fatalf("diff = added %d, removed %d, changed %d",
			view.Added.Total, view.Removed.Total, view.Changed.Total)
	}
	if len(view.Changed.Changes) != 1 || view.Changed.Changes[0].Name != "keep.txt" {
		t.Fatalf("changed = %+v", view.Changed.Changes)
	}

	stdout.Reset()
	code = Run(context.Background(),
		[]string{"compare", left, right, "--json", "--limit", "1", "--offset", "1"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("paged Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	var paged compareView
	if err := json.Unmarshal(stdout.Bytes(), &paged); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	if paged.Added.Total != 1 || len(paged.Added.Items) != 0 {
		t.Fatalf("added page past the end = %+v", paged.Added)
	}
	if paged.Changed.Total != 1 || len(paged.Changed.Changes) != 0 {
		t.Fatalf("changed page past the end = %+v", paged.Changed)
	}
}

func TestRunInventoryFormatAndKindErrors(t *testing.T) {
	t.Parallel()

	elf := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())
	zipPath := writeCLIFixture(t, "bundle.zip", cliZIP(t, "a.txt", "a"))

	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(),
		[]string{"compare", elf, zipPath}, &stdout, &stderr); code != ExitUsage {
		t.Fatalf("compare with an executable = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr.String(), "no inventory view") {
		t.Fatalf("stderr = %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(context.Background(),
		[]string{"inventory", zipPath, "--format", "apk"}, &stdout, &stderr); code != ExitFailure {
		t.Fatalf("mismatched format = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr.String(), "apk") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunInventoryUsage(t *testing.T) {
	t.Parallel()

	path := writeCLIFixture(t, "bundle.zip", cliZIP(t, "a.txt", "a"))
	tests := [][]string{
		{"inventory"},
		{"inventory", path, path},
		{"inventory", path, "--offset", "-1"},
		{"inventory", path, "--limit", "0"},
		{"inventory", path, "--limit", "1001"},
		{"inventory", path, "--bogus"},
		{"search", path},
		{"search", path, "--query", "  "},
		{"compare", path},
		{"compare", path, path, path},
	}
	for _, args := range tests {
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), args, &stdout, &stderr); code != ExitUsage {
			t.Fatalf("Run(%q) = %d, want %d; stderr=%q", args, code, ExitUsage, stderr.String())
		}
	}
}

func TestRunInventoryFailures(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing.zip")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"inventory", missing}, &stdout, &stderr)
	if code != ExitFailure {
		t.Fatalf("Run() = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr.String(), "artifact not found") {
		t.Fatalf("stderr = %q", stderr.String())
	}

	stdout.Reset()
	code = Run(context.Background(), []string{"inventory", missing}, &stdout, &stderr)
	if code != ExitFailure {
		t.Fatalf("second Run() = %d, want %d", code, ExitFailure)
	}
}

func TestRunInventoryCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr bytes.Buffer
	if code := Run(ctx, []string{"inventory", "artifact.zip"}, &stdout, &stderr); code != ExitFailure {
		t.Fatalf("Run() = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr.String(), "context canceled") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestSplitFlagsValueFlags(t *testing.T) {
	t.Parallel()

	got := splitFlags([]string{"artifact.zip", "--offset", "2", "--limit=5", "--json"},
		valueFlags("offset", "limit"))
	want := []string{"--offset", "2", "--limit=5", "--json", "artifact.zip"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("splitFlags = %q, want %q", got, want)
	}
}
