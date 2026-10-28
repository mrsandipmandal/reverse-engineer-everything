package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/usecase/analyze"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/version"
)

func TestRunAnalyzeJSON(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"analyze", path, "--json"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	var summary analyze.Summary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode summary: %v; output=%q", err, stdout.String())
	}
	if summary.Format != analyze.FormatELF {
		t.Fatalf("format = %q, want %q", summary.Format, analyze.FormatELF)
	}
	if summary.ProviderID != "builtin.elf" || summary.Profile != "default" {
		t.Fatalf("provider = %s/%s, want builtin.elf/default", summary.ProviderID, summary.Profile)
	}
	if summary.Version != version.Get().Version {
		t.Fatalf("version = %q, want %q", summary.Version, version.Get().Version)
	}
	if summary.Size != int64(len(minimalAnalyzeELF64())) {
		t.Fatalf("size = %d, want %d", summary.Size, len(minimalAnalyzeELF64()))
	}
	if len(summary.SHA256) != 64 || len(summary.RecordSHA256) != 64 {
		t.Fatalf("digests = %q / %q, want 64 hex characters", summary.SHA256, summary.RecordSHA256)
	}
	if summary.Coverage != "complete" {
		t.Fatalf("coverage = %q, want complete", summary.Coverage)
	}
	if summary.Counts.Sections != 0 || summary.Counts.Segments != 0 || summary.Counts.Symbols != 0 {
		t.Fatalf("counts = %+v, want zero tables", summary.Counts)
	}
}

func TestRunAnalyzePE(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "sample.exe", minimalAnalyzePE32())

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"analyze", path, "--json", "--format", "pe"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}

	var summary analyze.Summary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode summary: %v; output=%q", err, stdout.String())
	}
	if summary.Format != analyze.FormatPE || summary.ProviderID != "builtin.pe" {
		t.Fatalf("summary = %+v, want a PE summary", summary)
	}
	if summary.Counts.Imports != 0 || summary.Counts.Exports != 0 || summary.Counts.Resources != 0 || summary.Counts.Certificates != 0 {
		t.Fatalf("counts = %+v, want zero directory tables", summary.Counts)
	}
}

func TestRunAnalyzeText(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"analyze", path}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}

	for _, want := range []string{
		"REE Analyze",
		"artifact: sample.elf",
		"format: elf",
		"provider: builtin.elf/default (" + version.Get().Version + ")",
		"size: 64 bytes",
		"coverage: complete",
		"counts: sections=0 segments=0 symbols=0 imports=0 exports=0 resources=0 certificates=0",
		"limitations: none",
		"unknowns: none",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want substring %q", stdout.String(), want)
		}
	}
}

func TestRunAnalyzeWritesRecord(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())
	outPath := filepath.Join(t.TempDir(), "record.json")

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"analyze", path, "--json", "--out", outPath}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	if !strings.Contains(stderr.String(), "wrote ") {
		t.Fatalf("stderr = %q, want a write confirmation", stderr.String())
	}

	var summary analyze.Summary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("stdout is not valid JSON: %v; output=%q", err, stdout.String())
	}

	written, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	record, err := evidence.Decode(written)
	if err != nil {
		t.Fatalf("decode record: %v", err)
	}
	digest, err := record.Digest()
	if err != nil {
		t.Fatalf("digest record: %v", err)
	}
	if digest != summary.RecordSHA256 {
		t.Fatalf("record digest = %q, want summary digest %q", digest, summary.RecordSHA256)
	}
}

func TestRunAnalyzeRefusesOverwrite(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())
	outPath := filepath.Join(t.TempDir(), "record.json")
	const sentinel = "keep me"

	if err := os.WriteFile(outPath, []byte(sentinel), 0o600); err != nil {
		t.Fatalf("seed record: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"analyze", path, "--out", outPath}, &stdout, &stderr)
	if code != ExitFailure {
		t.Fatalf("Run() = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr.String(), "use --force") {
		t.Fatalf("stderr = %q, want an overwrite refusal", stderr.String())
	}
	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if string(content) != sentinel {
		t.Fatalf("existing record content = %q, want it unchanged", content)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"analyze", path, "--out", outPath, "--force"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() with --force = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	content, err = os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if _, err := evidence.Decode(content); err != nil {
		t.Fatalf("forced record does not decode: %v", err)
	}
}

func TestRunAnalyzeRefusesArtifactAsOut(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"analyze", path, "--out", path, "--force"}, &stdout, &stderr)
	if code != ExitUsage {
		t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--out must not name the artifact") {
		t.Fatalf("stderr = %q, want the artifact guard message", stderr.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	if !bytes.Equal(data, minimalAnalyzeELF64()) {
		t.Fatalf("artifact was modified by analyze")
	}
}

func TestRunAnalyzeDeterministic(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())

	var first, second bytes.Buffer
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"analyze", path, "--json"}, &first, &stderr); code != ExitOK {
		t.Fatalf("first Run() = %d; stderr=%q", code, stderr.String())
	}
	stderr.Reset()
	if code := Run(context.Background(), []string{"analyze", path, "--json"}, &second, &stderr); code != ExitOK {
		t.Fatalf("second Run() = %d; stderr=%q", code, stderr.String())
	}
	if first.String() != second.String() {
		t.Fatalf("outputs differ:\nfirst=%q\nsecond=%q", first.String(), second.String())
	}
}

func TestRunAnalyzeDoesNotLeakPath(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())
	dir := filepath.Dir(path)

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"analyze", path, "--json"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	for _, leak := range []string{dir, "sample.elf"} {
		if strings.Contains(stdout.String(), leak) {
			t.Fatalf("stdout leaks %q: %q", leak, stdout.String())
		}
	}
}

func TestRunAnalyzeUsage(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())

	tests := []struct {
		name string
		args []string
	}{
		{name: "missing path", args: nil},
		{name: "extra path", args: []string{path, path}},
		{name: "unknown format", args: []string{path, "--format", "macho"}},
		{name: "negative max bytes", args: []string{path, "--max-bytes", "-1"}},
		{name: "non-numeric max bytes", args: []string{path, "--max-bytes", "lots"}},
		{name: "force without out", args: []string{path, "--force"}},
		{name: "bad flag", args: []string{path, "--nope"}},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), append([]string{"analyze"}, tt.args...), &stdout, &stderr); code != ExitUsage {
				t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitUsage, stderr.String())
			}
		})
	}
}

func TestRunAnalyzeFailures(t *testing.T) {
	t.Parallel()

	elfPath := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())
	pePath := writeAnalyzeFixture(t, "sample.exe", minimalAnalyzePE32())
	textPath := writeAnalyzeFixture(t, "notes.txt", []byte("not an executable"))
	missing := filepath.Join(t.TempDir(), "missing.elf")
	dirPath := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "absent", "record.json")

	tests := []struct {
		name       string
		args       []string
		wantStderr string
	}{
		{name: "unsupported artifact", args: []string{textPath}, wantStderr: "unsupported format"},
		{name: "missing artifact", args: []string{missing}, wantStderr: "artifact not found"},
		{name: "directory", args: []string{dirPath}, wantStderr: "not a regular file"},
		{name: "too large", args: []string{elfPath, "--max-bytes", "32"}, wantStderr: "exceeds"},
		{name: "format mismatch", args: []string{pePath, "--format", "elf"}, wantStderr: "elf"},
		{name: "unwritable out", args: []string{elfPath, "--out", outDir}, wantStderr: "write record"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), append([]string{"analyze"}, tt.args...), &stdout, &stderr); code != ExitFailure {
				t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitFailure, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestSplitAnalyzeArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "path first", in: []string{"a", "--json"}, want: []string{"--json", "a"}},
		{name: "flags first", in: []string{"--json", "a"}, want: []string{"--json", "a"}},
		{name: "value flag", in: []string{"a", "--format", "pe"}, want: []string{"--format", "pe", "a"}},
		{name: "inline value", in: []string{"a", "--format=pe"}, want: []string{"--format=pe", "a"}},
		{name: "negative value", in: []string{"a", "--max-bytes", "-1"}, want: []string{"--max-bytes", "-1", "a"}},
		{name: "terminator", in: []string{"--json", "--", "-x"}, want: []string{"--json", "-x"}},
		{name: "single dash positional", in: []string{"-", "--json"}, want: []string{"--json", "-"}},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := splitAnalyzeArgs(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("splitAnalyzeArgs(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRunAnalyzeCanceledContext(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr bytes.Buffer
	code := runAnalyze(ctx, []string{path}, &stdout, &stderr)
	if code != ExitFailure {
		t.Fatalf("runAnalyze() = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr.String(), context.Canceled.Error()) {
		t.Fatalf("stderr = %q, want cancellation error", stderr.String())
	}
}

// minimalAnalyzeELF64 is a valid 64-byte ELF64 header with no sections or
// segments.
func minimalAnalyzeELF64() []byte {
	data := make([]byte, 64)
	copy(data[0:4], "\x7fELF")
	data[4] = 2
	data[5] = 1
	data[6] = 1
	binary.LittleEndian.PutUint16(data[16:], 2)
	binary.LittleEndian.PutUint16(data[18:], 0x3e)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint16(data[52:], 64)
	return data
}

// minimalAnalyzePE32 is a valid 512-byte PE32 image with no data directories
// and no sections.
func minimalAnalyzePE32() []byte {
	const (
		peOffset  = 0x80
		coffSize  = 20
		optOffset = peOffset + 4 + coffSize
	)
	data := make([]byte, 512)
	binary.LittleEndian.PutUint16(data[0:], 0x5a4d)
	binary.LittleEndian.PutUint32(data[0x3c:], peOffset)

	copy(data[peOffset:], "PE\x00\x00")
	coff := data[peOffset+4:]
	binary.LittleEndian.PutUint16(coff[0:], 0x14c)
	binary.LittleEndian.PutUint16(coff[2:], 0)
	binary.LittleEndian.PutUint16(coff[16:], 96)
	binary.LittleEndian.PutUint16(coff[18:], 0x0102)

	opt := data[optOffset:]
	binary.LittleEndian.PutUint16(opt[0:], 0x10b)
	binary.LittleEndian.PutUint32(opt[28:], 0x400000)
	binary.LittleEndian.PutUint32(opt[32:], 0x1000)
	binary.LittleEndian.PutUint32(opt[36:], 0x200)
	binary.LittleEndian.PutUint32(opt[56:], 0x1000)
	binary.LittleEndian.PutUint32(opt[60:], 0x200)
	binary.LittleEndian.PutUint16(opt[68:], 3)
	binary.LittleEndian.PutUint32(opt[92:], 0)
	return data
}

func writeAnalyzeFixture(t testing.TB, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture %q: %v", name, err)
	}
	return path
}
