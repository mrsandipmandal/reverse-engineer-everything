package analyze

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
)

const testVersion = "0.1.0"

func TestAnalyzeELF(t *testing.T) {
	path := writeArtifact(t, "sample.elf", minimalELF64())

	result, err := Analyze(context.Background(), path, Options{ProviderVersion: testVersion})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	summary := result.Summary
	if summary.Format != FormatELF {
		t.Errorf("format = %q, want %q", summary.Format, FormatELF)
	}
	if summary.ProviderID != "builtin.elf" {
		t.Errorf("provider id = %q, want builtin.elf", summary.ProviderID)
	}
	if summary.Profile != "default" {
		t.Errorf("profile = %q, want default", summary.Profile)
	}
	if summary.Version != testVersion {
		t.Errorf("version = %q, want %q", summary.Version, testVersion)
	}
	if summary.Size != 64 {
		t.Errorf("size = %d, want 64", summary.Size)
	}
	if summary.Coverage != string(evidence.CoverageComplete) {
		t.Errorf("coverage = %q, want complete; limitations=%v unknowns=%v",
			summary.Coverage, summary.Limitations, summary.Unknowns)
	}
	if summary.SHA256 == "" || summary.RecordSHA256 == "" {
		t.Error("digests must be set")
	}
	if len(summary.Limitations) != 0 || len(summary.Unknowns) != 0 {
		t.Errorf("limitations=%v unknowns=%v, want empty", summary.Limitations, summary.Unknowns)
	}
	if summary.Counts != (Counts{}) {
		t.Errorf("counts = %+v, want zero", summary.Counts)
	}

	assertRecordRoundTrip(t, result)
}

func TestAnalyzePE(t *testing.T) {
	path := writeArtifact(t, "sample.exe", minimalPE32())

	result, err := Analyze(context.Background(), path, Options{ProviderVersion: testVersion})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	summary := result.Summary
	if summary.Format != FormatPE {
		t.Errorf("format = %q, want %q", summary.Format, FormatPE)
	}
	if summary.ProviderID != "builtin.pe" {
		t.Errorf("provider id = %q, want builtin.pe", summary.ProviderID)
	}
	if summary.Size != 512 {
		t.Errorf("size = %d, want 512", summary.Size)
	}
	if summary.Coverage != string(evidence.CoverageComplete) {
		t.Errorf("coverage = %q, want complete; limitations=%v unknowns=%v",
			summary.Coverage, summary.Limitations, summary.Unknowns)
	}
	if summary.Counts != (Counts{}) {
		t.Errorf("counts = %+v, want zero", summary.Counts)
	}

	assertRecordRoundTrip(t, result)
}

// assertRecordRoundTrip checks that the sealed bytes decode, that the digest
// matches, and that the decoded record equals the returned one.
func assertRecordRoundTrip(t *testing.T, result Result) {
	t.Helper()

	decoded, err := evidence.Decode(result.Bytes)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	digest, err := decoded.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if digest != result.Summary.RecordSHA256 {
		t.Errorf("record digest = %q, summary = %q", digest, result.Summary.RecordSHA256)
	}
	if decoded.Subject.SHA256 != result.Summary.SHA256 {
		t.Errorf("subject digest = %q, summary = %q", decoded.Subject.SHA256, result.Summary.SHA256)
	}
	if decoded.Subject.Size != result.Summary.Size {
		t.Errorf("subject size = %d, summary = %d", decoded.Subject.Size, result.Summary.Size)
	}
	if decoded.Provider.Version != result.Summary.Version {
		t.Errorf("provider version = %q, summary = %q", decoded.Provider.Version, result.Summary.Version)
	}
	if decoded.Coverage != evidence.Coverage(result.Summary.Coverage) {
		t.Errorf("coverage = %q, summary = %q", decoded.Coverage, result.Summary.Coverage)
	}
}

func TestAnalyzeExplicitFormat(t *testing.T) {
	tests := []struct {
		name   string
		format string
		data   []byte
		want   string
	}{
		{name: "elf padded case and spaces", format: " ELF ", data: minimalELF64(), want: FormatELF},
		{name: "elf uppercased", format: "Elf", data: minimalELF64(), want: FormatELF},
		{name: "pe uppercased", format: "PE", data: minimalPE32(), want: FormatPE},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeArtifact(t, "artifact.bin", tc.data)
			result, err := Analyze(context.Background(), path, Options{
				Format:          tc.format,
				ProviderVersion: testVersion,
			})
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if result.Summary.Format != tc.want {
				t.Errorf("format = %q, want %q", result.Summary.Format, tc.want)
			}
		})
	}
}

// TestAnalyzeExplicitFormatMismatch checks that a wrong explicit format fails
// instead of silently falling back to magic detection.
func TestAnalyzeExplicitFormatMismatch(t *testing.T) {
	tests := []struct {
		name   string
		format string
		data   []byte
	}{
		{name: "elf bytes as pe", format: FormatPE, data: minimalELF64()},
		{name: "pe bytes as elf", format: FormatELF, data: minimalPE32()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeArtifact(t, "artifact.bin", tc.data)
			_, err := Analyze(context.Background(), path, Options{
				Format:          tc.format,
				ProviderVersion: testVersion,
			})
			if err == nil {
				t.Fatal("Analyze succeeded, want a provider parse error")
			}
			if errors.Is(err, ErrUnsupportedFormat) {
				t.Errorf("error = %v, want a provider error rather than unsupported format", err)
			}
		})
	}
}

func TestAnalyzeUnsupportedFormat(t *testing.T) {
	path := writeArtifact(t, "notes.txt", []byte("this is not an executable artifact\n"))

	_, err := Analyze(context.Background(), path, Options{ProviderVersion: testVersion})
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("error = %v, want ErrUnsupportedFormat", err)
	}
}

func TestAnalyzeRejectsOptions(t *testing.T) {
	path := writeArtifact(t, "sample.elf", minimalELF64())

	tests := []struct {
		name    string
		opts    Options
		want    error
		wantMsg string
	}{
		{name: "missing version", opts: Options{}, want: ErrOptions, wantMsg: "provider version"},
		{name: "unknown format", opts: Options{Format: "macho", ProviderVersion: testVersion}, want: ErrOptions, wantMsg: "unknown format"},
		{name: "negative max bytes", opts: Options{ProviderVersion: testVersion, MaxBytes: -1}, want: ErrOptions, wantMsg: "negative"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Analyze(context.Background(), path, tc.opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantMsg)
			}
		})
	}
}

func TestAnalyzeTooLarge(t *testing.T) {
	path := writeArtifact(t, "sample.elf", minimalELF64())

	_, err := Analyze(context.Background(), path, Options{ProviderVersion: testVersion, MaxBytes: 32})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v, want ErrTooLarge", err)
	}
}

// TestAnalyzeMaxBytesClamped checks that a limit above the hard cap is clamped
// rather than rejected, so a caller cannot raise the parser bound.
func TestAnalyzeMaxBytesClamped(t *testing.T) {
	path := writeArtifact(t, "sample.elf", minimalELF64())

	if _, err := Analyze(context.Background(), path, Options{
		ProviderVersion: testVersion,
		MaxBytes:        MaxArtifactBytes * 2,
	}); err != nil {
		t.Fatalf("Analyze: %v", err)
	}
}

func TestAnalyzeNotRegular(t *testing.T) {
	if _, err := Analyze(context.Background(), t.TempDir(), Options{ProviderVersion: testVersion}); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("error = %v, want ErrNotRegular", err)
	}
}

func TestAnalyzeMissingFile(t *testing.T) {
	_, err := Analyze(context.Background(), writeTempPath(t, "absent.elf"), Options{ProviderVersion: testVersion})
	if err == nil {
		t.Fatal("Analyze succeeded for a missing file")
	}
	if errors.Is(err, ErrUnsupportedFormat) || errors.Is(err, ErrTooLarge) {
		t.Errorf("error = %v, want a file system error", err)
	}
}

func TestAnalyzeContextCanceled(t *testing.T) {
	path := writeArtifact(t, "sample.elf", minimalELF64())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := Analyze(ctx, path, Options{ProviderVersion: testVersion}); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

// TestAnalyzeDeterministic checks that identical bytes and options produce
// identical record bytes and summaries, independent of the file path.
func TestAnalyzeDeterministic(t *testing.T) {
	data := minimalPE32()
	first := writeArtifact(t, "first.exe", data)
	second := writeArtifact(t, "second.exe", data)

	a, err := Analyze(context.Background(), first, Options{ProviderVersion: testVersion})
	if err != nil {
		t.Fatalf("Analyze first: %v", err)
	}
	b, err := Analyze(context.Background(), second, Options{ProviderVersion: testVersion})
	if err != nil {
		t.Fatalf("Analyze second: %v", err)
	}
	if string(a.Bytes) != string(b.Bytes) {
		t.Error("record bytes differ for identical artifacts")
	}
	if a.Summary.RecordSHA256 != b.Summary.RecordSHA256 {
		t.Errorf("record digests differ: %q and %q", a.Summary.RecordSHA256, b.Summary.RecordSHA256)
	}
}

// TestAnalyzeNoPathInEvidence checks that neither the summary JSON nor the
// sealed record discloses the artifact path.
func TestAnalyzeNoPathInEvidence(t *testing.T) {
	const marker = "host-secret-marker"
	dir := t.TempDir()
	path := filepath.Join(dir, marker+".elf")
	if err := os.WriteFile(path, minimalELF64(), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	result, err := Analyze(context.Background(), path, Options{ProviderVersion: testVersion})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	summary, err := json.Marshal(result.Summary)
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	for name, data := range map[string][]byte{
		"summary": summary,
		"record":  result.Bytes,
	} {
		if strings.Contains(string(data), marker) {
			t.Errorf("%s contains the artifact file name", name)
		}
		if strings.Contains(string(data), dir) {
			t.Errorf("%s contains the artifact directory", name)
		}
	}
}

func TestAnalyzeSummaryJSONShape(t *testing.T) {
	path := writeArtifact(t, "sample.elf", minimalELF64())

	result, err := Analyze(context.Background(), path, Options{ProviderVersion: testVersion})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	data, err := json.Marshal(result.Summary)
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}

	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		t.Fatalf("unmarshal summary: %v", err)
	}
	for _, name := range []string{
		"format", "provider_id", "profile", "version", "size", "sha256",
		"record_sha256", "coverage", "limitations", "unknowns", "counts",
	} {
		if _, ok := members[name]; !ok {
			t.Errorf("summary is missing %q", name)
		}
	}
	// Empty lists must encode as [] rather than null.
	if got := string(members["limitations"]); got != "[]" {
		t.Errorf("limitations = %s, want []", got)
	}
	if got := string(members["unknowns"]); got != "[]" {
		t.Errorf("unknowns = %s, want []", got)
	}
}

func TestCountPayload(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		payload string
		want    Counts
	}{
		{
			name:    "elf tables",
			format:  FormatELF,
			payload: `{"schema":"ree.payload.elf/1","sections":[{},{}],"segments":[{}],"symbols":[{},{},{}]}`,
			want:    Counts{Sections: 2, Segments: 1, Symbols: 3},
		},
		{
			name:    "elf empty",
			format:  FormatELF,
			payload: `{"schema":"ree.payload.elf/1","sections":[],"segments":[],"symbols":[]}`,
			want:    Counts{},
		},
		{
			name:    "pe tables",
			format:  FormatPE,
			payload: `{"schema":"ree.payload.pe/1","sections":[{},{}],"imports":{"modules":[{},{}]},"exports":{"exports":[{}]},"resources":{"resources":[{},{},{}]},"certificates":{"certificates":[{}]}}`,
			want:    Counts{Sections: 2, Imports: 2, Exports: 1, Resources: 3, Certificates: 1},
		},
		{
			name:    "pe absent directories",
			format:  FormatPE,
			payload: `{"schema":"ree.payload.pe/1","sections":[{}],"imports":null,"exports":null,"resources":null,"certificates":null}`,
			want:    Counts{Sections: 1},
		},
		{
			name:    "pe exported but empty tables",
			format:  FormatPE,
			payload: `{"schema":"ree.payload.pe/1","sections":[],"imports":{"modules":[]},"exports":{"exports":[]},"resources":{"resources":[]},"certificates":{"certificates":[]}}`,
			want:    Counts{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := countPayload(tc.format, []byte(tc.payload))
			if err != nil {
				t.Fatalf("countPayload: %v", err)
			}
			if got != tc.want {
				t.Errorf("counts = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestCountPayloadRejects(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		payload string
	}{
		{name: "unknown format", format: "macho", payload: `{}`},
		{name: "invalid json", format: FormatELF, payload: `{`},
		{name: "wrong elf schema", format: FormatELF, payload: `{"schema":"ree.payload.pe/1"}`},
		{name: "missing elf schema", format: FormatELF, payload: `{}`},
		{name: "invalid pe json", format: FormatPE, payload: `{`},
		{name: "wrong pe schema", format: FormatPE, payload: `{"schema":"ree.payload.elf/1"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := countPayload(tc.format, []byte(tc.payload)); err == nil {
				t.Fatal("countPayload succeeded, want an error")
			}
		})
	}
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{name: "elf", data: minimalELF64(), want: FormatELF},
		{name: "pe", data: minimalPE32(), want: FormatPE},
		{name: "bare mz", data: []byte("MZ"), want: FormatPE},
		{name: "three bytes", data: []byte("\x7fEL"), wantErr: true},
		{name: "empty", data: nil, wantErr: true},
		{name: "text", data: []byte("PK\x03\x04"), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeArtifact(t, "artifact.bin", tc.data)
			file, err := os.Open(path)
			if err != nil {
				t.Fatalf("open fixture: %v", err)
			}
			defer func() { _ = file.Close() }()

			got, err := detect(file)
			if tc.wantErr {
				if !errors.Is(err, ErrUnsupportedFormat) {
					t.Fatalf("error = %v, want ErrUnsupportedFormat", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("detect: %v", err)
			}
			if got != tc.want {
				t.Errorf("format = %q, want %q", got, tc.want)
			}
		})
	}
}

// errReader fails every read, so detection has to surface the reader error
// rather than reporting an unsupported format.
type errReader struct{ err error }

func (r errReader) ReadAt([]byte, int64) (int, error) { return 0, r.err }

func TestDetectReadError(t *testing.T) {
	want := errors.New("device gone")
	if _, err := detect(errReader{err: want}); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}
