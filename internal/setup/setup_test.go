package setup

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestDefaultSpecs(t *testing.T) {
	t.Parallel()

	specs := DefaultSpecs()
	got := make(map[string]Spec, len(specs))
	for _, spec := range specs {
		got[spec.Name] = spec
	}

	want := []string{
		"go", "git", "make", "golangci-lint", "govulncheck",
		"actionlint", "goreleaser", "cosign", "syft",
	}
	if len(got) != len(want) {
		t.Fatalf("DefaultSpecs() has %d unique tools, want %d", len(got), len(want))
	}
	for _, name := range want {
		spec, ok := got[name]
		if !ok {
			t.Fatalf("DefaultSpecs() missing %q", name)
		}
		if name == "go" || name == "git" {
			if !spec.Required {
				t.Fatalf("%q is not required", name)
			}
		} else if spec.Required {
			t.Fatalf("%q is required", name)
		}
		if len(spec.Args) == 0 {
			t.Fatalf("%q has no version arguments", name)
		}
	}
}

func TestDiagnoseMissingRequired(t *testing.T) {
	t.Parallel()

	report := Diagnose(context.Background(), []Spec{{
		Name:     "ree-tool-that-does-not-exist",
		Required: true,
		Args:     []string{"--version"},
	}})
	if report.OK {
		t.Fatal("Diagnose() OK = true, want false")
	}
	if len(report.Tools) != 1 {
		t.Fatalf("len(Tools) = %d, want 1", len(report.Tools))
	}
	if report.Tools[0].Status != StatusMissing {
		t.Fatalf("status = %q, want %q", report.Tools[0].Status, StatusMissing)
	}
	if report.Tools[0].Error == "" {
		t.Fatal("missing tool has empty error")
	}
}

func TestDiagnoseMissingOptional(t *testing.T) {
	t.Parallel()

	report := Diagnose(context.Background(), []Spec{{
		Name: "ree-tool-that-does-not-exist",
		Args: []string{"--version"},
	}})
	if !report.OK {
		t.Fatal("Diagnose() OK = false, want true")
	}
	if report.Tools[0].Status != StatusMissing {
		t.Fatalf("status = %q, want %q", report.Tools[0].Status, StatusMissing)
	}
}

func TestDiagnoseGo(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH")
	}

	report := Diagnose(context.Background(), []Spec{{
		Name:         "go",
		Required:     true,
		Args:         []string{"version"},
		VersionMatch: "go version",
	}})
	if !report.OK {
		t.Fatalf("Diagnose() OK = false; tools=%+v", report.Tools)
	}
	tool := report.Tools[0]
	if tool.Status != StatusOK {
		t.Fatalf("status = %q, want %q; error=%q", tool.Status, StatusOK, tool.Error)
	}
	if tool.Path == "" {
		t.Fatal("path is empty")
	}
	if !strings.Contains(tool.Version, "go version") {
		t.Fatalf("version = %q, want a go version line", tool.Version)
	}
}

func TestDiagnoseCommandError(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH")
	}

	report := Diagnose(context.Background(), []Spec{{
		Name: "go",
		Args: []string{"command-that-does-not-exist"},
	}})
	if !report.OK {
		t.Fatal("Diagnose() OK = false for an optional failed tool")
	}
	tool := report.Tools[0]
	if tool.Status != StatusError {
		t.Fatalf("status = %q, want %q; version=%q", tool.Status, StatusError, tool.Version)
	}
	if tool.Error == "" {
		t.Fatal("failed tool has empty error")
	}
}

func TestDiagnoseCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	report := Diagnose(ctx, []Spec{{
		Name:     "go",
		Required: true,
		Args:     []string{"version"},
	}})
	if report.OK {
		t.Fatal("Diagnose() OK = true, want false")
	}
	if report.Tools[0].Status != StatusError {
		t.Fatalf("status = %q, want %q", report.Tools[0].Status, StatusError)
	}
	if !strings.Contains(report.Tools[0].Error, context.Canceled.Error()) {
		t.Fatalf("error = %q, want cancellation", report.Tools[0].Error)
	}
}

func TestDiagnoseReportMetadata(t *testing.T) {
	t.Parallel()

	report := Diagnose(context.Background(), nil)
	if report.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version = %q, want %q", report.SchemaVersion, SchemaVersion)
	}
	if !report.OK {
		t.Fatal("empty report is not OK")
	}
	if report.Tools == nil {
		t.Fatal("tools is nil, want an empty slice")
	}
	if report.Platform.OS == "" || report.Platform.Arch == "" || report.Platform.GoVersion == "" {
		t.Fatalf("platform = %+v, want populated fields", report.Platform)
	}
}

func TestExtractVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		output string
		match  string
		want   string
	}{
		{
			name:   "first line",
			output: "go version go1.26.10 linux/amd64\n",
			want:   "go version go1.26.10 linux/amd64",
		},
		{
			name:   "matching line",
			output: "Go: go1.26.10\nScanner: govulncheck@v1.1.4\n",
			match:  "govulncheck",
			want:   "Scanner: govulncheck@v1.1.4",
		},
		{
			name:   "match not found",
			output: "Application: syft\nVersion: 1.55.0\n",
			match:  "missing",
			want:   "Application: syft",
		},
		{
			name:   "controls removed",
			output: "\x1b[31mversion 1.0\x1b[0m\r\n",
			want:   "[31mversion 1.0[0m",
		},
		{
			name: "empty",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := extractVersion(tt.output, tt.match); got != tt.want {
				t.Fatalf("extractVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCappedBuffer(t *testing.T) {
	t.Parallel()

	var buf cappedBuffer
	buf.max = 5
	n, err := buf.Write([]byte("abcdefgh"))
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != 8 {
		t.Fatalf("Write() = %d, want 8", n)
	}
	if got := buf.String(); got != "abcde" {
		t.Fatalf("String() = %q, want %q", got, "abcde")
	}

	if _, err := buf.Write([]byte("z")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if got := buf.String(); got != "abcde" {
		t.Fatalf("String() after overflow = %q, want %q", got, "abcde")
	}
}
