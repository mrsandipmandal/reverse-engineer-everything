package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/setup"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/version"
)

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "no arguments",
			wantCode:   ExitOK,
			wantStdout: "Usage: ree",
		},
		{
			name:       "help",
			args:       []string{"help"},
			wantCode:   ExitOK,
			wantStdout: "Usage: ree",
		},
		{
			name:       "unknown command",
			args:       []string{"nope"},
			wantCode:   ExitUsage,
			wantStderr: `unknown command "nope"`,
		},
		{
			name:       "version text",
			args:       []string{"version"},
			wantCode:   ExitOK,
			wantStdout: "Reverse Engineer Everything",
		},
		{
			name:       "version extra argument",
			args:       []string{"version", "extra"},
			wantCode:   ExitUsage,
			wantStderr: "version accepts no positional arguments",
		},
		{
			name:     "version bad flag",
			args:     []string{"version", "--bad"},
			wantCode: ExitUsage,
		},
		{
			name:     "version help",
			args:     []string{"version", "-h"},
			wantCode: ExitOK,
		},
		{
			name:     "doctor help",
			args:     []string{"doctor", "-h"},
			wantCode: ExitOK,
		},
		{
			name:       "doctor extra argument",
			args:       []string{"doctor", "extra"},
			wantCode:   ExitUsage,
			wantStderr: "doctor accepts no positional arguments",
		},
		{
			name:     "doctor bad flag",
			args:     []string{"doctor", "--bad"},
			wantCode: ExitUsage,
		},
		{
			name:     "mcp help",
			args:     []string{"mcp", "-h"},
			wantCode: ExitOK,
		},
		{
			name:       "mcp extra argument",
			args:       []string{"mcp", "extra"},
			wantCode:   ExitUsage,
			wantStderr: "mcp accepts no positional arguments",
		},
		{
			name:     "mcp bad flag",
			args:     []string{"mcp", "--bad"},
			wantCode: ExitUsage,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("Run() = %d, want %d; stdout=%q stderr=%q", code, tt.wantCode, stdout.String(), stderr.String())
			}
			if tt.wantStdout != "" && !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Fatalf("stdout = %q, want substring %q", stdout.String(), tt.wantStdout)
			}
			if tt.wantStderr != "" && !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestRunVersionJSON(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"version", "--json"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}

	var got version.Info
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode JSON: %v; output=%q", err, stdout.String())
	}
	want := version.Get()
	if got.Name != want.Name {
		t.Fatalf("name = %q, want %q", got.Name, want.Name)
	}
	if got.GoVersion != want.GoVersion {
		t.Fatalf("go_version = %q, want %q", got.GoVersion, want.GoVersion)
	}
	if got.OS != want.OS || got.Arch != want.Arch {
		t.Fatalf("platform = %s/%s, want %s/%s", got.OS, got.Arch, want.OS, want.Arch)
	}
}

func TestRunCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr bytes.Buffer
	code := Run(ctx, []string{"version"}, &stdout, &stderr)
	if code != ExitFailure {
		t.Fatalf("Run() = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr.String(), context.Canceled.Error()) {
		t.Fatalf("stderr = %q, want cancellation error", stderr.String())
	}
}

func TestRunDoctorJSON(t *testing.T) {
	t.Parallel()

	want := testDoctorReport(false)
	var stdout, stderr bytes.Buffer
	code := runDoctorWith(
		context.Background(),
		[]string{"--json"},
		&stdout,
		&stderr,
		func(context.Context) setup.Report { return want },
	)
	if code != ExitOK {
		t.Fatalf("runDoctorWith() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	var got setup.Report
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode JSON: %v; output=%q", err, stdout.String())
	}
	if got.SchemaVersion != want.SchemaVersion {
		t.Fatalf("schema_version = %q, want %q", got.SchemaVersion, want.SchemaVersion)
	}
	if got.OK != want.OK {
		t.Fatalf("ok = %t, want %t", got.OK, want.OK)
	}
	if len(got.Tools) != len(want.Tools) {
		t.Fatalf("tools = %d, want %d", len(got.Tools), len(want.Tools))
	}
	if got.Tools[0].Name != "go" || got.Tools[0].Status != setup.StatusMissing {
		t.Fatalf("first tool = %+v, want missing go", got.Tools[0])
	}
}

func TestRunDoctorText(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := runDoctorWith(
		context.Background(),
		nil,
		&stdout,
		&stderr,
		func(context.Context) setup.Report { return testDoctorReport(false) },
	)
	if code != ExitOK {
		t.Fatalf("runDoctorWith() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	for _, want := range []string{
		"REE Doctor",
		"platform: linux/amd64 (go1.26.10)",
		"result: required tools missing or broken",
		"missing  go (required)",
		"missing  goreleaser (optional)",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want substring %q", stdout.String(), want)
		}
	}
}

func TestRunDoctorReady(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := runDoctorWith(
		context.Background(),
		nil,
		&stdout,
		&stderr,
		func(context.Context) setup.Report { return testDoctorReport(true) },
	)
	if code != ExitOK {
		t.Fatalf("runDoctorWith() = %d, want %d; stderr=%q", code, ExitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "result: ready") {
		t.Fatalf("stdout = %q, want ready result", stdout.String())
	}
}

func TestRunDoctorCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr bytes.Buffer
	code := runDoctorWith(ctx, nil, &stdout, &stderr, func(context.Context) setup.Report {
		t.Fatal("diagnose called with a canceled context")
		return setup.Report{}
	})
	if code != ExitFailure {
		t.Fatalf("runDoctorWith() = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr.String(), context.Canceled.Error()) {
		t.Fatalf("stderr = %q, want cancellation error", stderr.String())
	}
}

func TestRunHelpListsCommands(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"help"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run() = %d, want %d", code, ExitOK)
	}
	for _, want := range []string{"analyze", "doctor", "mcp", "version"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
}

func testDoctorReport(ok bool) setup.Report {
	status := setup.StatusMissing
	if ok {
		status = setup.StatusOK
	}
	return setup.Report{
		SchemaVersion: setup.SchemaVersion,
		OK:            ok,
		Platform: setup.Platform{
			OS:        "linux",
			Arch:      "amd64",
			GoVersion: "go1.26.10",
		},
		Tools: []setup.Tool{
			{Name: "go", Required: true, Status: status, Version: "go version go1.26.10 linux/amd64"},
			{Name: "goreleaser", Status: setup.StatusMissing},
		},
	}
}
