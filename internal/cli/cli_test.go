package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

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
