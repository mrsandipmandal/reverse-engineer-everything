// Package setup detects local development and release tools.
package setup

import (
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	// SchemaVersion identifies the doctor report contract.
	SchemaVersion = "1"

	versionTimeout  = 2 * time.Second
	maxOutputBytes  = 64 << 10
	maxVersionRunes = 200
)

// Status describes the outcome of one tool probe.
type Status string

const (
	// StatusOK means the tool was found and its version command succeeded.
	StatusOK Status = "ok"
	// StatusMissing means the tool was not found on PATH.
	StatusMissing Status = "missing"
	// StatusError means the tool was found but could not be probed successfully.
	StatusError Status = "error"
)

// Spec declares one tool probe.
type Spec struct {
	// Name is the executable name passed to PATH lookup.
	Name string
	// Required controls whether a failure changes the overall report status.
	Required bool
	// Args are passed to the executable without shell interpretation.
	Args []string
	// VersionMatch selects the output line containing this case-insensitive
	// text. The first non-empty line is used when it is empty or not found.
	VersionMatch string
}

// Tool records the observed state of one tool.
type Tool struct {
	// Name is the executable name from its specification.
	Name string `json:"name"`
	// Required reports whether the tool is required for the overall report.
	Required bool `json:"required"`
	// Status is the probe outcome.
	Status Status `json:"status"`
	// Path is the resolved executable path when lookup succeeded.
	Path string `json:"path,omitempty"`
	// Version is the selected version output line.
	Version string `json:"version,omitempty"`
	// Error explains a missing or failed probe.
	Error string `json:"error,omitempty"`
}

// Platform describes the running build environment.
type Platform struct {
	// OS is the runtime operating system.
	OS string `json:"os"`
	// Arch is the runtime architecture.
	Arch string `json:"arch"`
	// GoVersion is the Go runtime version.
	GoVersion string `json:"go_version"`
}

// Report is the stable doctor output contract.
type Report struct {
	// SchemaVersion identifies the report format.
	SchemaVersion string `json:"schema_version"`
	// OK is false when any required tool is missing or failed.
	OK bool `json:"ok"`
	// Platform describes the environment running the probe.
	Platform Platform `json:"platform"`
	// Tools contains one entry per requested specification in input order.
	Tools []Tool `json:"tools"`
}

// DefaultSpecs returns the Phase 0b development and release tool probes.
func DefaultSpecs() []Spec {
	return []Spec{
		{Name: "go", Required: true, Args: []string{"version"}, VersionMatch: "go version"},
		{Name: "git", Required: true, Args: []string{"--version"}, VersionMatch: "git version"},
		{Name: "make", Args: []string{"--version"}, VersionMatch: "Make"},
		{Name: "golangci-lint", Args: []string{"--version"}, VersionMatch: "golangci-lint"},
		{Name: "govulncheck", Args: []string{"-version"}, VersionMatch: "govulncheck"},
		{Name: "actionlint", Args: []string{"-version"}},
		{Name: "goreleaser", Args: []string{"--version"}, VersionMatch: "GitVersion"},
		{Name: "cosign", Args: []string{"version"}, VersionMatch: "GitVersion"},
		{Name: "syft", Args: []string{"version"}, VersionMatch: "Version:"},
	}
}

// Diagnose probes every specification and returns an ordered report.
func Diagnose(ctx context.Context, specs []Spec) Report {
	report := Report{
		SchemaVersion: SchemaVersion,
		OK:            true,
		Platform: Platform{
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
			GoVersion: runtime.Version(),
		},
		Tools: make([]Tool, 0, len(specs)),
	}
	for _, spec := range specs {
		tool := checkTool(ctx, spec)
		report.Tools = append(report.Tools, tool)
		if spec.Required && tool.Status != StatusOK {
			report.OK = false
		}
	}
	return report
}

// DiagnoseDefault probes the Phase 0b tool set.
func DiagnoseDefault(ctx context.Context) Report {
	return Diagnose(ctx, DefaultSpecs())
}

func checkTool(ctx context.Context, spec Spec) Tool {
	tool := Tool{
		Name:     spec.Name,
		Required: spec.Required,
		Status:   StatusMissing,
	}
	if err := ctx.Err(); err != nil {
		tool.Status = StatusError
		tool.Error = err.Error()
		return tool
	}

	path, err := exec.LookPath(spec.Name)
	if err != nil {
		tool.Error = err.Error()
		return tool
	}
	tool.Path = path

	probeCtx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()

	cmd := exec.CommandContext(probeCtx, path, spec.Args...)
	cmd.WaitDelay = 500 * time.Millisecond

	var output cappedBuffer
	output.max = maxOutputBytes
	cmd.Stdout = &output
	cmd.Stderr = &output

	err = cmd.Run()
	tool.Version = extractVersion(output.String(), spec.VersionMatch)
	if err != nil {
		tool.Status = StatusError
		if probeCtx.Err() != nil {
			tool.Error = probeCtx.Err().Error()
		} else {
			tool.Error = err.Error()
		}
		return tool
	}

	tool.Status = StatusOK
	return tool
}

func extractVersion(output, match string) string {
	var first string
	for _, line := range strings.Split(output, "\n") {
		line = cleanLine(line)
		if line == "" {
			continue
		}
		if first == "" {
			first = line
		}
		if match == "" || strings.Contains(strings.ToLower(line), strings.ToLower(match)) {
			return line
		}
	}
	return first
}

func cleanLine(line string) string {
	line = strings.TrimSpace(line)
	line = strings.Map(func(r rune) rune {
		if r == '\t' || (r >= 0x20 && r != 0x7f) {
			return r
		}
		return -1
	}, line)
	runes := []rune(line)
	if len(runes) > maxVersionRunes {
		line = string(runes[:maxVersionRunes])
	}
	return strings.TrimSpace(line)
}

type cappedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	n := len(p)
	if b.max > 0 && b.buf.Len() < b.max {
		remaining := b.max - b.buf.Len()
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.buf.Write(p)
	}
	return n, nil
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
