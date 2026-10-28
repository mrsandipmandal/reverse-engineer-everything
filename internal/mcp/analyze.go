package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/usecase/analyze"
)

const (
	// AnalyzeToolName is the artifact analysis tool.
	AnalyzeToolName = "ree_analyze"
	// MaxRecordToolBytes bounds the evidence record a tool result carries.
	MaxRecordToolBytes = 1 << 20
)

// analyzeInput is the ree_analyze argument object.
type analyzeInput struct {
	Path          string `json:"path" jsonschema:"Path to one local ELF, PE, or Mach-O artifact."`
	Format        string `json:"format,omitempty" jsonschema:"Provider selection: auto (default), elf, pe, or macho. Detection never falls back when a format is given."`
	MaxBytes      int64  `json:"max_bytes,omitempty" jsonschema:"Maximum artifact size in bytes. Zero uses the built-in limit of 2 GiB."`
	IncludeRecord bool   `json:"include_record,omitempty" jsonschema:"Return the sealed ree.evidence/1 record when it fits the tool limit. The default is false."`
}

// analyzeReport is the ree_analyze result object.
type analyzeReport struct {
	Summary       analyze.Summary `json:"summary"`
	Record        any             `json:"record,omitempty" jsonschema:"The sealed ree.evidence/1 record, present only when include_record is true and the record fits the tool limit."`
	RecordOmitted string          `json:"record_omitted,omitempty" jsonschema:"Why the record is absent although include_record was true."`
}

// analyzeArtifact runs one analysis for the tool with a path-free result.
func analyzeArtifact(ctx context.Context, in analyzeInput, providerVersion string) (analyzeReport, error) {
	path := strings.TrimSpace(in.Path)
	if path == "" {
		return analyzeReport{}, errors.New("path is required")
	}
	result, err := analyze.Analyze(ctx, path, analyze.Options{
		Format:          in.Format,
		ProviderVersion: providerVersion,
		MaxBytes:        in.MaxBytes,
	})
	if err != nil {
		return analyzeReport{}, analyzeToolError(path, err)
	}
	return analyzeReportFor(result, in.IncludeRecord), nil
}

// analyzeReportFor projects a result into the tool shape.
//
// The record is the exact canonical ree.evidence/1 bytes, so its digest matches
// summary.record_sha256. A record above MaxRecordToolBytes is replaced by an
// explanation instead of being sent, because the tool result is not the place
// for an unbounded document.
func analyzeReportFor(result analyze.Result, includeRecord bool) analyzeReport {
	report := analyzeReport{Summary: result.Summary}
	if !includeRecord {
		return report
	}
	if len(result.Bytes) > MaxRecordToolBytes {
		report.RecordOmitted = fmt.Sprintf(
			"record is %d bytes, above the %d-byte tool limit; export it with ree analyze --out",
			len(result.Bytes), MaxRecordToolBytes,
		)
		return report
	}
	report.Record = json.RawMessage(result.Bytes)
	return report
}

// analyzeToolError maps use case failures to a message an agent can act on.
func analyzeToolError(path string, err error) error {
	path = strings.TrimSpace(path)
	switch {
	case errors.Is(err, analyze.ErrOptions):
		return fmt.Errorf("invalid arguments: %w", err)
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("artifact not found: %s", path)
	case errors.Is(err, analyze.ErrNotRegular):
		return fmt.Errorf("path is not a regular file: %s", path)
	case errors.Is(err, analyze.ErrTooLarge):
		return fmt.Errorf("artifact exceeds the size limit: %w", err)
	case errors.Is(err, analyze.ErrUnsupportedFormat):
		return fmt.Errorf("unsupported format: %w (set format to elf, pe, or macho to read it anyway)", err)
	default:
		return err
	}
}
