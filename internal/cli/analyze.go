package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/usecase/analyze"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/version"
)

func runAnalyze(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if err := ctx.Err(); err != nil {
		_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
		return ExitFailure
	}

	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "print the summary as JSON")
	format := fs.String("format", analyze.FormatAuto, "artifact format: auto, elf, pe, macho, zip, tar, gzip, apk, asar, or plist")
	maxBytes := fs.Int64("max-bytes", 0, "maximum artifact size in bytes; 0 uses the built-in limit")
	outPath := fs.String("out", "", "write the canonical evidence record to this file")
	force := fs.Bool("force", false, "overwrite an existing --out file")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr,
			"Usage: ree analyze <path> [--json] [--format auto|elf|pe|macho|zip|tar|gzip|apk|asar|plist] [--max-bytes N] [--out FILE] [--force]")
	}
	if err := fs.Parse(splitAnalyzeArgs(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "ree: analyze requires exactly one artifact path")
		return ExitUsage
	}
	if *force && *outPath == "" {
		_, _ = fmt.Fprintln(stderr, "ree: --force requires --out")
		return ExitUsage
	}
	if *outPath != "" && sameFile(fs.Arg(0), *outPath) {
		_, _ = fmt.Fprintln(stderr, "ree: --out must not name the artifact")
		return ExitUsage
	}

	result, err := analyze.Analyze(ctx, fs.Arg(0), analyze.Options{
		Format:          *format,
		ProviderVersion: version.Get().Version,
		MaxBytes:        *maxBytes,
	})
	if err != nil {
		switch {
		case errors.Is(err, analyze.ErrOptions):
			_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
			return ExitUsage
		case errors.Is(err, os.ErrNotExist):
			_, _ = fmt.Fprintf(stderr, "ree: artifact not found: %s\n", fs.Arg(0))
			return ExitFailure
		default:
			_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
			return ExitFailure
		}
	}

	if *outPath != "" {
		if err := writeRecord(*outPath, result.Bytes, *force); err != nil {
			_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
			return ExitFailure
		}
		_, _ = fmt.Fprintf(stderr, "ree: wrote %d-byte evidence record to %s\n", len(result.Bytes), *outPath)
	}

	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result.Summary); err != nil {
			_, _ = fmt.Fprintf(stderr, "ree: encode summary: %v\n", err)
			return ExitFailure
		}
		return ExitOK
	}

	printAnalyze(stdout, fs.Arg(0), result.Summary)
	return ExitOK
}

// splitAnalyzeArgs moves analyze flags ahead of the positional path.
func splitAnalyzeArgs(args []string) []string {
	return splitFlags(args, valueFlags("format", "max-bytes", "out"))
}

// splitFlags moves flags ahead of the positional arguments so that
// "ree inventory path --json" and "ree inventory --json path" behave the same.
// The standard flag package stops parsing at the first positional argument.
// valueFlags names the flags whose value is the next argument.
func splitFlags(args []string, valueFlags map[string]struct{}) []string {
	flags := make([]string, 0, len(args))
	positional := make([]string, 0, 1)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			positional = append(positional, arg)
			continue
		}
		flags = append(flags, arg)
		if strings.Contains(arg, "=") {
			continue
		}
		if _, ok := valueFlags[arg]; ok && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positional...)
}

// sameFile reports whether both paths name the same existing file.
func sameFile(a, b string) bool {
	first, err := os.Stat(a)
	if err != nil {
		return false
	}
	second, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(first, second)
}

// writeRecord writes canonical evidence bytes without a trailing newline.
//
// Existing files are preserved unless force is set: a record is evidence, and
// silently replacing one hides that two records share a path.
func writeRecord(path string, data []byte, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE
	if force {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	file, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite %s (use --force)", path)
		}
		return fmt.Errorf("write record: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write record: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	return nil
}

func printAnalyze(w io.Writer, path string, summary analyze.Summary) {
	_, _ = fmt.Fprintln(w, "REE Analyze")
	_, _ = fmt.Fprintf(w, "artifact: %s\n", filepath.Base(path))
	_, _ = fmt.Fprintf(w, "format: %s\n", summary.Format)
	_, _ = fmt.Fprintf(w, "provider: %s/%s (%s)\n", summary.ProviderID, summary.Profile, summary.Version)
	_, _ = fmt.Fprintf(w, "size: %d bytes\n", summary.Size)
	_, _ = fmt.Fprintf(w, "sha256: %s\n", summary.SHA256)
	_, _ = fmt.Fprintf(w, "record: %s\n", summary.RecordSHA256)
	_, _ = fmt.Fprintf(w, "coverage: %s\n", summary.Coverage)
	_, _ = fmt.Fprintf(w, "counts: sections=%d segments=%d symbols=%d imports=%d exports=%d resources=%d certificates=%d\n",
		summary.Counts.Sections,
		summary.Counts.Segments,
		summary.Counts.Symbols,
		summary.Counts.Imports,
		summary.Counts.Exports,
		summary.Counts.Resources,
		summary.Counts.Certificates,
	)
	printNotes(w, "limitations", summary.Limitations)
	printNotes(w, "unknowns", summary.Unknowns)
}

func printNotes(w io.Writer, label string, notes []string) {
	if len(notes) == 0 {
		_, _ = fmt.Fprintf(w, "%s: none\n", label)
		return
	}
	_, _ = fmt.Fprintf(w, "%s: %d\n", label, len(notes))
	for _, note := range notes {
		_, _ = fmt.Fprintf(w, "  - %s\n", note)
	}
}
