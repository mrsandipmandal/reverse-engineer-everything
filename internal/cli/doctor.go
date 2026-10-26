package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/setup"
)

func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runDoctorWith(ctx, args, stdout, stderr, setup.DiagnoseDefault)
}

func runDoctorWith(
	ctx context.Context,
	args []string,
	stdout, stderr io.Writer,
	diagnose func(context.Context) setup.Report,
) int {
	if err := ctx.Err(); err != nil {
		_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
		return ExitFailure
	}

	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "print machine-readable JSON")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: ree doctor [--json]")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "ree: doctor accepts no positional arguments")
		return ExitUsage
	}

	report := diagnose(ctx)
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			_, _ = fmt.Fprintf(stderr, "ree: encode doctor report: %v\n", err)
			return ExitFailure
		}
		return ExitOK
	}

	printDoctor(stdout, report)
	return ExitOK
}

func printDoctor(w io.Writer, report setup.Report) {
	_, _ = fmt.Fprintln(w, "REE Doctor")
	_, _ = fmt.Fprintf(w, "platform: %s/%s (%s)\n", report.Platform.OS, report.Platform.Arch, report.Platform.GoVersion)
	if report.OK {
		_, _ = fmt.Fprintln(w, "result: ready")
	} else {
		_, _ = fmt.Fprintln(w, "result: required tools missing or broken")
	}
	_, _ = fmt.Fprintln(w)

	for _, tool := range report.Tools {
		requirement := "optional"
		if tool.Required {
			requirement = "required"
		}
		switch tool.Status {
		case setup.StatusOK:
			_, _ = fmt.Fprintf(w, "  ok       %s (%s): %s\n", tool.Name, requirement, tool.Version)
		case setup.StatusMissing:
			_, _ = fmt.Fprintf(w, "  missing  %s (%s)\n", tool.Name, requirement)
		case setup.StatusError:
			_, _ = fmt.Fprintf(w, "  error    %s (%s): %s\n", tool.Name, requirement, tool.Error)
		default:
			_, _ = fmt.Fprintf(w, "  unknown  %s (%s): %s\n", tool.Name, requirement, tool.Status)
		}
	}
}
