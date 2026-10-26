package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/version"
)

func runVersion(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if err := ctx.Err(); err != nil {
		_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
		return ExitFailure
	}

	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "print machine-readable JSON")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: ree version [--json]")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "ree: version accepts no positional arguments")
		return ExitUsage
	}

	info := version.Get()
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(info); err != nil {
			_, _ = fmt.Fprintf(stderr, "ree: encode version: %v\n", err)
			return ExitFailure
		}
		return ExitOK
	}

	_, _ = fmt.Fprintf(stdout,
		"%s\nversion: %s\ncommit: %s\nbuilt: %s\ngo: %s\nplatform: %s/%s\n",
		version.DisplayName,
		info.Version,
		info.Commit,
		info.Built,
		info.GoVersion,
		info.OS,
		info.Arch,
	)
	return ExitOK
}
