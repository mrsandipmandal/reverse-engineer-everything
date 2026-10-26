package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/mcp"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/version"
)

func runMCP(ctx context.Context, args []string, stderr io.Writer) int {
	if err := ctx.Err(); err != nil {
		_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
		return ExitFailure
	}

	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: ree mcp")
		_, _ = fmt.Fprintln(stderr, "Run the REE MCP server over stdin/stdout.")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "ree: mcp accepts no positional arguments")
		return ExitUsage
	}

	if err := mcp.Run(ctx, version.Get()); err != nil {
		_, _ = fmt.Fprintf(stderr, "ree: mcp: %v\n", err)
		return ExitFailure
	}
	return ExitOK
}
