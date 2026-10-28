// Package cli implements the ree command tree.
package cli

import (
	"context"
	"fmt"
	"io"
)

const (
	// ExitOK indicates success.
	ExitOK = 0
	// ExitFailure indicates an operational failure.
	ExitFailure = 1
	// ExitUsage indicates invalid command-line usage.
	ExitUsage = 2
)

// Run executes one CLI invocation and returns a process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if err := ctx.Err(); err != nil {
		_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
		return ExitFailure
	}

	if len(args) == 0 {
		printUsage(stdout)
		return ExitOK
	}

	switch args[0] {
	case "analyze":
		return runAnalyze(ctx, args[1:], stdout, stderr)
	case "version":
		return runVersion(ctx, args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout, stderr)
	case "mcp":
		return runMCP(ctx, args[1:], stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return ExitOK
	default:
		_, _ = fmt.Fprintf(stderr, "ree: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return ExitUsage
	}
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Reverse Engineer Everything
Usage: ree <command> [options]

Commands:
  analyze   Analyze one local artifact and emit evidence
  version   Print version information
  doctor    Check local tools and environment
  mcp       Run the MCP server over stdio
  help      Show this help

Run "ree analyze --json", "ree version --json", or "ree doctor --json" for machine-readable output.`)
}
