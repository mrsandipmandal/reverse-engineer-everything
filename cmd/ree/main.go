// Command ree is the command-line entry point for Reverse Engineer Everything.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
