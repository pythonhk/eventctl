package main

import (
	"flag"
	"io"

	"github.com/pythonhk/eventctl/internal/buildinfo"
)

func runVersion(args []string, output io.Writer) int {
	flags := newFlagSet("version")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !*jsonOutput {
		return emitFailure(output, "version", asCommandError(usageError("usage: eventctl version --json")))
	}
	return emitRaw(output, buildinfo.Current())
}

func emitRaw(output io.Writer, value any) int { return emit(output, value, 0) }

func newFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}
