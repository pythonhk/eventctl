package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return emitFailure(stdout, "root", commandError{Code: "usage", Message: "a command is required", Exit: 2})
	}
	if exit, handled := maybeRunHelp(args, stdout); handled {
		return exit
	}
	var result any
	var err error
	command := args[0]
	switch command {
	case "version":
		return runVersion(args[1:], stdout)
	case "config":
		result, err = runConfig(args[1:], stderr)
	case "envelope":
		result, err = runEnvelope(args[1:])
	case "key":
		result, err = runKey(args[1:], stderr)
	case "recipient":
		result, err = runRecipient(args[1:], stderr)
	case "identity":
		result, err = runIdentity(args[1:], stderr)
	case "team":
		result, err = runTeam(args[1:], stderr)
	case "submission":
		result, err = runSubmission(args[1:], stderr)
	case "replay":
		result, err = runReplay(args[1:])
	case "receipt":
		result, err = runReceipt(args[1:], stderr)
	case "scorer":
		result, err = runScorer(args[1:], stderr)
	case "doctor":
		result, err = runDoctor(args[1:])
	default:
		err = usageError(fmt.Sprintf("unknown command %q", command))
	}
	if err != nil {
		return emitFailure(stdout, command, asCommandError(err))
	}
	return emitSuccess(stdout, commandName(args), result)
}

func commandName(args []string) string {
	if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		return args[0] + "." + args[1]
	}
	return args[0]
}
