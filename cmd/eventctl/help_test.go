package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

type decodedHelpResponse struct {
	OutputVersion string       `json:"output_version"`
	OK            bool         `json:"ok"`
	Command       string       `json:"command"`
	Result        helpResult   `json:"result"`
	Error         *errorObject `json:"error"`
}

func TestTopLevelHelpAliasesExitZeroAndListEveryCommand(t *testing.T) {
	t.Parallel()
	wantCommands := []string{
		"config", "doctor", "envelope", "help", "identity", "key", "receipt",
		"recipient", "replay", "scorer", "submission", "team", "version",
	}
	for _, args := range [][]string{{"help"}, {"--help"}, {"-h"}} {
		args := args
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			t.Parallel()
			got, stderr, exit := executeForHelpTest(args)
			if exit != 0 {
				t.Fatalf("run(%q) exit = %d, output = %#v", args, exit, got)
			}
			if stderr != "" {
				t.Fatalf("run(%q) stderr = %q", args, stderr)
			}
			if !got.OK || got.Error != nil || got.OutputVersion != outputVersion || got.Command != "help" {
				t.Fatalf("run(%q) response = %#v", args, got)
			}
			var names []string
			for _, command := range got.Result.Commands {
				names = append(names, command.Name)
				if command.Summary == "" || command.Usage == "" {
					t.Fatalf("command %q has incomplete help: %#v", command.Name, command)
				}
			}
			if !slices.Equal(names, wantCommands) {
				t.Fatalf("command names = %q, want %q", names, wantCommands)
			}
			if !containsSubstring(got.Result.Examples, "recipient generate") {
				t.Fatalf("top-level examples do not show encryption-key setup: %q", got.Result.Examples)
			}
		})
	}
}

func TestCommandFamilyHelpAliasesExitZero(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"help", "recipient"},
		{"recipient", "help"},
		{"recipient", "--help"},
		{"recipient", "-h"},
	} {
		args := args
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			t.Parallel()
			got, stderr, exit := executeForHelpTest(args)
			if exit != 0 || stderr != "" || !got.OK || got.Command != "help.recipient" {
				t.Fatalf("run(%q) exit=%d stderr=%q response=%#v", args, exit, stderr, got)
			}
			if got.Result.Usage != "eventctl recipient COMMAND [ARGS]" {
				t.Fatalf("run(%q) usage = %q", args, got.Result.Usage)
			}
			if len(got.Result.Commands) != 2 || got.Result.Commands[0].Name != "generate" || got.Result.Commands[1].Name != "show" {
				t.Fatalf("run(%q) commands = %#v", args, got.Result.Commands)
			}
			if !containsSubstring(got.Result.Examples, "recipient generate") {
				t.Fatalf("recipient examples = %q", got.Result.Examples)
			}
		})
	}
}

func TestExactCommandHelpAliasesExitZeroWithoutSideEffects(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"help", "recipient", "generate"},
		{"recipient", "generate", "--help"},
		{"recipient", "generate", "-h"},
	} {
		args := args
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			t.Parallel()
			got, stderr, exit := executeForHelpTest(args)
			if exit != 0 || stderr != "" || !got.OK || got.Command != "help.recipient.generate" {
				t.Fatalf("run(%q) exit=%d stderr=%q response=%#v", args, exit, stderr, got)
			}
			if !strings.Contains(got.Result.Usage, "--identity-out PATH --recipient-out PATH") {
				t.Fatalf("run(%q) usage = %q", args, got.Result.Usage)
			}
			if len(got.Result.Commands) != 0 || len(got.Result.Examples) != 1 {
				t.Fatalf("run(%q) result = %#v", args, got.Result)
			}
		})
	}
}

func TestDirectCommandHelpExitsZero(t *testing.T) {
	t.Parallel()
	got, stderr, exit := executeForHelpTest([]string{"doctor", "--help"})
	if exit != 0 || stderr != "" || !got.OK || got.Command != "help.doctor" {
		t.Fatalf("doctor --help exit=%d stderr=%q response=%#v", exit, stderr, got)
	}
	if got.Result.Usage != "eventctl doctor [--out PATH]" {
		t.Fatalf("doctor usage = %q", got.Result.Usage)
	}
}

func TestEveryRegisteredCommandFamilyAndSubcommandHasExitZeroHelp(t *testing.T) {
	t.Parallel()
	for family, group := range helpGroups {
		family := family
		group := group
		for _, args := range [][]string{
			{"help", family},
			{family, "help"},
			{family, "--help"},
			{family, "-h"},
		} {
			args := args
			t.Run(strings.Join(args, "_"), func(t *testing.T) {
				t.Parallel()
				assertHelpSuccess(t, args, "help."+family)
			})
		}
		for _, command := range group.Commands {
			command := command
			for _, args := range [][]string{
				{"help", family, command.Name},
				{family, command.Name, "--help"},
				{family, command.Name, "-h"},
			} {
				args := args
				t.Run(strings.Join(args, "_"), func(t *testing.T) {
					t.Parallel()
					assertHelpSuccess(t, args, "help."+family+"."+command.Name)
				})
			}
		}
	}
}

func TestEveryRegisteredDirectCommandHasExitZeroHelp(t *testing.T) {
	t.Parallel()
	for command := range directHelp {
		command := command
		t.Run("help_"+command, func(t *testing.T) {
			t.Parallel()
			assertHelpSuccess(t, []string{"help", command}, "help."+command)
		})
		if command == "help" {
			continue
		}
		for _, flag := range []string{"--help", "-h"} {
			flag := flag
			t.Run(command+"_"+flag, func(t *testing.T) {
				t.Parallel()
				assertHelpSuccess(t, []string{command, flag}, "help."+command)
			})
		}
	}
}

func TestUnknownHelpTopicUsesStableUsageFailure(t *testing.T) {
	t.Parallel()
	got, stderr, exit := executeForHelpTest([]string{"help", "missing"})
	if exit != 2 || stderr != "" || got.OK || got.Command != "help" || got.Error == nil {
		t.Fatalf("unknown help exit=%d stderr=%q response=%#v", exit, stderr, got)
	}
	if got.Error.Code != "usage" || !strings.Contains(got.Error.Message, `unknown help topic "missing"`) {
		t.Fatalf("unknown help error = %#v", got.Error)
	}
}

func executeForHelpTest(args []string) (decodedHelpResponse, string, int) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exit := run(args, &stdout, &stderr)
	var decoded decodedHelpResponse
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		panic("decode help response: " + err.Error() + ": " + stdout.String())
	}
	return decoded, stderr.String(), exit
}

func assertHelpSuccess(t *testing.T, args []string, wantCommand string) {
	t.Helper()
	got, stderr, exit := executeForHelpTest(args)
	if exit != 0 || stderr != "" || !got.OK || got.Error != nil || got.Command != wantCommand {
		t.Fatalf("run(%q) exit=%d stderr=%q response=%#v", args, exit, stderr, got)
	}
	if got.Result.Usage == "" || got.Result.Summary == "" || len(got.Result.Examples) == 0 {
		t.Fatalf("run(%q) returned incomplete help: %#v", args, got.Result)
	}
}

func containsSubstring(values []string, substring string) bool {
	for _, value := range values {
		if strings.Contains(value, substring) {
			return true
		}
	}
	return false
}
