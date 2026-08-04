package main

import (
	"fmt"
	"io"
	"strings"
)

type helpCommand struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
	Usage   string `json:"usage"`
}

type helpResult struct {
	Usage    string        `json:"usage"`
	Summary  string        `json:"summary"`
	Commands []helpCommand `json:"commands"`
	Examples []string      `json:"examples"`
}

type helpGroup struct {
	Command  helpCommand
	Commands []helpCommand
	Examples []string
}

var rootHelpCommands = []helpCommand{
	{"config", "Validate and authenticate immutable event configuration.", "eventctl config COMMAND [ARGS]"},
	{"doctor", "Run offline platform and cryptographic self-tests.", "eventctl doctor [--out PATH]"},
	{"envelope", "Strictly classify untrusted durable request routing metadata.", "eventctl envelope COMMAND [ARGS]"},
	{"help", "Show structured help for the CLI, a command family, or a subcommand.", "eventctl help [COMMAND [SUBCOMMAND]]"},
	{"identity", "Create and verify signed participant registration requests.", "eventctl identity COMMAND [ARGS]"},
	{"key", "Generate and manage passphrase-protected participant signing keys.", "eventctl key COMMAND [ARGS]"},
	{"receipt", "Sign and verify authoritative workflow receipts.", "eventctl receipt COMMAND [ARGS]"},
	{"recipient", "Generate passphrase-protected submission-encryption identities.", "eventctl recipient COMMAND [ARGS]"},
	{"replay", "Classify signed requests against durable replay state.", "eventctl replay COMMAND [ARGS]"},
	{"scorer", "Validate scoring requests and sign or verify scoring results.", "eventctl scorer COMMAND [ARGS]"},
	{"submission", "Create, inspect, verify, and decrypt authenticated encrypted submissions.", "eventctl submission COMMAND [ARGS]"},
	{"team", "Create and verify signed team proposals and consents.", "eventctl team COMMAND [ARGS]"},
	{"version", "Print machine-readable build information.", "eventctl version --json"},
}

var helpGroups = map[string]helpGroup{
	"config": {
		Command: rootHelpCommands[0],
		Commands: []helpCommand{
			{"validate", "Validate event YAML and write normalized JSON.", "eventctl config validate --config PATH --out PATH"},
			{"digest", "Validate event YAML and write normalized JSON with its digest.", "eventctl config digest --config PATH --out PATH"},
			{"sign", "Sign an unsigned event configuration.", "eventctl config sign --config PATH --key PATH --out PATH [--passphrase-file PATH|-]"},
			{"verify", "Verify config through adopted or bootstrap trust.", "eventctl config verify --config PATH --source-time RFC3339 (--authority PATH --state-meta PATH | --delegation PATH --root-key PATH --expect-event-id ID --expect-repository-id ID) --out PATH"},
			{"delegation-sign", "Add an organizer-root signature to a config delegation.", "eventctl config delegation-sign --delegation PATH --key PATH --out PATH [--passphrase-file PATH|-]"},
			{"delegation-verify", "Verify a config delegation against the exact organizer root set.", "eventctl config delegation-verify --delegation PATH --root-key PATH [--root-key PATH ...] --expect-event-id ID --expect-repository-id ID --source-time RFC3339 --out PATH"},
		},
		Examples: []string{
			"eventctl config validate --config event.yaml --out event.normalized.json",
			"eventctl help config verify",
		},
	},
	"envelope": {
		Command: rootHelpCommands[2],
		Commands: []helpCommand{
			{"classify", "Strictly extract unverified routing kind and request ID from one durable request.", "eventctl envelope classify --request PATH --out PATH"},
		},
		Examples: []string{"eventctl envelope classify --request request.json --out classification.json"},
	},
	"identity": {
		Command: rootHelpCommands[4],
		Commands: []helpCommand{
			{"register", "Create a signed participant registration request.", "eventctl identity register --config PATH --authority PATH --state-meta PATH --key PATH --actor-id ID --out PATH [--passphrase-file PATH|-] [--request-id UUID]"},
			{"verify", "Verify a registration at its trusted GitHub source time.", "eventctl identity verify --config PATH --authority PATH --state-meta PATH --request PATH --expect-actor-id ID --source-time RFC3339 --out PATH"},
		},
		Examples: []string{"eventctl help identity register"},
	},
	"key": {
		Command: rootHelpCommands[5],
		Commands: []helpCommand{
			{"generate", "Generate an Ed25519 signing key and public-key document.", "eventctl key generate --private-out PATH --public-out PATH [--passphrase-file PATH|-]"},
			{"show", "Decrypt a signing key and print its public identity.", "eventctl key show --key PATH [--passphrase-file PATH|-]"},
			{"public", "Alias for key show.", "eventctl key public --key PATH [--passphrase-file PATH|-]"},
			{"backup", "Re-encrypt a signing key into an exclusive backup file.", "eventctl key backup --key PATH --out PATH [--passphrase-file PATH|-] [--new-passphrase-file PATH|-]"},
		},
		Examples: []string{
			"eventctl key generate --private-out participant.key.age --public-out participant.pub.json",
			"eventctl key backup --key participant.key.age --out participant.key.backup.age",
		},
	},
	"receipt": {
		Command: rootHelpCommands[6],
		Commands: []helpCommand{
			{"sign", "Sign an authoritative receipt claim.", "eventctl receipt sign --config PATH --authority PATH --state-meta PATH --claim PATH --key PATH --out PATH [--passphrase-file PATH|-]"},
			{"verify", "Verify a receipt against its archived accepted configuration.", "eventctl receipt verify --config PATH --authority PATH --state-meta PATH --receipt PATH --out PATH"},
		},
		Examples: []string{"eventctl help receipt verify"},
	},
	"recipient": {
		Command: rootHelpCommands[7],
		Commands: []helpCommand{
			{"generate", "Generate a hybrid ML-KEM768/X25519 identity and public recipient.", "eventctl recipient generate --identity-out PATH --recipient-out PATH [--passphrase-file PATH|-]"},
			{"show", "Decrypt an identity and print its public recipient.", "eventctl recipient show --identity PATH [--passphrase-file PATH|-]"},
		},
		Examples: []string{
			"eventctl recipient generate --identity-out judge-recipient.age --recipient-out judge-recipient.txt",
			"eventctl recipient show --identity judge-recipient.age",
		},
	},
	"replay": {
		Command: rootHelpCommands[8],
		Commands: []helpCommand{
			{"classify", "Classify an incoming request as new, idempotent, or conflicting.", "eventctl replay classify --incoming PATH [--existing PATH] --out PATH"},
		},
		Examples: []string{"eventctl replay classify --incoming request.json --out replay.json"},
	},
	"scorer": {
		Command: rootHelpCommands[9],
		Commands: []helpCommand{
			{"validate-request", "Verify an accepted scoring request before judging.", "eventctl scorer validate-request --config PATH --authority PATH --state-meta PATH --request PATH --acceptance PATH --out PATH"},
			{"sign-result", "Validate and sign a scorer result.", "eventctl scorer sign-result --config PATH --authority PATH --state-meta PATH --request PATH --acceptance PATH --unsigned-result PATH --key PATH --out PATH [--passphrase-file PATH|-]"},
			{"verify", "Verify a signed scorer result.", "eventctl scorer verify --config PATH --authority PATH --state-meta PATH --request PATH --acceptance PATH --result PATH --out PATH"},
		},
		Examples: []string{"eventctl help scorer sign-result"},
	},
	"submission": {
		Command: rootHelpCommands[10],
		Commands: []helpCommand{
			{"pack", "Sign, archive, and encrypt a submission directory.", "eventctl submission pack --config PATH --authority PATH --state-meta PATH --registry PATH --teams PATH --team-id UUID --key PATH --actor-id ID --source DIR --bundle-out submission.eventctl --record-out PATH [--passphrase-file PATH|-] [--attempt-id UUID] [--request-id UUID]"},
			{"inspect", "Inspect the public framing metadata of an encrypted bundle.", "eventctl submission inspect --bundle PATH --out PATH"},
			{"verify", "Verify a bundle and its signed pack record without decrypting it.", "eventctl submission verify --config PATH --authority PATH --state-meta PATH --registry PATH --bundle submission.eventctl --record PATH --out PATH"},
			{"prepare", "Create a signed submission request for an existing bundle.", "eventctl submission prepare --config PATH --authority PATH --state-meta PATH --registry PATH --key PATH --actor-id ID --metadata PATH --bundle submission.eventctl --record PATH --out PATH [--passphrase-file PATH|-]"},
			{"verify-request", "Verify a submission request at its trusted source time.", "eventctl submission verify-request --config PATH --authority PATH --state-meta PATH --registry PATH --request PATH --metadata PATH --bundle PATH --expect-actor-id ID --source-time RFC3339 --out PATH"},
			{"decrypt-verify", "Verify acceptance, decrypt, and safely extract a submission.", "eventctl submission decrypt-verify --config ARCHIVED_PATH --authority PATH --state-meta PATH --registry PATH --request PATH --acceptance RECEIPT --bundle PATH --identity PATH [--identity PATH ...] --out-dir PRIVATE_DIR --out PATH [--record PATH] [--passphrase-file PATH|-] [--expect-actor-id ID] [--expect-attempt-id UUID]"},
		},
		Examples: []string{
			"eventctl help submission pack",
			"eventctl submission inspect --bundle submission.eventctl --out bundle-info.json",
		},
	},
	"team": {
		Command: rootHelpCommands[11],
		Commands: []helpCommand{
			{"propose", "Create a signed immutable team proposal.", "eventctl team propose --config PATH --authority PATH --state-meta PATH --registry PATH --key PATH --actor-id ID --members PATH --out PATH [--passphrase-file PATH|-] [--team-id UUID] [--request-id UUID]"},
			{"consent", "Create a member signature over an existing team proposal.", "eventctl team consent --config PATH --authority PATH --state-meta PATH --registry PATH --proposal PATH --key PATH --actor-id ID --out PATH [--passphrase-file PATH|-] [--request-id UUID]"},
			{"verify", "Verify a team proposal or consent at its trusted source time.", "eventctl team verify --config PATH --authority PATH --state-meta PATH --registry PATH --request PATH --source-time RFC3339 [--proposal VERIFIED_PROPOSAL] --out PATH"},
		},
		Examples: []string{"eventctl help team propose"},
	},
}

var directHelp = map[string]helpResult{
	"doctor": {
		Usage: "eventctl doctor [--out PATH]", Summary: rootHelpCommands[1].Summary,
		Commands: []helpCommand{}, Examples: []string{"eventctl doctor", "eventctl doctor --out doctor.json"},
	},
	"help": {
		Usage: "eventctl help [COMMAND [SUBCOMMAND]]", Summary: rootHelpCommands[3].Summary,
		Commands: []helpCommand{}, Examples: []string{"eventctl --help", "eventctl help submission", "eventctl submission pack --help"},
	},
	"version": {
		Usage: "eventctl version --json", Summary: rootHelpCommands[12].Summary,
		Commands: []helpCommand{}, Examples: []string{"eventctl version --json"},
	},
}

func maybeRunHelp(args []string, output io.Writer) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	if args[0] == "help" {
		return runHelp(args[1:], output), true
	}
	if isHelpFlag(args[0]) {
		if len(args) != 1 {
			return emitFailure(output, "help", asCommandError(usageError("usage: eventctl help [COMMAND [SUBCOMMAND]]"))), true
		}
		return runHelp(nil, output), true
	}
	if len(args) == 2 && (args[1] == "help" || isHelpFlag(args[1])) {
		return runHelp(args[:1], output), true
	}
	if len(args) == 3 && isHelpFlag(args[2]) {
		return runHelp(args[:2], output), true
	}
	return 0, false
}

func isHelpFlag(value string) bool { return value == "--help" || value == "-h" }

func runHelp(topic []string, output io.Writer) int {
	result, ok := helpFor(topic)
	if !ok {
		name := strings.Join(topic, " ")
		return emitFailure(output, "help", asCommandError(usageError(fmt.Sprintf("unknown help topic %q", name))))
	}
	command := "help"
	if len(topic) != 0 {
		command += "." + strings.Join(topic, ".")
	}
	return emitSuccess(output, command, result)
}

func helpFor(topic []string) (helpResult, bool) {
	if len(topic) == 0 {
		return helpResult{
			Usage:    "eventctl COMMAND [ARGS]",
			Summary:  "Offline signing, verification, and encrypted-submission tools for PythonHK GitHub events.",
			Commands: append([]helpCommand(nil), rootHelpCommands...),
			Examples: []string{
				"eventctl key generate --private-out participant.key.age --public-out participant.pub.json",
				"eventctl recipient generate --identity-out judge-recipient.age --recipient-out judge-recipient.txt",
				"eventctl help submission pack",
				"eventctl doctor",
			},
		}, true
	}
	if len(topic) == 1 {
		if group, ok := helpGroups[topic[0]]; ok {
			return helpResult{
				Usage: group.Command.Usage, Summary: group.Command.Summary,
				Commands: append([]helpCommand(nil), group.Commands...),
				Examples: append([]string(nil), group.Examples...),
			}, true
		}
		result, ok := directHelp[topic[0]]
		return result, ok
	}
	if len(topic) == 2 {
		group, ok := helpGroups[topic[0]]
		if !ok {
			return helpResult{}, false
		}
		for _, command := range group.Commands {
			if command.Name == topic[1] {
				return helpResult{
					Usage: command.Usage, Summary: command.Summary,
					Commands: []helpCommand{}, Examples: []string{command.Usage},
				}, true
			}
		}
	}
	return helpResult{}, false
}
