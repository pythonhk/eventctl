package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/caarlos0/env/v11"
	"github.com/spf13/cobra"

	"github.com/pythonhk/eventctl/internal/buildinfo"
	"github.com/pythonhk/eventctl/internal/protocol"
	"github.com/pythonhk/eventctl/internal/stream"
)

type response struct {
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	Result  any    `json:"result,omitempty"`
	Error   string `json:"error,omitempty"`
}

type doctorEnvironment struct {
	EventID    string `env:"EVENTCTL_EVENT_ID" envDefault:"unset"`
	EventEpoch int    `env:"EVENTCTL_EVENT_EPOCH" envDefault:"1"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	root := newRoot(stdout, stderr)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		command := strings.TrimSpace(strings.TrimPrefix(root.CommandPath(), "eventctl"))
		if command == "" {
			command = "eventctl"
		}
		_ = writeResponse(stdout, response{OK: false, Command: command, Error: err.Error()})
		return 1
	}
	return 0
}

func newRoot(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "eventctl",
		Short:         "PythonHK event registration and byte-stream cryptography",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(versionCommand(), doctorCommand(), keyGenCommand(), sigcryptCommand(), decverifyCommand(), identityCommand(), teamCommand(), submissionCommand())
	return root
}

func versionCommand() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "print version information", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		return emit(command, buildinfo.Current())
	}}
}

func doctorCommand() *cobra.Command {
	var eventPath, registryPath string
	command := &cobra.Command{Use: "doctor", Short: "check local eventctl configuration and protocol algorithms", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		if eventPath != "" {
			binding, err := protocol.ReadEventBinding(eventPath)
			if err != nil {
				return err
			}
			result := map[string]any{"protocol": protocol.Protocol, "event": binding.Reference(), "go": runtime.Version(), "algorithms": map[string]string{"signing": "Ed25519", "recipient": "age-hybrid-mlkem768-x25519"}}
			if registryPath != "" {
				registry, readErr := protocol.ReadRegistry(registryPath, binding)
				if readErr != nil {
					return readErr
				}
				result["registry"] = map[string]any{"revision": registry.Revision, "phase": registry.Phase, "enabled": registry.Enabled, "identities": len(registry.Identities), "teams": len(registry.Teams), "attempts": len(registry.Attempts)}
			}
			return emit(command, result)
		}
		if registryPath != "" {
			return errors.New("--registry requires --event")
		}
		var configuration doctorEnvironment
		if err := env.Parse(&configuration); err != nil {
			return fmt.Errorf("parse environment: %w", err)
		}
		if configuration.EventEpoch < 1 {
			return errors.New("EVENTCTL_EVENT_EPOCH must be positive")
		}
		return emit(command, map[string]any{"protocol": protocol.Protocol, "event_id": configuration.EventID, "event_epoch": configuration.EventEpoch, "go": runtime.Version(), "algorithms": map[string]string{"signing": "Ed25519", "recipient": "age-hybrid-mlkem768-x25519"}})
	}}
	command.Flags().StringVar(&eventPath, "event", "", "public event binding JSON")
	command.Flags().StringVar(&registryPath, "registry", "", "protected event registry JSON")
	return command
}

func keyGenCommand() *cobra.Command {
	var directory, passphraseFile string
	command := &cobra.Command{Use: "key-gen", Short: "create signing and recipient key pairs", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		passphrase, err := readPassphrase(passphraseFile)
		if err != nil {
			return err
		}
		value, err := protocol.GenerateKeyDirectory(directory, passphrase)
		if err != nil {
			return err
		}
		return emit(command, value)
	}}
	command.Flags().StringVar(&directory, "out", "", "key directory")
	command.Flags().StringVar(&passphraseFile, "passphrase-file", "", "key passphrase file")
	require(command, "out")
	return command
}

func sigcryptCommand() *cobra.Command {
	var input, output, context, signingPath, passphraseFile string
	var recipientPaths []string
	command := &cobra.Command{Use: "sigcrypt", Short: "sign and encrypt one byte stream", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadStreamBinding(context)
		if err != nil {
			return err
		}
		passphrase, err := readPassphrase(passphraseFile)
		if err != nil {
			return err
		}
		signingKey, err := protocol.LoadSigningPrivate(signingPath, passphrase)
		if err != nil {
			return err
		}
		recipients := make([]protocol.RecipientPublic, 0, len(recipientPaths))
		identities := make([]age.Recipient, 0, len(recipientPaths))
		seen := make(map[string]bool, len(recipientPaths))
		for _, path := range recipientPaths {
			recipient, loadErr := protocol.LoadRecipientPublic(path)
			if loadErr != nil {
				return loadErr
			}
			if seen[recipient.KeyID] {
				continue
			}
			seen[recipient.KeyID] = true
			recipients = append(recipients, recipient)
			identities = append(identities, recipient.Recipient)
		}
		value, err := stream.SealFile(input, output, binding, signingKey, recipients, identities)
		if err != nil {
			return err
		}
		return emit(command, value)
	}}
	command.Flags().StringVar(&input, "input", "", "input byte stream")
	command.Flags().StringVar(&output, "output", "", "encrypted output")
	command.Flags().StringVar(&context, "context", "", "stream binding JSON")
	command.Flags().StringVar(&signingPath, "sig-private-key", "", "encrypted signing key")
	command.Flags().StringVar(&passphraseFile, "passphrase-file", "", "signing key passphrase file")
	command.Flags().StringArrayVar(&recipientPaths, "enc-public-key", nil, "recipient public key (repeatable)")
	require(command, "input", "output", "context", "sig-private-key")
	return command
}

func decverifyCommand() *cobra.Command {
	var input, output, context, signerPath, recipientPath, passphraseFile string
	command := &cobra.Command{Use: "decverify", Short: "decrypt and verify one byte stream", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadStreamBinding(context)
		if err != nil {
			return err
		}
		signer, err := protocol.LoadSigningPublic(signerPath)
		if err != nil {
			return err
		}
		passphrase, err := readPassphrase(passphraseFile)
		if err != nil {
			return err
		}
		recipient, err := protocol.LoadRecipientPrivate(recipientPath, passphrase)
		if err != nil {
			return err
		}
		value, err := stream.OpenFile(input, output, binding, signer, recipient)
		if err != nil {
			return err
		}
		return emit(command, value)
	}}
	command.Flags().StringVar(&input, "input", "", "encrypted input")
	command.Flags().StringVar(&output, "output", "", "verified plaintext output")
	command.Flags().StringVar(&context, "context", "", "stream binding JSON")
	command.Flags().StringVar(&signerPath, "ver-public-key", "", "signing public key")
	command.Flags().StringVar(&recipientPath, "dec-private-key", "", "encrypted recipient key")
	command.Flags().StringVar(&passphraseFile, "passphrase-file", "", "recipient key passphrase file")
	require(command, "input", "output", "context", "ver-public-key", "dec-private-key")
	return command
}

func identityCommand() *cobra.Command {
	root := &cobra.Command{Use: "identity", Short: "register and verify participant identities"}
	var eventPath, actorID, registrationID, signingPath, recipientPath, passphraseFile, output string
	var keyEpoch int
	register := &cobra.Command{Use: "register", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadEventBinding(eventPath)
		if err != nil {
			return err
		}
		passphrase, err := readPassphrase(passphraseFile)
		if err != nil {
			return err
		}
		key, err := protocol.LoadSigningPrivate(signingPath, passphrase)
		if err != nil {
			return err
		}
		recipient, err := protocol.LoadRecipientPublic(recipientPath)
		if err != nil {
			return err
		}
		value, err := protocol.RegisterIdentity(binding, actorID, keyEpoch, registrationID, key, recipient, now())
		if err != nil {
			return err
		}
		if err := protocol.WriteJSON(output, value); err != nil {
			return err
		}
		return emit(command, map[string]string{"output": output, "actor_id": value.ActorID, "registration_id": value.RegistrationID})
	}}
	register.Flags().StringVar(&eventPath, "event", "", "public event binding JSON")
	register.Flags().StringVar(&actorID, "actor-id", "", "numeric GitHub actor ID")
	register.Flags().IntVar(&keyEpoch, "key-epoch", 1, "identity key epoch")
	register.Flags().StringVar(&registrationID, "registration-id", "", "UUIDv4 registration ID (generated if omitted)")
	register.Flags().StringVar(&signingPath, "sig-private-key", "", "encrypted signing key")
	register.Flags().StringVar(&recipientPath, "recipient-public-key", "", "age recipient public key")
	register.Flags().StringVar(&passphraseFile, "passphrase-file", "", "signing key passphrase file")
	register.Flags().StringVar(&output, "output", "", "registration JSON")
	require(register, "event", "actor-id", "sig-private-key", "recipient-public-key", "output")

	var verifyEvent, verifyInput, verifyActor, verifySourceTime, verifyOutput string
	verify := &cobra.Command{Use: "verify", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadEventBinding(verifyEvent)
		if err != nil {
			return err
		}
		var document protocol.IdentityRegistration
		if err := protocol.ReadJSON(verifyInput, &document); err != nil {
			return err
		}
		record, err := protocol.VerifyIdentity(document, binding, verifyActor, verifySourceTime)
		if err != nil {
			return err
		}
		if err := protocol.WriteJSON(verifyOutput, record); err != nil {
			return err
		}
		return emit(command, map[string]string{"output": verifyOutput, "actor_id": record.ActorID, "registration_id": record.RegistrationID})
	}}
	verify.Flags().StringVar(&verifyEvent, "event", "", "public event binding JSON")
	verify.Flags().StringVar(&verifyInput, "input", "", "registration JSON")
	verify.Flags().StringVar(&verifyActor, "expect-actor-id", "", "trusted GitHub actor ID")
	verify.Flags().StringVar(&verifySourceTime, "source-time", "", "trusted immutable source creation time")
	verify.Flags().StringVar(&verifyOutput, "output", "", "verified identity record JSON")
	require(verify, "event", "input", "expect-actor-id", "source-time", "output")
	root.AddCommand(register, verify)
	return root
}

func teamCommand() *cobra.Command {
	root := &cobra.Command{Use: "team", Short: "prepare, consent to, and verify team proposals"}
	var eventPath, registryPath, teamID, actorID, signingPath, passphraseFile, output string
	var members []string
	propose := &cobra.Command{Use: "propose", Aliases: []string{"register"}, Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadEventBinding(eventPath)
		if err != nil {
			return err
		}
		registry, err := protocol.ReadRegistry(registryPath, binding)
		if err != nil {
			return err
		}
		passphrase, err := readPassphrase(passphraseFile)
		if err != nil {
			return err
		}
		key, err := protocol.LoadSigningPrivate(signingPath, passphrase)
		if err != nil {
			return err
		}
		proposal, err := protocol.ProposeTeam(binding, registry, teamID, actorID, members, key, now())
		if err != nil {
			return err
		}
		if err := protocol.WriteJSON(output, proposal); err != nil {
			return err
		}
		return emit(command, map[string]string{"output": output, "team_id": proposal.TeamID})
	}}
	propose.Flags().StringVar(&eventPath, "event", "", "public event binding JSON")
	propose.Flags().StringVar(&registryPath, "registry", "", "protected active identity registry JSON")
	propose.Flags().StringVar(&teamID, "team-id", "", "UUIDv4 team ID (generated if omitted)")
	propose.Flags().StringVar(&actorID, "actor-id", "", "numeric proposer GitHub actor ID")
	propose.Flags().StringArrayVar(&members, "member", nil, "member actor ID (repeatable, including proposer)")
	propose.Flags().StringVar(&signingPath, "sig-private-key", "", "encrypted signing key")
	propose.Flags().StringVar(&passphraseFile, "passphrase-file", "", "signing key passphrase file")
	propose.Flags().StringVar(&output, "output", "", "team proposal JSON")
	require(propose, "event", "registry", "actor-id", "sig-private-key", "output")

	var consentEvent, consentRegistry, proposalPath, consentActor, consentSigning, consentPassphrase, consentOutput string
	consent := &cobra.Command{Use: "consent", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadEventBinding(consentEvent)
		if err != nil {
			return err
		}
		registry, err := protocol.ReadRegistry(consentRegistry, binding)
		if err != nil {
			return err
		}
		var proposal protocol.TeamProposal
		if err := protocol.ReadJSON(proposalPath, &proposal); err != nil {
			return err
		}
		passphrase, err := readPassphrase(consentPassphrase)
		if err != nil {
			return err
		}
		key, err := protocol.LoadSigningPrivate(consentSigning, passphrase)
		if err != nil {
			return err
		}
		value, err := protocol.ConsentTeam(binding, registry, proposal, consentActor, key, now())
		if err != nil {
			return err
		}
		if err := protocol.WriteJSON(consentOutput, value); err != nil {
			return err
		}
		return emit(command, map[string]string{"output": consentOutput, "actor_id": value.ActorID})
	}}
	consent.Flags().StringVar(&consentEvent, "event", "", "public event binding JSON")
	consent.Flags().StringVar(&consentRegistry, "registry", "", "protected active identity registry JSON")
	consent.Flags().StringVar(&proposalPath, "proposal", "", "team proposal JSON")
	consent.Flags().StringVar(&consentActor, "actor-id", "", "numeric member GitHub actor ID")
	consent.Flags().StringVar(&consentSigning, "sig-private-key", "", "encrypted signing key")
	consent.Flags().StringVar(&consentPassphrase, "passphrase-file", "", "signing key passphrase file")
	consent.Flags().StringVar(&consentOutput, "output", "", "team consent JSON")
	require(consent, "event", "registry", "proposal", "actor-id", "sig-private-key", "output")

	var verifyEvent, verifyRegistry, verifyProposal, proposalSourceTime, verifyOutput string
	var consentPaths, consentSourceTimes []string
	verify := &cobra.Command{Use: "verify", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadEventBinding(verifyEvent)
		if err != nil {
			return err
		}
		registry, err := protocol.ReadRegistry(verifyRegistry, binding)
		if err != nil {
			return err
		}
		var proposal protocol.TeamProposal
		if err := protocol.ReadJSON(verifyProposal, &proposal); err != nil {
			return err
		}
		if len(consentPaths) == 0 {
			return errors.New("at least one --consent is required")
		}
		consents := make([]protocol.TeamConsent, 0, len(consentPaths))
		for _, path := range consentPaths {
			var consent protocol.TeamConsent
			if err := protocol.ReadJSON(path, &consent); err != nil {
				return err
			}
			consents = append(consents, consent)
		}
		sourceTimes, err := parseActorTimes(consentSourceTimes)
		if err != nil {
			return err
		}
		value, err := protocol.VerifyTeam(binding, registry, proposal, proposalSourceTime, consents, sourceTimes)
		if err != nil {
			return err
		}
		if err := protocol.WriteJSON(verifyOutput, value); err != nil {
			return err
		}
		return emit(command, map[string]string{"output": verifyOutput, "team_id": value.TeamID, "proposal_sha256": value.ProposalSHA256})
	}}
	verify.Flags().StringVar(&verifyEvent, "event", "", "public event binding JSON")
	verify.Flags().StringVar(&verifyRegistry, "registry", "", "protected active identity registry JSON")
	verify.Flags().StringVar(&verifyProposal, "proposal", "", "team proposal JSON")
	verify.Flags().StringVar(&proposalSourceTime, "proposal-source-time", "", "trusted proposal pull-request creation time")
	verify.Flags().StringArrayVar(&consentPaths, "consent", nil, "team consent JSON (repeatable)")
	verify.Flags().StringArrayVar(&consentSourceTimes, "consent-source-time", nil, "actor_id=RFC3339 proof creation time (repeatable)")
	verify.Flags().StringVar(&verifyOutput, "output", "", "verified team plan JSON")
	require(verify, "event", "registry", "proposal", "proposal-source-time", "output")
	root.AddCommand(propose, consent, verify)
	return root
}

func submissionCommand() *cobra.Command {
	root := &cobra.Command{Use: "submission", Short: "prepare and verify event-bound submissions"}
	var eventPath, input, metadata, teamID, attemptID, actorID, signingPath, passphraseFile, output string
	var keyEpoch int
	prepare := &cobra.Command{Use: "prepare", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadEventBinding(eventPath)
		if err != nil {
			return err
		}
		payload, err := protocol.ReadBytes(input)
		if err != nil {
			return err
		}
		var metadataBytes []byte
		if metadata != "" {
			metadataBytes, err = protocol.ReadBytes(metadata)
			if err != nil {
				return err
			}
		}
		passphrase, err := readPassphrase(passphraseFile)
		if err != nil {
			return err
		}
		key, err := protocol.LoadSigningPrivate(signingPath, passphrase)
		if err != nil {
			return err
		}
		value, err := protocol.PrepareSubmission(binding, teamID, attemptID, actorID, keyEpoch, payload, metadataBytes, key, now())
		if err != nil {
			return err
		}
		if err := protocol.WriteJSON(output, value); err != nil {
			return err
		}
		return emit(command, map[string]string{"output": output, "attempt_id": value.AttemptID, "payload_sha256": value.PayloadSHA256})
	}}
	prepare.Flags().StringVar(&eventPath, "event", "", "public event binding JSON")
	prepare.Flags().StringVar(&input, "input", "", "submission byte stream")
	prepare.Flags().StringVar(&metadata, "metadata", "", "optional metadata JSON")
	prepare.Flags().StringVar(&teamID, "team-id", "", "active UUIDv4 team ID")
	prepare.Flags().StringVar(&attemptID, "attempt-id", "", "UUIDv4 attempt ID")
	prepare.Flags().StringVar(&actorID, "actor-id", "", "numeric submitter GitHub actor ID")
	prepare.Flags().IntVar(&keyEpoch, "key-epoch", 1, "identity key epoch")
	prepare.Flags().StringVar(&signingPath, "sig-private-key", "", "encrypted signing key")
	prepare.Flags().StringVar(&passphraseFile, "passphrase-file", "", "signing key passphrase file")
	prepare.Flags().StringVar(&output, "output", "", "submission request JSON")
	require(prepare, "event", "input", "team-id", "attempt-id", "actor-id", "sig-private-key", "output")

	var verifyEvent, verifyRegistry, requestPath, bundlePath, verifyMetadata, verifyActor, verifySourceTime, verifyOutput string
	verify := &cobra.Command{Use: "verify", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadEventBinding(verifyEvent)
		if err != nil {
			return err
		}
		registry, err := protocol.ReadRegistry(verifyRegistry, binding)
		if err != nil {
			return err
		}
		var document protocol.Submission
		if err := protocol.ReadJSON(requestPath, &document); err != nil {
			return err
		}
		bundle, err := protocol.ReadBytes(bundlePath)
		if err != nil {
			return err
		}
		var metadataBytes []byte
		if verifyMetadata != "" {
			metadataBytes, err = protocol.ReadBytes(verifyMetadata)
			if err != nil {
				return err
			}
		}
		if err := protocol.VerifySubmission(document, binding, registry, verifyActor, verifySourceTime, bundle, metadataBytes); err != nil {
			return err
		}
		if err := protocol.WriteJSON(verifyOutput, document); err != nil {
			return err
		}
		return emit(command, map[string]string{"output": verifyOutput, "attempt_id": document.AttemptID, "team_id": document.TeamID})
	}}
	verify.Flags().StringVar(&verifyEvent, "event", "", "public event binding JSON")
	verify.Flags().StringVar(&verifyRegistry, "registry", "", "protected active identity registry JSON")
	verify.Flags().StringVar(&requestPath, "request", "", "submission request JSON")
	verify.Flags().StringVar(&bundlePath, "bundle", "", "exact submitted bundle")
	verify.Flags().StringVar(&verifyMetadata, "metadata", "", "optional exact metadata")
	verify.Flags().StringVar(&verifyActor, "expect-actor-id", "", "trusted GitHub actor ID")
	verify.Flags().StringVar(&verifySourceTime, "source-time", "", "trusted immutable source creation time")
	verify.Flags().StringVar(&verifyOutput, "output", "", "verified submission request JSON")
	require(verify, "event", "registry", "request", "bundle", "expect-actor-id", "source-time", "output")
	root.AddCommand(prepare, verify)
	return root
}

func parseActorTimes(values []string) (map[string]string, error) {
	times := make(map[string]string, len(values))
	for _, value := range values {
		actorID, timestamp, found := strings.Cut(value, "=")
		if !found || actorID == "" || timestamp == "" || times[actorID] != "" {
			return nil, errors.New("consent source time must be unique actor_id=RFC3339")
		}
		times[actorID] = timestamp
	}
	return times, nil
}

func require(command *cobra.Command, names ...string) {
	for _, name := range names {
		_ = command.MarkFlagRequired(name)
	}
}

func now() time.Time { return time.Now().UTC() }

func readPassphrase(path string) (string, error) {
	if path == "" {
		return "", errors.New("--passphrase-file is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	passphrase := strings.TrimSpace(string(data))
	if passphrase == "" {
		return "", errors.New("passphrase file is empty")
	}
	return passphrase, nil
}

func emit(command *cobra.Command, value any) error {
	return writeResponse(command.OutOrStdout(), response{OK: true, Command: strings.TrimPrefix(command.CommandPath(), "eventctl "), Result: value})
}

func writeResponse(writer io.Writer, value response) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
