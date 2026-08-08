package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

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
		command := strings.TrimPrefix(root.CommandPath(), "eventctl")
		command = strings.TrimSpace(command)
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
	return &cobra.Command{Use: "doctor", Short: "check local eventctl configuration and protocol algorithms", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		var configuration doctorEnvironment
		if err := env.Parse(&configuration); err != nil {
			return fmt.Errorf("parse environment: %w", err)
		}
		if configuration.EventEpoch < 1 {
			return errors.New("EVENTCTL_EVENT_EPOCH must be positive")
		}
		return emit(command, map[string]any{"protocol": protocol.Protocol, "event_id": configuration.EventID, "event_epoch": configuration.EventEpoch, "go": runtime.Version(), "algorithms": map[string]any{"signing": "ed25519", "recipient": "age-hybrid-mlkem768-x25519"}})
	}}
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
	command.Flags().StringVar(&passphraseFile, "passphrase-file", "", "passphrase file")
	_ = command.MarkFlagRequired("out")
	return command
}

func sigcryptCommand() *cobra.Command {
	var input, output, context, signingPath, passphraseFile string
	var recipientPaths []string
	command := &cobra.Command{Use: "sigcrypt", Short: "sign and encrypt one byte stream", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadBinding(context)
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
		if len(recipientPaths) == 0 {
			return errors.New("at least one --enc-public-key is required")
		}
		recipients := make([]protocol.RecipientPublic, 0, len(recipientPaths))
		identities := make([]age.Recipient, 0, len(recipientPaths))
		seen := make(map[string]bool, len(recipientPaths))
		for _, path := range recipientPaths {
			recipient, err := protocol.LoadRecipientPublic(path)
			if err != nil {
				return err
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
	command.Flags().StringVar(&context, "context", "", "binding JSON")
	command.Flags().StringVar(&signingPath, "sig-private-key", "", "encrypted signing key")
	command.Flags().StringVar(&passphraseFile, "passphrase-file", "", "signing key passphrase")
	command.Flags().StringArrayVar(&recipientPaths, "enc-public-key", nil, "recipient public key (repeatable)")
	for _, name := range []string{"input", "output", "context", "sig-private-key", "passphrase-file"} {
		if name != "passphrase-file" {
			_ = command.MarkFlagRequired(name)
		}
	}
	return command
}

func decverifyCommand() *cobra.Command {
	var input, output, context, signerPath, recipientPath, passphraseFile string
	command := &cobra.Command{Use: "decverify", Short: "decrypt and verify one byte stream", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadBinding(context)
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
	command.Flags().StringVar(&context, "context", "", "binding JSON")
	command.Flags().StringVar(&signerPath, "ver-public-key", "", "signing public key")
	command.Flags().StringVar(&recipientPath, "dec-private-key", "", "encrypted recipient key")
	command.Flags().StringVar(&passphraseFile, "passphrase-file", "", "recipient key passphrase")
	for _, name := range []string{"input", "output", "context", "ver-public-key", "dec-private-key", "passphrase-file"} {
		if name != "passphrase-file" {
			_ = command.MarkFlagRequired(name)
		}
	}
	return command
}

func identityCommand() *cobra.Command {
	root := &cobra.Command{Use: "identity", Short: "register and verify participant identities"}
	var context, actorID, signingPath, passphraseFile, output string
	register := &cobra.Command{Use: "register", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadBinding(context)
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
		value, _ := protocol.RegisterIdentity(binding, actorID, key)
		if err := protocol.WriteJSON(output, value); err != nil {
			return err
		}
		return emit(command, map[string]any{"output": output, "actor_id": actorID})
	}}
	register.Flags().StringVar(&context, "context", "", "binding JSON")
	register.Flags().StringVar(&actorID, "actor-id", "", "numeric actor ID")
	register.Flags().StringVar(&signingPath, "sig-private-key", "", "encrypted signing key")
	register.Flags().StringVar(&passphraseFile, "passphrase-file", "", "signing key passphrase")
	register.Flags().StringVar(&output, "output", "", "registration JSON")
	identityRequired(register, "context", "actor-id", "sig-private-key", "passphrase-file", "output")
	var verifyContext, verifyInput, verifyKey string
	verify := &cobra.Command{Use: "verify", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadBinding(verifyContext)
		if err != nil {
			return err
		}
		var document protocol.IdentityRegistration
		if err := protocol.ReadJSON(verifyInput, &document); err != nil {
			return err
		}
		public, err := protocol.LoadSigningPublic(verifyKey)
		if err != nil {
			return err
		}
		if err := protocol.VerifyIdentity(document, binding, public); err != nil {
			return err
		}
		return emit(command, map[string]any{"verified": true, "actor_id": document.ActorID})
	}}
	verify.Flags().StringVar(&verifyContext, "context", "", "binding JSON")
	verify.Flags().StringVar(&verifyInput, "input", "", "registration JSON")
	verify.Flags().StringVar(&verifyKey, "ver-public-key", "", "signing public key")
	identityRequired(verify, "context", "input", "ver-public-key")
	root.AddCommand(register, verify)
	return root
}

func teamCommand() *cobra.Command {
	root := &cobra.Command{Use: "team", Short: "register teams and collect member consent"}
	var context, teamID, signingPath, passphraseFile, output string
	var members []string
	register := &cobra.Command{Use: "register", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadBinding(context)
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
		proposal, err := protocol.RegisterTeam(binding, teamID, members, key)
		if err != nil {
			return err
		}
		if err := protocol.WriteJSON(output, proposal); err != nil {
			return err
		}
		return emit(command, map[string]any{"output": output, "team_id": teamID, "members": proposal.Members})
	}}
	register.Flags().StringVar(&context, "context", "", "binding JSON")
	register.Flags().StringVar(&teamID, "team-id", "", "team identifier")
	register.Flags().StringArrayVar(&members, "member", nil, "member actor ID (repeatable)")
	register.Flags().StringVar(&signingPath, "sig-private-key", "", "encrypted signing key")
	register.Flags().StringVar(&passphraseFile, "passphrase-file", "", "signing key passphrase")
	register.Flags().StringVar(&output, "output", "", "team proposal JSON")
	identityRequired(register, "context", "team-id", "sig-private-key", "passphrase-file", "output")
	var proposalPath, consentActor, consentSigning, consentPass, consentOutput string
	consent := &cobra.Command{Use: "consent", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		var proposal protocol.TeamProposal
		if err := protocol.ReadJSON(proposalPath, &proposal); err != nil {
			return err
		}
		passphrase, err := readPassphrase(consentPass)
		if err != nil {
			return err
		}
		key, err := protocol.LoadSigningPrivate(consentSigning, passphrase)
		if err != nil {
			return err
		}
		value, err := protocol.RegisterConsent(proposal, consentActor, key)
		if err != nil {
			return err
		}
		if err := protocol.WriteJSON(consentOutput, value); err != nil {
			return err
		}
		return emit(command, map[string]any{"output": consentOutput, "actor_id": consentActor})
	}}
	consent.Flags().StringVar(&proposalPath, "proposal", "", "team proposal JSON")
	consent.Flags().StringVar(&consentActor, "actor-id", "", "member actor ID")
	consent.Flags().StringVar(&consentSigning, "sig-private-key", "", "encrypted signing key")
	consent.Flags().StringVar(&consentPass, "passphrase-file", "", "signing key passphrase")
	consent.Flags().StringVar(&consentOutput, "output", "", "team consent JSON")
	identityRequired(consent, "proposal", "actor-id", "sig-private-key", "passphrase-file", "output")
	var verifyProposal string
	var consentPaths []string
	verify := &cobra.Command{Use: "verify", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
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
		value, err := protocol.VerifyTeam(proposal, consents)
		if err != nil {
			return err
		}
		return emit(command, value)
	}}
	verify.Flags().StringVar(&verifyProposal, "proposal", "", "team proposal JSON")
	verify.Flags().StringArrayVar(&consentPaths, "consent", nil, "team consent JSON (repeatable)")
	identityRequired(verify, "proposal")
	root.AddCommand(register, consent, verify)
	return root
}

func submissionCommand() *cobra.Command {
	var context, input, metadata, signingPath, passphraseFile, output string
	command := &cobra.Command{Use: "submission", Short: "prepare event-bound submissions"}
	prepare := &cobra.Command{Use: "prepare", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		binding, err := protocol.ReadBinding(context)
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
		value, _ := protocol.PrepareSubmission(binding, payload, metadataBytes, key)
		if err := protocol.WriteJSON(output, value); err != nil {
			return err
		}
		return emit(command, map[string]any{"output": output, "payload_sha256": value.PayloadSHA256, "payload_size": value.PayloadSize})
	}}
	prepare.Flags().StringVar(&context, "context", "", "binding JSON")
	prepare.Flags().StringVar(&input, "input", "", "submission byte stream")
	prepare.Flags().StringVar(&metadata, "metadata", "", "optional metadata JSON")
	prepare.Flags().StringVar(&signingPath, "sig-private-key", "", "encrypted signing key")
	prepare.Flags().StringVar(&passphraseFile, "passphrase-file", "", "signing key passphrase")
	prepare.Flags().StringVar(&output, "output", "", "submission JSON")
	identityRequired(prepare, "context", "input", "sig-private-key", "passphrase-file", "output")
	command.AddCommand(prepare)
	return command
}

func identityRequired(command *cobra.Command, names ...string) {
	for _, name := range names {
		if name != "passphrase-file" {
			_ = command.MarkFlagRequired(name)
		}
	}
}

func readPassphrase(path string) (string, error) {
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
