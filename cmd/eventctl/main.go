package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"filippo.io/age"
	"github.com/caarlos0/env/v11"
	"github.com/samber/lo"
	"github.com/spf13/cobra"

	"github.com/pythonhk/eventctl/internal/buildinfo"
	"github.com/pythonhk/eventctl/protocol"
)

type response struct {
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	Result  any    `json:"result,omitempty"`
	Error   string `json:"error,omitempty"`
}

type doctorEnvironment struct {
	EventID string `env:"EVENTCTL_EVENT_ID" envDefault:""`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	root := newRoot(stdout, stderr)
	root.SetArgs(arguments)
	if err := root.Execute(); err != nil {
		command := strings.TrimSpace(strings.TrimPrefix(root.CommandPath(), "eventctl"))
		if command == "" {
			command = "eventctl"
		}
		writeResponse(stdout, response{OK: false, Command: command, Error: err.Error()})
		return 1
	}
	return 0
}

func newRoot(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "eventctl",
		Short:         "portable event artifacts and encrypted feedback",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(versionCommand(), doctorCommand(), keyGenCommand(), teamCommand(), submissionCommand(), sigcryptCommand(), decverifyCommand())
	return root
}

func versionCommand() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "print version information", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		return emit(command, buildinfo.Current())
	}}
}

func doctorCommand() *cobra.Command {
	return &cobra.Command{Use: "doctor", Short: "check local eventctl support", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		configuration := lo.Must(env.ParseAs[doctorEnvironment]())
		if configuration.EventID != "" {
			if err := protocol.ValidateEventID(configuration.EventID); err != nil {
				return err
			}
		}
		return emit(command, map[string]any{
			"protocol": protocol.Version,
			"event_id": configuration.EventID,
			"go":       runtime.Version(),
			"algorithms": map[string]string{
				"signature":  "Ed25519",
				"encryption": "age-hybrid-mlkem768-x25519",
			},
		})
	}}
}

func keyGenCommand() *cobra.Command {
	var output string
	command := &cobra.Command{Use: "key-gen", Short: "create signing and encryption key pairs", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		paths, err := protocol.GenerateKeyDirectory(output)
		if err != nil {
			return err
		}
		return emit(command, paths)
	}}
	command.Flags().StringVar(&output, "out", "", "key directory")
	require(command, "out")
	return command
}

func teamCommand() *cobra.Command {
	root := &cobra.Command{Use: "team", Short: "prepare one-off team onboarding artifacts"}
	root.AddCommand(teamFormCommand(), teamKeyCommand())
	return root
}

func teamFormCommand() *cobra.Command {
	var eventID, teamName, githubID, signingPath, encryptionPath, output string
	var members []string
	command := &cobra.Command{Use: "form", Short: "form a peer team and generate its UUID", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		private, err := protocol.LoadSigningPrivate(signingPath)
		if err != nil {
			return err
		}
		public := publicPEM(private)
		encryption, err := protocol.LoadEncryptionPublic(encryptionPath)
		if err != nil {
			return err
		}
		manifest, err := protocol.NewFormation(eventID, githubID, teamName, public, encryption.Text, members)
		if err != nil {
			return err
		}
		result, err := protocol.WriteArtifact(output, manifest, nil, private)
		if err != nil {
			return err
		}
		return emit(command, result)
	}}
	command.Flags().StringVar(&eventID, "event-id", "", "event repository slug")
	command.Flags().StringVar(&teamName, "team-name", "", "free-form team name")
	command.Flags().StringVar(&githubID, "github-id", "", "numeric GitHub account ID")
	command.Flags().StringArrayVar(&members, "member", nil, "numeric GitHub member ID (repeatable)")
	command.Flags().StringVar(&signingPath, "sig-priv-key", "", "Ed25519 private key")
	command.Flags().StringVar(&encryptionPath, "enc-pub-key", "", "age recipient public key")
	command.Flags().StringVar(&output, "out", "", "formation tar output")
	require(command, "event-id", "team-name", "github-id", "sig-priv-key", "enc-pub-key", "out")
	return command
}

func teamKeyCommand() *cobra.Command {
	var formationPath, githubID, signingPath, encryptionPath, output string
	command := &cobra.Command{Use: "key", Short: "prove one additional member key", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		formation, err := protocol.ReadArtifact(formationPath)
		if err != nil {
			return err
		}
		private, err := protocol.LoadSigningPrivate(signingPath)
		if err != nil {
			return err
		}
		public := publicPEM(private)
		encryption, err := protocol.LoadEncryptionPublic(encryptionPath)
		if err != nil {
			return err
		}
		manifest, err := protocol.NewTeamKey(formation, githubID, public, encryption.Text)
		if err != nil {
			return err
		}
		result, err := protocol.WriteArtifact(output, manifest, nil, private)
		if err != nil {
			return err
		}
		return emit(command, result)
	}}
	command.Flags().StringVar(&formationPath, "formation", "", "formation tar")
	command.Flags().StringVar(&githubID, "github-id", "", "numeric GitHub account ID")
	command.Flags().StringVar(&signingPath, "sig-priv-key", "", "Ed25519 private key")
	command.Flags().StringVar(&encryptionPath, "enc-pub-key", "", "age recipient public key")
	command.Flags().StringVar(&output, "out", "", "key tar output")
	require(command, "formation", "github-id", "sig-priv-key", "enc-pub-key", "out")
	return command
}

func submissionCommand() *cobra.Command {
	root := &cobra.Command{Use: "submission", Short: "prepare participant submissions"}
	var eventID, githubID, teamID, signingPath, output string
	var inputs []string
	prepare := &cobra.Command{Use: "prepare", Short: "sign and tar a submission", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		private, err := protocol.LoadSigningPrivate(signingPath)
		if err != nil {
			return err
		}
		public := publicPEM(private)
		manifest, err := protocol.NewSubmission(eventID, githubID, teamID, public)
		if err != nil {
			return err
		}
		result, err := protocol.WriteArtifact(output, manifest, inputs, private)
		if err != nil {
			return err
		}
		return emit(command, result)
	}}
	prepare.Flags().StringVar(&eventID, "event-id", "", "event repository slug")
	prepare.Flags().StringVar(&githubID, "github-id", "", "numeric GitHub account ID")
	prepare.Flags().StringVar(&teamID, "team-id", "", "team UUID")
	prepare.Flags().StringArrayVar(&inputs, "input", nil, "submission input file (repeatable)")
	prepare.Flags().StringVar(&signingPath, "sig-priv-key", "", "Ed25519 private key")
	prepare.Flags().StringVar(&output, "out", "", "submission tar output")
	require(prepare, "event-id", "github-id", "team-id", "sig-priv-key", "out")
	root.AddCommand(prepare)
	return root
}

func sigcryptCommand() *cobra.Command {
	var signingPath, output string
	var inputs, recipientPaths []string
	command := &cobra.Command{Use: "sigcrypt", Short: "sign and encrypt tarred input files", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		private, err := protocol.LoadSigningPrivate(signingPath)
		if err != nil {
			return err
		}
		recipients, err := loadRecipients(recipientPaths)
		if err != nil {
			return err
		}
		result, err := protocol.SealFeedback(inputs, output, private, recipients)
		if err != nil {
			return err
		}
		return emit(command, result)
	}}
	command.Flags().StringArrayVar(&inputs, "input", nil, "input file (repeatable)")
	command.Flags().StringVar(&output, "out", "", "encrypted tar output")
	command.Flags().StringVar(&signingPath, "sig-priv-key", "", "Ed25519 private key")
	command.Flags().StringArrayVar(&recipientPaths, "enc-pub-key", nil, "age recipient public key (repeatable)")
	require(command, "out", "sig-priv-key")
	return command
}

func decverifyCommand() *cobra.Command {
	var input, outputDirectory, signingPath, encryptionPath string
	command := &cobra.Command{Use: "decverify", Short: "decrypt and verify encrypted feedback", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		public, err := protocol.LoadSigningPublic(signingPath)
		if err != nil {
			return err
		}
		private, err := protocol.LoadEncryptionPrivate(encryptionPath)
		if err != nil {
			return err
		}
		result, err := protocol.OpenFeedback(input, outputDirectory, public, private)
		if err != nil {
			return err
		}
		return emit(command, result)
	}}
	command.Flags().StringVar(&input, "input", "", "encrypted feedback tar")
	command.Flags().StringVar(&outputDirectory, "out-dir", "", "empty extraction directory")
	command.Flags().StringVar(&signingPath, "sig-pub-key", "", "trusted Ed25519 public key")
	command.Flags().StringVar(&encryptionPath, "enc-priv-key", "", "age private key")
	require(command, "input", "out-dir", "sig-pub-key", "enc-priv-key")
	return command
}

func publicPEM(private ed25519.PrivateKey) string {
	return protocol.SigningPublicPEM(private.Public().(ed25519.PublicKey))
}

func loadRecipients(paths []string) ([]age.Recipient, error) {
	if len(paths) == 0 {
		return nil, errors.New("at least one --enc-pub-key is required")
	}
	loaded := make([]protocol.EncryptionPublic, 0, len(paths))
	for _, file := range paths {
		value, err := protocol.LoadEncryptionPublic(file)
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, value)
	}
	unique := lo.UniqBy(loaded, func(value protocol.EncryptionPublic) string { return value.Text })
	return lo.Map(unique, func(value protocol.EncryptionPublic, _ int) age.Recipient { return value.Recipient }), nil
}

func emit(command *cobra.Command, value any) error {
	writeResponse(command.OutOrStdout(), response{OK: true, Command: strings.TrimSpace(strings.TrimPrefix(command.CommandPath(), "eventctl")), Result: value})
	return nil
}

func writeResponse(writer io.Writer, value response) {
	_, _ = fmt.Fprintln(writer, string(lo.Must(json.Marshal(value))))
}

func require(command *cobra.Command, names ...string) {
	for _, name := range names {
		lo.Must0(command.MarkFlagRequired(name))
	}
}
