package main

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/keystore"
	organizerrecipient "github.com/pythonhk/eventctl/internal/recipient"
)

const recipientAlgorithm = "age-hybrid-mlkem768-x25519"

type recipientPublicDocument struct {
	Kind        string `json:"kind"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

func runRecipient(args []string, stderr io.Writer) (any, error) {
	if len(args) == 0 {
		return nil, usageError("usage: eventctl recipient generate|show")
	}
	switch args[0] {
	case "generate":
		return recipientGenerate(args[1:], stderr)
	case "show":
		return recipientShow(args[1:], stderr)
	default:
		return nil, usageError("usage: eventctl recipient generate|show")
	}
}

func recipientGenerate(args []string, stderr io.Writer) (any, error) {
	flags := newFlagSet("recipient generate")
	identityOut := flags.String("identity-out", "", "encrypted organizer identity output")
	recipientOut := flags.String("recipient-out", "", "public hybrid recipient output")
	passFile := flags.String("passphrase-file", "", "passphrase file or -")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *identityOut == "" || *recipientOut == "" {
		return nil, usageError("usage: eventctl recipient generate --identity-out PATH --recipient-out PATH [--passphrase-file PATH|-]")
	}
	if filepath.Clean(*identityOut) == filepath.Clean(*recipientOut) {
		return nil, invalidError("identity and recipient outputs must differ", nil)
	}
	passphrase, err := readPassphrase(*passFile, "New recipient identity passphrase: ", true, stderr)
	if err != nil {
		return nil, invalidError("read passphrase", err)
	}
	defer clear(passphrase)
	if err := os.MkdirAll(filepath.Dir(*identityOut), 0o700); err != nil {
		return nil, ioError("create recipient identity directory", err)
	}
	public, err := organizerrecipient.GenerateIdentityFile(context.Background(), *identityOut, passphrase, keystore.DefaultLimits())
	if err != nil {
		return nil, ioError("generate encrypted recipient identity", err)
	}
	document := recipientPublicDocument{
		Kind: "submission_recipient", Algorithm: recipientAlgorithm,
		PublicKey: public.Recipient, Fingerprint: public.Fingerprint,
	}
	raw, err := canonical.Marshal(document)
	if err != nil {
		_ = os.Remove(*identityOut)
		return nil, err
	}
	if err := writeExclusive(*recipientOut, append(raw, '\n'), 0o644); err != nil {
		_ = os.Remove(*identityOut)
		return nil, ioError("write public recipient", err)
	}
	return struct {
		IdentityPath  string `json:"identity_path"`
		RecipientPath string `json:"recipient_path"`
		Algorithm     string `json:"algorithm"`
		Fingerprint   string `json:"fingerprint"`
	}{*identityOut, *recipientOut, recipientAlgorithm, public.Fingerprint}, nil
}

func recipientShow(args []string, stderr io.Writer) (any, error) {
	flags := newFlagSet("recipient show")
	identityPath := flags.String("identity", "", "encrypted organizer identity")
	passFile := flags.String("passphrase-file", "", "passphrase file or -")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *identityPath == "" {
		return nil, usageError("usage: eventctl recipient show --identity PATH [--passphrase-file PATH|-]")
	}
	passphrase, err := readPassphrase(*passFile, "Recipient identity passphrase: ", false, stderr)
	if err != nil {
		return nil, invalidError("read passphrase", err)
	}
	defer clear(passphrase)
	identity, err := organizerrecipient.LoadIdentity(context.Background(), *identityPath, passphrase, keystore.DefaultLimits())
	if err != nil {
		return nil, verificationError("decrypt recipient identity", err)
	}
	public, err := organizerrecipient.Describe(identity)
	if err != nil {
		return nil, verificationError("validate recipient identity", err)
	}
	return recipientPublicDocument{
		Kind: "submission_recipient", Algorithm: recipientAlgorithm,
		PublicKey: public.Recipient, Fingerprint: public.Fingerprint,
	}, nil
}
