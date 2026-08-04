package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/pythonhk/eventctl/internal/identity"
	"golang.org/x/term"
)

type keyResult struct {
	KeyID       string          `json:"key_id"`
	PublicKey   identity.Public `json:"public_key"`
	PrivatePath string          `json:"private_path"`
	PublicPath  string          `json:"public_path"`
}

func runKey(args []string, stderr io.Writer) (any, error) {
	if len(args) == 0 {
		return nil, usageError("usage: eventctl key generate|show|backup")
	}
	switch args[0] {
	case "generate":
		return keyGenerate(args[1:], stderr)
	case "show", "public":
		return keyShow(args[1:], stderr)
	case "backup":
		return keyBackup(args[1:], stderr)
	default:
		return nil, usageError("usage: eventctl key generate|show|backup")
	}
}

func keyGenerate(args []string, stderr io.Writer) (any, error) {
	flags := newFlagSet("key generate")
	privateOut := flags.String("private-out", "", "encrypted private key output")
	publicOut := flags.String("public-out", "", "public key output")
	passFile := flags.String("passphrase-file", "", "passphrase file or - for stdin")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *privateOut == "" || *publicOut == "" {
		return nil, usageError("usage: eventctl key generate --private-out PATH --public-out PATH [--passphrase-file PATH|-]")
	}
	if *privateOut == *publicOut {
		return nil, invalidError("private and public outputs must differ", nil)
	}
	passphrase, err := readPassphrase(*passFile, "New key passphrase: ", true, stderr)
	if err != nil {
		return nil, invalidError("read passphrase", err)
	}
	pair, err := identity.Generate()
	if err != nil {
		return nil, err
	}
	privateBytes, err := encryptPrivate(pair.Private, passphrase)
	clear(passphrase)
	if err != nil {
		return nil, err
	}
	publicBytes, err := identity.MarshalPublic(pair.Public)
	if err != nil {
		return nil, err
	}
	if err := writeExclusive(*privateOut, privateBytes, 0o600); err != nil {
		return nil, ioError("write encrypted private key", err)
	}
	if err := writeExclusive(*publicOut, publicBytes, 0o644); err != nil {
		_ = os.Remove(*privateOut)
		return nil, ioError("write public key", err)
	}
	return keyResult{KeyID: pair.Public.KeyID, PublicKey: pair.Public, PrivatePath: *privateOut, PublicPath: *publicOut}, nil
}

func keyShow(args []string, stderr io.Writer) (any, error) {
	flags := newFlagSet("key show")
	keyPath := flags.String("key", "", "encrypted private key")
	passFile := flags.String("passphrase-file", "", "passphrase file or -")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *keyPath == "" {
		return nil, usageError("usage: eventctl key show --key PATH [--passphrase-file PATH|-]")
	}
	pair, err := loadPrivate(*keyPath, *passFile, stderr)
	if err != nil {
		return nil, verificationError("decrypt private key", err)
	}
	return struct {
		KeyID     string          `json:"key_id"`
		PublicKey identity.Public `json:"public_key"`
	}{pair.Public.KeyID, pair.Public}, nil
}

func keyBackup(args []string, stderr io.Writer) (any, error) {
	flags := newFlagSet("key backup")
	keyPath := flags.String("key", "", "encrypted private key")
	out := flags.String("out", "", "encrypted backup output")
	passFile := flags.String("passphrase-file", "", "current passphrase file")
	newPassFile := flags.String("new-passphrase-file", "", "new passphrase file")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *keyPath == "" || *out == "" {
		return nil, usageError("usage: eventctl key backup --key PATH --out PATH [--passphrase-file PATH|-] [--new-passphrase-file PATH|-]")
	}
	pair, err := loadPrivate(*keyPath, *passFile, stderr)
	if err != nil {
		return nil, verificationError("decrypt source key", err)
	}
	newPass, err := readPassphrase(*newPassFile, "Backup passphrase: ", true, stderr)
	if err != nil {
		return nil, invalidError("read backup passphrase", err)
	}
	encrypted, err := encryptPrivate(pair.Private, newPass)
	if err != nil {
		clear(newPass)
		return nil, err
	}
	verified, err := decryptPrivateBytes(encrypted, newPass)
	clear(newPass)
	if err != nil || verified.Public != pair.Public {
		return nil, verificationError("verify encrypted backup", err)
	}
	if err := writeExclusive(*out, encrypted, 0o600); err != nil {
		return nil, ioError("write encrypted backup", err)
	}
	return struct {
		Path  string `json:"path"`
		KeyID string `json:"key_id"`
	}{*out, pair.Public.KeyID}, nil
}

func encryptPrivate(private identity.Private, passphrase []byte) ([]byte, error) {
	raw, err := identity.MarshalPrivate(private)
	if err != nil {
		return nil, err
	}
	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return nil, fmt.Errorf("create scrypt recipient: %w", err)
	}
	var output bytes.Buffer
	writer, err := age.Encrypt(&output, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(raw); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
func decryptPrivateBytes(encrypted, passphrase []byte) (identity.KeyPair, error) {
	identityAge, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return identity.KeyPair{}, err
	}
	reader, err := age.Decrypt(bytes.NewReader(encrypted), identityAge)
	if err != nil {
		return identity.KeyPair{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maxSmallFile+1))
	if err != nil {
		return identity.KeyPair{}, err
	}
	if len(raw) > maxSmallFile {
		return identity.KeyPair{}, errors.New("decrypted key exceeds limit")
	}
	return identity.ParsePrivate(raw)
}
func loadPrivate(path, passFile string, stderr io.Writer) (identity.KeyPair, error) {
	encrypted, err := readBounded(path, maxSmallFile)
	if err != nil {
		return identity.KeyPair{}, err
	}
	pass, err := readPassphrase(passFile, "Key passphrase: ", false, stderr)
	if err != nil {
		return identity.KeyPair{}, err
	}
	defer clear(pass)
	return decryptPrivateBytes(encrypted, pass)
}

func readPassphrase(path, prompt string, confirm bool, stderr io.Writer) ([]byte, error) {
	if path != "" {
		var raw []byte
		var err error
		if path == "-" {
			raw, err = io.ReadAll(io.LimitReader(os.Stdin, 4097))
		} else {
			raw, err = readBounded(path, 4096)
		}
		if err != nil {
			return nil, err
		}
		if len(raw) > 4096 {
			return nil, errors.New("passphrase exceeds 4096 bytes")
		}
		raw = bytes.TrimSuffix(raw, []byte("\n"))
		raw = bytes.TrimSuffix(raw, []byte("\r"))
		if err := validatePassphrase(raw); err != nil {
			return nil, err
		}
		return append([]byte(nil), raw...), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("stdin is not a terminal; use --passphrase-file PATH or -")
	}
	fmt.Fprint(stderr, prompt)
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(stderr)
	if err != nil {
		return nil, err
	}
	if err := validatePassphrase(first); err != nil {
		clear(first)
		return nil, err
	}
	if confirm {
		fmt.Fprint(stderr, "Confirm "+strings.ToLower(prompt))
		second, err := term.ReadPassword(fd)
		fmt.Fprintln(stderr)
		if err != nil {
			clear(first)
			return nil, err
		}
		equal := bytes.Equal(first, second)
		clear(second)
		if !equal {
			clear(first)
			return nil, errors.New("passphrases do not match")
		}
	}
	return first, nil
}
func validatePassphrase(value []byte) error {
	if len(value) < 10 {
		return errors.New("passphrase must be at least 10 bytes")
	}
	if bytes.IndexByte(value, 0) >= 0 {
		return errors.New("passphrase contains NUL")
	}
	return nil
}
func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ = flag.ErrHelp
