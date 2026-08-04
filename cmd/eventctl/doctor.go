package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"runtime"

	"filippo.io/age"
	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/envelope"
)

type doctorResult struct {
	Status                   string   `json:"status"`
	Protocol                 string   `json:"protocol"`
	ProtocolVersion          int      `json:"protocol_version"`
	CanonicalProfile         string   `json:"canonical_profile"`
	Runtime                  string   `json:"runtime"`
	OperatingSystem          string   `json:"operating_system"`
	Architecture             string   `json:"architecture"`
	ParticipantSupported     bool     `json:"participant_supported"`
	JudgeExtractionSupported bool     `json:"judge_extraction_supported"`
	Cryptography             []string `json:"cryptography"`
}

func runDoctor(args []string) (any, error) {
	flags := newFlagSet("doctor")
	out := flags.String("out", "", "optional normalized doctor output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return nil, usageError("usage: eventctl doctor [--out PATH]")
	}
	supportedOS := runtime.GOOS == "darwin" || runtime.GOOS == "linux" || runtime.GOOS == "windows"
	supportedArch := runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
	if !supportedOS || !supportedArch {
		return nil, verificationError("unsupported eventctl platform", nil)
	}
	if err := doctorCryptoSelfTest(); err != nil {
		return nil, verificationError("cryptographic self-test failed", err)
	}
	canonicalProbe, err := canonical.Marshal(struct {
		A int `json:"a"`
		Z int `json:"z"`
	}{1, 2})
	if err != nil || !bytes.Equal(canonicalProbe, []byte(`{"a":1,"z":2}`)) {
		return nil, verificationError("canonical JSON self-test failed", err)
	}
	result := doctorResult{
		Status: "healthy", Protocol: envelope.Protocol, ProtocolVersion: envelope.ProtocolVersion,
		CanonicalProfile: "eventctl-canonical-json-v1", Runtime: runtime.Version(),
		OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH,
		ParticipantSupported: true, JudgeExtractionSupported: runtime.GOOS == "linux",
		Cryptography: []string{"Ed25519", "age-hybrid-mlkem768-x25519", "age-scrypt-private-key-storage", "SHA-256"},
	}
	if *out != "" {
		if err := writeCanonical(*out, result, 0o644); err != nil {
			return nil, ioError("write doctor result", err)
		}
	}
	return result, nil
}

func doctorCryptoSelfTest() error {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	message := []byte("eventctl doctor cryptographic self-test")
	signature := ed25519.Sign(privateKey, message)
	if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), message, signature) {
		return errors.New("Ed25519 sign/verify mismatch")
	}
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		return err
	}
	var encrypted bytes.Buffer
	writer, err := age.Encrypt(&encrypted, identity.Recipient())
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	reader, err := age.Decrypt(bytes.NewReader(encrypted.Bytes()), identity)
	if err != nil {
		return err
	}
	decrypted, err := io.ReadAll(io.LimitReader(reader, int64(len(message)+1)))
	if err != nil {
		return err
	}
	if !bytes.Equal(decrypted, message) {
		return errors.New("hybrid age encrypt/decrypt mismatch")
	}
	return nil
}
