// Package recipient manages organizer submission-decryption identities.
// Submission keys are strictly age HybridIdentity values (ML-KEM-768+X25519);
// local private-key files are encrypted at rest with the keystore package's
// age-scrypt profile.
package recipient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"filippo.io/age"
	"github.com/pythonhk/eventctl/internal/bundle"
	"github.com/pythonhk/eventctl/internal/keystore"
)

const identityDocumentHeader = "eventctl age hybrid identity v1\n"

var ErrInvalidIdentityDocument = errors.New("invalid hybrid identity document")

// Public is safe to publish in a signed event configuration.
type Public struct {
	Recipient   string
	Fingerprint string
}

// GenerateIdentityFile generates a native age HybridIdentity, stores its
// versioned secret document in an exclusive encrypted keystore file, and
// returns only its public recipient data.
func GenerateIdentityFile(
	ctx context.Context,
	outputPath string,
	passphrase []byte,
	limits keystore.Limits,
) (Public, error) {
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		return Public{}, fmt.Errorf("generate hybrid identity: %w", err)
	}
	public, err := Describe(identity)
	if err != nil {
		return Public{}, err
	}
	document := []byte(identityDocumentHeader + identity.String() + "\n")
	defer clear(document)
	if err := keystore.EncryptFile(ctx, outputPath, document, passphrase, limits); err != nil {
		return Public{}, err
	}
	return public, nil
}

// LoadIdentity decrypts and strictly parses a complete versioned identity
// document. The decrypted byte buffer is cleared before return.
func LoadIdentity(
	ctx context.Context,
	inputPath string,
	passphrase []byte,
	limits keystore.Limits,
) (*age.HybridIdentity, error) {
	document, err := keystore.DecryptFile(ctx, inputPath, passphrase, limits)
	if err != nil {
		return nil, err
	}
	defer clear(document)
	if !bytes.HasPrefix(document, []byte(identityDocumentHeader)) ||
		len(document) <= len(identityDocumentHeader)+1 || document[len(document)-1] != '\n' {
		return nil, ErrInvalidIdentityDocument
	}
	encodedBytes := document[len(identityDocumentHeader) : len(document)-1]
	if bytes.IndexByte(encodedBytes, '\n') >= 0 {
		return nil, ErrInvalidIdentityDocument
	}
	identity, err := age.ParseHybridIdentity(string(encodedBytes))
	if err != nil || identity.String() != string(encodedBytes) {
		return nil, ErrInvalidIdentityDocument
	}
	return identity, nil
}

// Describe returns the canonical public recipient and its v1 fingerprint.
func Describe(identity *age.HybridIdentity) (Public, error) {
	if identity == nil {
		return Public{}, fmt.Errorf("hybrid identity is nil")
	}
	recipient := identity.Recipient()
	encoded := recipient.String()
	if !strings.HasPrefix(encoded, "age1pq1") {
		return Public{}, fmt.Errorf("hybrid identity returned a non-hybrid recipient")
	}
	fingerprint, err := bundle.HybridRecipientFingerprint(recipient)
	if err != nil {
		return Public{}, err
	}
	return Public{Recipient: encoded, Fingerprint: fingerprint}, nil
}
