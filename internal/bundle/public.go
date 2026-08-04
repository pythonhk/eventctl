package bundle

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/pythonhk/eventctl/internal/identity"
)

// AuthenticatePublic verifies the detached signature on the small public
// envelope before hashing the bounded ciphertext. It does not decrypt the
// inner manifest and therefore makes no claim about confidential file content.
func AuthenticatePublic(
	ctx context.Context,
	bundlePath string,
	signingIdentity identity.Public,
	requestedLimits Limits,
) (Inspection, error) {
	if err := signingIdentity.Validate(); err != nil {
		return Inspection{}, fmt.Errorf("validate registered signing identity: %w", err)
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(signingIdentity.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return Inspection{}, errors.New("registered signing identity has an invalid public key")
	}
	parsed, limits, err := openBundle(bundlePath, requestedLimits)
	if err != nil {
		return Inspection{}, err
	}
	defer parsed.file.Close()
	if signingIdentity.KeyID != parsed.envelope.KeyID {
		return Inspection{}, fmt.Errorf("%w: signer key ID does not match registered key", ErrSignature)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), signingMessage(envelopeSignatureDomain, parsed.envelopeBytes), parsed.envelopeSignature) {
		return Inspection{}, fmt.Errorf("%w: outer envelope", ErrSignature)
	}
	return inspectDigests(ctx, parsed, limits)
}
