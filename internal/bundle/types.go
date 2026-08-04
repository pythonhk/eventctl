// Package bundle implements the authenticated encrypted submission bundle
// format used by eventctl.
//
// A bundle has two independently signed layers. The outer envelope signs the
// ciphertext digest and routing metadata, while the encrypted inner manifest
// signs the same metadata and the ordered file hashes. Callers must still bind
// the signing public key to the authenticated GitHub actor in event state.
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"

	protocolenvelope "github.com/pythonhk/eventctl/internal/envelope"
)

const (
	Protocol                         = protocolenvelope.Protocol
	ProtocolVersion                  = protocolenvelope.ProtocolVersion
	ManifestKind                     = "submission_inner_manifest"
	EnvelopeKind                     = "encrypted_bundle_envelope"
	EncryptionAlgorithm              = "age-hybrid-mlkem768-x25519"
	HybridRecipientFingerprintDomain = "age-hybrid-mlkem768-x25519\x00"

	MaxBundleBytesV1     uint64 = 48_000_000
	MaxCiphertextBytesV1 uint64 = 47_000_000
	MaxPlaintextBytesV1  uint64 = 42_000_000

	manifestSignatureDomain = "eventctl submission manifest v1\x00"
	envelopeSignatureDomain = "eventctl encrypted bundle envelope v1\x00"

	innerMagicSize = 8
	outerMagicSize = 8
)

var (
	innerMagic = [innerMagicSize]byte{'E', 'V', 'T', 'I', 'N', 'N', 'R', 1}
	outerMagic = [outerMagicSize]byte{'E', 'V', 'T', 'B', 'N', 'D', 'L', 1}

	ErrCiphertextDigest      = errors.New("bundle ciphertext digest mismatch")
	ErrDestinationExists     = errors.New("bundle destination already exists")
	ErrDisallowedExtension   = errors.New("bundle file extension is not allowed")
	ErrExtractionUnsupported = errors.New("bundle extraction is unsupported on this platform")
	ErrFileDigest            = errors.New("bundle file digest mismatch")
	ErrInvalidFormat         = errors.New("invalid bundle format")
	ErrLimitExceeded         = errors.New("bundle limit exceeded")
	ErrManifestMismatch      = errors.New("bundle inner and outer manifests differ")
	ErrNoRecipient           = errors.New("no age identity matched the bundle")
	ErrRecipientSet          = errors.New("bundle recipient set mismatch")
	ErrSignature             = errors.New("bundle signature verification failed")
	ErrSourceChanged         = errors.New("source file changed while packing")
	ErrUnsafePath            = errors.New("unsafe bundle path")
)

// Limits bounds every attacker-controlled allocation and stream processed by
// this package. A zero-value Limits selects DefaultLimits.
type Limits struct {
	MaxCiphertextBytes uint64
	MaxEnvelopeBytes   uint32
	MaxFileBytes       uint64
	MaxFiles           uint32
	MaxManifestBytes   uint32
	MaxPlaintextBytes  uint64
	MaxRecipients      uint32
	MaxTotalFileBytes  uint64
}

// DefaultLimits returns the v1 hard processing limits.
func DefaultLimits() Limits {
	return Limits{
		MaxCiphertextBytes: MaxCiphertextBytesV1,
		MaxEnvelopeBytes:   256 * 1024,
		MaxFileBytes:       MaxPlaintextBytesV1,
		MaxFiles:           protocolenvelope.MaxSubmissionFilesV1,
		MaxManifestBytes:   4 * 1024 * 1024,
		MaxPlaintextBytes:  MaxPlaintextBytesV1,
		MaxRecipients:      32,
		MaxTotalFileBytes:  MaxPlaintextBytesV1,
	}
}

func normalizeLimits(limits Limits) (Limits, error) {
	if limits == (Limits{}) {
		return DefaultLimits(), nil
	}
	if limits.MaxCiphertextBytes == 0 || limits.MaxEnvelopeBytes == 0 ||
		limits.MaxFileBytes == 0 || limits.MaxFiles == 0 ||
		limits.MaxManifestBytes == 0 || limits.MaxPlaintextBytes == 0 || limits.MaxRecipients == 0 ||
		limits.MaxTotalFileBytes == 0 {
		return Limits{}, fmt.Errorf("%w: every custom limit must be positive", ErrLimitExceeded)
	}
	if limits.MaxFileBytes > limits.MaxTotalFileBytes {
		return Limits{}, fmt.Errorf("%w: maximum file size exceeds maximum total size", ErrLimitExceeded)
	}
	if limits.MaxTotalFileBytes > limits.MaxPlaintextBytes {
		return Limits{}, fmt.Errorf("%w: maximum total file size exceeds maximum plaintext size", ErrLimitExceeded)
	}
	hard := DefaultLimits()
	if limits.MaxCiphertextBytes > hard.MaxCiphertextBytes ||
		limits.MaxEnvelopeBytes > hard.MaxEnvelopeBytes ||
		limits.MaxFileBytes > hard.MaxFileBytes || limits.MaxFiles > hard.MaxFiles ||
		limits.MaxManifestBytes > hard.MaxManifestBytes ||
		limits.MaxPlaintextBytes > hard.MaxPlaintextBytes ||
		limits.MaxRecipients > hard.MaxRecipients ||
		limits.MaxTotalFileBytes > hard.MaxTotalFileBytes {
		return Limits{}, fmt.Errorf("%w: custom limits exceed the v1 hard processing profile", ErrLimitExceeded)
	}
	if limits.MaxFileBytes >= math.MaxInt64 || limits.MaxTotalFileBytes >= math.MaxInt64 ||
		limits.MaxCiphertextBytes >= math.MaxInt64 || limits.MaxPlaintextBytes >= math.MaxInt64 {
		return Limits{}, fmt.Errorf("%w: stream limits must fit in signed 64-bit readers", ErrLimitExceeded)
	}
	return limits, nil
}

// Binding is the in-memory replay and actor-binding context copied into the
// flat signed JSON objects. Repository/ref/head and PR metadata are
// intentionally excluded because a separate post-push signed request binds
// those values and the complete bundle digest.
type Binding struct {
	EventID            string
	EventEpoch         string
	RequestID          string
	AttemptID          string
	ActorID            string
	KeyID              string
	KeyEpoch           string
	TeamID             string
	TeamProposalDigest string
	BaseRepositoryID   string
	ConfigDigest       string
	IssuedAt           string
	ExpiresAt          string
	RecipientEpoch     string
}

// File records one regular file in normalized slash-separated form.
type File struct {
	Path      string `json:"path"`
	SizeBytes uint64 `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

// Manifest is the signed plaintext manifest encrypted inside the age payload.
type Manifest struct {
	Kind               string `json:"kind"`
	Protocol           string `json:"protocol"`
	ProtocolVersion    int    `json:"protocol_version"`
	EventID            string `json:"event_id"`
	EventEpoch         string `json:"event_epoch"`
	RequestID          string `json:"request_id"`
	AttemptID          string `json:"attempt_id"`
	ActorID            string `json:"actor_id"`
	KeyID              string `json:"key_id"`
	KeyEpoch           string `json:"key_epoch"`
	TeamID             string `json:"team_id"`
	TeamProposalDigest string `json:"team_proposal_digest"`
	BaseRepositoryID   string `json:"base_repository_id"`
	ConfigDigest       string `json:"config_digest"`
	RecipientEpoch     string `json:"recipient_epoch"`
	IssuedAt           string `json:"issued_at"`
	ExpiresAt          string `json:"expires_at"`
	Files              []File `json:"files"`
}

// Envelope is the public, signed metadata placed before the age ciphertext.
// It intentionally omits filenames and file hashes.
type Envelope struct {
	Kind                string   `json:"kind"`
	Protocol            string   `json:"protocol"`
	ProtocolVersion     int      `json:"protocol_version"`
	EventID             string   `json:"event_id"`
	EventEpoch          string   `json:"event_epoch"`
	RequestID           string   `json:"request_id"`
	AttemptID           string   `json:"attempt_id"`
	ActorID             string   `json:"actor_id"`
	KeyID               string   `json:"key_id"`
	KeyEpoch            string   `json:"key_epoch"`
	TeamID              string   `json:"team_id"`
	TeamProposalDigest  string   `json:"team_proposal_digest"`
	BaseRepositoryID    string   `json:"base_repository_id"`
	ConfigDigest        string   `json:"config_digest"`
	RecipientEpoch      string   `json:"recipient_epoch"`
	RecipientKeyIDs     []string `json:"recipient_key_ids"`
	InnerManifestSHA256 string   `json:"inner_manifest_sha256"`
	FileCount           uint32   `json:"file_count"`
	PlaintextSize       uint64   `json:"plaintext_size"`
	CiphertextSize      uint64   `json:"ciphertext_size"`
	CiphertextSHA256    string   `json:"ciphertext_sha256"`
	Encryption          string   `json:"encryption"`
	SignatureAlgorithm  string   `json:"signature_algorithm"`
	IssuedAt            string   `json:"issued_at"`
	ExpiresAt           string   `json:"expires_at"`
}

// Inspection contains structurally validated public metadata and same-file
// digests. Inspect returns it without signer authentication;
// AuthenticatePublic authenticates the outer signer before returning it.
// Verify is still required for claims about the encrypted inner manifest and
// file contents.
type Inspection struct {
	Envelope       Envelope
	EnvelopeSHA256 string
	BundleSize     uint64
	BundleSHA256   string
}

// Packed contains the authenticated data used to build a new bundle plus the
// digest of the complete file that should be bound by the post-push submission
// request.
type Packed struct {
	Verified
}

// Verified contains the authenticated public envelope and decrypted manifest.
// Its digests and size were computed from the same open file descriptor that
// was authenticated and decrypted, so callers can safely compare them with a
// signed post-push bundle reference without a second path-based inspection.
type Verified struct {
	Envelope       Envelope
	Manifest       Manifest
	EnvelopeSHA256 string
	BundleSize     uint64
	BundleSHA256   string
}

func checkedAdd(values ...uint64) (uint64, error) {
	var total uint64
	for _, value := range values {
		if value > math.MaxUint64-total {
			return 0, fmt.Errorf("%w: byte count overflow", ErrLimitExceeded)
		}
		total += value
	}
	return total, nil
}

func signingMessage(domain string, payload []byte) []byte {
	message := make([]byte, 0, len(domain)+len(payload))
	message = append(message, domain...)
	message = append(message, payload...)
	return message
}

func bindingFromManifest(manifest Manifest) Binding {
	return Binding{
		EventID: manifest.EventID, EventEpoch: manifest.EventEpoch,
		RequestID: manifest.RequestID, AttemptID: manifest.AttemptID,
		ActorID: manifest.ActorID, KeyID: manifest.KeyID, KeyEpoch: manifest.KeyEpoch,
		TeamID: manifest.TeamID, TeamProposalDigest: manifest.TeamProposalDigest,
		BaseRepositoryID: manifest.BaseRepositoryID,
		ConfigDigest:     manifest.ConfigDigest, IssuedAt: manifest.IssuedAt,
		ExpiresAt: manifest.ExpiresAt, RecipientEpoch: manifest.RecipientEpoch,
	}
}

func bindingFromEnvelope(envelope Envelope) Binding {
	return Binding{
		EventID: envelope.EventID, EventEpoch: envelope.EventEpoch,
		RequestID: envelope.RequestID, AttemptID: envelope.AttemptID,
		ActorID: envelope.ActorID, KeyID: envelope.KeyID, KeyEpoch: envelope.KeyEpoch,
		TeamID: envelope.TeamID, TeamProposalDigest: envelope.TeamProposalDigest,
		BaseRepositoryID: envelope.BaseRepositoryID,
		ConfigDigest:     envelope.ConfigDigest, IssuedAt: envelope.IssuedAt,
		ExpiresAt: envelope.ExpiresAt, RecipientEpoch: envelope.RecipientEpoch,
	}
}

func manifestFromBinding(binding Binding, files []File) Manifest {
	return Manifest{
		Kind: ManifestKind, Protocol: Protocol, ProtocolVersion: ProtocolVersion,
		EventID: binding.EventID, EventEpoch: binding.EventEpoch,
		RequestID: binding.RequestID, AttemptID: binding.AttemptID,
		ActorID: binding.ActorID, KeyID: binding.KeyID, KeyEpoch: binding.KeyEpoch,
		TeamID: binding.TeamID, TeamProposalDigest: binding.TeamProposalDigest,
		BaseRepositoryID: binding.BaseRepositoryID,
		ConfigDigest:     binding.ConfigDigest, RecipientEpoch: binding.RecipientEpoch,
		IssuedAt: binding.IssuedAt, ExpiresAt: binding.ExpiresAt, Files: files,
	}
}

func envelopeFromBinding(binding Binding) Envelope {
	return Envelope{
		Kind: EnvelopeKind, Protocol: Protocol, ProtocolVersion: ProtocolVersion,
		EventID: binding.EventID, EventEpoch: binding.EventEpoch,
		RequestID: binding.RequestID, AttemptID: binding.AttemptID,
		ActorID: binding.ActorID, KeyID: binding.KeyID, KeyEpoch: binding.KeyEpoch,
		TeamID: binding.TeamID, TeamProposalDigest: binding.TeamProposalDigest,
		BaseRepositoryID: binding.BaseRepositoryID,
		ConfigDigest:     binding.ConfigDigest, RecipientEpoch: binding.RecipientEpoch,
		IssuedAt: binding.IssuedAt, ExpiresAt: binding.ExpiresAt,
	}
}

func validateSigningKey(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid Ed25519 private key length: got %d", len(privateKey))
	}
	derived := ed25519.NewKeyFromSeed(privateKey.Seed())
	if !bytes.Equal(privateKey, derived) {
		return errors.New("Ed25519 private key has an inconsistent public-key suffix")
	}
	return nil
}

func validateVerificationKey(publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key length: got %d", len(publicKey))
	}
	return nil
}
