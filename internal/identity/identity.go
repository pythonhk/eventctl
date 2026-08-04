// Package identity manages eventctl Ed25519 key material and public identities.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/pythonhk/eventctl/internal/canonical"
)

const (
	Algorithm          = "Ed25519"
	PrivateSchema      = "pythonhk.eventctl/private-key/v1"
	RegistrySchema     = "pythonhk.eventctl/identity-registry/v1"
	MaxRegistryEntries = 1_000
)

var (
	decimalPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	digestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Public matches the protocol public_key schema.
type Public struct {
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	KeyID     string `json:"key_id" yaml:"key_id"`
	PublicKey string `json:"public_key" yaml:"public_key"`
}

// Signature matches the protocol signature schema.
type Signature struct {
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	KeyID     string `json:"key_id" yaml:"key_id"`
	Value     string `json:"value" yaml:"value"`
}

// ValidateEncoding checks the closed protocol shape and canonical encoding of
// a signature. It does not authenticate the signature against any message.
func (signature Signature) ValidateEncoding() error {
	if signature.Algorithm != Algorithm {
		return fmt.Errorf("signature algorithm is %q, want %q", signature.Algorithm, Algorithm)
	}
	if !digestPattern.MatchString(signature.KeyID) {
		return errors.New("signature key_id must be 64 lower-case hexadecimal characters")
	}
	if _, err := decodeBase64(signature.Value, ed25519.SignatureSize, "signature"); err != nil {
		return err
	}
	return nil
}

// Private is the portable on-disk representation of an Ed25519 private key.
// It stores only the 32-byte seed; callers must protect the containing file.
type Private struct {
	Schema    string `json:"schema"`
	Algorithm string `json:"algorithm"`
	Seed      string `json:"seed"`
	PublicKey string `json:"public_key"`
}

// RegistryEntry binds a GitHub actor and key epoch to a trusted public key.
type RegistryEntry struct {
	ActorID  string `json:"actor_id"`
	KeyEpoch string `json:"key_epoch"`
	Identity Public `json:"identity"`
}

// Registry is generated from active protected event state. Inactive historical
// epochs are not represented; each actor and key ID therefore appears once.
// Team and submission verification must use it rather than keys claimed by
// untrusted documents.
type Registry struct {
	Schema     string          `json:"schema"`
	Identities []RegistryEntry `json:"identities"`
}

// KeyPair holds validated private and public key representations.
type KeyPair struct {
	Private Private
	Public  Public
}

// Generate creates a new key pair using crypto/rand.
func Generate() (KeyPair, error) {
	return GenerateFrom(rand.Reader)
}

// GenerateFrom creates a key pair using source. Production callers should use
// Generate; this form exists for deterministic tests.
func GenerateFrom(source io.Reader) (KeyPair, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(source, seed); err != nil {
		return KeyPair{}, fmt.Errorf("read Ed25519 randomness: %w", err)
	}
	return FromSeed(seed)
}

// FromSeed constructs a key pair from a 32-byte Ed25519 seed.
func FromSeed(seed []byte) (KeyPair, error) {
	if len(seed) != ed25519.SeedSize {
		return KeyPair{}, fmt.Errorf("Ed25519 seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	public := newPublic(publicKey)
	return KeyPair{
		Private: Private{
			Schema: PrivateSchema, Algorithm: Algorithm,
			Seed: encodeBase64(seed), PublicKey: public.PublicKey,
		},
		Public: public,
	}, nil
}

// ParsePrivate strictly decodes and validates a private-key document.
func ParsePrivate(raw []byte) (KeyPair, error) {
	var private Private
	if err := canonical.StrictUnmarshal(raw, &private); err != nil {
		return KeyPair{}, fmt.Errorf("decode private key: %w", err)
	}
	if private.Schema != PrivateSchema {
		return KeyPair{}, fmt.Errorf("private key schema is %q, want %q", private.Schema, PrivateSchema)
	}
	if private.Algorithm != Algorithm {
		return KeyPair{}, fmt.Errorf("private key algorithm is %q, want %q", private.Algorithm, Algorithm)
	}
	seed, err := decodeBase64(private.Seed, ed25519.SeedSize, "private seed")
	if err != nil {
		return KeyPair{}, err
	}
	pair, err := FromSeed(seed)
	if err != nil {
		return KeyPair{}, err
	}
	if subtle.ConstantTimeCompare([]byte(private.PublicKey), []byte(pair.Public.PublicKey)) != 1 {
		return KeyPair{}, errors.New("private key public_key does not match its seed")
	}
	return pair, nil
}

// MarshalPrivate validates and canonically encodes a private key.
func MarshalPrivate(private Private) ([]byte, error) {
	pair, err := parsePrivateValue(private)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(pair.Private)
}

// ParsePublic strictly decodes a public-key object.
func ParsePublic(raw []byte) (Public, error) {
	var public Public
	if err := canonical.StrictUnmarshal(raw, &public); err != nil {
		return Public{}, fmt.Errorf("decode public identity: %w", err)
	}
	if err := public.Validate(); err != nil {
		return Public{}, err
	}
	return public, nil
}

// Validate validates a public identity and its derived key ID.
func (public Public) Validate() error {
	if public.Algorithm != Algorithm {
		return fmt.Errorf("public identity algorithm is %q, want %q", public.Algorithm, Algorithm)
	}
	decoded, err := decodeBase64(public.PublicKey, ed25519.PublicKeySize, "public key")
	if err != nil {
		return err
	}
	if !digestPattern.MatchString(public.KeyID) {
		return errors.New("key_id must be 64 lower-case hexadecimal characters")
	}
	want := KeyID(ed25519.PublicKey(decoded))
	if subtle.ConstantTimeCompare([]byte(public.KeyID), []byte(want)) != 1 {
		return errors.New("key_id does not match public_key")
	}
	return nil
}

// VerificationKey returns a defensive copy of a validated Ed25519 public key.
func VerificationKey(public Public) (ed25519.PublicKey, error) {
	if err := public.Validate(); err != nil {
		return nil, err
	}
	decoded, err := decodeBase64(public.PublicKey, ed25519.PublicKeySize, "public key")
	if err != nil {
		return nil, err
	}
	return append(ed25519.PublicKey(nil), decoded...), nil
}

// MarshalPublic validates and canonically encodes a public key.
func MarshalPublic(public Public) ([]byte, error) {
	if err := public.Validate(); err != nil {
		return nil, err
	}
	return canonical.Marshal(public)
}

// KeyID derives the v1 protocol key identifier: SHA-256 of the algorithm tag,
// one NUL byte, and the decoded public-key bytes.
func KeyID(publicKey ed25519.PublicKey) string {
	hash := sha256.New()
	hash.Write([]byte(Algorithm))
	hash.Write([]byte{0})
	hash.Write(publicKey)
	return hex.EncodeToString(hash.Sum(nil))
}

// Sign creates a protocol signature over message.
func Sign(private Private, message []byte) (Signature, error) {
	key, pair, err := SigningKey(private)
	if err != nil {
		return Signature{}, err
	}
	value := ed25519.Sign(key, message)
	return Signature{Algorithm: Algorithm, KeyID: pair.Public.KeyID, Value: encodeBase64(value)}, nil
}

// SigningKey returns a defensive copy of the decoded Ed25519 private key and
// its validated pair. It is intended for internal bundle integration only.
func SigningKey(private Private) (ed25519.PrivateKey, KeyPair, error) {
	pair, err := parsePrivateValue(private)
	if err != nil {
		return nil, KeyPair{}, err
	}
	seed, err := decodeBase64(pair.Private.Seed, ed25519.SeedSize, "private seed")
	if err != nil {
		return nil, KeyPair{}, err
	}
	key := ed25519.NewKeyFromSeed(seed)
	return append(ed25519.PrivateKey(nil), key...), pair, nil
}

// Verify validates and verifies a protocol signature. Lengths are checked before
// ed25519.Verify, preventing panics on malformed input.
func Verify(public Public, message []byte, signature Signature) error {
	if err := public.Validate(); err != nil {
		return err
	}
	if err := signature.ValidateEncoding(); err != nil {
		return err
	}
	if signature.KeyID != public.KeyID {
		return errors.New("signature key_id does not match trusted public key")
	}
	publicKey, err := decodeBase64(public.PublicKey, ed25519.PublicKeySize, "public key")
	if err != nil {
		return err
	}
	signatureBytes, err := decodeBase64(signature.Value, ed25519.SignatureSize, "signature")
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signatureBytes) {
		return errors.New("Ed25519 signature is invalid")
	}
	return nil
}

// ParseRegistry strictly decodes and validates a trusted identity registry.
func ParseRegistry(raw []byte) (Registry, error) {
	var registry Registry
	if err := canonical.StrictUnmarshal(raw, &registry); err != nil {
		return Registry{}, fmt.Errorf("decode identity registry: %w", err)
	}
	if err := registry.Validate(); err != nil {
		return Registry{}, err
	}
	return registry, nil
}

// Validate validates sorted, unique registry bindings and public keys.
func (registry Registry) Validate() error {
	if registry.Schema != RegistrySchema {
		return fmt.Errorf("identity registry schema is %q, want %q", registry.Schema, RegistrySchema)
	}
	if len(registry.Identities) == 0 || len(registry.Identities) > MaxRegistryEntries {
		return fmt.Errorf("identity registry must contain between 1 and %d identities", MaxRegistryEntries)
	}
	seenActors := make(map[string]struct{}, len(registry.Identities))
	seenKeyIDs := make(map[string]string, len(registry.Identities))
	for index, entry := range registry.Identities {
		if err := ValidateDecimal(entry.ActorID, "actor_id"); err != nil {
			return fmt.Errorf("identity %d: %w", index, err)
		}
		if err := ValidateDecimal(entry.KeyEpoch, "key_epoch"); err != nil {
			return fmt.Errorf("identity %d: %w", index, err)
		}
		if err := entry.Identity.Validate(); err != nil {
			return fmt.Errorf("identity %d: %w", index, err)
		}
		if _, duplicate := seenActors[entry.ActorID]; duplicate {
			return fmt.Errorf("identity registry actor_id %s has more than one active key epoch", entry.ActorID)
		}
		seenActors[entry.ActorID] = struct{}{}
		if owner, duplicate := seenKeyIDs[entry.Identity.KeyID]; duplicate {
			return fmt.Errorf("identity registry key_id is bound to multiple actors %s and %s", owner, entry.ActorID)
		}
		seenKeyIDs[entry.Identity.KeyID] = entry.ActorID
	}
	if !sort.SliceIsSorted(registry.Identities, func(left, right int) bool {
		leftEntry, rightEntry := registry.Identities[left], registry.Identities[right]
		actorOrder := CompareDecimal(leftEntry.ActorID, rightEntry.ActorID)
		return actorOrder < 0 || (actorOrder == 0 && CompareDecimal(leftEntry.KeyEpoch, rightEntry.KeyEpoch) < 0)
	}) {
		return errors.New("identity registry must be sorted by numeric actor_id and key_epoch")
	}
	return nil
}

// Resolve returns the exact trusted identity for actorID and keyEpoch.
func (registry Registry) Resolve(actorID, keyEpoch string) (Public, bool) {
	for _, entry := range registry.Identities {
		if entry.ActorID == actorID && entry.KeyEpoch == keyEpoch {
			return entry.Identity, true
		}
	}
	return Public{}, false
}

// ValidateDecimal validates a positive GitHub-sized canonical decimal string.
func ValidateDecimal(value, field string) error {
	if !decimalPattern.MatchString(value) {
		return fmt.Errorf("%s must be a positive canonical decimal string of at most 20 digits", field)
	}
	return nil
}

// IsDigest reports whether value is a lower-case raw SHA-256 hex digest.
func IsDigest(value string) bool { return digestPattern.MatchString(value) }

// CompareDecimal compares validated positive canonical decimal strings.
func CompareDecimal(left, right string) int {
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return strings.Compare(left, right)
}

func newPublic(publicKey ed25519.PublicKey) Public {
	return Public{Algorithm: Algorithm, KeyID: KeyID(publicKey), PublicKey: encodeBase64(publicKey)}
}

func parsePrivateValue(private Private) (KeyPair, error) {
	raw, err := canonical.Marshal(private)
	if err != nil {
		return KeyPair{}, err
	}
	return ParsePrivate(raw)
}

func encodeBase64(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func decodeBase64(value string, size int, label string) ([]byte, error) {
	if strings.Contains(value, "=") {
		return nil, fmt.Errorf("%s must use unpadded base64url", label)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s as base64url: %w", label, err)
	}
	if len(decoded) != size {
		return nil, fmt.Errorf("%s is %d bytes, want %d", label, len(decoded), size)
	}
	if encodeBase64(decoded) != value {
		return nil, fmt.Errorf("%s is not canonically encoded", label)
	}
	return decoded, nil
}
