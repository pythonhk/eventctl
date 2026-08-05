// Package envelope implements strict, domain-separated signatures and common
// actor-bound protocol types for eventctl v1.
package envelope

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/identity"
)

const (
	Protocol             = "pythonhk.github-native-event"
	ProtocolVersion      = 1
	SigningPrefix        = "pythonhk:github-native-event:v1\x00"
	ReplayKeyPrefix      = "pythonhk.github-native-event/v1/replay-key\x00"
	MaxDocumentBytes     = 1 << 20
	MaxSubmissionFilesV1 = 4_096
	MaxGenericValidity   = 24 * time.Hour

	RegistrationKind   = "registration_request"
	RegistrationDomain = "registration_request"
)

var (
	eventIDPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{2,62}$`)
	requestKindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	uuidPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gitOIDPattern      = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	ownerPattern       = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	repositoryPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	refPattern         = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

// Repository is the immutable numeric GitHub repository identity plus its
// human-readable address.
type Repository struct {
	ID    string `json:"id"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Expected contains independently trusted workflow context. Empty fields are
// not compared by the library; machine-facing CLI verification requires all
// operation-relevant fields.
type Expected struct {
	EventID      string
	EventEpoch   string
	RepositoryID string
	ActorID      string
	ConfigDigest string
	KeyEpoch     string
	KeyID        string
	Now          time.Time
}

// Fingerprint is the protected-state replay primitive. ReplayKey identifies a
// logical request independently of its signed contents; RequestDigest covers
// the complete domain-separated signing input.
type Fingerprint struct {
	ReplayKey     string `json:"replay_key"`
	RequestDigest string `json:"request_digest"`
}

type ReplayDisposition string

const (
	ReplayNew       ReplayDisposition = "new"
	ReplayDuplicate ReplayDisposition = "duplicate"
	ReplayConflict  ReplayDisposition = "conflict"
)

// Registration is the authoritative flat v1 registration wire document.
type Registration struct {
	Kind            string             `json:"kind"`
	Protocol        string             `json:"protocol"`
	ProtocolVersion int                `json:"protocol_version"`
	EventID         string             `json:"event_id"`
	EventEpoch      string             `json:"event_epoch"`
	OperationID     string             `json:"operation_id"`
	ActorID         string             `json:"actor_id"`
	KeyID           string             `json:"key_id"`
	KeyEpoch        string             `json:"key_epoch"`
	BaseRepository  Repository         `json:"base_repository"`
	ConfigDigest    string             `json:"config_digest"`
	TermsDigest     string             `json:"terms_digest"`
	IssuedAt        string             `json:"issued_at"`
	ExpiresAt       string             `json:"expires_at"`
	ParticipantKey  identity.Public    `json:"participant_key"`
	Signature       identity.Signature `json:"signature"`
}

type registrationUnsigned struct {
	Kind            string          `json:"kind"`
	Protocol        string          `json:"protocol"`
	ProtocolVersion int             `json:"protocol_version"`
	EventID         string          `json:"event_id"`
	EventEpoch      string          `json:"event_epoch"`
	OperationID     string          `json:"operation_id"`
	ActorID         string          `json:"actor_id"`
	KeyID           string          `json:"key_id"`
	KeyEpoch        string          `json:"key_epoch"`
	BaseRepository  Repository      `json:"base_repository"`
	ConfigDigest    string          `json:"config_digest"`
	TermsDigest     string          `json:"terms_digest"`
	IssuedAt        string          `json:"issued_at"`
	ExpiresAt       string          `json:"expires_at"`
	ParticipantKey  identity.Public `json:"participant_key"`
}

// RegistrationParams are trusted local inputs for a registration request.
type RegistrationParams struct {
	EventID        string
	EventEpoch     string
	OperationID    string
	ActorID        string
	KeyEpoch       string
	BaseRepository Repository
	ConfigDigest   string
	TermsDigest    string
	IssuedAt       time.Time
	ExpiresAt      time.Time
}

// VerifiedRegistration is a verified request plus its replay fingerprint.
type VerifiedRegistration struct {
	Document    Registration
	Fingerprint Fingerprint
}

// ValidateUntrustedStructure validates the concrete registration schema and
// internal field relationships without authenticating its signature, trusted
// actor/config context, or current validity window.
func (value Registration) ValidateUntrustedStructure() error {
	if err := validateRegistration(value, time.Time{}, MaxGenericValidity); err != nil {
		return err
	}
	if value.ParticipantKey.KeyID != value.KeyID {
		return errors.New("participant_key.key_id does not match key_id")
	}
	if err := value.Signature.ValidateEncoding(); err != nil {
		return err
	}
	if value.Signature.KeyID != value.KeyID {
		return errors.New("signature.key_id does not match key_id")
	}
	return nil
}

// NewRequestID returns a lower-case RFC 4122 UUIDv4.
func NewRequestID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

// NewRegistration creates a self-signed epoch-1 registration request.
func NewRegistration(params RegistrationParams, private identity.Private) ([]byte, error) {
	pair, err := parsePrivate(private)
	if err != nil {
		return nil, err
	}
	if params.OperationID == "" {
		params.OperationID, err = NewRequestID()
		if err != nil {
			return nil, err
		}
	}
	if params.KeyEpoch == "" {
		params.KeyEpoch = "1"
	}
	registration := Registration{
		Kind: RegistrationKind, Protocol: Protocol, ProtocolVersion: ProtocolVersion,
		EventID: params.EventID, EventEpoch: params.EventEpoch, OperationID: params.OperationID, ActorID: params.ActorID,
		KeyID: pair.Public.KeyID, KeyEpoch: params.KeyEpoch,
		BaseRepository: params.BaseRepository, ConfigDigest: params.ConfigDigest,
		TermsDigest: params.TermsDigest, IssuedAt: formatTime(params.IssuedAt), ExpiresAt: formatTime(params.ExpiresAt),
		ParticipantKey: pair.Public,
	}
	if err := validateRegistration(registration, time.Time{}, MaxGenericValidity); err != nil {
		return nil, err
	}
	registration.Signature, err = Sign(RegistrationDomain, registrationUnsignedFrom(registration), pair.Private)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(registration)
}

// VerifyRegistration verifies strict structure, trusted context, validity
// window, self-signature, and epoch-1 proof of possession. requestTTL must be
// read from the authenticated event config bound by expected.ConfigDigest.
func VerifyRegistration(raw []byte, expected Expected, requestTTL time.Duration) (VerifiedRegistration, error) {
	if len(raw) > MaxDocumentBytes {
		return VerifiedRegistration{}, errors.New("registration document exceeds 1 MiB")
	}
	var registration Registration
	if err := canonical.StrictUnmarshal(raw, &registration); err != nil {
		return VerifiedRegistration{}, fmt.Errorf("decode registration: %w", err)
	}
	if err := validateRegistration(registration, expected.Now, requestTTL); err != nil {
		return VerifiedRegistration{}, err
	}
	if err := compareExpected(registration.EventID, registration.EventEpoch, registration.BaseRepository.ID, registration.ActorID, registration.ConfigDigest, registration.KeyEpoch, registration.KeyID, expected); err != nil {
		return VerifiedRegistration{}, err
	}
	if registration.ParticipantKey.KeyID != registration.KeyID {
		return VerifiedRegistration{}, errors.New("participant_key.key_id does not match key_id")
	}
	if err := Verify(RegistrationDomain, registrationUnsignedFrom(registration), registration.Signature, registration.ParticipantKey); err != nil {
		return VerifiedRegistration{}, err
	}
	intentDigest, err := SigningDigest(RegistrationDomain, registrationUnsignedFrom(registration))
	if err != nil {
		return VerifiedRegistration{}, err
	}
	fingerprint, err := NewFingerprint(RegistrationDomain, registration.EventID, registration.OperationID, intentDigest)
	if err != nil {
		return VerifiedRegistration{}, err
	}
	return VerifiedRegistration{Document: registration, Fingerprint: fingerprint}, nil
}

// Sign applies v1 domain separation and returns an Ed25519 protocol signature.
func Sign(domain string, unsigned any, private identity.Private) (identity.Signature, error) {
	input, err := SigningInput(domain, unsigned)
	if err != nil {
		return identity.Signature{}, err
	}
	return identity.Sign(private, input)
}

// Verify applies v1 domain separation and verifies a signature using trustedKey.
func Verify(domain string, unsigned any, signature identity.Signature, trustedKey identity.Public) error {
	input, err := SigningInput(domain, unsigned)
	if err != nil {
		return err
	}
	if err := identity.Verify(trustedKey, input, signature); err != nil {
		return fmt.Errorf("verify %s signature: %w", domain, err)
	}
	return nil
}

// SigningInput returns the exact bytes covered by an operation signature.
func SigningInput(domain string, unsigned any) ([]byte, error) {
	if domain == "" || strings.ContainsRune(domain, 0) {
		return nil, errors.New("invalid signing domain")
	}
	encoded, err := canonical.Marshal(unsigned)
	if err != nil {
		return nil, fmt.Errorf("canonicalize signed intent: %w", err)
	}
	input := make([]byte, 0, len(SigningPrefix)+len(domain)+1+len(encoded))
	input = append(input, SigningPrefix...)
	input = append(input, domain...)
	input = append(input, 0)
	input = append(input, encoded...)
	return input, nil
}

// SigningDigest returns raw lower-case SHA-256 hex of the signing input.
func SigningDigest(domain string, unsigned any) (string, error) {
	input, err := SigningInput(domain, unsigned)
	if err != nil {
		return "", err
	}
	return Digest(input), nil
}

// Digest returns raw lower-case SHA-256 hex.
func Digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

// DocumentDigest returns SHA-256 of a strict typed document's canonical JSON,
// including its signature fields.
func DocumentDigest(value any) (string, error) {
	raw, err := canonical.Marshal(value)
	if err != nil {
		return "", err
	}
	return Digest(raw), nil
}

// NewFingerprint derives the replay key from the operation kind, event, and
// logical request ID. Actor, repository, epochs, and config remain bound by
// RequestDigest and MUST be verified before a replay lookup is performed.
func NewFingerprint(requestKind, eventID, requestID, requestDigest string) (Fingerprint, error) {
	if !requestKindPattern.MatchString(requestKind) || !IsEventID(eventID) || !IsUUID(requestID) || !IsDigest(requestDigest) {
		return Fingerprint{}, errors.New("cannot fingerprint invalid verified request fields")
	}
	replayValue := struct {
		EventID     string `json:"event_id"`
		RequestKind string `json:"request_kind"`
		RequestID   string `json:"request_id"`
	}{eventID, requestKind, requestID}
	encoded, err := canonical.Marshal(replayValue)
	if err != nil {
		return Fingerprint{}, err
	}
	input := make([]byte, 0, len(ReplayKeyPrefix)+len(encoded))
	input = append(input, ReplayKeyPrefix...)
	input = append(input, encoded...)
	return Fingerprint{ReplayKey: Digest(input), RequestDigest: requestDigest}, nil
}

// ClassifyReplay performs stateless duplicate/conflict classification.
func ClassifyReplay(existing *Fingerprint, incoming Fingerprint) (ReplayDisposition, error) {
	if err := incoming.Validate(); err != nil {
		return "", fmt.Errorf("incoming fingerprint: %w", err)
	}
	if existing == nil {
		return ReplayNew, nil
	}
	if err := existing.Validate(); err != nil {
		return "", fmt.Errorf("existing fingerprint: %w", err)
	}
	if existing.ReplayKey != incoming.ReplayKey {
		return "", errors.New("fingerprints have different replay keys")
	}
	if existing.RequestDigest == incoming.RequestDigest {
		return ReplayDuplicate, nil
	}
	return ReplayConflict, nil
}

func (fingerprint Fingerprint) Validate() error {
	if !IsDigest(fingerprint.ReplayKey) || !IsDigest(fingerprint.RequestDigest) {
		return errors.New("fingerprint fields must be raw lower-case SHA-256 hex")
	}
	return nil
}

func ValidateRepository(repository Repository) error {
	if err := ValidateRepositoryID(repository.ID); err != nil {
		return err
	}
	if !ownerPattern.MatchString(repository.Owner) || len(repository.Owner) > 39 {
		return errors.New("repository owner is invalid")
	}
	if !repositoryPattern.MatchString(repository.Name) {
		return errors.New("repository name is invalid")
	}
	return nil
}

func ValidateRepositoryID(value string) error {
	return identity.ValidateDecimal(value, "repository_id")
}
func IsEventID(value string) bool { return eventIDPattern.MatchString(value) }
func IsUUID(value string) bool    { return uuidPattern.MatchString(value) }
func IsDigest(value string) bool  { return digestPattern.MatchString(value) }
func IsGitOID(value string) bool  { return gitOIDPattern.MatchString(value) }

func ValidateRef(value string) error {
	if len(value) == 0 || len(value) > 255 || !refPattern.MatchString(value) || strings.HasPrefix(value, "/") || strings.Contains(value, "//") || strings.Contains(value, "..") || strings.ContainsAny(value, "~^:?*[") || strings.HasSuffix(value, ".") || strings.HasSuffix(value, "/") || strings.HasSuffix(value, ".lock") || strings.Contains(value, ".lock/") {
		return errors.New("Git ref is invalid or unsafe")
	}
	return nil
}

func ParseTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	if err != nil || formatTime(parsed) != value {
		return time.Time{}, fmt.Errorf("timestamp %q must be UTC RFC3339 with whole seconds", value)
	}
	return parsed, nil
}

func ValidateWindow(issuedText, expiresText string, now time.Time) error {
	return validateWindowWithin(issuedText, expiresText, now, MaxGenericValidity, "validity window exceeds 24 hours")
}

// ValidateWindowWithin validates a protocol window against an operation-specific
// maximum. Callers must derive maximumValidity from independently trusted policy.
func ValidateWindowWithin(issuedText, expiresText string, now time.Time, maximumValidity time.Duration) error {
	if maximumValidity <= 0 || maximumValidity%time.Second != 0 {
		return errors.New("maximum validity window must be positive whole seconds")
	}
	return validateWindowWithin(
		issuedText,
		expiresText,
		now,
		maximumValidity,
		fmt.Sprintf("validity window exceeds configured maximum of %s", maximumValidity),
	)
}

func validateWindowWithin(issuedText, expiresText string, now time.Time, maximumValidity time.Duration, tooLongMessage string) error {
	issued, err := ParseTimestamp(issuedText)
	if err != nil {
		return err
	}
	expires, err := ParseTimestamp(expiresText)
	if err != nil {
		return err
	}
	if !expires.After(issued) {
		return errors.New("expires_at must be after issued_at")
	}
	if expires.Sub(issued) > maximumValidity {
		return errors.New(tooLongMessage)
	}
	if !now.IsZero() {
		now = now.UTC()
		if now.Before(issued) {
			return errors.New("request is not yet valid")
		}
		if now.After(expires) {
			return errors.New("request has expired")
		}
	}
	return nil
}

func DefaultWindow() (time.Time, time.Time) {
	issued := time.Now().UTC().Truncate(time.Second)
	return issued, issued.Add(15 * time.Minute)
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}

func validateRegistration(value Registration, now time.Time, requestTTL time.Duration) error {
	if value.Kind != RegistrationKind || value.Protocol != Protocol || value.ProtocolVersion != ProtocolVersion {
		return errors.New("registration protocol discriminator is invalid")
	}
	if !IsEventID(value.EventID) {
		return errors.New("event_id is invalid")
	}
	if err := identity.ValidateDecimal(value.EventEpoch, "event_epoch"); err != nil {
		return err
	}
	if !IsUUID(value.OperationID) {
		return errors.New("operation_id must be a lower-case UUIDv4")
	}
	if err := identity.ValidateDecimal(value.ActorID, "actor_id"); err != nil {
		return err
	}
	if value.KeyEpoch != "1" {
		return errors.New("registration v1 requires key_epoch 1")
	}
	if !IsDigest(value.KeyID) || !IsDigest(value.ConfigDigest) || !IsDigest(value.TermsDigest) {
		return errors.New("key_id, config_digest, and terms_digest must be raw lower-case SHA-256 hex")
	}
	if err := ValidateRepository(value.BaseRepository); err != nil {
		return err
	}
	if err := value.ParticipantKey.Validate(); err != nil {
		return err
	}
	return validateRequestWindow(value.IssuedAt, value.ExpiresAt, now, requestTTL)
}

func validateRequestWindow(issuedAt, expiresAt string, now time.Time, maximumValidity time.Duration) error {
	if maximumValidity > MaxGenericValidity {
		return errors.New("configured validity window exceeds protocol maximum of 24 hours")
	}
	if maximumValidity == MaxGenericValidity {
		return ValidateWindow(issuedAt, expiresAt, now)
	}
	return ValidateWindowWithin(issuedAt, expiresAt, now, maximumValidity)
}

func registrationUnsignedFrom(value Registration) registrationUnsigned {
	return registrationUnsigned{
		value.Kind, value.Protocol, value.ProtocolVersion, value.EventID, value.EventEpoch, value.OperationID,
		value.ActorID, value.KeyID, value.KeyEpoch, value.BaseRepository, value.ConfigDigest,
		value.TermsDigest, value.IssuedAt, value.ExpiresAt, value.ParticipantKey,
	}
}

func compareExpected(eventID, eventEpoch, repositoryID, actorID, configDigest, keyEpoch, keyID string, expected Expected) error {
	checks := []struct{ field, got, want string }{
		{"event_id", eventID, expected.EventID}, {"event_epoch", eventEpoch, expected.EventEpoch}, {"repository_id", repositoryID, expected.RepositoryID},
		{"actor_id", actorID, expected.ActorID}, {"config_digest", configDigest, expected.ConfigDigest},
		{"key_epoch", keyEpoch, expected.KeyEpoch}, {"key_id", keyID, expected.KeyID},
	}
	for _, check := range checks {
		if check.want != "" && check.got != check.want {
			return fmt.Errorf("%s is %q, trusted value is %q", check.field, check.got, check.want)
		}
	}
	return nil
}

func parsePrivate(private identity.Private) (identity.KeyPair, error) {
	raw, err := canonical.Marshal(private)
	if err != nil {
		return identity.KeyPair{}, err
	}
	return identity.ParsePrivate(raw)
}

func ParsePositiveInt(value, field string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", field)
	}
	return parsed, nil
}
