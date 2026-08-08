package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/samber/lo"
)

const (
	Protocol      = "eventctl/v2"
	SchemaVersion = 2
	MaxBytes      = 64 << 20
)

var (
	eventIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
	decimalPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	digestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	uuidV4Pattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type TTLSeconds struct {
	Registration uint64 `json:"registration"`
	Team         uint64 `json:"team"`
	Submission   uint64 `json:"submission"`
}

type Limits struct {
	TeamMinimum     uint64 `json:"team_min"`
	TeamMaximum     uint64 `json:"team_max"`
	AttemptsPerTeam uint64 `json:"attempts_per_team"`
	AttemptsTotal   uint64 `json:"attempts_total"`
}

// EventBinding is public event policy from trusted main. The repository and
// its reviewed registry are the trust boundary; no app or organizer secret is
// part of normal eventctl operation.
type EventBinding struct {
	Version      int        `json:"v"`
	Kind         string     `json:"kind"`
	Protocol     string     `json:"protocol"`
	EventID      string     `json:"event_id"`
	EventEpoch   int        `json:"event_epoch"`
	RepositoryID string     `json:"repository_id"`
	ValidFrom    string     `json:"valid_from"`
	ValidUntil   string     `json:"valid_until"`
	TermsSHA256  string     `json:"terms_sha256"`
	TTLSeconds   TTLSeconds `json:"ttl_seconds"`
	Limits       Limits     `json:"limits"`
}

type EventReference struct {
	EventID       string `json:"event_id"`
	EventEpoch    int    `json:"event_epoch"`
	RepositoryID  string `json:"repository_id"`
	BindingSHA256 string `json:"binding_sha256"`
}

func (binding EventBinding) Validate() error {
	if binding.Version != SchemaVersion || binding.Kind != "event-binding" || binding.Protocol != Protocol {
		return errors.New("event binding protocol discriminator is invalid")
	}
	if !eventIDPattern.MatchString(binding.EventID) || binding.EventEpoch < 1 || !decimalPattern.MatchString(binding.RepositoryID) || !digestPattern.MatchString(binding.TermsSHA256) {
		return errors.New("event binding identity is invalid")
	}
	validFrom, err := parseTimestamp(binding.ValidFrom)
	if err != nil {
		return fmt.Errorf("event binding valid_from: %w", err)
	}
	validUntil, err := parseTimestamp(binding.ValidUntil)
	if err != nil || !validUntil.After(validFrom) {
		return errors.New("event binding validity window is invalid")
	}
	if binding.TTLSeconds.Registration == 0 || binding.TTLSeconds.Team == 0 || binding.TTLSeconds.Submission == 0 {
		return errors.New("event binding request TTL is invalid")
	}
	if binding.Limits.TeamMinimum < 1 || binding.Limits.TeamMaximum < binding.Limits.TeamMinimum || binding.Limits.TeamMaximum > 64 || binding.Limits.AttemptsPerTeam < 1 || binding.Limits.AttemptsTotal < binding.Limits.AttemptsPerTeam {
		return errors.New("event binding limits are invalid")
	}
	return nil
}

func (binding EventBinding) Reference() EventReference {
	return EventReference{
		EventID:       binding.EventID,
		EventEpoch:    binding.EventEpoch,
		RepositoryID:  binding.RepositoryID,
		BindingSHA256: DigestJSON(binding),
	}
}

func (reference EventReference) Validate() error {
	if !eventIDPattern.MatchString(reference.EventID) || reference.EventEpoch < 1 || !decimalPattern.MatchString(reference.RepositoryID) || !digestPattern.MatchString(reference.BindingSHA256) {
		return errors.New("event reference is invalid")
	}
	return nil
}

func (reference EventReference) Match(binding EventBinding) error {
	if err := reference.Validate(); err != nil {
		return err
	}
	if reference != binding.Reference() {
		return errors.New("event reference does not match binding")
	}
	return nil
}

func ReadEventBinding(path string) (EventBinding, error) {
	var binding EventBinding
	if err := ReadJSON(path, &binding); err != nil {
		return binding, fmt.Errorf("read event binding: %w", err)
	}
	if err := binding.Validate(); err != nil {
		return binding, err
	}
	return binding, nil
}

type SigningPublic struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	PublicKey string `json:"public"`
}

type signingPrivate struct {
	Kind       string `json:"kind"`
	Algorithm  string `json:"alg"`
	KeyID      string `json:"kid"`
	PrivateKey string `json:"private"`
}

type RecipientPublic struct {
	Algorithm string        `json:"alg"`
	KeyID     string        `json:"kid"`
	PublicKey string        `json:"recipient"`
	Recipient age.Recipient `json:"-"`
}

type recipientPrivate struct {
	Kind      string `json:"kind"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Identity  string `json:"identity"`
}

type KeyGenerationResult struct {
	SigningPrivate   string `json:"signing_private_key"`
	SigningPublic    string `json:"signing_public_key"`
	RecipientPrivate string `json:"recipient_private_key"`
	RecipientPublic  string `json:"recipient_public_key"`
	SigningKeyID     string `json:"signing_key_id"`
	RecipientKeyID   string `json:"recipient_key_id"`
}

type SigningKey struct {
	Public  SigningPublic
	Private ed25519.PrivateKey
}

type RecipientKey struct {
	Public   RecipientPublic
	Identity *age.HybridIdentity
}

func GenerateKeyDirectory(directory, passphrase string) (KeyGenerationResult, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return KeyGenerationResult{}, fmt.Errorf("create key directory: %w", err)
	}
	// Go 1.26 guarantees crypto/rand.Read either fills the buffer or crashes;
	// this CLI's minimum Go version makes an ignored error impossible here.
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(seed)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	signingID := fingerprint(public)
	signingPublic := SigningPublic{Algorithm: "Ed25519", KeyID: signingID, PublicKey: base64.RawURLEncoding.EncodeToString(public)}
	signingPrivate := signingPrivate{Kind: "signing-private", Algorithm: "Ed25519", KeyID: signingID, PrivateKey: base64.RawURLEncoding.EncodeToString(private)}
	// age hybrid generation uses crypto/rand, whose failure exits this Go
	// runtime before an error can be returned.
	identity := lo.Must(age.GenerateHybridIdentity())
	recipientID := fingerprint([]byte(identity.Recipient().String()))
	recipientPublic := RecipientPublic{Algorithm: "age-hybrid-mlkem768-x25519", KeyID: recipientID, PublicKey: identity.Recipient().String(), Recipient: identity.Recipient()}
	recipientPrivate := recipientPrivate{Kind: "recipient-private", Algorithm: recipientPublic.Algorithm, KeyID: recipientID, Identity: identity.String()}
	signingData := canonicalJSON(signingPrivate)
	recipientData := canonicalJSON(recipientPrivate)
	signingCiphertext := encryptWithPass(signingData, passphrase)
	recipientCiphertext := encryptWithPass(recipientData, passphrase)
	signingPublicData := canonicalJSON(signingPublic)
	recipientPublicData := canonicalJSON(recipientPublic)
	signingPrivatePath := filepath.Join(directory, "signing.private.age")
	signingPublicPath := filepath.Join(directory, "signing.public.json")
	recipientPrivatePath := filepath.Join(directory, "recipient.private.age")
	recipientPublicPath := filepath.Join(directory, "recipient.public.json")
	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{signingPrivatePath, signingCiphertext, 0o600},
		{signingPublicPath, signingPublicData, 0o644},
		{recipientPrivatePath, recipientCiphertext, 0o600},
		{recipientPublicPath, recipientPublicData, 0o644},
	} {
		if err := writeExclusive(file.path, file.data, file.mode); err != nil {
			return KeyGenerationResult{}, fmt.Errorf("write key file %s: %w", file.path, err)
		}
	}
	return KeyGenerationResult{SigningPrivate: signingPrivatePath, SigningPublic: signingPublicPath, RecipientPrivate: recipientPrivatePath, RecipientPublic: recipientPublicPath, SigningKeyID: signingID, RecipientKeyID: recipientID}, nil
}

func LoadSigningPrivate(path, passphrase string) (SigningKey, error) {
	data, err := readFile(path)
	if err != nil {
		return SigningKey{}, fmt.Errorf("read signing key: %w", err)
	}
	plain, err := decryptWithPass(data, passphrase)
	if err != nil {
		return SigningKey{}, fmt.Errorf("decrypt signing key: %w", err)
	}
	var document signingPrivate
	if err := decodeJSON(plain, &document); err != nil {
		return SigningKey{}, fmt.Errorf("decode signing key: %w", err)
	}
	key, err := base64.RawURLEncoding.DecodeString(document.PrivateKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return SigningKey{}, errors.New("invalid signing private key")
	}
	private := ed25519.PrivateKey(key)
	public := private.Public().(ed25519.PublicKey)
	if document.Kind != "signing-private" || document.Algorithm != "Ed25519" || document.KeyID != fingerprint(public) {
		return SigningKey{}, errors.New("signing key metadata does not match")
	}
	return SigningKey{Public: SigningPublic{Algorithm: document.Algorithm, KeyID: document.KeyID, PublicKey: base64.RawURLEncoding.EncodeToString(public)}, Private: private}, nil
}

func LoadSigningPublic(path string) (SigningPublic, error) {
	var document SigningPublic
	if err := ReadJSON(path, &document); err != nil {
		return document, fmt.Errorf("read signing public key: %w", err)
	}
	if _, err := decodeSigningPublic(document); err != nil {
		return document, err
	}
	return document, nil
}

func LoadRecipientPublic(path string) (RecipientPublic, error) {
	var document RecipientPublic
	if err := ReadJSON(path, &document); err != nil {
		return document, fmt.Errorf("read recipient public key: %w", err)
	}
	if err := validateRecipientPublic(&document); err != nil {
		return document, err
	}
	return document, nil
}

func LoadRecipientPrivate(path, passphrase string) (RecipientKey, error) {
	data, err := readFile(path)
	if err != nil {
		return RecipientKey{}, fmt.Errorf("read recipient key: %w", err)
	}
	plain, err := decryptWithPass(data, passphrase)
	if err != nil {
		return RecipientKey{}, fmt.Errorf("decrypt recipient key: %w", err)
	}
	var document recipientPrivate
	if err := decodeJSON(plain, &document); err != nil {
		return RecipientKey{}, fmt.Errorf("decode recipient key: %w", err)
	}
	if document.Kind != "recipient-private" || document.Algorithm != "age-hybrid-mlkem768-x25519" {
		return RecipientKey{}, errors.New("invalid recipient private key metadata")
	}
	identity, err := age.ParseHybridIdentity(document.Identity)
	if err != nil {
		return RecipientKey{}, fmt.Errorf("parse recipient private key: %w", err)
	}
	public := identity.Recipient().String()
	if document.KeyID != fingerprint([]byte(public)) {
		return RecipientKey{}, errors.New("recipient private key fingerprint mismatch")
	}
	return RecipientKey{Public: RecipientPublic{Algorithm: document.Algorithm, KeyID: document.KeyID, PublicKey: public, Recipient: identity.Recipient()}, Identity: identity}, nil
}

type Signature struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Value     string `json:"value"`
}

func Sign(domain string, value any, key SigningKey) Signature {
	message := signedMessage(domain, value)
	return Signature{Algorithm: "Ed25519", KeyID: key.Public.KeyID, Value: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key.Private, message))}
}

func Verify(domain string, value any, signature Signature, public SigningPublic) error {
	key, err := decodeSigningPublic(public)
	if err != nil {
		return err
	}
	if signature.Algorithm != "Ed25519" || signature.KeyID != public.KeyID {
		return errors.New("signature metadata does not match signer")
	}
	signed, err := base64.RawURLEncoding.DecodeString(signature.Value)
	if err != nil || len(signed) != ed25519.SignatureSize {
		return errors.New("invalid signature encoding")
	}
	if !ed25519.Verify(key, signedMessage(domain, value), signed) {
		return errors.New("signature verification failed")
	}
	return nil
}

type IdentityRegistration struct {
	Version        int             `json:"v"`
	Kind           string          `json:"kind"`
	Event          EventReference  `json:"event"`
	RegistrationID string          `json:"registration_id"`
	ActorID        string          `json:"actor_id"`
	KeyEpoch       int             `json:"key_epoch"`
	SigningKey     SigningPublic   `json:"signing_key"`
	RecipientKey   RecipientPublic `json:"recipient_key"`
	IssuedAt       string          `json:"issued_at"`
	ExpiresAt      string          `json:"expires_at"`
	Signature      Signature       `json:"signature"`
}

type identityUnsigned struct {
	Version        int             `json:"v"`
	Kind           string          `json:"kind"`
	Event          EventReference  `json:"event"`
	RegistrationID string          `json:"registration_id"`
	ActorID        string          `json:"actor_id"`
	KeyEpoch       int             `json:"key_epoch"`
	SigningKey     SigningPublic   `json:"signing_key"`
	RecipientKey   RecipientPublic `json:"recipient_key"`
	IssuedAt       string          `json:"issued_at"`
	ExpiresAt      string          `json:"expires_at"`
}

func (document IdentityRegistration) unsigned() identityUnsigned {
	return identityUnsigned{Version: document.Version, Kind: document.Kind, Event: document.Event, RegistrationID: document.RegistrationID, ActorID: document.ActorID, KeyEpoch: document.KeyEpoch, SigningKey: document.SigningKey, RecipientKey: document.RecipientKey, IssuedAt: document.IssuedAt, ExpiresAt: document.ExpiresAt}
}

func RegisterIdentity(binding EventBinding, actorID string, keyEpoch int, registrationID string, signing SigningKey, recipient RecipientPublic, now time.Time) (IdentityRegistration, error) {
	if !validActorID(actorID) || keyEpoch < 1 {
		return IdentityRegistration{}, errors.New("identity registration actor or key epoch is invalid")
	}
	if registrationID == "" {
		registrationID = newUUIDv4()
	}
	if !uuidV4Pattern.MatchString(registrationID) {
		return IdentityRegistration{}, errors.New("identity registration ID is invalid")
	}
	issuedAt, expiresAt, err := issueWindow(binding, binding.TTLSeconds.Registration, now)
	if err != nil {
		return IdentityRegistration{}, err
	}
	document := IdentityRegistration{Version: SchemaVersion, Kind: "identity-registration", Event: binding.Reference(), RegistrationID: registrationID, ActorID: actorID, KeyEpoch: keyEpoch, SigningKey: signing.Public, RecipientKey: recipient, IssuedAt: issuedAt, ExpiresAt: expiresAt}
	document.Signature = Sign("identity.register", document.unsigned(), signing)
	return document, nil
}

type IdentityRecord struct {
	ActorID            string          `json:"actor_id"`
	RegistrationID     string          `json:"registration_id"`
	RegistrationSHA256 string          `json:"registration_sha256"`
	KeyEpoch           int             `json:"key_epoch"`
	SigningKey         SigningPublic   `json:"signing_key"`
	RecipientKey       RecipientPublic `json:"recipient_key"`
}

func VerifyIdentity(document IdentityRegistration, binding EventBinding, expectedActorID, sourceTime string) (IdentityRecord, error) {
	if document.Version != SchemaVersion || document.Kind != "identity-registration" || !validActorID(document.ActorID) || document.ActorID != expectedActorID || document.KeyEpoch < 1 || !uuidV4Pattern.MatchString(document.RegistrationID) {
		return IdentityRecord{}, errors.New("identity registration identity is invalid")
	}
	if err := document.Event.Match(binding); err != nil {
		return IdentityRecord{}, err
	}
	at, err := parseTimestamp(sourceTime)
	if err != nil {
		return IdentityRecord{}, fmt.Errorf("identity registration source time: %w", err)
	}
	if err := validateDocumentWindow(document.IssuedAt, document.ExpiresAt, binding, binding.TTLSeconds.Registration, at); err != nil {
		return IdentityRecord{}, err
	}
	if err := validateRecipientPublic(&document.RecipientKey); err != nil {
		return IdentityRecord{}, err
	}
	if err := Verify("identity.register", document.unsigned(), document.Signature, document.SigningKey); err != nil {
		return IdentityRecord{}, err
	}
	return IdentityRecord{ActorID: document.ActorID, RegistrationID: document.RegistrationID, RegistrationSHA256: DigestJSON(document), KeyEpoch: document.KeyEpoch, SigningKey: document.SigningKey, RecipientKey: document.RecipientKey}, nil
}

type Registry struct {
	Version        int              `json:"v"`
	Kind           string           `json:"kind"`
	Event          EventReference   `json:"event"`
	Revision       uint64           `json:"revision"`
	Phase          string           `json:"phase"`
	Enabled        bool             `json:"enabled"`
	DisabledReason string           `json:"disabled_reason"`
	Identities     []IdentityRecord `json:"identities"`
	Teams          []TeamRecord     `json:"teams"`
	Attempts       []AttemptRecord  `json:"attempts"`
}

type TeamRecord struct {
	TeamID         string       `json:"team_id"`
	ProposalSHA256 string       `json:"proposal_sha256"`
	Members        []TeamMember `json:"members"`
}

type AttemptRecord struct {
	AttemptID        string `json:"attempt_id"`
	TeamID           string `json:"team_id"`
	ActorID          string `json:"actor_id"`
	SubmissionSHA256 string `json:"submission_sha256"`
	PayloadSHA256    string `json:"payload_sha256"`
}

func ReadRegistry(path string, binding EventBinding) (Registry, error) {
	var registry Registry
	if err := ReadJSON(path, &registry); err != nil {
		return registry, fmt.Errorf("read registry: %w", err)
	}
	if err := registry.Validate(binding); err != nil {
		return registry, err
	}
	return registry, nil
}

func (registry Registry) Validate(binding EventBinding) error {
	if registry.Version != SchemaVersion || registry.Kind != "event-registry" {
		return errors.New("registry protocol discriminator is invalid")
	}
	if err := registry.Event.Match(binding); err != nil {
		return err
	}
	if !lo.Contains([]string{"draft", "registration_open", "formation_open", "submissions_open", "closed"}, registry.Phase) {
		return errors.New("registry phase is invalid")
	}
	if registry.Enabled && registry.DisabledReason != "" {
		return errors.New("enabled registry cannot have a disabled reason")
	}
	if !registry.Enabled && registry.DisabledReason == "" {
		return errors.New("disabled registry requires a disabled reason")
	}
	for index, identity := range registry.Identities {
		if !validActorID(identity.ActorID) || !uuidV4Pattern.MatchString(identity.RegistrationID) || !digestPattern.MatchString(identity.RegistrationSHA256) || identity.KeyEpoch < 1 {
			return errors.New("registry identity is invalid")
		}
		if _, err := decodeSigningPublic(identity.SigningKey); err != nil {
			return err
		}
		if err := validateRecipientPublic(&identity.RecipientKey); err != nil {
			return err
		}
		if index > 0 && compareActorIDs(registry.Identities[index-1].ActorID, identity.ActorID) >= 0 {
			return errors.New("registry identities must be strictly sorted")
		}
	}
	activeMembers := make(map[string]bool)
	for index, team := range registry.Teams {
		if !uuidV4Pattern.MatchString(team.TeamID) || !digestPattern.MatchString(team.ProposalSHA256) || uint64(len(team.Members)) < binding.Limits.TeamMinimum || uint64(len(team.Members)) > binding.Limits.TeamMaximum {
			return errors.New("registry team is invalid")
		}
		if index > 0 && registry.Teams[index-1].TeamID >= team.TeamID {
			return errors.New("registry teams must be strictly sorted")
		}
		for memberIndex, member := range team.Members {
			identity, err := registry.Lookup(member.ActorID)
			if err != nil || member != memberFromIdentity(identity) || activeMembers[member.ActorID] {
				return errors.New("registry team member does not match an available identity")
			}
			if memberIndex > 0 && compareActorIDs(team.Members[memberIndex-1].ActorID, member.ActorID) >= 0 {
				return errors.New("registry team members must be strictly sorted")
			}
			activeMembers[member.ActorID] = true
		}
	}
	for index, attempt := range registry.Attempts {
		if !uuidV4Pattern.MatchString(attempt.AttemptID) || !uuidV4Pattern.MatchString(attempt.TeamID) || !validActorID(attempt.ActorID) || !digestPattern.MatchString(attempt.SubmissionSHA256) || !digestPattern.MatchString(attempt.PayloadSHA256) {
			return errors.New("registry attempt is invalid")
		}
		if index > 0 && registry.Attempts[index-1].AttemptID >= attempt.AttemptID {
			return errors.New("registry attempts must be strictly sorted")
		}
		team, err := registry.LookupTeam(attempt.TeamID)
		if err != nil || !lo.ContainsBy(team.Members, func(member TeamMember) bool { return member.ActorID == attempt.ActorID }) {
			return errors.New("registry attempt submitter is not an active team member")
		}
	}
	return nil
}

func (registry Registry) Lookup(actorID string) (IdentityRecord, error) {
	for _, identity := range registry.Identities {
		if identity.ActorID == actorID {
			return identity, nil
		}
	}
	return IdentityRecord{}, errors.New("actor has no active registered identity")
}

func (registry Registry) LookupTeam(teamID string) (TeamRecord, error) {
	for _, team := range registry.Teams {
		if team.TeamID == teamID {
			return team, nil
		}
	}
	return TeamRecord{}, errors.New("team is not active")
}

func (registry Registry) RequirePhase(phase string) error {
	if !registry.Enabled || registry.Phase != phase {
		return errors.New("registry is not open for this operation")
	}
	return nil
}

func (registry Registry) teamAvailable(teamID string, members []TeamMember) error {
	if _, err := registry.LookupTeam(teamID); err == nil {
		return errors.New("team ID is already active")
	}
	for _, member := range members {
		for _, team := range registry.Teams {
			if lo.ContainsBy(team.Members, func(active TeamMember) bool { return active.ActorID == member.ActorID }) {
				return errors.New("team member already belongs to an active team")
			}
		}
	}
	return nil
}

func (registry Registry) hasAttempt(attemptID string) bool {
	return lo.ContainsBy(registry.Attempts, func(attempt AttemptRecord) bool { return attempt.AttemptID == attemptID })
}

func (registry Registry) attemptsForTeam(teamID string) uint64 {
	return uint64(len(lo.Filter(registry.Attempts, func(attempt AttemptRecord, _ int) bool { return attempt.TeamID == teamID })))
}

type TeamMember struct {
	ActorID        string `json:"actor_id"`
	KeyEpoch       int    `json:"key_epoch"`
	SigningKeyID   string `json:"signing_kid"`
	RecipientKeyID string `json:"recipient_kid"`
}

type TeamProposal struct {
	Version   int            `json:"v"`
	Kind      string         `json:"kind"`
	Event     EventReference `json:"event"`
	TeamID    string         `json:"team_id"`
	Proposer  TeamMember     `json:"proposer"`
	Members   []TeamMember   `json:"members"`
	IssuedAt  string         `json:"issued_at"`
	ExpiresAt string         `json:"expires_at"`
	Signature Signature      `json:"signature"`
}

type teamProposalUnsigned struct {
	Version   int            `json:"v"`
	Kind      string         `json:"kind"`
	Event     EventReference `json:"event"`
	TeamID    string         `json:"team_id"`
	Proposer  TeamMember     `json:"proposer"`
	Members   []TeamMember   `json:"members"`
	IssuedAt  string         `json:"issued_at"`
	ExpiresAt string         `json:"expires_at"`
}

func (proposal TeamProposal) unsigned() teamProposalUnsigned {
	return teamProposalUnsigned{Version: proposal.Version, Kind: proposal.Kind, Event: proposal.Event, TeamID: proposal.TeamID, Proposer: proposal.Proposer, Members: proposal.Members, IssuedAt: proposal.IssuedAt, ExpiresAt: proposal.ExpiresAt}
}

type TeamConsent struct {
	Version        int            `json:"v"`
	Kind           string         `json:"kind"`
	Event          EventReference `json:"event"`
	TeamID         string         `json:"team_id"`
	ProposalSHA256 string         `json:"proposal_sha256"`
	ActorID        string         `json:"actor_id"`
	KeyEpoch       int            `json:"key_epoch"`
	SigningKeyID   string         `json:"signing_kid"`
	IssuedAt       string         `json:"issued_at"`
	ExpiresAt      string         `json:"expires_at"`
	Signature      Signature      `json:"signature"`
}

type teamConsentUnsigned struct {
	Version        int            `json:"v"`
	Kind           string         `json:"kind"`
	Event          EventReference `json:"event"`
	TeamID         string         `json:"team_id"`
	ProposalSHA256 string         `json:"proposal_sha256"`
	ActorID        string         `json:"actor_id"`
	KeyEpoch       int            `json:"key_epoch"`
	SigningKeyID   string         `json:"signing_kid"`
	IssuedAt       string         `json:"issued_at"`
	ExpiresAt      string         `json:"expires_at"`
}

func (consent TeamConsent) unsigned() teamConsentUnsigned {
	return teamConsentUnsigned{Version: consent.Version, Kind: consent.Kind, Event: consent.Event, TeamID: consent.TeamID, ProposalSHA256: consent.ProposalSHA256, ActorID: consent.ActorID, KeyEpoch: consent.KeyEpoch, SigningKeyID: consent.SigningKeyID, IssuedAt: consent.IssuedAt, ExpiresAt: consent.ExpiresAt}
}

type TeamVerification struct {
	TeamID         string       `json:"team_id"`
	ProposalSHA256 string       `json:"proposal_sha256"`
	Members        []TeamMember `json:"members"`
	Verified       bool         `json:"verified"`
}

func ProposeTeam(binding EventBinding, registry Registry, teamID, proposerActorID string, memberActorIDs []string, signing SigningKey, now time.Time) (TeamProposal, error) {
	if err := registry.RequirePhase("formation_open"); err != nil {
		return TeamProposal{}, err
	}
	if teamID == "" {
		teamID = newUUIDv4()
	}
	if !uuidV4Pattern.MatchString(teamID) || !validActorID(proposerActorID) {
		return TeamProposal{}, errors.New("team proposal ID or proposer is invalid")
	}
	memberActorIDs = normalizeActorIDs(memberActorIDs)
	if uint64(len(memberActorIDs)) < binding.Limits.TeamMinimum || uint64(len(memberActorIDs)) > binding.Limits.TeamMaximum || !lo.Contains(memberActorIDs, proposerActorID) {
		return TeamProposal{}, errors.New("team proposal members are invalid")
	}
	proposer, err := registry.Lookup(proposerActorID)
	if err != nil {
		return TeamProposal{}, err
	}
	if signing.Public.KeyID != proposer.SigningKey.KeyID {
		return TeamProposal{}, errors.New("team proposer key is not the active registered key")
	}
	members := make([]TeamMember, 0, len(memberActorIDs))
	for _, actorID := range memberActorIDs {
		identity, lookupErr := registry.Lookup(actorID)
		if lookupErr != nil {
			return TeamProposal{}, lookupErr
		}
		members = append(members, memberFromIdentity(identity))
	}
	if err := registry.teamAvailable(teamID, members); err != nil {
		return TeamProposal{}, err
	}
	issuedAt, expiresAt, err := issueWindow(binding, binding.TTLSeconds.Team, now)
	if err != nil {
		return TeamProposal{}, err
	}
	document := TeamProposal{Version: SchemaVersion, Kind: "team-proposal", Event: binding.Reference(), TeamID: teamID, Proposer: memberFromIdentity(proposer), Members: members, IssuedAt: issuedAt, ExpiresAt: expiresAt}
	document.Signature = Sign("team.propose", document.unsigned(), signing)
	return document, nil
}

func ConsentTeam(binding EventBinding, registry Registry, proposal TeamProposal, actorID string, signing SigningKey, now time.Time) (TeamConsent, error) {
	if err := registry.RequirePhase("formation_open"); err != nil {
		return TeamConsent{}, err
	}
	issued := now.UTC().Truncate(time.Second)
	if err := verifyProposal(proposal, binding, registry, issued); err != nil {
		return TeamConsent{}, err
	}
	if err := registry.teamAvailable(proposal.TeamID, proposal.Members); err != nil {
		return TeamConsent{}, err
	}
	identity, err := registry.Lookup(actorID)
	if err != nil {
		return TeamConsent{}, err
	}
	if !lo.ContainsBy(proposal.Members, func(member TeamMember) bool { return member.ActorID == actorID }) || identity.SigningKey.KeyID != signing.Public.KeyID {
		return TeamConsent{}, errors.New("team consent actor is not an active proposed member")
	}
	document := TeamConsent{Version: SchemaVersion, Kind: "team-consent", Event: binding.Reference(), TeamID: proposal.TeamID, ProposalSHA256: DigestJSON(proposal), ActorID: actorID, KeyEpoch: identity.KeyEpoch, SigningKeyID: identity.SigningKey.KeyID, IssuedAt: issued.Format(time.RFC3339), ExpiresAt: proposal.ExpiresAt}
	document.Signature = Sign("team.consent", document.unsigned(), signing)
	return document, nil
}

func VerifyTeam(binding EventBinding, registry Registry, proposal TeamProposal, proposalSourceTime string, consents []TeamConsent, consentSourceTimes map[string]string) (TeamVerification, error) {
	if err := registry.RequirePhase("formation_open"); err != nil {
		return TeamVerification{}, err
	}
	proposalAt, err := parseTimestamp(proposalSourceTime)
	if err != nil {
		return TeamVerification{}, fmt.Errorf("team proposal source time: %w", err)
	}
	if err := verifyProposal(proposal, binding, registry, proposalAt); err != nil {
		return TeamVerification{}, err
	}
	if err := registry.teamAvailable(proposal.TeamID, proposal.Members); err != nil {
		return TeamVerification{}, err
	}
	if len(consents) != len(proposal.Members) || len(consentSourceTimes) != len(proposal.Members) {
		return TeamVerification{}, errors.New("team consents and source times must cover every member")
	}
	seen := make(map[string]bool, len(consents))
	proposalDigest := DigestJSON(proposal)
	for _, consent := range consents {
		if seen[consent.ActorID] {
			return TeamVerification{}, errors.New("duplicate team consent")
		}
		atText, found := consentSourceTimes[consent.ActorID]
		if !found {
			return TeamVerification{}, errors.New("team consent source time is missing")
		}
		at, parseErr := parseTimestamp(atText)
		if parseErr != nil {
			return TeamVerification{}, fmt.Errorf("team consent source time: %w", parseErr)
		}
		if err := verifyConsent(consent, proposal, proposalDigest, binding, registry, at); err != nil {
			return TeamVerification{}, err
		}
		seen[consent.ActorID] = true
	}
	return TeamVerification{TeamID: proposal.TeamID, ProposalSHA256: proposalDigest, Members: proposal.Members, Verified: true}, nil
}

func verifyProposal(proposal TeamProposal, binding EventBinding, registry Registry, sourceTime time.Time) error {
	if proposal.Version != SchemaVersion || proposal.Kind != "team-proposal" || !uuidV4Pattern.MatchString(proposal.TeamID) {
		return errors.New("team proposal is invalid")
	}
	if err := proposal.Event.Match(binding); err != nil {
		return err
	}
	if uint64(len(proposal.Members)) < binding.Limits.TeamMinimum || uint64(len(proposal.Members)) > binding.Limits.TeamMaximum {
		return errors.New("team proposal size is invalid")
	}
	if err := validateDocumentWindow(proposal.IssuedAt, proposal.ExpiresAt, binding, binding.TTLSeconds.Team, sourceTime); err != nil {
		return err
	}
	var proposer SigningPublic
	proposerMatches := false
	for index, member := range proposal.Members {
		identity, err := registry.Lookup(member.ActorID)
		if err != nil || member != memberFromIdentity(identity) {
			return errors.New("team proposal member does not match active registry")
		}
		if index > 0 && compareActorIDs(proposal.Members[index-1].ActorID, member.ActorID) >= 0 {
			return errors.New("team proposal members must be strictly sorted")
		}
		if member == proposal.Proposer {
			proposer = identity.SigningKey
			proposerMatches = true
		}
	}
	if !proposerMatches {
		return errors.New("team proposer is not a proposed member")
	}
	return Verify("team.propose", proposal.unsigned(), proposal.Signature, proposer)
}

func verifyConsent(consent TeamConsent, proposal TeamProposal, proposalDigest string, binding EventBinding, registry Registry, sourceTime time.Time) error {
	if consent.Version != SchemaVersion || consent.Kind != "team-consent" || consent.TeamID != proposal.TeamID || consent.ProposalSHA256 != proposalDigest || !validActorID(consent.ActorID) || consent.KeyEpoch < 1 || !digestPattern.MatchString(consent.SigningKeyID) {
		return errors.New("team consent is invalid")
	}
	if err := consent.Event.Match(binding); err != nil {
		return err
	}
	if err := validateDocumentWindow(consent.IssuedAt, consent.ExpiresAt, binding, binding.TTLSeconds.Team, sourceTime); err != nil {
		return err
	}
	identity, err := registry.Lookup(consent.ActorID)
	if err != nil || identity.KeyEpoch != consent.KeyEpoch || identity.SigningKey.KeyID != consent.SigningKeyID || !lo.ContainsBy(proposal.Members, func(member TeamMember) bool { return member.ActorID == consent.ActorID }) {
		return errors.New("team consent signer does not match active proposed member")
	}
	return Verify("team.consent", consent.unsigned(), consent.Signature, identity.SigningKey)
}

type Submission struct {
	Version        int            `json:"v"`
	Kind           string         `json:"kind"`
	Event          EventReference `json:"event"`
	TeamID         string         `json:"team_id"`
	AttemptID      string         `json:"attempt_id"`
	ActorID        string         `json:"actor_id"`
	KeyEpoch       int            `json:"key_epoch"`
	SigningKeyID   string         `json:"signing_kid"`
	PayloadSHA256  string         `json:"payload_sha256"`
	PayloadSize    int64          `json:"payload_size"`
	MetadataSHA256 string         `json:"metadata_sha256,omitempty"`
	MetadataSize   int64          `json:"metadata_size,omitempty"`
	IssuedAt       string         `json:"issued_at"`
	ExpiresAt      string         `json:"expires_at"`
	Signature      Signature      `json:"signature"`
}

type submissionUnsigned struct {
	Version        int            `json:"v"`
	Kind           string         `json:"kind"`
	Event          EventReference `json:"event"`
	TeamID         string         `json:"team_id"`
	AttemptID      string         `json:"attempt_id"`
	ActorID        string         `json:"actor_id"`
	KeyEpoch       int            `json:"key_epoch"`
	SigningKeyID   string         `json:"signing_kid"`
	PayloadSHA256  string         `json:"payload_sha256"`
	PayloadSize    int64          `json:"payload_size"`
	MetadataSHA256 string         `json:"metadata_sha256,omitempty"`
	MetadataSize   int64          `json:"metadata_size,omitempty"`
	IssuedAt       string         `json:"issued_at"`
	ExpiresAt      string         `json:"expires_at"`
}

func (submission Submission) unsigned() submissionUnsigned {
	return submissionUnsigned{Version: submission.Version, Kind: submission.Kind, Event: submission.Event, TeamID: submission.TeamID, AttemptID: submission.AttemptID, ActorID: submission.ActorID, KeyEpoch: submission.KeyEpoch, SigningKeyID: submission.SigningKeyID, PayloadSHA256: submission.PayloadSHA256, PayloadSize: submission.PayloadSize, MetadataSHA256: submission.MetadataSHA256, MetadataSize: submission.MetadataSize, IssuedAt: submission.IssuedAt, ExpiresAt: submission.ExpiresAt}
}

func PrepareSubmission(binding EventBinding, teamID, attemptID, actorID string, keyEpoch int, payload, metadata []byte, signing SigningKey, now time.Time) (Submission, error) {
	if !uuidV4Pattern.MatchString(teamID) || !uuidV4Pattern.MatchString(attemptID) || !validActorID(actorID) || keyEpoch < 1 {
		return Submission{}, errors.New("submission identity is invalid")
	}
	issuedAt, expiresAt, err := issueWindow(binding, binding.TTLSeconds.Submission, now)
	if err != nil {
		return Submission{}, err
	}
	document := Submission{Version: SchemaVersion, Kind: "submission", Event: binding.Reference(), TeamID: teamID, AttemptID: attemptID, ActorID: actorID, KeyEpoch: keyEpoch, SigningKeyID: signing.Public.KeyID, PayloadSHA256: digest(payload), PayloadSize: int64(len(payload)), IssuedAt: issuedAt, ExpiresAt: expiresAt}
	if len(metadata) > 0 {
		document.MetadataSHA256 = digest(metadata)
		document.MetadataSize = int64(len(metadata))
	}
	document.Signature = Sign("submission.prepare", document.unsigned(), signing)
	return document, nil
}

func VerifySubmission(document Submission, binding EventBinding, registry Registry, expectedActorID, sourceTime string, payload, metadata []byte) error {
	if document.Version != SchemaVersion || document.Kind != "submission" || !uuidV4Pattern.MatchString(document.TeamID) || !uuidV4Pattern.MatchString(document.AttemptID) || !validActorID(document.ActorID) || document.ActorID != expectedActorID || document.KeyEpoch < 1 || !digestPattern.MatchString(document.SigningKeyID) || !digestPattern.MatchString(document.PayloadSHA256) || document.PayloadSize < 0 || (document.MetadataSHA256 != "" && !digestPattern.MatchString(document.MetadataSHA256)) || document.MetadataSize < 0 {
		return errors.New("submission is invalid")
	}
	if err := document.Event.Match(binding); err != nil {
		return err
	}
	at, err := parseTimestamp(sourceTime)
	if err != nil {
		return fmt.Errorf("submission source time: %w", err)
	}
	if err := validateDocumentWindow(document.IssuedAt, document.ExpiresAt, binding, binding.TTLSeconds.Submission, at); err != nil {
		return err
	}
	if err := registry.RequirePhase("submissions_open"); err != nil {
		return err
	}
	identity, err := registry.Lookup(document.ActorID)
	if err != nil || identity.KeyEpoch != document.KeyEpoch || identity.SigningKey.KeyID != document.SigningKeyID {
		return errors.New("submission signer does not match active registry")
	}
	if document.PayloadSHA256 != digest(payload) || document.PayloadSize != int64(len(payload)) || (document.MetadataSHA256 == "" && len(metadata) != 0) || (document.MetadataSHA256 != "" && (document.MetadataSHA256 != digest(metadata) || document.MetadataSize != int64(len(metadata)))) {
		return errors.New("submission payload does not match signed document")
	}
	team, err := registry.LookupTeam(document.TeamID)
	if err != nil || !lo.ContainsBy(team.Members, func(member TeamMember) bool {
		return member.ActorID == document.ActorID && member.KeyEpoch == document.KeyEpoch && member.SigningKeyID == document.SigningKeyID
	}) {
		return errors.New("submission signer is not an active team member")
	}
	if registry.hasAttempt(document.AttemptID) || uint64(len(registry.Attempts)) >= binding.Limits.AttemptsTotal || registry.attemptsForTeam(document.TeamID) >= binding.Limits.AttemptsPerTeam {
		return errors.New("submission attempt is not available")
	}
	return Verify("submission.prepare", document.unsigned(), document.Signature, identity.SigningKey)
}

type StreamBinding struct {
	Version    int            `json:"v"`
	Kind       string         `json:"kind"`
	Event      EventReference `json:"event"`
	Purpose    string         `json:"purpose"`
	TeamID     string         `json:"team_id"`
	AttemptID  string         `json:"attempt_id"`
	ArtifactID string         `json:"artifact_id"`
}

func (binding StreamBinding) Validate() error {
	if binding.Version != SchemaVersion || binding.Kind != "stream-binding" || binding.Purpose == "" || !uuidV4Pattern.MatchString(binding.TeamID) || !uuidV4Pattern.MatchString(binding.AttemptID) || binding.ArtifactID == "" {
		return errors.New("stream binding is invalid")
	}
	return binding.Event.Validate()
}

func ReadStreamBinding(path string) (StreamBinding, error) {
	var binding StreamBinding
	if err := ReadJSON(path, &binding); err != nil {
		return binding, fmt.Errorf("read stream binding: %w", err)
	}
	if err := binding.Validate(); err != nil {
		return binding, err
	}
	return binding, nil
}

func DigestJSON(value any) string {
	return digest(canonicalJSON(value))
}

func WriteJSON(path string, value any) error {
	return writeExclusive(path, canonicalJSON(value), 0o644)
}

func ReadJSON(path string, value any) error {
	data, err := readFile(path)
	if err != nil {
		return err
	}
	return decodeJSON(data, value)
}

func ReadBytes(path string) ([]byte, error) { return readFile(path) }

func WriteExclusive(path string, data []byte, mode os.FileMode) error {
	return writeExclusive(path, data, mode)
}

func memberFromIdentity(identity IdentityRecord) TeamMember {
	return TeamMember{ActorID: identity.ActorID, KeyEpoch: identity.KeyEpoch, SigningKeyID: identity.SigningKey.KeyID, RecipientKeyID: identity.RecipientKey.KeyID}
}

func normalizeActorIDs(values []string) []string {
	values = lo.Map(values, func(value string, _ int) string { return strings.TrimSpace(value) })
	values = lo.Filter(values, func(value string, _ int) bool { return validActorID(value) })
	values = lo.Uniq(values)
	sort.Slice(values, func(left, right int) bool { return compareActorIDs(values[left], values[right]) < 0 })
	return values
}

func validateRecipientPublic(document *RecipientPublic) error {
	if document.Algorithm != "age-hybrid-mlkem768-x25519" || !digestPattern.MatchString(document.KeyID) {
		return errors.New("invalid recipient public key metadata")
	}
	recipient, err := age.ParseHybridRecipient(document.PublicKey)
	if err != nil {
		return fmt.Errorf("parse recipient public key: %w", err)
	}
	if document.KeyID != fingerprint([]byte(recipient.String())) {
		return errors.New("recipient public key fingerprint mismatch")
	}
	document.Recipient = recipient
	return nil
}

func decodeSigningPublic(document SigningPublic) (ed25519.PublicKey, error) {
	if document.Algorithm != "Ed25519" || !digestPattern.MatchString(document.KeyID) {
		return nil, errors.New("invalid signing public key metadata")
	}
	key, err := base64.RawURLEncoding.DecodeString(document.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || document.KeyID != fingerprint(key) {
		return nil, errors.New("invalid signing public key")
	}
	return ed25519.PublicKey(key), nil
}

func issueWindow(binding EventBinding, ttl uint64, now time.Time) (string, string, error) {
	validFrom, _ := parseTimestamp(binding.ValidFrom)
	validUntil, _ := parseTimestamp(binding.ValidUntil)
	issued := now.UTC().Truncate(time.Second)
	expires := issued.Add(time.Duration(ttl) * time.Second)
	if issued.Before(validFrom) || expires.After(validUntil) {
		return "", "", errors.New("request window falls outside event binding")
	}
	return issued.Format(time.RFC3339), expires.Format(time.RFC3339), nil
}

func validateDocumentWindow(issuedText, expiresText string, binding EventBinding, ttl uint64, sourceTime time.Time) error {
	issued, err := parseTimestamp(issuedText)
	if err != nil {
		return fmt.Errorf("invalid issued_at: %w", err)
	}
	expires, err := parseTimestamp(expiresText)
	if err != nil || !expires.After(issued) || expires.Sub(issued) > time.Duration(ttl)*time.Second {
		return errors.New("document validity window is invalid")
	}
	validFrom, _ := parseTimestamp(binding.ValidFrom)
	validUntil, _ := parseTimestamp(binding.ValidUntil)
	if issued.Before(validFrom) || expires.After(validUntil) || sourceTime.Before(issued) || sourceTime.After(expires) {
		return errors.New("document is not valid at trusted source time")
	}
	return nil
}

func parseTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, errors.New("timestamp must be UTC RFC3339 whole seconds")
	}
	return parsed.UTC(), nil
}

func validActorID(value string) bool { return decimalPattern.MatchString(value) }

func compareActorIDs(left, right string) int {
	leftValue, _ := strconv.ParseUint(left, 10, 64)
	rightValue, _ := strconv.ParseUint(right, 10, 64)
	switch {
	case leftValue < rightValue:
		return -1
	case leftValue > rightValue:
		return 1
	default:
		return 0
	}
}

func newUUIDv4() string {
	value := make([]byte, 16)
	_, _ = rand.Read(value)
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

func fingerprint(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

func digest(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

func signedMessage(domain string, value any) []byte {
	return append([]byte("eventctl:"+Protocol+":"+domain+"\x00"), canonicalJSON(value)...)
}

func canonicalJSON(value any) []byte {
	// Every caller supplies one of this package's concrete document structs.
	// Their fields are JSON-encodable, so json.Marshal cannot fail here.
	data := lo.Must(json.Marshal(value))
	return append(data, '\n')
}

func encryptWithPass(data []byte, passphrase string) []byte {
	// readPassphrase has already rejected the only invalid ScryptRecipient
	// input, and bytes.Buffer never returns a write error.
	recipient := lo.Must(age.NewScryptRecipient(passphrase))
	var output bytes.Buffer
	writer := lo.Must(age.Encrypt(&output, recipient))
	lo.Must(writer.Write(data))
	lo.Must0(writer.Close())
	return output.Bytes()
}

func decryptWithPass(data []byte, passphrase string) ([]byte, error) {
	identity := lo.Must(age.NewScryptIdentity(passphrase))
	reader, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(io.LimitReader(reader, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read decrypted key: %w", err)
	}
	return plain, nil
}

func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBytes {
		return nil, errors.New("file exceeds size limit")
	}
	return data, nil
}

func decodeJSON(data []byte, value any) error {
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	return requireEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	if delimiter == '{' {
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("JSON object has duplicate or invalid key")
			}
			seen[key] = true
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	// Token returns only opening delimiters at a value boundary. The object
	// case returned above, so the remaining delimiter is an array opener.
	for decoder.More() {
		if err := scanJSONValue(decoder); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func requireEOF(decoder *json.Decoder) error {
	_, err := decoder.Token()
	if err != io.EOF {
		return errors.New("JSON document contains trailing data")
	}
	return nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	return errors.Join(writeErr, file.Close())
}
