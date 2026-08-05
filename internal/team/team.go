// Package team implements immutable proposals and unanimous individual consent
// using the flat v1 protocol documents.
package team

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
)

const (
	ProposalKind                 = "team_proposal"
	ProposalDomain               = "team_proposal"
	ConsentKind                  = "team_consent"
	ConsentDomain                = "team_consent"
	MinProposalTTLSeconds uint64 = 300
	MaxProposalTTLSeconds uint64 = 1_209_600
	MinProposalTTL               = time.Duration(MinProposalTTLSeconds) * time.Second
	MaxProposalTTL               = time.Duration(MaxProposalTTLSeconds) * time.Second
)

// Proposal is the authoritative flat team-proposal wire document.
type Proposal struct {
	Kind            string              `json:"kind"`
	Protocol        string              `json:"protocol"`
	ProtocolVersion int                 `json:"protocol_version"`
	EventID         string              `json:"event_id"`
	EventEpoch      string              `json:"event_epoch"`
	OperationID     string              `json:"operation_id"`
	TeamID          string              `json:"team_id"`
	ProposerActorID string              `json:"proposer_actor_id"`
	KeyID           string              `json:"key_id"`
	KeyEpoch        string              `json:"key_epoch"`
	MemberActorIDs  []string            `json:"member_actor_ids"`
	BaseRepository  envelope.Repository `json:"base_repository"`
	ConfigDigest    string              `json:"config_digest"`
	IssuedAt        string              `json:"issued_at"`
	ExpiresAt       string              `json:"expires_at"`
	Signature       identity.Signature  `json:"signature"`
}

type proposalUnsigned struct {
	Kind            string              `json:"kind"`
	Protocol        string              `json:"protocol"`
	ProtocolVersion int                 `json:"protocol_version"`
	EventID         string              `json:"event_id"`
	EventEpoch      string              `json:"event_epoch"`
	OperationID     string              `json:"operation_id"`
	TeamID          string              `json:"team_id"`
	ProposerActorID string              `json:"proposer_actor_id"`
	KeyID           string              `json:"key_id"`
	KeyEpoch        string              `json:"key_epoch"`
	MemberActorIDs  []string            `json:"member_actor_ids"`
	BaseRepository  envelope.Repository `json:"base_repository"`
	ConfigDigest    string              `json:"config_digest"`
	IssuedAt        string              `json:"issued_at"`
	ExpiresAt       string              `json:"expires_at"`
}

// Consent is one participant's consent to the digest of an exact proposal.
type Consent struct {
	Kind            string              `json:"kind"`
	Protocol        string              `json:"protocol"`
	ProtocolVersion int                 `json:"protocol_version"`
	EventID         string              `json:"event_id"`
	EventEpoch      string              `json:"event_epoch"`
	OperationID     string              `json:"operation_id"`
	TeamID          string              `json:"team_id"`
	ProposalDigest  string              `json:"proposal_digest"`
	ActorID         string              `json:"actor_id"`
	KeyID           string              `json:"key_id"`
	KeyEpoch        string              `json:"key_epoch"`
	Decision        string              `json:"decision"`
	BaseRepository  envelope.Repository `json:"base_repository"`
	ConfigDigest    string              `json:"config_digest"`
	IssuedAt        string              `json:"issued_at"`
	ExpiresAt       string              `json:"expires_at"`
	Signature       identity.Signature  `json:"signature"`
}

// ValidateUntrustedStructure validates the concrete team-proposal schema and
// internal field relationships without authenticating its signature, trusted
// actor/config context, or current validity window.
func (value Proposal) ValidateUntrustedStructure() error {
	if err := validateProposal(value, time.Time{}, MaxProposalTTL); err != nil {
		return err
	}
	if err := value.Signature.ValidateEncoding(); err != nil {
		return err
	}
	if value.Signature.KeyID != value.KeyID {
		return errors.New("signature.key_id does not match key_id")
	}
	return nil
}

// ValidateUntrustedStructure validates the concrete team-consent schema and
// internal field relationships without authenticating its signature, trusted
// actor/config context, proposal binding, or current validity window.
func (value Consent) ValidateUntrustedStructure() error {
	if err := validateConsent(value, time.Time{}, MaxProposalTTL); err != nil {
		return err
	}
	if err := value.Signature.ValidateEncoding(); err != nil {
		return err
	}
	if value.Signature.KeyID != value.KeyID {
		return errors.New("signature.key_id does not match key_id")
	}
	return nil
}

type consentUnsigned struct {
	Kind            string              `json:"kind"`
	Protocol        string              `json:"protocol"`
	ProtocolVersion int                 `json:"protocol_version"`
	EventID         string              `json:"event_id"`
	EventEpoch      string              `json:"event_epoch"`
	OperationID     string              `json:"operation_id"`
	TeamID          string              `json:"team_id"`
	ProposalDigest  string              `json:"proposal_digest"`
	ActorID         string              `json:"actor_id"`
	KeyID           string              `json:"key_id"`
	KeyEpoch        string              `json:"key_epoch"`
	Decision        string              `json:"decision"`
	BaseRepository  envelope.Repository `json:"base_repository"`
	ConfigDigest    string              `json:"config_digest"`
	IssuedAt        string              `json:"issued_at"`
	ExpiresAt       string              `json:"expires_at"`
}

type ProposalParams struct {
	EventID         string
	EventEpoch      string
	OperationID     string
	TeamID          string
	ProposerActorID string
	KeyEpoch        string
	MemberActorIDs  []string
	BaseRepository  envelope.Repository
	ConfigDigest    string
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

type ConsentParams struct {
	OperationID string
	ActorID     string
	KeyEpoch    string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

type VerifiedProposal struct {
	Document       Proposal
	ProposalDigest string
	Fingerprint    envelope.Fingerprint
}

type VerifiedConsent struct {
	Document    Consent
	Fingerprint envelope.Fingerprint
}

// ActivationCandidate proves cryptographic unanimity. Protected state must
// still atomically recheck lifecycle and membership before activation.
type ActivationCandidate struct {
	TeamID          string                 `json:"team_id"`
	MemberActorIDs  []string               `json:"member_actor_ids"`
	ProposalDigest  string                 `json:"proposal_digest"`
	Proposal        envelope.Fingerprint   `json:"proposal"`
	ConsentRequests []envelope.Fingerprint `json:"consent_requests"`
}

func NewProposal(params ProposalParams, private identity.Private) ([]byte, error) {
	pair, err := privatePair(private)
	if err != nil {
		return nil, err
	}
	if params.OperationID == "" {
		params.OperationID, err = envelope.NewRequestID()
		if err != nil {
			return nil, err
		}
	}
	if params.TeamID == "" {
		params.TeamID, err = envelope.NewRequestID()
		if err != nil {
			return nil, err
		}
	}
	if params.KeyEpoch == "" {
		params.KeyEpoch = "1"
	}
	members := append([]string(nil), params.MemberActorIDs...)
	sort.Slice(members, func(i, j int) bool { return identity.CompareDecimal(members[i], members[j]) < 0 })
	proposal := Proposal{
		Kind: ProposalKind, Protocol: envelope.Protocol, ProtocolVersion: envelope.ProtocolVersion,
		EventID: params.EventID, EventEpoch: params.EventEpoch, OperationID: params.OperationID, TeamID: params.TeamID,
		ProposerActorID: params.ProposerActorID, KeyID: pair.Public.KeyID, KeyEpoch: params.KeyEpoch,
		MemberActorIDs: members, BaseRepository: params.BaseRepository, ConfigDigest: params.ConfigDigest,
		IssuedAt: formatTime(params.IssuedAt), ExpiresAt: formatTime(params.ExpiresAt),
	}
	if err := validateProposal(proposal, time.Time{}, MaxProposalTTL); err != nil {
		return nil, err
	}
	proposal.Signature, err = envelope.Sign(ProposalDomain, unsignedProposal(proposal), pair.Private)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(proposal)
}

// VerifyProposal authenticates a proposal and enforces the proposal TTL from
// the signed event config bound by expected.ConfigDigest.
func VerifyProposal(raw []byte, expected envelope.Expected, proposalTTL time.Duration, registry identity.Registry) (VerifiedProposal, error) {
	if len(raw) > envelope.MaxDocumentBytes {
		return VerifiedProposal{}, errors.New("team proposal exceeds 1 MiB")
	}
	var proposal Proposal
	if err := canonical.StrictUnmarshal(raw, &proposal); err != nil {
		return VerifiedProposal{}, fmt.Errorf("decode team proposal: %w", err)
	}
	if err := validateProposal(proposal, expected.Now, proposalTTL); err != nil {
		return VerifiedProposal{}, err
	}
	if err := compareExpected(proposal.EventID, proposal.EventEpoch, proposal.BaseRepository.ID, proposal.ProposerActorID, proposal.ConfigDigest, proposal.KeyEpoch, proposal.KeyID, expected); err != nil {
		return VerifiedProposal{}, err
	}
	trusted, ok := registry.Resolve(proposal.ProposerActorID, proposal.KeyEpoch)
	if !ok || trusted.KeyID != proposal.KeyID {
		return VerifiedProposal{}, errors.New("proposal signer does not match trusted registration")
	}
	if err := envelope.Verify(ProposalDomain, unsignedProposal(proposal), proposal.Signature, trusted); err != nil {
		return VerifiedProposal{}, err
	}
	canonicalProposal, err := canonical.Marshal(proposal)
	if err != nil {
		return VerifiedProposal{}, err
	}
	proposalDigest := envelope.Digest(canonicalProposal)
	intentDigest, err := envelope.SigningDigest(ProposalDomain, unsignedProposal(proposal))
	if err != nil {
		return VerifiedProposal{}, err
	}
	fingerprint, err := envelope.NewFingerprint(ProposalDomain, proposal.EventID, proposal.OperationID, intentDigest)
	if err != nil {
		return VerifiedProposal{}, err
	}
	return VerifiedProposal{Document: proposal, ProposalDigest: proposalDigest, Fingerprint: fingerprint}, nil
}

// NewConsent verifies the proposal against trusted registrations before signing
// one exact participant's separate consent.
func NewConsent(proposalRaw []byte, params ConsentParams, private identity.Private, registry identity.Registry) ([]byte, error) {
	pair, err := privatePair(private)
	if err != nil {
		return nil, err
	}
	proposal, err := VerifyProposal(proposalRaw, envelope.Expected{}, MaxProposalTTL, registry)
	if err != nil {
		return nil, fmt.Errorf("verify proposal before consent: %w", err)
	}
	if params.OperationID == "" {
		params.OperationID, err = envelope.NewRequestID()
		if err != nil {
			return nil, err
		}
	}
	if params.KeyEpoch == "" {
		params.KeyEpoch = "1"
	}
	consent := Consent{
		Kind: ConsentKind, Protocol: envelope.Protocol, ProtocolVersion: envelope.ProtocolVersion,
		EventID: proposal.Document.EventID, EventEpoch: proposal.Document.EventEpoch, OperationID: params.OperationID, TeamID: proposal.Document.TeamID,
		ProposalDigest: proposal.ProposalDigest, ActorID: params.ActorID, KeyID: pair.Public.KeyID, KeyEpoch: params.KeyEpoch,
		Decision: "consent", BaseRepository: proposal.Document.BaseRepository, ConfigDigest: proposal.Document.ConfigDigest,
		IssuedAt: formatTime(params.IssuedAt), ExpiresAt: formatTime(params.ExpiresAt),
	}
	if !contains(proposal.Document.MemberActorIDs, consent.ActorID) {
		return nil, errors.New("consent actor is not a proposal member")
	}
	trusted, ok := registry.Resolve(consent.ActorID, consent.KeyEpoch)
	if !ok || trusted != pair.Public {
		return nil, errors.New("consent signing key does not match trusted registration")
	}
	if err := validateConsent(consent, time.Time{}, MaxProposalTTL); err != nil {
		return nil, err
	}
	consent.Signature, err = envelope.Sign(ConsentDomain, unsignedConsent(consent), pair.Private)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(consent)
}

// VerifyUnanimous verifies the proposal and every member consent under the
// proposal TTL from the signed event config.
func VerifyUnanimous(proposalRaw []byte, consentDocuments [][]byte, expected envelope.Expected, proposalTTL time.Duration, registry identity.Registry) (ActivationCandidate, error) {
	proposal, err := VerifyProposal(proposalRaw, expected, proposalTTL, registry)
	if err != nil {
		return ActivationCandidate{}, err
	}
	if len(consentDocuments) != len(proposal.Document.MemberActorIDs) {
		return ActivationCandidate{}, fmt.Errorf("got %d consents, want exactly %d", len(consentDocuments), len(proposal.Document.MemberActorIDs))
	}
	seen := make(map[string]struct{}, len(consentDocuments))
	fingerprints := make([]envelope.Fingerprint, 0, len(consentDocuments))
	for index, raw := range consentDocuments {
		consent, err := verifyConsent(raw, proposal, expected, proposalTTL, registry)
		if err != nil {
			return ActivationCandidate{}, fmt.Errorf("consent %d: %w", index, err)
		}
		if _, duplicate := seen[consent.Document.ActorID]; duplicate {
			return ActivationCandidate{}, fmt.Errorf("duplicate consent from actor_id %s", consent.Document.ActorID)
		}
		seen[consent.Document.ActorID] = struct{}{}
		fingerprints = append(fingerprints, consent.Fingerprint)
	}
	for _, actorID := range proposal.Document.MemberActorIDs {
		if _, ok := seen[actorID]; !ok {
			return ActivationCandidate{}, fmt.Errorf("missing consent from actor_id %s", actorID)
		}
	}
	sort.Slice(fingerprints, func(i, j int) bool { return fingerprints[i].ReplayKey < fingerprints[j].ReplayKey })
	return ActivationCandidate{
		TeamID: proposal.Document.TeamID, MemberActorIDs: append([]string(nil), proposal.Document.MemberActorIDs...),
		ProposalDigest: proposal.ProposalDigest, Proposal: proposal.Fingerprint, ConsentRequests: fingerprints,
	}, nil
}

// VerifyConsent verifies one consent against one exact proposal and trusted
// registry under the proposal TTL from the signed event config. Unanimity
// remains a protected-state aggregation concern.
func VerifyConsent(proposalRaw, consentRaw []byte, expected envelope.Expected, proposalTTL time.Duration, registry identity.Registry) (VerifiedConsent, error) {
	proposal, err := VerifyProposal(proposalRaw, expected, proposalTTL, registry)
	if err != nil {
		return VerifiedConsent{}, err
	}
	return verifyConsent(consentRaw, proposal, expected, proposalTTL, registry)
}

func verifyConsent(raw []byte, proposal VerifiedProposal, expected envelope.Expected, proposalTTL time.Duration, registry identity.Registry) (VerifiedConsent, error) {
	if len(raw) > envelope.MaxDocumentBytes {
		return VerifiedConsent{}, errors.New("team consent exceeds 1 MiB")
	}
	var consent Consent
	if err := canonical.StrictUnmarshal(raw, &consent); err != nil {
		return VerifiedConsent{}, fmt.Errorf("decode team consent: %w", err)
	}
	if err := validateConsent(consent, expected.Now, proposalTTL); err != nil {
		return VerifiedConsent{}, err
	}
	if consent.EventID != proposal.Document.EventID || consent.EventEpoch != proposal.Document.EventEpoch || consent.TeamID != proposal.Document.TeamID || consent.ProposalDigest != proposal.ProposalDigest || consent.BaseRepository != proposal.Document.BaseRepository || consent.ConfigDigest != proposal.Document.ConfigDigest {
		return VerifiedConsent{}, errors.New("consent does not bind the exact proposal context")
	}
	if !contains(proposal.Document.MemberActorIDs, consent.ActorID) {
		return VerifiedConsent{}, errors.New("consent actor is not a proposal member")
	}
	if err := compareExpected(consent.EventID, consent.EventEpoch, consent.BaseRepository.ID, consent.ActorID, consent.ConfigDigest, consent.KeyEpoch, consent.KeyID, expectedWithoutActor(expected)); err != nil {
		return VerifiedConsent{}, err
	}
	trusted, ok := registry.Resolve(consent.ActorID, consent.KeyEpoch)
	if !ok || trusted.KeyID != consent.KeyID {
		return VerifiedConsent{}, errors.New("consent signer does not match trusted registration")
	}
	if err := envelope.Verify(ConsentDomain, unsignedConsent(consent), consent.Signature, trusted); err != nil {
		return VerifiedConsent{}, err
	}
	intentDigest, err := envelope.SigningDigest(ConsentDomain, unsignedConsent(consent))
	if err != nil {
		return VerifiedConsent{}, err
	}
	fingerprint, err := envelope.NewFingerprint(ConsentDomain, consent.EventID, consent.OperationID, intentDigest)
	if err != nil {
		return VerifiedConsent{}, err
	}
	return VerifiedConsent{Document: consent, Fingerprint: fingerprint}, nil
}

func validateProposal(value Proposal, now time.Time, proposalTTL time.Duration) error {
	if value.Kind != ProposalKind || value.Protocol != envelope.Protocol || value.ProtocolVersion != envelope.ProtocolVersion {
		return errors.New("team proposal protocol discriminator is invalid")
	}
	if !envelope.IsEventID(value.EventID) || !envelope.IsUUID(value.OperationID) || !envelope.IsUUID(value.TeamID) {
		return errors.New("proposal event_id, operation_id, or team_id is invalid")
	}
	if err := identity.ValidateDecimal(value.EventEpoch, "event_epoch"); err != nil {
		return err
	}
	if err := identity.ValidateDecimal(value.ProposerActorID, "proposer_actor_id"); err != nil {
		return err
	}
	if err := identity.ValidateDecimal(value.KeyEpoch, "key_epoch"); err != nil {
		return err
	}
	if !envelope.IsDigest(value.KeyID) || !envelope.IsDigest(value.ConfigDigest) {
		return errors.New("proposal key_id/config_digest is invalid")
	}
	if err := envelope.ValidateRepository(value.BaseRepository); err != nil {
		return err
	}
	if len(value.MemberActorIDs) == 0 || len(value.MemberActorIDs) > 64 {
		return errors.New("proposal must have 1 to 64 members")
	}
	for index, actorID := range value.MemberActorIDs {
		if err := identity.ValidateDecimal(actorID, "member_actor_id"); err != nil {
			return err
		}
		if index > 0 && identity.CompareDecimal(value.MemberActorIDs[index-1], actorID) >= 0 {
			return errors.New("member_actor_ids must be strictly numerically sorted and unique")
		}
	}
	if !contains(value.MemberActorIDs, value.ProposerActorID) {
		return errors.New("proposer must be a member")
	}
	return validateTeamWindow(value.IssuedAt, value.ExpiresAt, now, proposalTTL)
}

func validateConsent(value Consent, now time.Time, proposalTTL time.Duration) error {
	if value.Kind != ConsentKind || value.Protocol != envelope.Protocol || value.ProtocolVersion != envelope.ProtocolVersion || value.Decision != "consent" {
		return errors.New("team consent protocol discriminator is invalid")
	}
	if !envelope.IsEventID(value.EventID) || !envelope.IsUUID(value.OperationID) || !envelope.IsUUID(value.TeamID) {
		return errors.New("consent event_id, operation_id, or team_id is invalid")
	}
	if err := identity.ValidateDecimal(value.EventEpoch, "event_epoch"); err != nil {
		return err
	}
	if err := identity.ValidateDecimal(value.ActorID, "actor_id"); err != nil {
		return err
	}
	if err := identity.ValidateDecimal(value.KeyEpoch, "key_epoch"); err != nil {
		return err
	}
	if !envelope.IsDigest(value.KeyID) || !envelope.IsDigest(value.ProposalDigest) || !envelope.IsDigest(value.ConfigDigest) {
		return errors.New("consent digest/key fields are invalid")
	}
	if err := envelope.ValidateRepository(value.BaseRepository); err != nil {
		return err
	}
	return validateTeamWindow(value.IssuedAt, value.ExpiresAt, now, proposalTTL)
}

func validateTeamWindow(issuedAt, expiresAt string, now time.Time, proposalTTL time.Duration) error {
	if proposalTTL < MinProposalTTL || proposalTTL > MaxProposalTTL || proposalTTL%time.Second != 0 {
		return fmt.Errorf("team proposal TTL must be %d to %d whole seconds", MinProposalTTLSeconds, MaxProposalTTLSeconds)
	}
	return envelope.ValidateWindowWithin(issuedAt, expiresAt, now, proposalTTL)
}

func unsignedProposal(v Proposal) proposalUnsigned {
	return proposalUnsigned{v.Kind, v.Protocol, v.ProtocolVersion, v.EventID, v.EventEpoch, v.OperationID, v.TeamID, v.ProposerActorID, v.KeyID, v.KeyEpoch, append([]string(nil), v.MemberActorIDs...), v.BaseRepository, v.ConfigDigest, v.IssuedAt, v.ExpiresAt}
}
func unsignedConsent(v Consent) consentUnsigned {
	return consentUnsigned{v.Kind, v.Protocol, v.ProtocolVersion, v.EventID, v.EventEpoch, v.OperationID, v.TeamID, v.ProposalDigest, v.ActorID, v.KeyID, v.KeyEpoch, v.Decision, v.BaseRepository, v.ConfigDigest, v.IssuedAt, v.ExpiresAt}
}
func formatTime(v time.Time) string {
	if v.IsZero() {
		return ""
	}
	return v.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func privatePair(private identity.Private) (identity.KeyPair, error) {
	raw, err := canonical.Marshal(private)
	if err != nil {
		return identity.KeyPair{}, err
	}
	return identity.ParsePrivate(raw)
}
func compareExpected(eventID, eventEpoch, repoID, actorID, configDigest, keyEpoch, keyID string, e envelope.Expected) error {
	checks := [][3]string{{"event_id", eventID, e.EventID}, {"event_epoch", eventEpoch, e.EventEpoch}, {"repository_id", repoID, e.RepositoryID}, {"actor_id", actorID, e.ActorID}, {"config_digest", configDigest, e.ConfigDigest}, {"key_epoch", keyEpoch, e.KeyEpoch}, {"key_id", keyID, e.KeyID}}
	for _, c := range checks {
		if c[2] != "" && c[1] != c[2] {
			return fmt.Errorf("%s is %q, trusted value is %q", c[0], c[1], c[2])
		}
	}
	return nil
}
func expectedWithoutActor(e envelope.Expected) envelope.Expected {
	e.ActorID = ""
	e.KeyEpoch = ""
	e.KeyID = ""
	return e
}
