// Package config strictly parses, validates, signs, and verifies organizer YAML.
// Bash must treat configuration as opaque and invoke eventctl for these tasks.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"regexp"
	"sort"
	"time"

	"filippo.io/age"
	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
	"github.com/pythonhk/eventctl/internal/scorer"
	"github.com/pythonhk/eventctl/internal/statepointer"
	"github.com/pythonhk/eventctl/internal/team"
	"go.yaml.in/yaml/v3"
)

const (
	Kind                             = "event_config"
	SigningDomain                    = "event_config"
	MaxBytes                         = 1 << 20
	MaxExternalJudgeURLBytes         = 2_048
	MaxTeamProposalsPerParticipantV1 = 16
	MaxTotalSubmissionAttemptsV1     = 1_000
	MaxDerivedBusinessRecordsV1      = 2_028
	MaxDerivedStateRecordsV1         = statepointer.MaxSequenceV1
	maxYAMLDepth                     = 64
	maxSubmissionCiphertextBytes     = 47_000_000
	maxSubmissionPlaintextBytes      = 42_000_000
	maxSubmissionFileBytes           = 42_000_000
)

var (
	idPattern              = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
	appSlugPattern         = regexp.MustCompile(`^[a-z][a-z0-9-]{2,63}$`)
	recipientIDPattern     = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,31}$`)
	extensionPattern       = regexp.MustCompile(`^\.[a-z0-9][a-z0-9._-]{0,15}$`)
	semverPattern          = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	base64SignaturePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{86}$`)
	rfc3986ASCIIPattern    = regexp.MustCompile(`^[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$`)
)

type Event struct {
	Kind                 string               `json:"kind" yaml:"kind"`
	Protocol             string               `json:"protocol" yaml:"protocol"`
	ProtocolVersion      int                  `json:"protocol_version" yaml:"protocol_version"`
	EventID              string               `json:"event_id" yaml:"event_id"`
	EventEpoch           string               `json:"event_epoch" yaml:"event_epoch"`
	BaseRepository       envelope.Repository  `json:"base_repository" yaml:"base_repository"`
	ConfigEpoch          uint64               `json:"config_epoch" yaml:"config_epoch"`
	DelegationEpoch      uint64               `json:"delegation_epoch" yaml:"delegation_epoch"`
	PreviousConfigDigest *string              `json:"previous_config_digest" yaml:"previous_config_digest"`
	DelegationDigest     string               `json:"delegation_digest" yaml:"delegation_digest"`
	IssuedAt             string               `json:"issued_at" yaml:"issued_at"`
	ExpiresAt            string               `json:"expires_at" yaml:"expires_at"`
	InitialState         InitialState         `json:"initial_state" yaml:"initial_state"`
	Registration         Registration         `json:"registration" yaml:"registration"`
	Teams                Teams                `json:"teams" yaml:"teams"`
	Submissions          Submissions          `json:"submissions" yaml:"submissions"`
	Scoring              Scoring              `json:"scoring" yaml:"scoring"`
	State                State                `json:"state" yaml:"state"`
	Receipts             Receipts             `json:"receipts" yaml:"receipts"`
	Signatures           []identity.Signature `json:"signatures" yaml:"signatures"`
}

type InitialState struct {
	Phase          string `json:"phase" yaml:"phase"`
	Enabled        bool   `json:"enabled" yaml:"enabled"`
	DisabledReason string `json:"disabled_reason" yaml:"disabled_reason"`
}

type Registration struct {
	MaximumParticipants uint64 `json:"maximum_participants" yaml:"maximum_participants"`
	RequestTTLSeconds   uint64 `json:"request_ttl_seconds" yaml:"request_ttl_seconds"`
	TermsDigest         string `json:"terms_digest" yaml:"terms_digest"`
	KeyAlgorithm        string `json:"key_algorithm" yaml:"key_algorithm"`
	KeyRotationPolicy   string `json:"key_rotation_policy" yaml:"key_rotation_policy"`
}

type Teams struct {
	MinimumSize                    uint64 `json:"minimum_size" yaml:"minimum_size"`
	MaximumSize                    uint64 `json:"maximum_size" yaml:"maximum_size"`
	MaximumProposalsPerParticipant uint64 `json:"maximum_proposals_per_participant" yaml:"maximum_proposals_per_participant"`
	ProposalTTLSeconds             uint64 `json:"proposal_ttl_seconds" yaml:"proposal_ttl_seconds"`
	MembershipLockPhase            string `json:"membership_lock_phase" yaml:"membership_lock_phase"`
}

type Submissions struct {
	BaseRef                string     `json:"base_ref" yaml:"base_ref"`
	MaximumAttemptsPerTeam uint64     `json:"maximum_attempts_per_team" yaml:"maximum_attempts_per_team"`
	MaximumTotalAttempts   uint64     `json:"maximum_total_attempts" yaml:"maximum_total_attempts"`
	MaximumCiphertextBytes uint64     `json:"maximum_ciphertext_bytes" yaml:"maximum_ciphertext_bytes"`
	MaximumPlaintextBytes  uint64     `json:"maximum_plaintext_bytes" yaml:"maximum_plaintext_bytes"`
	MaximumFileBytes       uint64     `json:"maximum_file_bytes" yaml:"maximum_file_bytes"`
	MaximumPlaintextFiles  uint64     `json:"maximum_plaintext_files" yaml:"maximum_plaintext_files"`
	EnvelopeTTLSeconds     uint64     `json:"envelope_ttl_seconds" yaml:"envelope_ttl_seconds"`
	DeliveryMode           string     `json:"delivery_mode" yaml:"delivery_mode"`
	FailedConsumeQuota     bool       `json:"failed_attempts_consume_quota" yaml:"failed_attempts_consume_quota"`
	AllowedExtensions      []string   `json:"allowed_extensions" yaml:"allowed_extensions"`
	Encryption             Encryption `json:"encryption" yaml:"encryption"`
}

type Encryption struct {
	Algorithm      string      `json:"algorithm" yaml:"algorithm"`
	RecipientEpoch string      `json:"recipient_epoch" yaml:"recipient_epoch"`
	Recipients     []Recipient `json:"recipients" yaml:"recipients"`
}

type Recipient struct {
	RecipientID string `json:"recipient_id" yaml:"recipient_id"`
	PublicKey   string `json:"public_key" yaml:"public_key"`
}

type Scoring struct {
	Mode               string          `json:"mode" yaml:"mode"`
	ScorerID           string          `json:"scorer_id" yaml:"scorer_id"`
	ScorerVersion      string          `json:"scorer_version" yaml:"scorer_version"`
	PolicyDigest       string          `json:"policy_digest" yaml:"policy_digest"`
	MaximumResultBytes uint64          `json:"maximum_result_bytes" yaml:"maximum_result_bytes"`
	ResultKey          identity.Public `json:"result_key" yaml:"result_key"`
	ExternalJudgeURL   *string         `json:"external_judge_url" yaml:"external_judge_url"`
}

type State struct {
	Branch                 string `json:"branch" yaml:"branch"`
	Public                 bool   `json:"public" yaml:"public"`
	WriterAppSlug          string `json:"writer_app_slug" yaml:"writer_app_slug"`
	WriterConcurrencyGroup string `json:"writer_concurrency_group" yaml:"writer_concurrency_group"`
	JournalFormat          string `json:"journal_format" yaml:"journal_format"`
}

type Receipts struct {
	SigningKey identity.Public `json:"signing_key" yaml:"signing_key"`
}

type unsignedEvent struct {
	Kind                 string              `json:"kind"`
	Protocol             string              `json:"protocol"`
	ProtocolVersion      int                 `json:"protocol_version"`
	EventID              string              `json:"event_id"`
	EventEpoch           string              `json:"event_epoch"`
	BaseRepository       envelope.Repository `json:"base_repository"`
	ConfigEpoch          uint64              `json:"config_epoch"`
	DelegationEpoch      uint64              `json:"delegation_epoch"`
	PreviousConfigDigest *string             `json:"previous_config_digest"`
	DelegationDigest     string              `json:"delegation_digest"`
	IssuedAt             string              `json:"issued_at"`
	ExpiresAt            string              `json:"expires_at"`
	InitialState         InitialState        `json:"initial_state"`
	Registration         Registration        `json:"registration"`
	Teams                Teams               `json:"teams"`
	Submissions          Submissions         `json:"submissions"`
	Scoring              Scoring             `json:"scoring"`
	State                State               `json:"state"`
	Receipts             Receipts            `json:"receipts"`
}

type Verification struct {
	Digest      string   `json:"digest"`
	ValidKeyIDs []string `json:"valid_key_ids"`
	Required    int      `json:"required"`
}

// DerivedCapacity is the closed v1 upper bound on protected-state records.
// BusinessRecords is N + N*P + N*P*M + 2*A. StateRecords additionally
// includes the genesis record, two journal records per business record, six
// emergency-control records, and 32 journal-transition records.
type DerivedCapacity struct {
	BusinessRecords uint64
	StateRecords    uint64
}

// Parse strictly decodes one bounded YAML document and validates it.
func Parse(raw []byte) (Event, error) {
	return parseYAML(raw, true)
}

// ParseUnsigned is the only parser that permits an empty signatures array. It
// exists solely so config sign can start from a clean authoring document.
func ParseUnsigned(raw []byte) (Event, error) {
	return parseYAML(raw, false)
}

func parseYAML(raw []byte, requireSignatures bool) (Event, error) {
	if len(raw) > MaxBytes {
		return Event{}, fmt.Errorf("event config is %d bytes, limit is %d", len(raw), MaxBytes)
	}
	if !bytes.Equal(bytes.TrimSpace(raw), []byte("")) {
		var root yaml.Node
		decoder := yaml.NewDecoder(bytes.NewReader(raw))
		decoder.KnownFields(true)
		if err := decoder.Decode(&root); err != nil {
			return Event{}, fmt.Errorf("decode event YAML: %w", err)
		}
		if err := inspectYAML(&root, 0); err != nil {
			return Event{}, err
		}
		var extra yaml.Node
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			if err == nil {
				return Event{}, errors.New("event YAML contains multiple documents")
			}
			return Event{}, fmt.Errorf("read trailing YAML: %w", err)
		}
	} else {
		return Event{}, errors.New("event config is empty")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	var event Event
	if err := decoder.Decode(&event); err != nil {
		return Event{}, fmt.Errorf("decode typed event YAML: %w", err)
	}
	if err := event.validate(requireSignatures); err != nil {
		return Event{}, err
	}
	return event, nil
}

func (event Event) Validate() error {
	return event.validate(true)
}

func (event Event) validate(requireSignatures bool) error {
	if event.Kind != Kind || event.Protocol != envelope.Protocol || event.ProtocolVersion != envelope.ProtocolVersion {
		return errors.New("event config protocol discriminator is invalid")
	}
	if !envelope.IsEventID(event.EventID) {
		return errors.New("event_id is invalid")
	}
	if event.EventEpoch != "1" {
		return errors.New("v1 requires event_epoch 1")
	}
	if err := envelope.ValidateRepository(event.BaseRepository); err != nil {
		return err
	}
	if event.ConfigEpoch != 1 {
		return errors.New("v1 requires config_epoch 1")
	}
	if event.DelegationEpoch != 1 {
		return errors.New("v1 requires delegation_epoch 1")
	}
	if event.PreviousConfigDigest != nil {
		return errors.New("v1 requires null previous_config_digest")
	}
	if !envelope.IsDigest(event.DelegationDigest) {
		return errors.New("delegation_digest is invalid")
	}
	issued, err := envelope.ParseTimestamp(event.IssuedAt)
	if err != nil {
		return err
	}
	expires, err := envelope.ParseTimestamp(event.ExpiresAt)
	if err != nil || !expires.After(issued) {
		return errors.New("config expires_at must be valid and after issued_at")
	}
	if err := validateInitialState(event.InitialState); err != nil {
		return err
	}
	if err := validateRegistration(event.Registration); err != nil {
		return err
	}
	if err := validateTeams(event.Teams); err != nil {
		return err
	}
	if event.Teams.MinimumSize > event.Registration.MaximumParticipants || event.Teams.MaximumSize > event.Registration.MaximumParticipants {
		return errors.New("team sizes must not exceed maximum_participants")
	}
	if err := validateSubmissions(event.Submissions); err != nil {
		return err
	}
	if _, err := DeriveCapacity(event.Registration, event.Teams, event.Submissions); err != nil {
		return err
	}
	if err := validateScoring(event.Scoring); err != nil {
		return err
	}
	if event.State.Branch != "event-state" || !event.State.Public || !appSlugPattern.MatchString(event.State.WriterAppSlug) || event.State.WriterConcurrencyGroup != "event-state-writer" || event.State.JournalFormat != "hash-linked-json-v1" {
		return errors.New("state configuration is invalid")
	}
	if err := event.Receipts.SigningKey.Validate(); err != nil {
		return fmt.Errorf("receipt signing key: %w", err)
	}
	if event.Receipts.SigningKey.KeyID == event.Scoring.ResultKey.KeyID {
		return errors.New("receipt and scorer result authorities must be distinct")
	}
	if (requireSignatures && len(event.Signatures) < 1) || len(event.Signatures) > 16 {
		return errors.New("config must contain 1 to 16 signatures")
	}
	seen := map[string]struct{}{}
	for i, sig := range event.Signatures {
		if err := validateProtocolSignature(sig); err != nil {
			return fmt.Errorf("signature %d: %w", i, err)
		}
		if _, ok := seen[sig.KeyID]; ok {
			return errors.New("duplicate config signature key_id")
		}
		seen[sig.KeyID] = struct{}{}
		if i > 0 && event.Signatures[i-1].KeyID >= sig.KeyID {
			return errors.New("config signatures must be strictly sorted by key_id")
		}
	}
	return nil
}

// Digest returns SHA-256 of the strict config's canonical JSON representation.
func Digest(event Event) (string, error) {
	if err := event.Validate(); err != nil {
		return "", err
	}
	raw, err := canonical.Marshal(event)
	if err != nil {
		return "", err
	}
	return envelope.Digest(raw), nil
}

// Sign replaces signatures with one signature from private. Threshold assembly
// can combine independently reviewed signatures before publication.
func Sign(event Event, private identity.Private) (Event, error) {
	pairRaw, err := canonical.Marshal(private)
	if err != nil {
		return Event{}, err
	}
	pair, err := identity.ParsePrivate(pairRaw)
	if err != nil {
		return Event{}, err
	}
	if err := event.validate(false); err != nil {
		return Event{}, err
	}
	sig, err := envelope.Sign(SigningDomain, unsigned(event), pair.Private)
	if err != nil {
		return Event{}, err
	}
	remaining := make([]identity.Signature, 0, len(event.Signatures)+1)
	for _, existing := range event.Signatures {
		if existing.KeyID != sig.KeyID {
			remaining = append(remaining, existing)
		}
	}
	event.Signatures = append(remaining, sig)
	sort.Slice(event.Signatures, func(left, right int) bool { return event.Signatures[left].KeyID < event.Signatures[right].KeyID })
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	return event, nil
}

// Verify checks threshold distinct signatures against explicitly trusted keys.
func Verify(event Event, trusted []identity.Public, threshold int, now time.Time) (Verification, error) {
	if err := event.Validate(); err != nil {
		return Verification{}, err
	}
	if threshold < 1 || threshold > len(trusted) {
		return Verification{}, errors.New("signature threshold is invalid")
	}
	issued, _ := envelope.ParseTimestamp(event.IssuedAt)
	expires, _ := envelope.ParseTimestamp(event.ExpiresAt)
	if !now.IsZero() && (now.UTC().Before(issued) || now.UTC().After(expires)) {
		return Verification{}, errors.New("event config is outside its validity window")
	}
	trustedByID := map[string]identity.Public{}
	for _, key := range trusted {
		if err := key.Validate(); err != nil {
			return Verification{}, err
		}
		trustedByID[key.KeyID] = key
	}
	valid := make([]string, 0, len(event.Signatures))
	seen := map[string]struct{}{}
	for _, sig := range event.Signatures {
		key, ok := trustedByID[sig.KeyID]
		if !ok {
			continue
		}
		if _, dup := seen[sig.KeyID]; dup {
			continue
		}
		if envelope.Verify(SigningDomain, unsigned(event), sig, key) == nil {
			seen[sig.KeyID] = struct{}{}
			valid = append(valid, sig.KeyID)
		}
	}
	if len(valid) < threshold {
		return Verification{}, fmt.Errorf("got %d valid trusted signatures, require %d", len(valid), threshold)
	}
	sort.Strings(valid)
	digest, err := Digest(event)
	if err != nil {
		return Verification{}, err
	}
	return Verification{Digest: digest, ValidKeyIDs: valid, Required: threshold}, nil
}

func MarshalYAML(event Event) ([]byte, error) {
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return yaml.Marshal(event)
}

func unsigned(e Event) unsignedEvent {
	return unsignedEvent{e.Kind, e.Protocol, e.ProtocolVersion, e.EventID, e.EventEpoch, e.BaseRepository, e.ConfigEpoch, e.DelegationEpoch, e.PreviousConfigDigest, e.DelegationDigest, e.IssuedAt, e.ExpiresAt, e.InitialState, e.Registration, e.Teams, e.Submissions, e.Scoring, e.State, e.Receipts}
}

func inspectYAML(node *yaml.Node, depth int) error {
	if depth > maxYAMLDepth {
		return errors.New("event YAML nesting exceeds limit")
	}
	if node.Kind == yaml.AliasNode {
		return errors.New("YAML aliases are not allowed")
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]struct{}{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode {
				return errors.New("YAML mapping keys must be scalars")
			}
			if key.Value == "<<" {
				return errors.New("YAML merge keys are not allowed")
			}
			if _, ok := seen[key.Value]; ok {
				return fmt.Errorf("duplicate YAML key %q", key.Value)
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := inspectYAML(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func validateInitialState(v InitialState) error {
	if v.Phase != "draft" || v.Enabled || v.DisabledReason != "template_not_bootstrapped" {
		return errors.New("initial_state must be draft, disabled, and template_not_bootstrapped")
	}
	return nil
}
func validateRegistration(v Registration) error {
	if v.MaximumParticipants < 1 || v.MaximumParticipants > identity.MaxRegistryEntries || v.RequestTTLSeconds < 60 || v.RequestTTLSeconds > 86400 || !envelope.IsDigest(v.TermsDigest) || v.KeyAlgorithm != identity.Algorithm || v.KeyRotationPolicy != "unsupported" {
		return errors.New("registration configuration is invalid")
	}
	return nil
}
func validateTeams(v Teams) error {
	if v.MinimumSize < 1 || v.MaximumSize < 1 || v.MinimumSize > v.MaximumSize || v.MaximumSize > 64 || v.MaximumProposalsPerParticipant < 1 || v.MaximumProposalsPerParticipant > MaxTeamProposalsPerParticipantV1 || v.ProposalTTLSeconds < team.MinProposalTTLSeconds || v.ProposalTTLSeconds > team.MaxProposalTTLSeconds || v.MembershipLockPhase != "submissions_open" {
		return errors.New("team configuration is invalid")
	}
	return nil
}
func validateSubmissions(v Submissions) error {
	if envelope.ValidateRef(v.BaseRef) != nil || v.MaximumAttemptsPerTeam < 1 || v.MaximumAttemptsPerTeam > MaxTotalSubmissionAttemptsV1 || v.MaximumTotalAttempts < 1 || v.MaximumTotalAttempts > MaxTotalSubmissionAttemptsV1 || v.MaximumAttemptsPerTeam > v.MaximumTotalAttempts || v.MaximumCiphertextBytes < 1 || v.MaximumCiphertextBytes > maxSubmissionCiphertextBytes || v.MaximumPlaintextBytes < 1 || v.MaximumPlaintextBytes > maxSubmissionPlaintextBytes || v.MaximumCiphertextBytes < v.MaximumPlaintextBytes+4*1024*1024 || v.MaximumFileBytes < 1 || v.MaximumFileBytes > maxSubmissionFileBytes || v.MaximumFileBytes > v.MaximumPlaintextBytes || v.MaximumPlaintextFiles < 1 || v.MaximumPlaintextFiles > envelope.MaxSubmissionFilesV1 || v.EnvelopeTTLSeconds < 60 || v.EnvelopeTTLSeconds > 86400 || v.DeliveryMode != envelope.SubmissionDeliveryMode || !v.FailedConsumeQuota {
		return errors.New("submission configuration is invalid")
	}
	if len(v.AllowedExtensions) < 1 || len(v.AllowedExtensions) > 64 {
		return errors.New("allowed_extensions count is invalid")
	}
	seen := map[string]struct{}{}
	for index, ext := range v.AllowedExtensions {
		if !extensionPattern.MatchString(ext) {
			return errors.New("allowed extension is invalid")
		}
		if _, ok := seen[ext]; ok {
			return errors.New("duplicate allowed extension")
		}
		seen[ext] = struct{}{}
		if index > 0 && v.AllowedExtensions[index-1] >= ext {
			return errors.New("allowed_extensions must be strictly sorted")
		}
	}
	if v.Encryption.Algorithm != "age-hybrid-mlkem768-x25519" || identity.ValidateDecimal(v.Encryption.RecipientEpoch, "recipient_epoch") != nil || len(v.Encryption.Recipients) < 1 || len(v.Encryption.Recipients) > 16 {
		return errors.New("encryption configuration is invalid")
	}
	recipientSeen := map[string]struct{}{}
	publicKeySeen := map[string]struct{}{}
	for index, r := range v.Encryption.Recipients {
		parsedRecipient, parseErr := age.ParseHybridRecipient(r.PublicKey)
		if !recipientIDPattern.MatchString(r.RecipientID) || parseErr != nil || parsedRecipient.String() != r.PublicKey {
			return errors.New("encryption recipient is invalid")
		}
		if _, ok := recipientSeen[r.RecipientID]; ok {
			return errors.New("duplicate recipient_id")
		}
		recipientSeen[r.RecipientID] = struct{}{}
		if _, ok := publicKeySeen[r.PublicKey]; ok {
			return errors.New("duplicate recipient public_key")
		}
		publicKeySeen[r.PublicKey] = struct{}{}
		if index > 0 && v.Encryption.Recipients[index-1].RecipientID >= r.RecipientID {
			return errors.New("recipients must be strictly sorted by recipient_id")
		}
	}
	return nil
}

// DeriveCapacity calculates the v1 protected-state capacity bound with
// checked uint64 arithmetic. Callers may use the result only after the three
// policy sections have passed their ordinary field validation.
func DeriveCapacity(registration Registration, teams Teams, submissions Submissions) (DerivedCapacity, error) {
	np, err := checkedMultiply(registration.MaximumParticipants, teams.MaximumProposalsPerParticipant)
	if err != nil {
		return DerivedCapacity{}, err
	}
	npm, err := checkedMultiply(np, teams.MaximumSize)
	if err != nil {
		return DerivedCapacity{}, err
	}
	twiceAttempts, err := checkedMultiply(2, submissions.MaximumTotalAttempts)
	if err != nil {
		return DerivedCapacity{}, err
	}
	business, err := checkedSum(registration.MaximumParticipants, np, npm, twiceAttempts)
	if err != nil {
		return DerivedCapacity{}, err
	}
	if business > MaxDerivedBusinessRecordsV1 {
		return DerivedCapacity{}, fmt.Errorf("derived business record capacity %d exceeds v1 limit %d", business, MaxDerivedBusinessRecordsV1)
	}
	twiceBusiness, err := checkedMultiply(2, business)
	if err != nil {
		return DerivedCapacity{}, err
	}
	stateRecords, err := checkedSum(1, twiceBusiness, 6, 32)
	if err != nil {
		return DerivedCapacity{}, err
	}
	if stateRecords > MaxDerivedStateRecordsV1 {
		return DerivedCapacity{}, fmt.Errorf("derived state record capacity %d exceeds v1 limit %d", stateRecords, MaxDerivedStateRecordsV1)
	}
	return DerivedCapacity{BusinessRecords: business, StateRecords: stateRecords}, nil
}

func checkedMultiply(left, right uint64) (uint64, error) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, errors.New("derived capacity arithmetic overflow")
	}
	return left * right, nil
}

func checkedSum(values ...uint64) (uint64, error) {
	var total uint64
	for _, value := range values {
		if value > math.MaxUint64-total {
			return 0, errors.New("derived capacity arithmetic overflow")
		}
		total += value
	}
	return total, nil
}
func validateScoring(v Scoring) error {
	if v.Mode != "public_data" && v.Mode != "external_judge" {
		return errors.New("scoring mode is invalid")
	}
	if !idPattern.MatchString(v.ScorerID) || len(v.ScorerVersion) > 64 || !semverPattern.MatchString(v.ScorerVersion) || !envelope.IsDigest(v.PolicyDigest) || v.MaximumResultBytes < scorer.MinResultBytes || v.MaximumResultBytes > scorer.MaxResultBytes {
		return errors.New("scoring configuration is invalid")
	}
	if err := v.ResultKey.Validate(); err != nil {
		return fmt.Errorf("scoring result key: %w", err)
	}
	if v.Mode == "external_judge" {
		if v.ExternalJudgeURL == nil {
			return errors.New("external judge URL is required")
		}
		if len(*v.ExternalJudgeURL) > MaxExternalJudgeURLBytes {
			return fmt.Errorf("external judge URL exceeds %d-byte limit", MaxExternalJudgeURLBytes)
		}
		if !rfc3986ASCIIPattern.MatchString(*v.ExternalJudgeURL) {
			return errors.New("external judge URL must contain only printable ASCII RFC3986 characters; Unicode must be percent-encoded")
		}
		parsed, err := url.Parse(*v.ExternalJudgeURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.Opaque != "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" || parsed.RawQuery != "" || parsed.ForceQuery {
			return errors.New("external judge URL must be an absolute HTTPS endpoint without credentials, query, or fragment")
		}
	} else if v.ExternalJudgeURL != nil {
		return errors.New("public_data scoring requires null external_judge_url")
	}
	return nil
}
func validateProtocolSignature(v identity.Signature) error {
	if v.Algorithm != identity.Algorithm || !envelope.IsDigest(v.KeyID) || !base64SignaturePattern.MatchString(v.Value) {
		return errors.New("protocol signature is malformed")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(v.Value)
	if err != nil || len(decoded) != 64 {
		return errors.New("protocol signature encoding is invalid")
	}
	return nil
}
