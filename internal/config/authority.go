package config

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
	"github.com/pythonhk/eventctl/internal/statepointer"
)

var stateReasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)

type Authority struct {
	Threshold int               `json:"threshold"`
	Keys      []identity.Public `json:"keys"`
}

type Writer struct {
	AppSlug        string `json:"app_slug"`
	InstallationID string `json:"installation_id"`
	Provenance     string `json:"provenance"`
}

// Genesis is the complete protected state genesis document accepted by
// --authority. Accepting the whole object prevents helpers from accidentally
// dropping event/repository/delegation bindings while extracting keys.
type Genesis struct {
	SchemaVersion                      int             `json:"schema_version"`
	EventID                            string          `json:"event_id"`
	EventEpoch                         string          `json:"event_epoch"`
	BaseRepositoryID                   string          `json:"base_repository_id"`
	ConfigDigest                       string          `json:"config_digest"`
	GenesisDelegationDigest            string          `json:"genesis_delegation_digest"`
	ConfigDelegationValidFrom          string          `json:"config_delegation_valid_from"`
	ConfigDelegationExpiresAt          string          `json:"config_delegation_expires_at"`
	ConfigAuthority                    Authority       `json:"config_authority"`
	ReceiptAuthority                   identity.Public `json:"receipt_authority"`
	CreatedAt                          string          `json:"created_at"`
	OperationID                        string          `json:"operation_id"`
	OrganizerActorID                   string          `json:"organizer_actor_id"`
	TeamMinimumSize                    uint64          `json:"team_minimum_size"`
	TeamMaximumSize                    uint64          `json:"team_maximum_size"`
	TeamMaximumProposalsPerParticipant uint64          `json:"team_maximum_proposals_per_participant"`
	SubmissionQuota                    uint64          `json:"submission_quota"`
	SubmissionMaximumTotalAttempts     uint64          `json:"submission_maximum_total_attempts"`
	Writer                             Writer          `json:"writer"`
}

type StateMeta struct {
	Kind                  string          `json:"kind"`
	Protocol              string          `json:"protocol"`
	ProtocolVersion       int             `json:"protocol_version"`
	EventID               string          `json:"event_id"`
	EventEpoch            string          `json:"event_epoch"`
	BaseRepositoryID      string          `json:"base_repository_id"`
	ConfigDigest          string          `json:"config_digest"`
	ConfigAuthorityDigest string          `json:"config_authority_digest"`
	ReceiptAuthority      identity.Public `json:"receipt_authority"`
	Sequence              uint64          `json:"sequence"`
	JournalEventDigest    string          `json:"journal_event_digest"`
	LifecyclePhase        string          `json:"lifecycle_phase"`
	Enabled               bool            `json:"enabled"`
	DisabledReason        *string         `json:"disabled_reason"`
}

func ParseAuthority(raw []byte) (Genesis, error) {
	if len(raw) > MaxBytes {
		return Genesis{}, errors.New("authority document exceeds 1 MiB")
	}
	var genesis Genesis
	if err := canonical.StrictUnmarshal(raw, &genesis); err != nil {
		return Genesis{}, fmt.Errorf("decode protected genesis authority: %w", err)
	}
	if err := genesis.Validate(); err != nil {
		return Genesis{}, err
	}
	return genesis, nil
}

func ParseStateMeta(raw []byte) (StateMeta, error) {
	if len(raw) > MaxBytes {
		return StateMeta{}, errors.New("state metadata exceeds 1 MiB")
	}
	var meta StateMeta
	if err := canonical.StrictUnmarshal(raw, &meta); err != nil {
		return StateMeta{}, fmt.Errorf("decode protected state metadata: %w", err)
	}
	if err := meta.Validate(); err != nil {
		return StateMeta{}, err
	}
	return meta, nil
}

func (meta StateMeta) Validate() error {
	if meta.Kind != "state_meta_view" || meta.Protocol != envelope.Protocol || meta.ProtocolVersion != envelope.ProtocolVersion || !envelope.IsEventID(meta.EventID) || meta.EventEpoch != "1" || envelope.ValidateRepositoryID(meta.BaseRepositoryID) != nil || !envelope.IsDigest(meta.ConfigDigest) || !envelope.IsDigest(meta.ConfigAuthorityDigest) || meta.ReceiptAuthority.Validate() != nil || meta.Sequence < 1 || meta.Sequence > statepointer.MaxSequenceV1 || !envelope.IsDigest(meta.JournalEventDigest) {
		return errors.New("protected state metadata binding is invalid")
	}
	phases := map[string]bool{"draft": true, "registration_open": true, "formation_open": true, "submissions_open": true, "frozen": true, "closed": true, "archived": true}
	if !phases[meta.LifecyclePhase] {
		return errors.New("state lifecycle phase is invalid")
	}
	if meta.Enabled && meta.DisabledReason != nil {
		return errors.New("enabled state must have null disabled_reason")
	}
	if !meta.Enabled && (meta.DisabledReason == nil || !stateReasonPattern.MatchString(*meta.DisabledReason)) {
		return errors.New("disabled state requires a reason code")
	}
	return nil
}

func (g Genesis) Validate() error {
	if g.SchemaVersion != 1 || !envelope.IsEventID(g.EventID) || g.EventEpoch != "1" || envelope.ValidateRepositoryID(g.BaseRepositoryID) != nil {
		return errors.New("genesis protocol/event/repository binding is invalid")
	}
	if !envelope.IsDigest(g.ConfigDigest) || !envelope.IsDigest(g.GenesisDelegationDigest) {
		return errors.New("genesis config/delegation digest is invalid")
	}
	delegationValidFrom, err := envelope.ParseTimestamp(g.ConfigDelegationValidFrom)
	if err != nil {
		return fmt.Errorf("config delegation valid_from: %w", err)
	}
	delegationExpiresAt, err := envelope.ParseTimestamp(g.ConfigDelegationExpiresAt)
	if err != nil || !delegationExpiresAt.After(delegationValidFrom) {
		return errors.New("config delegation validity window is invalid")
	}
	if _, err := envelope.ParseTimestamp(g.CreatedAt); err != nil {
		return err
	}
	if !envelope.IsUUID(g.OperationID) || identity.ValidateDecimal(g.OrganizerActorID, "organizer_actor_id") != nil {
		return errors.New("genesis operation metadata is invalid")
	}
	if g.TeamMinimumSize < 1 || g.TeamMaximumSize < g.TeamMinimumSize || g.TeamMaximumSize > 64 || g.TeamMaximumProposalsPerParticipant < 1 || g.TeamMaximumProposalsPerParticipant > MaxTeamProposalsPerParticipantV1 || g.SubmissionQuota < 1 || g.SubmissionQuota > MaxTotalSubmissionAttemptsV1 || g.SubmissionMaximumTotalAttempts < 1 || g.SubmissionMaximumTotalAttempts > MaxTotalSubmissionAttemptsV1 || g.SubmissionQuota > g.SubmissionMaximumTotalAttempts {
		return errors.New("genesis team/quota policy is invalid")
	}
	if !appSlugPattern.MatchString(g.Writer.AppSlug) || identity.ValidateDecimal(g.Writer.InstallationID, "installation_id") != nil || g.Writer.Provenance != "local_bootstrap" {
		return errors.New("genesis writer identity is invalid")
	}
	if g.ConfigAuthority.Threshold < 1 || g.ConfigAuthority.Threshold > 16 || len(g.ConfigAuthority.Keys) < g.ConfigAuthority.Threshold || len(g.ConfigAuthority.Keys) > 16 {
		return errors.New("genesis config authority threshold/key count is invalid")
	}
	for index, key := range g.ConfigAuthority.Keys {
		if err := key.Validate(); err != nil {
			return fmt.Errorf("authority key %d: %w", index, err)
		}
		if index > 0 && g.ConfigAuthority.Keys[index-1].KeyID >= key.KeyID {
			return errors.New("authority keys must be strictly sorted by key_id")
		}
	}
	if err := g.ReceiptAuthority.Validate(); err != nil {
		return fmt.Errorf("receipt authority: %w", err)
	}
	return nil
}

// VerifyWithAuthority binds config verification to the complete protected
// genesis authority. Genesis config epoch 1 is additionally digest-pinned.
func VerifyWithAuthority(event Event, genesis Genesis, now time.Time) (Verification, error) {
	if err := genesis.Validate(); err != nil {
		return Verification{}, err
	}
	if event.EventID != genesis.EventID || event.EventEpoch != genesis.EventEpoch || event.BaseRepository.ID != genesis.BaseRepositoryID || event.DelegationEpoch != 1 || event.DelegationDigest != genesis.GenesisDelegationDigest || event.Receipts.SigningKey != genesis.ReceiptAuthority || event.Teams.MinimumSize != genesis.TeamMinimumSize || event.Teams.MaximumSize != genesis.TeamMaximumSize || event.Teams.MaximumProposalsPerParticipant != genesis.TeamMaximumProposalsPerParticipant || event.Submissions.MaximumAttemptsPerTeam != genesis.SubmissionQuota || event.Submissions.MaximumTotalAttempts != genesis.SubmissionMaximumTotalAttempts {
		return Verification{}, errors.New("event config does not match protected genesis authority")
	}
	delegationValidFrom, _ := envelope.ParseTimestamp(genesis.ConfigDelegationValidFrom)
	delegationExpiresAt, _ := envelope.ParseTimestamp(genesis.ConfigDelegationExpiresAt)
	if !now.IsZero() && (now.UTC().Before(delegationValidFrom) || now.UTC().After(delegationExpiresAt)) {
		return Verification{}, errors.New("config delegation is outside its protected validity window")
	}
	verification, err := Verify(event, genesis.ConfigAuthority.Keys, genesis.ConfigAuthority.Threshold, now)
	if err != nil {
		return Verification{}, err
	}
	if verification.Digest != genesis.ConfigDigest {
		return Verification{}, errors.New("genesis config digest does not match protected state")
	}
	return verification, nil
}

// VerifyAdoptedConfig additionally proves the config digest and trust bindings
// are adopted by the protected current-state view fetched at one immutable ref.
func VerifyAdoptedConfig(event Event, genesis Genesis, meta StateMeta, now time.Time) (Verification, error) {
	verification, err := VerifyArchivedConfig(event, genesis, meta, now)
	if err != nil {
		return Verification{}, err
	}
	if verification.Digest != meta.ConfigDigest {
		return Verification{}, errors.New("event config is not the config adopted by protected current state")
	}
	return verification, nil
}

// VerifyArchivedConfig authenticates a historical signed config at the trusted
// immutable GitHub source creation time while using current state only to confirm the same immutable
// event/repository authorities. It intentionally does not require the
// historical digest to equal the currently adopted config digest.
func VerifyArchivedConfig(event Event, genesis Genesis, meta StateMeta, sourceCreatedAt time.Time) (Verification, error) {
	if err := VerifyAuthorityState(genesis, meta); err != nil {
		return Verification{}, err
	}
	verification, err := VerifyWithAuthority(event, genesis, sourceCreatedAt)
	if err != nil {
		return Verification{}, err
	}
	if event.EventID != meta.EventID || event.EventEpoch != meta.EventEpoch || event.BaseRepository.ID != meta.BaseRepositoryID || meta.ConfigAuthorityDigest != event.DelegationDigest || meta.ReceiptAuthority != event.Receipts.SigningKey {
		return Verification{}, errors.New("archived event config does not match protected event authorities")
	}
	return verification, nil
}

// VerifyAuthorityState binds current metadata to the complete protected
// genesis without consulting a mutable configuration file.
func VerifyAuthorityState(genesis Genesis, meta StateMeta) error {
	if err := genesis.Validate(); err != nil {
		return err
	}
	if err := meta.Validate(); err != nil {
		return err
	}
	if genesis.EventID != meta.EventID || genesis.EventEpoch != meta.EventEpoch || genesis.BaseRepositoryID != meta.BaseRepositoryID || meta.ConfigDigest != genesis.ConfigDigest || meta.ConfigAuthorityDigest != genesis.GenesisDelegationDigest || meta.ReceiptAuthority != genesis.ReceiptAuthority {
		return errors.New("protected current state does not match genesis authorities")
	}
	return nil
}
