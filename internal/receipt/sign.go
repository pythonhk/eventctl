package receipt

import (
	"errors"
	"fmt"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
	"github.com/pythonhk/eventctl/internal/statepointer"
)

const ClaimKind = "committed_operation_receipt_claim"

// CommittedClaim is the narrow, deterministic handoff from a successful
// protected-state CAS commit to the isolated receipt signer. issued_at is the
// committed journal event's recorded_at, never signer wall-clock time.
type CommittedClaim struct {
	Kind                     string               `json:"kind"`
	Protocol                 string               `json:"protocol"`
	ProtocolVersion          int                  `json:"protocol_version"`
	EventID                  string               `json:"event_id"`
	EventEpoch               string               `json:"event_epoch"`
	BaseRepositoryID         string               `json:"base_repository_id"`
	ConfigDigest             string               `json:"config_digest"`
	CommitStatus             string               `json:"commit_status"`
	Operation                string               `json:"operation"`
	ReceiptID                string               `json:"receipt_id"`
	OperationID              string               `json:"operation_id"`
	RequestKind              string               `json:"request_kind"`
	ReplayKey                string               `json:"replay_key"`
	RequestDigest            string               `json:"request_digest"`
	RequestDocumentDigest    string               `json:"request_document_digest"`
	ActorID                  string               `json:"actor_id"`
	TeamID                   *string              `json:"team_id"`
	AttemptID                *string              `json:"attempt_id"`
	Outcome                  string               `json:"outcome"`
	ReasonCode               *string              `json:"reason_code"`
	QuotaCharged             bool                 `json:"quota_charged"`
	StateBefore              statepointer.Pointer `json:"state_before"`
	StateAfter               statepointer.Pointer `json:"state_after"`
	ScorerResultDigest       *string              `json:"scorer_result_digest"`
	ReservationReceiptDigest *string              `json:"reservation_receipt_digest"`
	SourceCreatedAt          string               `json:"source_created_at"`
	IssuedAt                 string               `json:"issued_at"`
}

// SignExpected binds a committed claim to independently verified context.
type SignExpected struct {
	EventID          string
	EventEpoch       string
	BaseRepositoryID string
	ConfigDigest     string
	SigningKey       identity.Public
	CurrentState     statepointer.Pointer
}

// ParseCommittedClaim strictly decodes one bounded post-commit signer input.
func ParseCommittedClaim(raw []byte) (CommittedClaim, error) {
	if len(raw) > envelope.MaxDocumentBytes {
		return CommittedClaim{}, errors.New("committed receipt claim exceeds 1 MiB")
	}
	var claim CommittedClaim
	if err := canonical.StrictUnmarshal(raw, &claim); err != nil {
		return CommittedClaim{}, fmt.Errorf("decode committed receipt claim: %w", err)
	}
	if err := claim.Validate(); err != nil {
		return CommittedClaim{}, err
	}
	return claim, nil
}

// SignCommitted signs only a committed pending claim whose state-after pointer
// exactly matches the independently trusted protected-state head. The
// deterministic receipt_id and issued_at make retry bytes identical.
func SignCommitted(claim CommittedClaim, expected SignExpected, private identity.Private) (Receipt, error) {
	if err := claim.Validate(); err != nil {
		return Receipt{}, err
	}
	if claim.EventID != expected.EventID || claim.EventEpoch != expected.EventEpoch || claim.BaseRepositoryID != expected.BaseRepositoryID || claim.ConfigDigest != expected.ConfigDigest {
		return Receipt{}, errors.New("receipt claim does not match trusted event/config/repository")
	}
	if err := expected.CurrentState.Validate(); err != nil {
		return Receipt{}, fmt.Errorf("trusted current state: %w", err)
	}
	if !claim.StateAfter.Equal(expected.CurrentState) {
		return Receipt{}, errors.New("receipt claim committed state does not exactly match trusted current state")
	}
	_, pair, err := identity.SigningKey(private)
	if err != nil {
		return Receipt{}, err
	}
	if err := expected.SigningKey.Validate(); err != nil {
		return Receipt{}, fmt.Errorf("configured receipt key: %w", err)
	}
	if pair.Public != expected.SigningKey {
		return Receipt{}, errors.New("private receipt key does not match configured signing key")
	}
	document := Receipt{
		Kind: Kind, Protocol: envelope.Protocol, ProtocolVersion: envelope.ProtocolVersion,
		EventID: claim.EventID, EventEpoch: claim.EventEpoch,
		BaseRepositoryID: claim.BaseRepositoryID, ConfigDigest: claim.ConfigDigest,
		ReceiptID:   claim.ReceiptID,
		OperationID: claim.OperationID, RequestKind: claim.RequestKind,
		ReplayKey: claim.ReplayKey, RequestDigest: claim.RequestDigest,
		RequestDocumentDigest: claim.RequestDocumentDigest,
		ActorID:               claim.ActorID, TeamID: claim.TeamID,
		AttemptID: claim.AttemptID, Outcome: claim.Outcome, ReasonCode: claim.ReasonCode,
		QuotaCharged: claim.QuotaCharged, StateBefore: claim.StateBefore,
		StateAfter: claim.StateAfter, ScorerResultDigest: claim.ScorerResultDigest,
		ReservationReceiptDigest: claim.ReservationReceiptDigest,
		SourceCreatedAt:          claim.SourceCreatedAt,
		IssuedAt:                 claim.IssuedAt,
		Signature:                identity.Signature{Algorithm: identity.Algorithm, KeyID: pair.Public.KeyID},
	}
	if err := document.Validate(); err != nil {
		return Receipt{}, err
	}
	document.Signature, err = envelope.Sign(Domain, unsigned(document), private)
	if err != nil {
		return Receipt{}, err
	}
	raw, err := canonical.Marshal(document)
	if err != nil {
		return Receipt{}, err
	}
	if len(raw) > MaxSignedBytes {
		return Receipt{}, fmt.Errorf("signed receipt is %d bytes, limit is %d", len(raw), MaxSignedBytes)
	}
	return document, nil
}

// Validate enforces the closed post-commit signer input schema.
func (claim CommittedClaim) Validate() error {
	if claim.Kind != ClaimKind || claim.Protocol != envelope.Protocol || claim.ProtocolVersion != envelope.ProtocolVersion || claim.CommitStatus != "receipt_pending" {
		return errors.New("receipt claim protocol/commit discriminator is invalid")
	}
	if envelope.ValidateRepositoryID(claim.BaseRepositoryID) != nil || !envelope.IsDigest(claim.ConfigDigest) {
		return errors.New("receipt claim repository/config binding is invalid")
	}
	if claim.ReceiptID != claim.OperationID {
		return errors.New("v1 receipt_id must equal committed operation_id for deterministic retry")
	}
	operationKinds := map[string]string{
		"participant.register": "registration_request",
		"team.propose":         "team_proposal",
		"team.consent":         "team_consent",
		"submission.reserve":   "submission_envelope",
		"submission.finalize":  "scorer_result",
	}
	if operationKinds[claim.Operation] != claim.RequestKind {
		return errors.New("receipt claim operation/request_kind binding is invalid")
	}
	document := Receipt{
		Kind: Kind, Protocol: envelope.Protocol, ProtocolVersion: envelope.ProtocolVersion,
		EventID: claim.EventID, EventEpoch: claim.EventEpoch,
		BaseRepositoryID: claim.BaseRepositoryID, ConfigDigest: claim.ConfigDigest,
		ReceiptID:   claim.ReceiptID,
		OperationID: claim.OperationID, RequestKind: claim.RequestKind,
		ReplayKey: claim.ReplayKey, RequestDigest: claim.RequestDigest,
		RequestDocumentDigest: claim.RequestDocumentDigest,
		ActorID:               claim.ActorID, TeamID: claim.TeamID,
		AttemptID: claim.AttemptID, Outcome: claim.Outcome, ReasonCode: claim.ReasonCode,
		QuotaCharged: claim.QuotaCharged, StateBefore: claim.StateBefore,
		StateAfter: claim.StateAfter, ScorerResultDigest: claim.ScorerResultDigest,
		ReservationReceiptDigest: claim.ReservationReceiptDigest,
		SourceCreatedAt:          claim.SourceCreatedAt,
		IssuedAt:                 claim.IssuedAt,
		Signature:                identity.Signature{Algorithm: identity.Algorithm, KeyID: zeroDigest},
	}
	if err := document.Validate(); err != nil {
		return err
	}
	return nil
}

const zeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"
