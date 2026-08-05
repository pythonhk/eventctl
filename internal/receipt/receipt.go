// Package receipt parses and verifies signed receipts for committed event
// operations. It intentionally exposes no receipt-construction API: the state
// writer first commits an operation, and only the dedicated receipt signer may
// turn that committed record into a receipt.
package receipt

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

const (
	Kind                  = "operation_receipt"
	Domain                = "operation_receipt"
	CancellationKind      = "submission_cancellation"
	CancellationOperation = "submission.cancel"
	MaxSignedBytes        = 1_682
	MaxPaddedBase64Chars  = 2_244
	MaxSignedBytesWithLF  = MaxSignedBytes + 1
)

var reasonCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)

type cancellationRequest struct {
	AttemptID                string `json:"attempt_id"`
	ReservationReceiptDigest string `json:"reservation_receipt_digest"`
	ReasonCode               string `json:"reason_code"`
}

// Receipt is the complete signed v1 committed-operation receipt.
type Receipt struct {
	Kind                     string               `json:"kind"`
	Protocol                 string               `json:"protocol"`
	ProtocolVersion          int                  `json:"protocol_version"`
	EventID                  string               `json:"event_id"`
	EventEpoch               string               `json:"event_epoch"`
	BaseRepositoryID         string               `json:"base_repository_id"`
	ConfigDigest             string               `json:"config_digest"`
	ReceiptID                string               `json:"receipt_id"`
	OperationID              string               `json:"operation_id"`
	RequestKind              string               `json:"request_kind"`
	ReplayKey                string               `json:"replay_key"`
	RequestDigest            string               `json:"request_digest"`
	RequestDocumentDigest    *string              `json:"request_document_digest"`
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
	Signature                identity.Signature   `json:"signature"`
}

type unsignedReceipt struct {
	Kind                     string               `json:"kind"`
	Protocol                 string               `json:"protocol"`
	ProtocolVersion          int                  `json:"protocol_version"`
	EventID                  string               `json:"event_id"`
	EventEpoch               string               `json:"event_epoch"`
	BaseRepositoryID         string               `json:"base_repository_id"`
	ConfigDigest             string               `json:"config_digest"`
	ReceiptID                string               `json:"receipt_id"`
	OperationID              string               `json:"operation_id"`
	RequestKind              string               `json:"request_kind"`
	ReplayKey                string               `json:"replay_key"`
	RequestDigest            string               `json:"request_digest"`
	RequestDocumentDigest    *string              `json:"request_document_digest"`
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

// Expected is independently trusted context for receipt verification.
type Expected struct {
	EventID          string
	EventEpoch       string
	BaseRepositoryID string
	ConfigDigest     string
	SigningKey       identity.Public
	CurrentState     statepointer.Pointer
	Now              time.Time
}

// Verified contains the authenticated document and its complete canonical
// document digest. All outcome data remains inside Document and is signed.
type Verified struct {
	Document       Receipt
	DocumentDigest string
}

// Parse strictly decodes one bounded receipt without authenticating it.
func Parse(raw []byte) (Receipt, error) {
	documentBytes, err := boundedSignedDocument(raw)
	if err != nil {
		return Receipt{}, err
	}
	var document Receipt
	if err := canonical.StrictUnmarshal(documentBytes, &document); err != nil {
		return Receipt{}, fmt.Errorf("decode receipt: %w", err)
	}
	if err := document.Validate(); err != nil {
		return Receipt{}, err
	}
	return document, nil
}

// boundedSignedDocument treats one terminal LF as file framing outside the
// signed-document limit. This lets CLI output remain POSIX text while keeping
// the canonical signed JSON bounded to MaxSignedBytes.
func boundedSignedDocument(raw []byte) ([]byte, error) {
	if len(raw) <= MaxSignedBytes {
		return raw, nil
	}
	if len(raw) == MaxSignedBytesWithLF && raw[MaxSignedBytes] == '\n' {
		return raw[:MaxSignedBytes], nil
	}
	return nil, fmt.Errorf("signed receipt exceeds %d-byte document limit", MaxSignedBytes)
}

// Verify authenticates a strict receipt with the exact configured receipt key
// and proves that its committed state-after pointer exactly matches the trusted
// protected-state head.
func Verify(raw []byte, expected Expected) (Verified, error) {
	document, err := Parse(raw)
	if err != nil {
		return Verified{}, err
	}
	if document.EventID != expected.EventID || document.EventEpoch != expected.EventEpoch || document.BaseRepositoryID != expected.BaseRepositoryID || document.ConfigDigest != expected.ConfigDigest {
		return Verified{}, errors.New("receipt event/repository/config binding does not match trusted config")
	}
	if err := expected.SigningKey.Validate(); err != nil {
		return Verified{}, fmt.Errorf("configured receipt key: %w", err)
	}
	if err := envelope.Verify(Domain, unsigned(document), document.Signature, expected.SigningKey); err != nil {
		return Verified{}, err
	}
	if err := expected.CurrentState.Validate(); err != nil {
		return Verified{}, fmt.Errorf("trusted current state: %w", err)
	}
	if !document.StateAfter.Equal(expected.CurrentState) {
		return Verified{}, errors.New("receipt committed state pointer does not exactly match trusted current state")
	}
	issuedAt, _ := envelope.ParseTimestamp(document.IssuedAt)
	if !expected.Now.IsZero() && issuedAt.After(expected.Now.UTC().Add(5*time.Minute)) {
		return Verified{}, errors.New("receipt issued_at is implausibly in the future")
	}
	digest, err := envelope.DocumentDigest(document)
	if err != nil {
		return Verified{}, err
	}
	return Verified{Document: document, DocumentDigest: digest}, nil
}

// Validate enforces the closed v1 receipt schema and committed-state shape.
func (document Receipt) Validate() error {
	if document.Kind != Kind || document.Protocol != envelope.Protocol || document.ProtocolVersion != envelope.ProtocolVersion {
		return errors.New("receipt protocol discriminator is invalid")
	}
	if !envelope.IsEventID(document.EventID) || identity.ValidateDecimal(document.EventEpoch, "event_epoch") != nil || envelope.ValidateRepositoryID(document.BaseRepositoryID) != nil || !envelope.IsDigest(document.ConfigDigest) || !envelope.IsUUID(document.ReceiptID) || !envelope.IsUUID(document.OperationID) {
		return errors.New("receipt event/operation identifier is invalid")
	}
	requestKinds := map[string]bool{
		envelope.RegistrationKind: true,
		"team_proposal":           true,
		"team_consent":            true,
		envelope.SubmissionKind:   true,
		"scorer_result":           true,
		CancellationKind:          true,
	}
	if !requestKinds[document.RequestKind] || !envelope.IsDigest(document.ReplayKey) || !envelope.IsDigest(document.RequestDigest) {
		return errors.New("receipt request binding is invalid")
	}
	if document.RequestDocumentDigest != nil && !envelope.IsDigest(*document.RequestDocumentDigest) {
		return errors.New("receipt request document digest is invalid")
	}
	if err := identity.ValidateDecimal(document.ActorID, "actor_id"); err != nil {
		return err
	}
	if document.TeamID != nil && !envelope.IsUUID(*document.TeamID) {
		return errors.New("receipt team_id is invalid")
	}
	if document.AttemptID != nil && !envelope.IsUUID(*document.AttemptID) {
		return errors.New("receipt attempt_id is invalid")
	}
	if document.Outcome != "accepted" && document.Outcome != "failed" {
		return errors.New("receipt outcome is invalid")
	}
	if document.Outcome == "accepted" && document.ReasonCode != nil {
		return errors.New("accepted receipt must have null reason_code")
	}
	if document.Outcome == "failed" && (document.ReasonCode == nil || !reasonCodePattern.MatchString(*document.ReasonCode)) {
		return errors.New("failed receipt requires a bounded reason_code")
	}
	if err := document.StateBefore.Validate(); err != nil {
		return fmt.Errorf("state_before: %w", err)
	}
	if err := document.StateAfter.Validate(); err != nil {
		return fmt.Errorf("state_after: %w", err)
	}
	if document.StateBefore.Sequence == ^uint64(0) || document.StateAfter.Sequence != document.StateBefore.Sequence+1 {
		return errors.New("committed receipt state_after must immediately follow state_before")
	}
	if document.ScorerResultDigest != nil && !envelope.IsDigest(*document.ScorerResultDigest) {
		return errors.New("receipt scorer_result_digest is invalid")
	}
	if document.ReservationReceiptDigest != nil && !envelope.IsDigest(*document.ReservationReceiptDigest) {
		return errors.New("receipt reservation_receipt_digest is invalid")
	}
	switch document.RequestKind {
	case "scorer_result":
		if document.RequestDocumentDigest == nil || document.TeamID == nil || document.AttemptID == nil || document.QuotaCharged || document.ScorerResultDigest == nil || *document.ScorerResultDigest != *document.RequestDocumentDigest || document.ReservationReceiptDigest == nil {
			return errors.New("scorer result receipt must bind result and reservation receipt digests")
		}
		if document.Outcome != "accepted" && document.Outcome != "failed" {
			return errors.New("scorer result receipt outcome is invalid")
		}
	case CancellationKind:
		if document.RequestDocumentDigest != nil || document.TeamID == nil || document.AttemptID == nil || document.Outcome != "failed" || document.QuotaCharged || document.ScorerResultDigest != nil || document.ReservationReceiptDigest == nil {
			return errors.New("submission cancellation receipt must bind a failed reserved attempt without a request document")
		}
		requestDigest, err := cancellationRequestDigest(*document.AttemptID, *document.ReservationReceiptDigest, *document.ReasonCode)
		if err != nil {
			return err
		}
		if document.RequestDigest != requestDigest {
			return errors.New("submission cancellation request_digest does not bind the canonical cancellation request")
		}
	default:
		if document.RequestDocumentDigest == nil {
			return errors.New("non-cancellation receipt requires request_document_digest")
		}
		if document.ScorerResultDigest != nil || document.ReservationReceiptDigest != nil {
			return errors.New("non-scorer receipt must have null scorer/reservation receipt digests")
		}
		if document.Outcome == "failed" {
			return errors.New("only a committed scorer result may have failed outcome")
		}
		if document.RequestKind == envelope.SubmissionKind {
			if document.TeamID == nil || document.AttemptID == nil || !document.QuotaCharged {
				return errors.New("submission reservation receipt requires team, attempt, and quota charge")
			}
		} else {
			if document.QuotaCharged {
				return errors.New("non-submission receipt must not charge quota")
			}
			switch document.RequestKind {
			case envelope.RegistrationKind:
				if document.TeamID != nil || document.AttemptID != nil {
					return errors.New("registration receipt must not carry team or attempt IDs")
				}
			case "team_proposal", "team_consent":
				if document.TeamID == nil || document.AttemptID != nil {
					return errors.New("team receipt requires team_id and no attempt_id")
				}
			}
		}
	}
	sourceCreatedAt, err := envelope.ParseTimestamp(document.SourceCreatedAt)
	if err != nil {
		return err
	}
	issuedAt, err := envelope.ParseTimestamp(document.IssuedAt)
	if err != nil {
		return err
	}
	if sourceCreatedAt.After(issuedAt) {
		return errors.New("receipt source_created_at must not follow committed issued_at")
	}
	if document.RequestKind == CancellationKind && !sourceCreatedAt.Equal(issuedAt) {
		return errors.New("submission cancellation source_created_at must equal committed issued_at")
	}
	if document.Signature.Algorithm != identity.Algorithm || !envelope.IsDigest(document.Signature.KeyID) {
		return errors.New("receipt signature metadata is invalid")
	}
	return nil
}

func cancellationRequestDigest(attemptID, reservationReceiptDigest, reasonCode string) (string, error) {
	raw, err := canonical.Marshal(cancellationRequest{
		AttemptID: attemptID, ReservationReceiptDigest: reservationReceiptDigest, ReasonCode: reasonCode,
	})
	if err != nil {
		return "", fmt.Errorf("encode canonical submission cancellation request: %w", err)
	}
	return envelope.Digest(raw), nil
}

func unsigned(document Receipt) unsignedReceipt {
	return unsignedReceipt{
		document.Kind, document.Protocol, document.ProtocolVersion, document.EventID,
		document.EventEpoch, document.BaseRepositoryID, document.ConfigDigest,
		document.ReceiptID, document.OperationID, document.RequestKind,
		document.ReplayKey, document.RequestDigest, document.RequestDocumentDigest,
		document.ActorID, document.TeamID, document.AttemptID,
		document.Outcome, document.ReasonCode, document.QuotaCharged, document.StateBefore,
		document.StateAfter, document.ScorerResultDigest, document.ReservationReceiptDigest,
		document.SourceCreatedAt, document.IssuedAt,
	}
}

// ValidateSourceWindow proves that the trusted immutable GitHub source time
// fell within the original participant-signed request window. It is timeless:
// current wall-clock time is deliberately irrelevant to archival verification.
func (document Receipt) ValidateSourceWindow(issuedAt, expiresAt string) error {
	issued, err := envelope.ParseTimestamp(issuedAt)
	if err != nil {
		return err
	}
	expires, err := envelope.ParseTimestamp(expiresAt)
	if err != nil || !expires.After(issued) {
		return errors.New("original request window is invalid")
	}
	source, err := envelope.ParseTimestamp(document.SourceCreatedAt)
	if err != nil {
		return err
	}
	if source.Before(issued) || source.After(expires) {
		return errors.New("receipt source_created_at is outside original request window")
	}
	return nil
}
