// Package scorer defines and authenticates the strict v1 isolated-scorer wire
// artifacts. A scorer request is intentionally unsigned; its exact canonical
// bytes travel over the authenticated judge channel. The configured scorer key
// signs the result, which binds the complete request digest.
package scorer

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
	RequestKind                              = "scorer_request"
	ResultKind                               = "scorer_result"
	ResultDomain                             = "scorer_result"
	BundleMediaType                          = "application/vnd.pythonhk.eventctl-bundle.v1"
	Provenance                               = "protected_state_reservation"
	MaxRequestBytes                   uint64 = 16_384
	MinResultBytes                    uint64 = 256
	MaxResultBytes                    uint64 = 65_536
	MaxSynchronousResponseBytes              = 294_912
	MaxSynchronousResponseBase64Bytes        = 393_216
	maxSafeInteger                           = int64(9007199254740991)
	maxBundleBytes                           = uint64(48_000_000)
	maxCiphertextBytes                       = uint64(47_000_000)
)

var (
	idPattern         = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
	semverPattern     = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	metricNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)
	reasonCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
)

// Bundle binds the fixed encrypted submission artifact and all public digests.
type Bundle struct {
	Path             string `json:"path"`
	MediaType        string `json:"media_type"`
	SizeBytes        uint64 `json:"size_bytes"`
	SHA256           string `json:"sha256"`
	EnvelopeSHA256   string `json:"envelope_sha256"`
	CiphertextSize   uint64 `json:"ciphertext_size"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
}

// Identity names the exact configured scoring implementation and policy.
type Identity struct {
	ID           string `json:"id"`
	Version      string `json:"version"`
	PolicyDigest string `json:"policy_digest"`
}

// Request is the complete unsigned descriptor delivered through the
// authenticated judge channel after a protected-state reservation.
type Request struct {
	Kind                     string               `json:"kind"`
	Protocol                 string               `json:"protocol"`
	ProtocolVersion          int                  `json:"protocol_version"`
	EventID                  string               `json:"event_id"`
	EventEpoch               string               `json:"event_epoch"`
	AttemptID                string               `json:"attempt_id"`
	ActorID                  string               `json:"actor_id"`
	TeamID                   string               `json:"team_id"`
	TeamProposalDigest       string               `json:"team_proposal_digest"`
	ConfigDigest             string               `json:"config_digest"`
	SubmissionEnvelopeDigest string               `json:"submission_envelope_digest"`
	ReservationReceiptDigest string               `json:"reservation_receipt_digest"`
	Reservation              statepointer.Pointer `json:"reservation"`
	SourceCreatedAt          string               `json:"source_created_at"`
	AcceptedAt               string               `json:"accepted_at"`
	PullRequest              envelope.PullRequest `json:"pull_request"`
	Bundle                   Bundle               `json:"bundle"`
	Scorer                   Identity             `json:"scorer"`
	Provenance               string               `json:"provenance"`
	IssuedAt                 string               `json:"issued_at"`
	ExpiresAt                string               `json:"expires_at"`
}

// Metric is one bounded integer score component. V1 publishes no prose.
type Metric struct {
	Name        string `json:"name"`
	Micropoints int64  `json:"micropoints"`
}

// Result is the complete signed terminal scorer result.
type Result struct {
	Kind                     string               `json:"kind"`
	Protocol                 string               `json:"protocol"`
	ProtocolVersion          int                  `json:"protocol_version"`
	EventID                  string               `json:"event_id"`
	EventEpoch               string               `json:"event_epoch"`
	ResultID                 string               `json:"result_id"`
	AttemptID                string               `json:"attempt_id"`
	ActorID                  string               `json:"actor_id"`
	TeamID                   string               `json:"team_id"`
	ScorerRequestDigest      string               `json:"scorer_request_digest"`
	SubmissionEnvelopeDigest string               `json:"submission_envelope_digest"`
	CiphertextDigest         string               `json:"ciphertext_digest"`
	ConfigDigest             string               `json:"config_digest"`
	Reservation              statepointer.Pointer `json:"reservation"`
	Scorer                   Identity             `json:"scorer"`
	Status                   string               `json:"status"`
	TotalMicropoints         *int64               `json:"total_micropoints"`
	Metrics                  []Metric             `json:"metrics"`
	ReasonCode               *string              `json:"reason_code"`
	CompletedAt              string               `json:"completed_at"`
	Signature                identity.Signature   `json:"signature"`
}

// UnsignedResult is the exact payload covered by a scorer-result signature.
type UnsignedResult struct {
	Kind                     string               `json:"kind"`
	Protocol                 string               `json:"protocol"`
	ProtocolVersion          int                  `json:"protocol_version"`
	EventID                  string               `json:"event_id"`
	EventEpoch               string               `json:"event_epoch"`
	ResultID                 string               `json:"result_id"`
	AttemptID                string               `json:"attempt_id"`
	ActorID                  string               `json:"actor_id"`
	TeamID                   string               `json:"team_id"`
	ScorerRequestDigest      string               `json:"scorer_request_digest"`
	SubmissionEnvelopeDigest string               `json:"submission_envelope_digest"`
	CiphertextDigest         string               `json:"ciphertext_digest"`
	ConfigDigest             string               `json:"config_digest"`
	Reservation              statepointer.Pointer `json:"reservation"`
	Scorer                   Identity             `json:"scorer"`
	Status                   string               `json:"status"`
	TotalMicropoints         *int64               `json:"total_micropoints"`
	Metrics                  []Metric             `json:"metrics"`
	ReasonCode               *string              `json:"reason_code"`
	CompletedAt              string               `json:"completed_at"`
}

// Expected is independently trusted config and protected-state context.
type Expected struct {
	EventID                string
	EventEpoch             string
	BaseRepositoryID       string
	BaseRef                string
	ConfigDigest           string
	Scorer                 Identity
	ResultKey              identity.Public
	MaximumResultBytes     uint64
	MaximumCiphertextBytes uint64
	CurrentState           statepointer.Pointer
	Now                    time.Time
}

// Verified contains the authenticated result and replay/digest primitives.
type Verified struct {
	Request             Request
	ScorerRequestDigest string
	Document            Result
	DocumentDigest      string
	Fingerprint         envelope.Fingerprint
}

// ParseRequest strictly decodes and validates one bounded scorer request.
func ParseRequest(raw []byte) (Request, error) {
	if uint64(len(raw)) > MaxRequestBytes {
		return Request{}, fmt.Errorf("scorer request exceeds %d-byte limit", MaxRequestBytes)
	}
	var request Request
	if err := canonical.StrictUnmarshal(raw, &request); err != nil {
		return Request{}, fmt.Errorf("decode scorer request: %w", err)
	}
	if err := request.Validate(); err != nil {
		return Request{}, err
	}
	return request, nil
}

// ParseResult strictly decodes and validates one bounded signed result.
func ParseResult(raw []byte, maximumBytes uint64) (Result, error) {
	if maximumBytes < MinResultBytes || maximumBytes > MaxResultBytes {
		return Result{}, errors.New("configured scorer result limit is invalid")
	}
	if uint64(len(raw)) > maximumBytes {
		return Result{}, fmt.Errorf("scorer result exceeds configured %d-byte limit", maximumBytes)
	}
	var result Result
	if err := canonical.StrictUnmarshal(raw, &result); err != nil {
		return Result{}, fmt.Errorf("decode scorer result: %w", err)
	}
	if err := result.Validate(); err != nil {
		return Result{}, err
	}
	return result, nil
}

// ParseUnsignedResult strictly decodes a result payload before signing.
func ParseUnsignedResult(raw []byte, maximumBytes uint64) (UnsignedResult, error) {
	if maximumBytes < MinResultBytes || maximumBytes > MaxResultBytes {
		return UnsignedResult{}, errors.New("configured scorer result limit is invalid")
	}
	if uint64(len(raw)) > maximumBytes {
		return UnsignedResult{}, fmt.Errorf("unsigned scorer result exceeds configured %d-byte limit", maximumBytes)
	}
	var result UnsignedResult
	if err := canonical.StrictUnmarshal(raw, &result); err != nil {
		return UnsignedResult{}, fmt.Errorf("decode unsigned scorer result: %w", err)
	}
	if err := validateUnsigned(result); err != nil {
		return UnsignedResult{}, err
	}
	return result, nil
}

// Verify authenticates a result against the exact canonical request and the
// scorer key pinned in the adopted event configuration.
func Verify(requestRaw, resultRaw []byte, expected Expected) (Verified, error) {
	request, err := ParseRequest(requestRaw)
	if err != nil {
		return Verified{}, err
	}
	if err := VerifyRequestContext(request, expected); err != nil {
		return Verified{}, err
	}
	result, err := ParseResult(resultRaw, expected.MaximumResultBytes)
	if err != nil {
		return Verified{}, err
	}
	if err := verifyResultContext(result, request, expected); err != nil {
		return Verified{}, err
	}
	if err := expected.ResultKey.Validate(); err != nil {
		return Verified{}, fmt.Errorf("configured scorer result key: %w", err)
	}
	if err := envelope.Verify(ResultDomain, unsigned(result), result.Signature, expected.ResultKey); err != nil {
		return Verified{}, err
	}
	requestDigest, err := envelope.DocumentDigest(request)
	if err != nil {
		return Verified{}, err
	}
	if result.ScorerRequestDigest != requestDigest {
		return Verified{}, errors.New("scorer result does not bind the exact canonical scorer request")
	}
	requestIntentDigest, err := envelope.SigningDigest(ResultDomain, unsigned(result))
	if err != nil {
		return Verified{}, err
	}
	fingerprint, err := envelope.NewFingerprint(ResultDomain, result.EventID, result.ResultID, requestIntentDigest)
	if err != nil {
		return Verified{}, err
	}
	documentDigest, err := envelope.DocumentDigest(result)
	if err != nil {
		return Verified{}, err
	}
	return Verified{request, requestDigest, result, documentDigest, fingerprint}, nil
}

// SignResult signs an already strict result payload after checking every
// request/config/state binding. It is intended for an isolated trusted judge,
// not participant or state-writer workflows.
func SignResult(payload UnsignedResult, request Request, expected Expected, private identity.Private) (Result, error) {
	if err := request.Validate(); err != nil {
		return Result{}, err
	}
	if err := VerifyRequestContext(request, expected); err != nil {
		return Result{}, err
	}
	if err := validateUnsigned(payload); err != nil {
		return Result{}, err
	}
	result := resultFromUnsigned(payload)
	if err := verifyResultContext(result, request, expected); err != nil {
		return Result{}, err
	}
	_, pair, err := identity.SigningKey(private)
	if err != nil {
		return Result{}, err
	}
	if pair.Public != expected.ResultKey {
		return Result{}, errors.New("private scorer key does not match configured result key")
	}
	result.Signature, err = envelope.Sign(ResultDomain, payload, private)
	if err != nil {
		return Result{}, err
	}
	encoded, err := canonical.Marshal(result)
	if err != nil {
		return Result{}, err
	}
	if uint64(len(encoded)) > expected.MaximumResultBytes {
		return Result{}, fmt.Errorf("signed scorer result exceeds configured %d-byte limit", expected.MaximumResultBytes)
	}
	return result, nil
}

// Validate enforces the closed unsigned request schema.
func (request Request) Validate() error {
	if request.Kind != RequestKind || request.Protocol != envelope.Protocol || request.ProtocolVersion != envelope.ProtocolVersion || request.Provenance != Provenance {
		return errors.New("scorer request protocol discriminator is invalid")
	}
	if !envelope.IsEventID(request.EventID) || identity.ValidateDecimal(request.EventEpoch, "event_epoch") != nil || !envelope.IsUUID(request.AttemptID) || identity.ValidateDecimal(request.ActorID, "actor_id") != nil || !envelope.IsUUID(request.TeamID) {
		return errors.New("scorer request event/actor/team/attempt binding is invalid")
	}
	if !envelope.IsDigest(request.TeamProposalDigest) || !envelope.IsDigest(request.ConfigDigest) || !envelope.IsDigest(request.SubmissionEnvelopeDigest) || !envelope.IsDigest(request.ReservationReceiptDigest) {
		return errors.New("scorer request digest binding is invalid")
	}
	if err := request.Reservation.Validate(); err != nil {
		return fmt.Errorf("scorer request reservation: %w", err)
	}
	if err := envelope.ValidatePullRequestAddress(request.PullRequest); err != nil {
		return fmt.Errorf("scorer request pull request: %w", err)
	}
	if err := request.Bundle.Validate(); err != nil {
		return err
	}
	if err := request.Scorer.Validate(); err != nil {
		return err
	}
	if err := envelope.ValidateWindow(request.IssuedAt, request.ExpiresAt, time.Time{}); err != nil {
		return err
	}
	issuedAt, _ := envelope.ParseTimestamp(request.IssuedAt)
	expiresAt, _ := envelope.ParseTimestamp(request.ExpiresAt)
	sourceCreatedAt, err := envelope.ParseTimestamp(request.SourceCreatedAt)
	if err != nil {
		return err
	}
	acceptedAt, err := envelope.ParseTimestamp(request.AcceptedAt)
	if err != nil {
		return err
	}
	if sourceCreatedAt.Before(issuedAt) || sourceCreatedAt.After(expiresAt) {
		return errors.New("scorer request source_created_at is outside original submission window")
	}
	if acceptedAt.Before(sourceCreatedAt) {
		return errors.New("scorer request accepted_at precedes immutable source creation")
	}
	return nil
}

// Validate enforces the closed signed result schema before authentication.
func (result Result) Validate() error {
	if err := validateUnsigned(unsigned(result)); err != nil {
		return err
	}
	if result.Signature.Algorithm != identity.Algorithm || !envelope.IsDigest(result.Signature.KeyID) {
		return errors.New("scorer result signature metadata is invalid")
	}
	return nil
}

func (bundle Bundle) Validate() error {
	if bundle.Path != "submission.eventctl" || bundle.MediaType != BundleMediaType {
		return errors.New("scorer request bundle path/media_type is invalid")
	}
	if bundle.SizeBytes < 1 || bundle.SizeBytes > maxBundleBytes || bundle.CiphertextSize < 1 || bundle.CiphertextSize > maxCiphertextBytes || bundle.SizeBytes <= bundle.CiphertextSize {
		return errors.New("scorer request bundle size is invalid")
	}
	if !envelope.IsDigest(bundle.SHA256) || !envelope.IsDigest(bundle.EnvelopeSHA256) || !envelope.IsDigest(bundle.CiphertextSHA256) {
		return errors.New("scorer request bundle digest is invalid")
	}
	return nil
}

func (scorer Identity) Validate() error {
	if !idPattern.MatchString(scorer.ID) || len(scorer.Version) > 64 || !semverPattern.MatchString(scorer.Version) || !envelope.IsDigest(scorer.PolicyDigest) {
		return errors.New("scorer identity/version/policy is invalid")
	}
	return nil
}

func validateUnsigned(result UnsignedResult) error {
	if result.Kind != ResultKind || result.Protocol != envelope.Protocol || result.ProtocolVersion != envelope.ProtocolVersion {
		return errors.New("scorer result protocol discriminator is invalid")
	}
	if !envelope.IsEventID(result.EventID) || identity.ValidateDecimal(result.EventEpoch, "event_epoch") != nil || !envelope.IsUUID(result.ResultID) || !envelope.IsUUID(result.AttemptID) || identity.ValidateDecimal(result.ActorID, "actor_id") != nil || !envelope.IsUUID(result.TeamID) {
		return errors.New("scorer result event/result/actor/team/attempt binding is invalid")
	}
	if !envelope.IsDigest(result.ScorerRequestDigest) || !envelope.IsDigest(result.SubmissionEnvelopeDigest) || !envelope.IsDigest(result.CiphertextDigest) || !envelope.IsDigest(result.ConfigDigest) {
		return errors.New("scorer result digest binding is invalid")
	}
	if err := result.Reservation.Validate(); err != nil {
		return fmt.Errorf("scorer result reservation: %w", err)
	}
	if err := result.Scorer.Validate(); err != nil {
		return err
	}
	if _, err := envelope.ParseTimestamp(result.CompletedAt); err != nil {
		return err
	}
	if len(result.Metrics) > 128 {
		return errors.New("scorer result has more than 128 metrics")
	}
	seenMetrics := make(map[string]struct{}, len(result.Metrics))
	for index, metric := range result.Metrics {
		if !metricNamePattern.MatchString(metric.Name) || metric.Micropoints < -maxSafeInteger || metric.Micropoints > maxSafeInteger {
			return fmt.Errorf("scorer result metric %d is invalid", index)
		}
		if index > 0 && result.Metrics[index-1].Name >= metric.Name {
			return errors.New("scorer result metrics must be strictly sorted by name")
		}
		if _, duplicate := seenMetrics[metric.Name]; duplicate {
			return errors.New("scorer result metric names must be unique")
		}
		seenMetrics[metric.Name] = struct{}{}
	}
	switch result.Status {
	case "scored":
		if result.TotalMicropoints == nil || *result.TotalMicropoints < -maxSafeInteger || *result.TotalMicropoints > maxSafeInteger || result.ReasonCode != nil {
			return errors.New("scored result requires a bounded total and null reason_code")
		}
	case "invalid", "timeout", "internal_error":
		if result.TotalMicropoints != nil || len(result.Metrics) != 0 || result.ReasonCode == nil || !reasonCodePattern.MatchString(*result.ReasonCode) {
			return errors.New("non-scored result requires no score/metrics and a bounded reason_code")
		}
	default:
		return errors.New("scorer result status is invalid")
	}
	return nil
}

// VerifyRequestContext binds an unsigned request to trusted configuration and
// protected state. It is intentionally timeless: source_created_at is checked
// against the original signed window, while delayed scoring can happen later.
func VerifyRequestContext(request Request, expected Expected) error {
	if expected.MaximumResultBytes < MinResultBytes || expected.MaximumResultBytes > MaxResultBytes {
		return errors.New("configured scorer result limit is invalid")
	}
	if request.EventID != expected.EventID || request.EventEpoch != expected.EventEpoch || request.ConfigDigest != expected.ConfigDigest || request.PullRequest.BaseRepositoryID != expected.BaseRepositoryID || request.PullRequest.BaseRef != expected.BaseRef || request.Scorer != expected.Scorer {
		return errors.New("scorer request does not match trusted event/config/scoring policy")
	}
	if expected.MaximumCiphertextBytes < 1 || request.Bundle.CiphertextSize > expected.MaximumCiphertextBytes {
		return errors.New("scorer request ciphertext exceeds configured limit")
	}
	maximumBundleBytes := expected.MaximumCiphertextBytes + 256*1024 + 8 + 4 + 64
	if maximumBundleBytes < expected.MaximumCiphertextBytes || request.Bundle.SizeBytes > maximumBundleBytes {
		return errors.New("scorer request bundle exceeds configured limit")
	}
	if err := request.Reservation.IsAtOrBefore(expected.CurrentState); err != nil {
		return fmt.Errorf("scorer request reservation: %w", err)
	}
	if err := envelope.ValidateWindow(request.IssuedAt, request.ExpiresAt, time.Time{}); err != nil {
		return fmt.Errorf("scorer request validity window: %w", err)
	}
	return nil
}

func verifyResultContext(result Result, request Request, expected Expected) error {
	requestDigest, err := envelope.DocumentDigest(request)
	if err != nil {
		return err
	}
	if result.EventID != request.EventID || result.EventEpoch != request.EventEpoch || result.AttemptID != request.AttemptID || result.ActorID != request.ActorID || result.TeamID != request.TeamID || result.ScorerRequestDigest != requestDigest || result.SubmissionEnvelopeDigest != request.SubmissionEnvelopeDigest || result.CiphertextDigest != request.Bundle.CiphertextSHA256 || result.ConfigDigest != request.ConfigDigest || !result.Reservation.Equal(request.Reservation) || result.Scorer != request.Scorer {
		return errors.New("scorer result does not exactly bind the scorer request")
	}
	if result.EventID != expected.EventID || result.EventEpoch != expected.EventEpoch || result.ConfigDigest != expected.ConfigDigest || result.Scorer != expected.Scorer {
		return errors.New("scorer result does not match trusted event/config/scoring policy")
	}
	acceptedAt, _ := envelope.ParseTimestamp(request.AcceptedAt)
	completedAt, err := envelope.ParseTimestamp(result.CompletedAt)
	if err != nil {
		return err
	}
	if completedAt.Before(acceptedAt) {
		return errors.New("scorer result completed_at precedes accepted reservation")
	}
	if !expected.Now.IsZero() && completedAt.After(expected.Now.UTC().Add(5*time.Minute)) {
		return errors.New("scorer result completed_at is implausibly in the future")
	}
	return nil
}

func unsigned(result Result) UnsignedResult {
	return UnsignedResult{
		result.Kind, result.Protocol, result.ProtocolVersion, result.EventID, result.EventEpoch,
		result.ResultID, result.AttemptID, result.ActorID, result.TeamID,
		result.ScorerRequestDigest, result.SubmissionEnvelopeDigest, result.CiphertextDigest,
		result.ConfigDigest, result.Reservation, result.Scorer, result.Status,
		result.TotalMicropoints, result.Metrics, result.ReasonCode, result.CompletedAt,
	}
}

func resultFromUnsigned(result UnsignedResult) Result {
	return Result{
		Kind: result.Kind, Protocol: result.Protocol, ProtocolVersion: result.ProtocolVersion,
		EventID: result.EventID, EventEpoch: result.EventEpoch, ResultID: result.ResultID,
		AttemptID: result.AttemptID, ActorID: result.ActorID, TeamID: result.TeamID,
		ScorerRequestDigest:      result.ScorerRequestDigest,
		SubmissionEnvelopeDigest: result.SubmissionEnvelopeDigest,
		CiphertextDigest:         result.CiphertextDigest, ConfigDigest: result.ConfigDigest,
		Reservation: result.Reservation, Scorer: result.Scorer, Status: result.Status,
		TotalMicropoints: result.TotalMicropoints, Metrics: result.Metrics,
		ReasonCode: result.ReasonCode, CompletedAt: result.CompletedAt,
	}
}
