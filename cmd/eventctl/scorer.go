package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/config"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/receipt"
	"github.com/pythonhk/eventctl/internal/scorer"
)

type normalizedScorerRequest struct {
	Status         string         `json:"status"`
	Kind           string         `json:"kind"`
	DocumentDigest string         `json:"document_digest"`
	Document       scorer.Request `json:"document"`
}

type normalizedScorerResult struct {
	Status              string        `json:"status"`
	Kind                string        `json:"kind"`
	RequestDigest       string        `json:"request_digest"`
	DocumentDigest      string        `json:"document_digest"`
	ReplayKey           string        `json:"replay_key"`
	ScorerRequestDigest string        `json:"scorer_request_digest"`
	Document            scorer.Result `json:"document"`
}

func runScorer(args []string, stderr io.Writer) (any, error) {
	if len(args) == 0 {
		return nil, usageError("usage: eventctl scorer validate-request|sign-result|verify")
	}
	switch args[0] {
	case "validate-request":
		return scorerValidateRequest(args[1:])
	case "sign-result":
		return scorerSignResult(args[1:], stderr)
	case "verify":
		return scorerVerify(args[1:])
	default:
		return nil, usageError("usage: eventctl scorer validate-request|sign-result|verify")
	}
}

func scorerValidateRequest(args []string) (any, error) {
	flags := newFlagSet("scorer validate-request")
	configPath := flags.String("config", "", "signed event config")
	authorityPath := flags.String("authority", "", "protected genesis authority")
	statePath := flags.String("state-meta", "", "protected current state metadata")
	requestPath := flags.String("request", "", "unsigned scorer request")
	acceptancePath := flags.String("acceptance", "", "signed accepted submission reservation receipt")
	out := flags.String("out", "", "normalized scorer request output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authorityPath == "" || *statePath == "" || *requestPath == "" || *acceptancePath == "" || *out == "" {
		return nil, usageError("usage: eventctl scorer validate-request --config PATH --authority PATH --state-meta PATH --request PATH --acceptance PATH --out PATH")
	}
	raw, err := readBounded(*requestPath, envelope.MaxDocumentBytes)
	if err != nil {
		return nil, ioError("read scorer request", err)
	}
	request, err := scorer.ParseRequest(raw)
	if err != nil {
		return nil, invalidError("validate scorer request", err)
	}
	event, digest, meta, _, err := loadScorerTrust(*configPath, *authorityPath, *statePath, *acceptancePath, request)
	if err != nil {
		return nil, verificationError("verify historical event trust context", err)
	}
	expected := scorerExpected(event, digest, meta, time.Now().UTC())
	if err := scorer.VerifyRequestContext(request, expected); err != nil {
		return nil, verificationError("verify scorer request context", err)
	}
	documentDigest, err := envelope.DocumentDigest(request)
	if err != nil {
		return nil, err
	}
	normalized := normalizedScorerRequest{"valid", scorer.RequestKind, documentDigest, request}
	if err := writeCanonical(*out, normalized, 0o644); err != nil {
		return nil, ioError("write normalized scorer request", err)
	}
	return struct {
		Path           string `json:"path"`
		Kind           string `json:"kind"`
		DocumentDigest string `json:"document_digest"`
		AttemptID      string `json:"attempt_id"`
	}{*out, scorer.RequestKind, documentDigest, request.AttemptID}, nil
}

func scorerVerify(args []string) (any, error) {
	flags := newFlagSet("scorer verify")
	configPath := flags.String("config", "", "signed event config")
	authorityPath := flags.String("authority", "", "protected genesis authority")
	statePath := flags.String("state-meta", "", "protected current state metadata")
	requestPath := flags.String("request", "", "exact unsigned scorer request")
	acceptancePath := flags.String("acceptance", "", "signed accepted submission reservation receipt")
	resultPath := flags.String("result", "", "signed scorer result")
	out := flags.String("out", "", "normalized verified scorer result")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authorityPath == "" || *statePath == "" || *requestPath == "" || *acceptancePath == "" || *resultPath == "" || *out == "" {
		return nil, usageError("usage: eventctl scorer verify --config PATH --authority PATH --state-meta PATH --request PATH --acceptance PATH --result PATH --out PATH")
	}
	requestRaw, err := readBounded(*requestPath, envelope.MaxDocumentBytes)
	if err != nil {
		return nil, ioError("read scorer request", err)
	}
	parsedRequest, err := scorer.ParseRequest(requestRaw)
	if err != nil {
		return nil, invalidError("validate scorer request", err)
	}
	event, digest, meta, _, err := loadScorerTrust(*configPath, *authorityPath, *statePath, *acceptancePath, parsedRequest)
	if err != nil {
		return nil, verificationError("verify historical event trust context", err)
	}
	resultRaw, err := readBounded(*resultPath, int64(event.Scoring.MaximumResultBytes))
	if err != nil {
		return nil, ioError("read scorer result", err)
	}
	verified, err := scorer.Verify(requestRaw, resultRaw, scorerExpected(event, digest, meta, time.Now().UTC()))
	if err != nil {
		return nil, verificationError("verify scorer result", err)
	}
	normalized := normalizedScorerResult{"verified", scorer.ResultKind, verified.Fingerprint.RequestDigest, verified.DocumentDigest, verified.Fingerprint.ReplayKey, verified.ScorerRequestDigest, verified.Document}
	if err := writeCanonical(*out, normalized, 0o644); err != nil {
		return nil, ioError("write verified scorer result", err)
	}
	return requestSummary{*out, scorer.ResultKind, verified.Fingerprint.RequestDigest, verified.DocumentDigest, verified.Fingerprint.ReplayKey}, nil
}

func scorerSignResult(args []string, stderr io.Writer) (any, error) {
	flags := newFlagSet("scorer sign-result")
	configPath := flags.String("config", "", "signed archived event config")
	authorityPath := flags.String("authority", "", "protected genesis authority")
	statePath := flags.String("state-meta", "", "protected current state metadata")
	requestPath := flags.String("request", "", "exact unsigned scorer request")
	acceptancePath := flags.String("acceptance", "", "signed accepted submission reservation receipt")
	unsignedPath := flags.String("unsigned-result", "", "strict unsigned scorer result")
	keyPath := flags.String("key", "", "encrypted dedicated scorer result key")
	passphraseFile := flags.String("passphrase-file", "", "passphrase file or -")
	out := flags.String("out", "", "raw signed scorer result output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authorityPath == "" || *statePath == "" || *requestPath == "" || *acceptancePath == "" || *unsignedPath == "" || *keyPath == "" || *out == "" {
		return nil, usageError("usage: eventctl scorer sign-result --config PATH --authority PATH --state-meta PATH --request PATH --acceptance PATH --unsigned-result PATH --key PATH --out PATH [--passphrase-file PATH|-]")
	}
	requestRaw, err := readBounded(*requestPath, envelope.MaxDocumentBytes)
	if err != nil {
		return nil, ioError("read scorer request", err)
	}
	request, err := scorer.ParseRequest(requestRaw)
	if err != nil {
		return nil, invalidError("validate scorer request", err)
	}
	event, digest, meta, _, err := loadScorerTrust(*configPath, *authorityPath, *statePath, *acceptancePath, request)
	if err != nil {
		return nil, verificationError("verify accepted scorer request", err)
	}
	unsignedRaw, err := readBounded(*unsignedPath, int64(event.Scoring.MaximumResultBytes))
	if err != nil {
		return nil, ioError("read unsigned scorer result", err)
	}
	payload, err := scorer.ParseUnsignedResult(unsignedRaw, event.Scoring.MaximumResultBytes)
	if err != nil {
		return nil, invalidError("validate unsigned scorer result", err)
	}
	pair, err := loadPrivate(*keyPath, *passphraseFile, stderr)
	if err != nil {
		return nil, verificationError("decrypt scorer result key", err)
	}
	expected := scorerExpected(event, digest, meta, time.Now().UTC())
	document, err := scorer.SignResult(payload, request, expected, pair.Private)
	if err != nil {
		return nil, verificationError("sign scorer result", err)
	}
	resultRaw, err := canonical.Marshal(document)
	if err != nil {
		return nil, err
	}
	verified, err := scorer.Verify(requestRaw, resultRaw, expected)
	if err != nil {
		return nil, verificationError("self-verify scorer result", err)
	}
	if err := writeExclusive(*out, append(resultRaw, '\n'), 0o644); err != nil {
		return nil, ioError("write signed scorer result", err)
	}
	return requestSummary{*out, scorer.ResultKind, verified.Fingerprint.RequestDigest, verified.DocumentDigest, verified.Fingerprint.ReplayKey}, nil
}

func loadScorerTrust(configPath, authorityPath, statePath, acceptancePath string, request scorer.Request) (config.Event, string, config.StateMeta, receipt.Verified, error) {
	acceptanceRaw, err := readBounded(acceptancePath, envelope.MaxDocumentBytes)
	if err != nil {
		return config.Event{}, "", config.StateMeta{}, receipt.Verified{}, err
	}
	parsedAcceptance, err := receipt.Parse(acceptanceRaw)
	if err != nil {
		return config.Event{}, "", config.StateMeta{}, receipt.Verified{}, err
	}
	sourceCreatedAt, err := envelope.ParseTimestamp(parsedAcceptance.SourceCreatedAt)
	if err != nil {
		return config.Event{}, "", config.StateMeta{}, receipt.Verified{}, err
	}
	event, digest, meta, err := loadArchivedTrustedContext(configPath, authorityPath, statePath, sourceCreatedAt)
	if err != nil {
		return config.Event{}, "", config.StateMeta{}, receipt.Verified{}, err
	}
	if err := requireOneOfPhases(meta, "submissions_open", "frozen"); err != nil {
		return config.Event{}, "", config.StateMeta{}, receipt.Verified{}, fmt.Errorf("scoring is not allowed by current protected control state: %w", err)
	}
	if digest != parsedAcceptance.ConfigDigest || event.BaseRepository.ID != parsedAcceptance.BaseRepositoryID || request.ConfigDigest != digest {
		return config.Event{}, "", config.StateMeta{}, receipt.Verified{}, errors.New("accepted reservation does not bind archived config/current authorities")
	}
	verified, err := receipt.Verify(acceptanceRaw, receipt.Expected{
		EventID: event.EventID, EventEpoch: event.EventEpoch,
		BaseRepositoryID: event.BaseRepository.ID, ConfigDigest: digest,
		SigningKey: event.Receipts.SigningKey, CurrentState: currentPointer(meta),
		Now: time.Now().UTC(),
	})
	if err != nil {
		return config.Event{}, "", config.StateMeta{}, receipt.Verified{}, err
	}
	if err := verifyScorerAcceptance(verified, request); err != nil {
		return config.Event{}, "", config.StateMeta{}, receipt.Verified{}, err
	}
	return event, digest, meta, verified, nil
}

func verifyScorerAcceptance(verified receipt.Verified, request scorer.Request) error {
	document := verified.Document
	if verified.DocumentDigest != request.ReservationReceiptDigest || document.RequestKind != envelope.SubmissionKind || document.Outcome != "accepted" || !document.QuotaCharged || document.ActorID != request.ActorID || document.TeamID == nil || *document.TeamID != request.TeamID || document.AttemptID == nil || *document.AttemptID != request.AttemptID || document.RequestDocumentDigest == nil || *document.RequestDocumentDigest != request.SubmissionEnvelopeDigest || !document.StateAfter.Equal(request.Reservation) || document.SourceCreatedAt != request.SourceCreatedAt || document.IssuedAt != request.AcceptedAt || document.ScorerResultDigest != nil || document.ReservationReceiptDigest != nil {
		return errors.New("reservation receipt does not exactly bind scorer request acceptance")
	}
	if err := document.ValidateSourceWindow(request.IssuedAt, request.ExpiresAt); err != nil {
		return err
	}
	return nil
}

func scorerExpected(event config.Event, digest string, meta config.StateMeta, now time.Time) scorer.Expected {
	return scorer.Expected{
		EventID: event.EventID, EventEpoch: event.EventEpoch,
		BaseRepositoryID: event.BaseRepository.ID, BaseRef: event.Submissions.BaseRef,
		ConfigDigest: digest,
		Scorer:       scorer.Identity{ID: event.Scoring.ScorerID, Version: event.Scoring.ScorerVersion, PolicyDigest: event.Scoring.PolicyDigest},
		ResultKey:    event.Scoring.ResultKey, MaximumResultBytes: event.Scoring.MaximumResultBytes,
		MaximumCiphertextBytes: event.Submissions.MaximumCiphertextBytes,
		CurrentState:           currentPointer(meta), Now: now,
	}
}
