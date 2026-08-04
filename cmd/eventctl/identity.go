package main

import (
	"io"
	"time"

	"github.com/pythonhk/eventctl/internal/envelope"
)

type normalizedRequest struct {
	Status         string `json:"status"`
	Kind           string `json:"kind"`
	RequestDigest  string `json:"request_digest"`
	DocumentDigest string `json:"document_digest"`
	ReplayKey      string `json:"replay_key"`
	Document       any    `json:"document"`
}

type requestSummary struct {
	Path           string `json:"path"`
	Kind           string `json:"kind"`
	RequestDigest  string `json:"request_digest"`
	DocumentDigest string `json:"document_digest"`
	ReplayKey      string `json:"replay_key"`
}

func runIdentity(args []string, stderr io.Writer) (any, error) {
	if len(args) == 0 {
		return nil, usageError("usage: eventctl identity register|verify")
	}
	switch args[0] {
	case "register":
		return identityRegister(args[1:], stderr)
	case "verify":
		return identityVerify(args[1:])
	default:
		return nil, usageError("usage: eventctl identity register|verify")
	}
}

func identityRegister(args []string, stderr io.Writer) (any, error) {
	flags := newFlagSet("identity register")
	configPath := flags.String("config", "", "signed event config")
	authority := flags.String("authority", "", "protected genesis")
	stateMeta := flags.String("state-meta", "", "protected current state metadata")
	keyPath := flags.String("key", "", "encrypted participant key")
	passFile := flags.String("passphrase-file", "", "passphrase file or -")
	actorID := flags.String("actor-id", "", "numeric GitHub actor ID")
	keyEpoch := flags.String("key-epoch", "1", "registration key epoch")
	requestID := flags.String("request-id", "", "UUIDv4 (generated if omitted)")
	out := flags.String("out", "", "registration request output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authority == "" || *stateMeta == "" || *keyPath == "" || *actorID == "" || *out == "" {
		return nil, usageError("usage: eventctl identity register --config PATH --authority PATH --state-meta PATH --key PATH --actor-id ID --out PATH [--passphrase-file PATH|-] [--request-id UUID]")
	}
	event, digest, meta, err := loadTrustedContext(*configPath, *authority, *stateMeta, time.Now().UTC())
	if err != nil {
		return nil, verificationError("verify event trust context", err)
	}
	if err := requireOneOfPhases(meta, "registration_open", "formation_open"); err != nil {
		return nil, verificationError("registration is not open", err)
	}
	pair, err := loadPrivate(*keyPath, *passFile, stderr)
	if err != nil {
		return nil, verificationError("decrypt participant key", err)
	}
	issued := time.Now().UTC().Truncate(time.Second)
	requestTTL := time.Duration(event.Registration.RequestTTLSeconds) * time.Second
	raw, err := envelope.NewRegistration(envelope.RegistrationParams{EventID: event.EventID, EventEpoch: event.EventEpoch, OperationID: *requestID, ActorID: *actorID, KeyEpoch: *keyEpoch, BaseRepository: event.BaseRepository, ConfigDigest: digest, TermsDigest: event.Registration.TermsDigest, IssuedAt: issued, ExpiresAt: issued.Add(requestTTL)}, pair.Private)
	if err != nil {
		return nil, invalidError("create registration", err)
	}
	verified, err := envelope.VerifyRegistration(raw, envelope.Expected{EventID: event.EventID, EventEpoch: event.EventEpoch, RepositoryID: event.BaseRepository.ID, ActorID: *actorID, ConfigDigest: digest, Now: issued}, requestTTL)
	if err != nil {
		return nil, verificationError("self-verify registration", err)
	}
	if err := writeExclusive(*out, append(raw, '\n'), 0o644); err != nil {
		return nil, ioError("write registration request", err)
	}
	docDigest, err := envelope.DocumentDigest(verified.Document)
	if err != nil {
		return nil, err
	}
	return requestSummary{*out, envelope.RegistrationKind, verified.Fingerprint.RequestDigest, docDigest, verified.Fingerprint.ReplayKey}, nil
}

func identityVerify(args []string) (any, error) {
	flags := newFlagSet("identity verify")
	configPath := flags.String("config", "", "signed event config")
	authority := flags.String("authority", "", "protected genesis")
	stateMeta := flags.String("state-meta", "", "protected current state metadata")
	requestPath := flags.String("request", "", "registration request")
	actorID := flags.String("expect-actor-id", "", "trusted GitHub actor ID")
	sourceTimeText := flags.String("source-time", "", "trusted immutable GitHub source creation time")
	out := flags.String("out", "", "normalized verification output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authority == "" || *stateMeta == "" || *requestPath == "" || *actorID == "" || *sourceTimeText == "" || *out == "" {
		return nil, usageError("usage: eventctl identity verify --config PATH --authority PATH --state-meta PATH --request PATH --expect-actor-id ID --source-time RFC3339 --out PATH")
	}
	sourceTime, err := parseTrustedSourceTime(*sourceTimeText)
	if err != nil {
		return nil, invalidError("validate trusted source time", err)
	}
	event, digest, meta, err := loadTrustedContext(*configPath, *authority, *stateMeta, sourceTime)
	if err != nil {
		return nil, verificationError("verify event trust context", err)
	}
	if err := requireOneOfPhases(meta, "registration_open", "formation_open"); err != nil {
		return nil, verificationError("registration is not open", err)
	}
	raw, err := readBounded(*requestPath, envelope.MaxDocumentBytes)
	if err != nil {
		return nil, ioError("read registration request", err)
	}
	requestTTL := time.Duration(event.Registration.RequestTTLSeconds) * time.Second
	verified, err := envelope.VerifyRegistration(raw, envelope.Expected{EventID: event.EventID, EventEpoch: event.EventEpoch, RepositoryID: event.BaseRepository.ID, ActorID: *actorID, ConfigDigest: digest, Now: sourceTime}, requestTTL)
	if err != nil {
		return nil, verificationError("verify registration", err)
	}
	docDigest, err := envelope.DocumentDigest(verified.Document)
	if err != nil {
		return nil, err
	}
	normalized := normalizedRequest{"verified", envelope.RegistrationKind, verified.Fingerprint.RequestDigest, docDigest, verified.Fingerprint.ReplayKey, verified.Document}
	if err := writeCanonical(*out, normalized, 0o644); err != nil {
		return nil, ioError("write verified registration", err)
	}
	return requestSummary{*out, envelope.RegistrationKind, verified.Fingerprint.RequestDigest, docDigest, verified.Fingerprint.ReplayKey}, nil
}
