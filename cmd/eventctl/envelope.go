package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pythonhk/eventctl/internal/canonical"
	protocolenvelope "github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/team"
)

type envelopeClassification struct {
	Status    string `json:"status"`
	Trust     string `json:"trust"`
	Kind      string `json:"kind"`
	RequestID string `json:"request_id"`
}

func runEnvelope(args []string) (any, error) {
	if len(args) == 0 || args[0] != "classify" {
		return nil, usageError("usage: eventctl envelope classify --request PATH --out PATH")
	}
	flags := newFlagSet("envelope classify")
	requestPath := flags.String("request", "", "raw durable request JSON")
	out := flags.String("out", "", "unverified routing classification")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *requestPath == "" || *out == "" {
		return nil, usageError("usage: eventctl envelope classify --request PATH --out PATH")
	}
	raw, err := readBounded(*requestPath, protocolenvelope.MaxDocumentBytes)
	if err != nil {
		return nil, ioError("read durable request", err)
	}
	result, err := classifyEnvelope(raw)
	if err != nil {
		return nil, invalidError("classify untrusted durable request", err)
	}
	if err := writeCanonical(*out, result, 0o644); err != nil {
		return nil, ioError("write envelope classification", err)
	}
	return result, nil
}

// classifyEnvelope extracts only routing metadata. It deliberately does not
// verify a signature or compare trusted actor, repository, config, time, or
// GitHub source context; callers must pass the original request to its full
// intake verifier before any state effect.
func classifyEnvelope(raw []byte) (envelopeClassification, error) {
	if len(raw) > protocolenvelope.MaxDocumentBytes {
		return envelopeClassification{}, fmt.Errorf("durable request exceeds %d-byte limit", protocolenvelope.MaxDocumentBytes)
	}
	var transport map[string]json.RawMessage
	if err := canonical.StrictUnmarshal(raw, &transport); err != nil {
		return envelopeClassification{}, fmt.Errorf("decode durable request: %w", err)
	}
	if transport == nil {
		return envelopeClassification{}, errors.New("durable request must be a JSON object")
	}
	documentRaw := raw
	if wrapped, present := transport["envelope"]; present {
		if len(transport) != 1 {
			return envelopeClassification{}, errors.New("durable request wrapper must contain exactly one envelope field")
		}
		var embedded map[string]json.RawMessage
		if err := canonical.StrictUnmarshal(wrapped, &embedded); err != nil || embedded == nil {
			if err == nil {
				err = errors.New("envelope is null")
			}
			return envelopeClassification{}, fmt.Errorf("decode wrapped durable request: %w", err)
		}
		documentRaw = wrapped
		transport = embedded
	}
	kindRaw, ok := transport["kind"]
	if !ok {
		return envelopeClassification{}, errors.New("durable request is missing kind")
	}
	var kind string
	if err := canonical.StrictUnmarshal(kindRaw, &kind); err != nil {
		return envelopeClassification{}, fmt.Errorf("decode durable request kind: %w", err)
	}

	requestID := ""
	switch kind {
	case protocolenvelope.RegistrationKind:
		var document protocolenvelope.Registration
		if err := canonical.StrictUnmarshal(documentRaw, &document); err != nil {
			return envelopeClassification{}, fmt.Errorf("decode registration request: %w", err)
		}
		if err := document.ValidateUntrustedStructure(); err != nil {
			return envelopeClassification{}, fmt.Errorf("validate untrusted registration structure: %w", err)
		}
		requestID = document.OperationID
	case team.ProposalKind:
		var document team.Proposal
		if err := canonical.StrictUnmarshal(documentRaw, &document); err != nil {
			return envelopeClassification{}, fmt.Errorf("decode team proposal: %w", err)
		}
		if err := document.ValidateUntrustedStructure(); err != nil {
			return envelopeClassification{}, fmt.Errorf("validate untrusted team proposal structure: %w", err)
		}
		requestID = document.OperationID
	case team.ConsentKind:
		var document team.Consent
		if err := canonical.StrictUnmarshal(documentRaw, &document); err != nil {
			return envelopeClassification{}, fmt.Errorf("decode team consent: %w", err)
		}
		if err := document.ValidateUntrustedStructure(); err != nil {
			return envelopeClassification{}, fmt.Errorf("validate untrusted team consent structure: %w", err)
		}
		requestID = document.OperationID
	case protocolenvelope.SubmissionKind:
		var document protocolenvelope.Submission
		if err := canonical.StrictUnmarshal(documentRaw, &document); err != nil {
			return envelopeClassification{}, fmt.Errorf("decode submission request: %w", err)
		}
		if err := document.ValidateUntrustedStructure(); err != nil {
			return envelopeClassification{}, fmt.Errorf("validate untrusted submission structure: %w", err)
		}
		requestID = document.RequestID
	default:
		return envelopeClassification{}, fmt.Errorf("unsupported durable request kind %q", kind)
	}

	return envelopeClassification{Status: "classified", Trust: "unverified", Kind: kind, RequestID: requestID}, nil
}
