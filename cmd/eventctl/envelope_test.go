package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pythonhk/eventctl/internal/canonical"
	protocolenvelope "github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
	"github.com/pythonhk/eventctl/internal/team"
)

type classifierFixture struct {
	name      string
	raw       []byte
	kind      string
	requestID string
}

func TestClassifyEnvelopeDurableKindsAsUnverified(t *testing.T) {
	t.Parallel()
	for _, fixture := range classifierFixtures(t) {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			got, err := classifyEnvelope(fixture.raw)
			if err != nil {
				t.Fatal(err)
			}
			want := envelopeClassification{
				Status: "classified", Trust: "unverified",
				Kind: fixture.kind, RequestID: fixture.requestID,
			}
			if got != want {
				t.Fatalf("classification = %#v, want %#v", got, want)
			}
		})
	}
}

func TestClassifyEnvelopeRawAndExactWrapperAreIdentical(t *testing.T) {
	t.Parallel()
	for _, fixture := range classifierFixtures(t) {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			rawClassification, err := classifyEnvelope(fixture.raw)
			if err != nil {
				t.Fatal(err)
			}
			wrapped := wrapClassifierRequest(fixture.raw)
			wrappedClassification, err := classifyEnvelope(wrapped)
			if err != nil {
				t.Fatal(err)
			}
			if wrappedClassification != rawClassification {
				t.Fatalf("wrapped classification = %#v, raw = %#v", wrappedClassification, rawClassification)
			}
		})
	}
}

func TestClassifyEnvelopeDoesNotAuthenticateStructurallyEncodedSignature(t *testing.T) {
	t.Parallel()
	fixture := classifierFixtures(t)[0]
	document := fixture.registration(t)
	if err := identity.Verify(document.ParticipantKey, []byte("not the signed request"), document.Signature); err == nil {
		t.Fatal("zero-filled test signature unexpectedly authenticated")
	}
	classification, err := classifyEnvelope(fixture.raw)
	if err != nil {
		t.Fatal(err)
	}
	if classification.Trust != "unverified" {
		t.Fatalf("classification trust = %q, want unverified", classification.Trust)
	}
}

func TestEnvelopeClassifyCommandWritesExactCanonicalArtifact(t *testing.T) {
	fixture := classifierFixtures(t)[0]
	directory := t.TempDir()
	requestPath := filepath.Join(directory, "request.json")
	outPath := filepath.Join(directory, "classification.json")
	if err := os.WriteFile(requestPath, fixture.raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exit := run([]string{"envelope", "classify", "--request", requestPath, "--out", outPath}, &stdout, &stderr)
	if exit != 0 || stderr.String() != "" {
		t.Fatalf("run exit=%d stderr=%q stdout=%q", exit, stderr.String(), stdout.String())
	}
	var response struct {
		OutputVersion string                 `json:"output_version"`
		OK            bool                   `json:"ok"`
		Command       string                 `json:"command"`
		Result        envelopeClassification `json:"result"`
		Error         *errorObject           `json:"error"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	want := envelopeClassification{
		Status: "classified", Trust: "unverified",
		Kind: fixture.kind, RequestID: fixture.requestID,
	}
	if response.OutputVersion != outputVersion || !response.OK || response.Command != "envelope.classify" || response.Error != nil || response.Result != want {
		t.Fatalf("response = %#v, want result %#v", response, want)
	}
	wantRaw, err := canonical.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	wantRaw = append(wantRaw, '\n')
	gotRaw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotRaw, wantRaw) {
		t.Fatalf("classification artifact = %s, want %s", gotRaw, wantRaw)
	}
}

func TestClassifyEnvelopeRejectsNonConcreteOrMalformedInput(t *testing.T) {
	t.Parallel()
	fixtures := classifierFixtures(t)
	valid := fixtures[0].raw
	registration := fixtures[0].registration(t)
	badID := registration
	badID.OperationID = "not-a-uuid"
	badIDRaw, err := canonical.Marshal(badID)
	if err != nil {
		t.Fatal(err)
	}
	badSignature := registration
	badSignature.Signature.Value = "A"
	badSignatureRaw, err := canonical.Marshal(badSignature)
	if err != nil {
		t.Fatal(err)
	}
	wrongSignatureKey := registration
	wrongSignatureKey.Signature.KeyID = strings.Repeat("f", 64)
	wrongSignatureKeyRaw, err := canonical.Marshal(wrongSignatureKey)
	if err != nil {
		t.Fatal(err)
	}

	nestedDuplicate := append([]byte(`{"kind":"registration_request",`), valid[1:]...)
	outerDuplicate := append([]byte(`{"envelope":`), valid...)
	outerDuplicate = append(outerDuplicate, []byte(`,"envelope":`)...)
	outerDuplicate = append(outerDuplicate, valid...)
	outerDuplicate = append(outerDuplicate, '}')
	outerExtra := append([]byte(`{"envelope":`), valid...)
	outerExtra = append(outerExtra, []byte(`,"extra":true}`)...)
	fractional := []byte(strings.Replace(string(valid), `"protocol_version":1`, `"protocol_version":1.5`, 1))
	exponent := []byte(strings.Replace(string(valid), `"protocol_version":1`, `"protocol_version":1e0`, 1))

	cases := map[string][]byte{
		"unknown field":       append([]byte(`{"unknown":true,`), valid[1:]...),
		"duplicate kind":      append([]byte(`{"kind":"registration_request",`), valid[1:]...),
		"case variant field":  append([]byte(`{"Kind":"registration_request",`), valid[1:]...),
		"incomplete concrete": []byte(`{"kind":"registration_request"}`),
		"unknown kind":        []byte(`{"kind":"scorer_request"}`),
		"outer duplicate":     outerDuplicate,
		"outer extra field":   outerExtra,
		"wrapper null":        []byte(`{"envelope":null}`),
		"wrapper string":      []byte(`{"envelope":"request"}`),
		"wrapper array":       []byte(`{"envelope":[]}`),
		"nested duplicate":    wrapClassifierRequest(nestedDuplicate),
		"trailing value":      append(append([]byte(nil), valid...), []byte(` {}`)...),
		"malformed":           []byte(`{"kind":`),
		"invalid UTF-8":       []byte{0xff},
		"top-level array":     []byte(`[]`),
		"fractional number":   fractional,
		"exponent number":     exponent,
		"bad request ID":      badIDRaw,
		"bad signature":       badSignatureRaw,
		"wrong signature key": wrongSignatureKeyRaw,
		"oversize":            bytes.Repeat([]byte{' '}, protocolenvelope.MaxDocumentBytes+1),
	}
	for name, raw := range cases {
		name := name
		raw := raw
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got, err := classifyEnvelope(raw); err == nil {
				t.Fatalf("classifyEnvelope accepted %s as %#v", name, got)
			}
		})
	}
}

func classifierFixtures(t *testing.T) []classifierFixture {
	t.Helper()
	pair, err := identity.FromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	// Structurally canonical but cryptographically invalid. Classification must
	// remain explicitly unverified and leave authentication to intake handlers.
	signature := identity.Signature{
		Algorithm: identity.Algorithm,
		KeyID:     pair.Public.KeyID,
		Value:     base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	repository := protocolenvelope.Repository{ID: "123", Owner: "pythonhk", Name: "example-event"}
	const (
		registrationID = "11111111-1111-4111-8111-111111111111"
		proposalID     = "22222222-2222-4222-8222-222222222222"
		consentID      = "33333333-3333-4333-8333-333333333333"
		submissionID   = "44444444-4444-4444-8444-444444444444"
		teamID         = "55555555-5555-4555-8555-555555555555"
		attemptID      = "66666666-6666-4666-8666-666666666666"
	)
	registration := protocolenvelope.Registration{
		Kind: protocolenvelope.RegistrationKind, Protocol: protocolenvelope.Protocol,
		ProtocolVersion: protocolenvelope.ProtocolVersion, EventID: "example-event-2026", EventEpoch: "1",
		OperationID: registrationID, ActorID: "42", KeyID: pair.Public.KeyID, KeyEpoch: "1",
		BaseRepository: repository, ConfigDigest: strings.Repeat("1", 64), TermsDigest: strings.Repeat("2", 64),
		IssuedAt: "2026-08-05T00:00:00Z", ExpiresAt: "2026-08-05T00:15:00Z",
		ParticipantKey: pair.Public, Signature: signature,
	}
	proposal := team.Proposal{
		Kind: team.ProposalKind, Protocol: protocolenvelope.Protocol,
		ProtocolVersion: protocolenvelope.ProtocolVersion, EventID: registration.EventID, EventEpoch: "1",
		OperationID: proposalID, TeamID: teamID, ProposerActorID: "42", KeyID: pair.Public.KeyID, KeyEpoch: "1",
		MemberActorIDs: []string{"42", "100"}, BaseRepository: repository,
		ConfigDigest: strings.Repeat("1", 64), IssuedAt: registration.IssuedAt, ExpiresAt: registration.ExpiresAt,
		Signature: signature,
	}
	consent := team.Consent{
		Kind: team.ConsentKind, Protocol: protocolenvelope.Protocol,
		ProtocolVersion: protocolenvelope.ProtocolVersion, EventID: registration.EventID, EventEpoch: "1",
		OperationID: consentID, TeamID: teamID, ProposalDigest: strings.Repeat("3", 64),
		ActorID: "42", KeyID: pair.Public.KeyID, KeyEpoch: "1", Decision: "consent",
		BaseRepository: repository, ConfigDigest: strings.Repeat("1", 64),
		IssuedAt: registration.IssuedAt, ExpiresAt: registration.ExpiresAt, Signature: signature,
	}
	submission := protocolenvelope.Submission{
		Kind: protocolenvelope.SubmissionKind, Protocol: protocolenvelope.Protocol,
		ProtocolVersion: protocolenvelope.ProtocolVersion, EventID: registration.EventID, EventEpoch: "1",
		RequestID: submissionID, AttemptID: attemptID, ActorID: "42", KeyID: pair.Public.KeyID, KeyEpoch: "1",
		TeamID: teamID, TeamProposalDigest: strings.Repeat("3", 64), BaseRepository: repository,
		PullRequest: protocolenvelope.PullRequest{
			Number: 7, ID: "700", BaseRepositoryID: repository.ID, BaseRef: "main",
			HeadRepositoryID: "456", HeadOwner: "participant", HeadRef: "submission",
			HeadSHA: strings.Repeat("4", 40),
		},
		ConfigDigest: strings.Repeat("1", 64), IssuedAt: registration.IssuedAt, ExpiresAt: registration.ExpiresAt,
		DeliveryMode: protocolenvelope.SubmissionDeliveryMode,
		Bundle: protocolenvelope.BundleReference{
			Path: "submission.eventctl", SizeBytes: 2048, SHA256: strings.Repeat("5", 64),
			EnvelopeSHA256: strings.Repeat("6", 64), CiphertextSize: 1024,
			CiphertextSHA256: strings.Repeat("7", 64), Format: protocolenvelope.SubmissionBundleFormat,
		},
		Signature: signature,
	}
	return []classifierFixture{
		fixtureFromValue(t, "registration", registration, registration.Kind, registrationID),
		fixtureFromValue(t, "team proposal", proposal, proposal.Kind, proposalID),
		fixtureFromValue(t, "team consent", consent, consent.Kind, consentID),
		fixtureFromValue(t, "submission", submission, submission.Kind, submissionID),
	}
}

func fixtureFromValue(t *testing.T, name string, value any, kind, requestID string) classifierFixture {
	t.Helper()
	raw, err := canonical.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return classifierFixture{name: name, raw: raw, kind: kind, requestID: requestID}
}

func wrapClassifierRequest(raw []byte) []byte {
	wrapped := append([]byte(`{"envelope":`), raw...)
	return append(wrapped, '}')
}

func (fixture classifierFixture) registration(t *testing.T) protocolenvelope.Registration {
	t.Helper()
	var document protocolenvelope.Registration
	if err := canonical.StrictUnmarshal(fixture.raw, &document); err != nil {
		t.Fatal(err)
	}
	return document
}
