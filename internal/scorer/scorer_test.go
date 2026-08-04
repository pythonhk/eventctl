package scorer

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
	"github.com/pythonhk/eventctl/internal/statepointer"
)

func TestSignAndVerifyDelayedScorerResultGolden(t *testing.T) {
	pair := scorerTestPair(t, 11)
	request := scorerTestRequest()
	expected := scorerTestExpected(pair.Public)
	requestDigest, err := envelope.DocumentDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	total := int64(1250000)
	payload := UnsignedResult{
		Kind: ResultKind, Protocol: envelope.Protocol, ProtocolVersion: envelope.ProtocolVersion,
		EventID: request.EventID, EventEpoch: request.EventEpoch,
		ResultID: "77777777-7777-4777-8777-777777777777", AttemptID: request.AttemptID,
		ActorID: request.ActorID, TeamID: request.TeamID, ScorerRequestDigest: requestDigest,
		SubmissionEnvelopeDigest: request.SubmissionEnvelopeDigest,
		CiphertextDigest:         request.Bundle.CiphertextSHA256, ConfigDigest: request.ConfigDigest,
		Reservation: request.Reservation, Scorer: request.Scorer, Status: "scored",
		TotalMicropoints: &total, Metrics: []Metric{{Name: "correctness", Micropoints: total}},
		CompletedAt: "2030-06-02T03:00:00Z",
	}
	document, err := SignResult(payload, request, expected, pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	requestRaw, _ := canonical.Marshal(request)
	resultRaw, _ := canonical.Marshal(document)
	verified, err := Verify(requestRaw, resultRaw, expected)
	if err != nil {
		t.Fatal(err)
	}
	const wantRequestDigest = "940161da12a674103009c9b6908ab56f9a4fc7a5aef25fe60784cc3e220159b7"
	const wantDocumentDigest = "6526a4b0fbb5a9df6ef640a6d36f0e680455493e2d19b84b713dc448bd3c184d"
	const wantReplayDigest = "63a928509e6bfa575b0dadf3c376dcf3d76963b2d18745947155e20230bb92f5"
	if verified.ScorerRequestDigest != wantRequestDigest {
		t.Fatalf("scorer request digest = %s, want %s", verified.ScorerRequestDigest, wantRequestDigest)
	}
	if verified.DocumentDigest != wantDocumentDigest {
		t.Fatalf("result document digest = %s, want %s", verified.DocumentDigest, wantDocumentDigest)
	}
	if verified.Fingerprint.RequestDigest != wantReplayDigest {
		t.Fatalf("result request digest = %s, want %s", verified.Fingerprint.RequestDigest, wantReplayDigest)
	}
}

func TestScorerRejectsBindingAndSchemaAttacks(t *testing.T) {
	pair := scorerTestPair(t, 11)
	request := scorerTestRequest()
	expected := scorerTestExpected(pair.Public)
	requestDigest, _ := envelope.DocumentDigest(request)
	reason := "judge_timeout"
	payload := UnsignedResult{
		Kind: ResultKind, Protocol: envelope.Protocol, ProtocolVersion: envelope.ProtocolVersion,
		EventID: request.EventID, EventEpoch: request.EventEpoch,
		ResultID: "77777777-7777-4777-8777-777777777777", AttemptID: request.AttemptID,
		ActorID: request.ActorID, TeamID: request.TeamID, ScorerRequestDigest: requestDigest,
		SubmissionEnvelopeDigest: request.SubmissionEnvelopeDigest,
		CiphertextDigest:         request.Bundle.CiphertextSHA256, ConfigDigest: request.ConfigDigest,
		Reservation: request.Reservation, Scorer: request.Scorer, Status: "timeout",
		Metrics: []Metric{}, ReasonCode: &reason, CompletedAt: "2030-06-02T03:00:00Z",
	}
	document, err := SignResult(payload, request, expected, pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	requestRaw, _ := canonical.Marshal(request)
	resultRaw, _ := canonical.Marshal(document)

	t.Run("tampered exact request", func(t *testing.T) {
		tampered := request
		tampered.Bundle.SHA256 = strings.Repeat("1", 64)
		tamperedRaw, _ := canonical.Marshal(tampered)
		if _, err := Verify(tamperedRaw, resultRaw, expected); err == nil {
			t.Fatal("Verify() accepted a different scorer request")
		}
	})

	t.Run("wrong configured signer", func(t *testing.T) {
		wrong := expected
		wrong.ResultKey = scorerTestPair(t, 12).Public
		if _, err := Verify(requestRaw, resultRaw, wrong); err == nil {
			t.Fatal("Verify() accepted wrong scorer key")
		}
	})

	t.Run("unknown result field", func(t *testing.T) {
		withUnknown := append([]byte(`{"unknown":true,`), resultRaw[1:]...)
		if _, err := Verify(requestRaw, withUnknown, expected); err == nil {
			t.Fatal("Verify() accepted unknown result field")
		}
	})

	t.Run("score on failure", func(t *testing.T) {
		total := int64(1)
		invalid := payload
		invalid.TotalMicropoints = &total
		if _, err := SignResult(invalid, request, expected, pair.Private); err == nil {
			t.Fatal("SignResult() accepted score for timeout")
		}
	})

	t.Run("source outside original window", func(t *testing.T) {
		invalid := request
		invalid.SourceCreatedAt = "2030-06-01T02:16:00Z"
		if err := invalid.Validate(); err == nil {
			t.Fatal("Request.Validate() accepted late immutable source")
		}
	})

	t.Run("completion before acceptance", func(t *testing.T) {
		invalid := payload
		invalid.CompletedAt = "2030-06-01T02:04:59Z"
		if _, err := SignResult(invalid, request, expected, pair.Private); err == nil {
			t.Fatal("SignResult() accepted result before reservation")
		}
	})

	t.Run("signed form exceeds configured result bytes", func(t *testing.T) {
		tight := expected
		tight.MaximumResultBytes = MinResultBytes
		if _, err := SignResult(payload, request, tight, pair.Private); err == nil {
			t.Fatal("SignResult() emitted a signed document above the configured byte cap")
		}
	})

	t.Run("unsorted metrics", func(t *testing.T) {
		total := int64(2)
		invalid := payload
		invalid.Status = "scored"
		invalid.TotalMicropoints = &total
		invalid.ReasonCode = nil
		invalid.Metrics = []Metric{{Name: "z_metric", Micropoints: 1}, {Name: "a_metric", Micropoints: 1}}
		if _, err := SignResult(invalid, request, expected, pair.Private); err == nil {
			t.Fatal("SignResult() accepted non-canonical metric ordering")
		}
	})
}

func TestScorerSynchronousTransportBudget(t *testing.T) {
	t.Parallel()
	const (
		responsePrefix = `{"kind":"scorer_response","protocol":"pythonhk.github-native-event","protocol_version":1,"scorer_request":`
		responseMiddle = `,"scorer_result":`
		responseSuffix = `}`
	)
	worstCaseRaw := uint64(len(responsePrefix)+len(responseMiddle)+len(responseSuffix)) + MaxRequestBytes + MaxResultBytes
	if worstCaseRaw > MaxSynchronousResponseBytes {
		t.Fatalf("worst-case strict scorer response = %d bytes, transport cap = %d", worstCaseRaw, MaxSynchronousResponseBytes)
	}
	t.Logf("worst-case strict scorer response uses %d of %d raw bytes", worstCaseRaw, MaxSynchronousResponseBytes)
	worstCaseBase64 := base64.StdEncoding.EncodedLen(int(worstCaseRaw))
	if worstCaseBase64 > MaxSynchronousResponseBase64Bytes {
		t.Fatalf("worst-case base64 scorer response = %d bytes, transport cap = %d", worstCaseBase64, MaxSynchronousResponseBase64Bytes)
	}
	if got := base64.StdEncoding.EncodedLen(MaxSynchronousResponseBytes); got != MaxSynchronousResponseBase64Bytes {
		t.Fatalf("raw/base64 transport caps disagree: encoded raw cap = %d, base64 cap = %d", got, MaxSynchronousResponseBase64Bytes)
	}
}

func TestScorerParserEnforcesFrozenTransportLimits(t *testing.T) {
	t.Parallel()
	if _, err := ParseRequest(bytes.Repeat([]byte{' '}, int(MaxRequestBytes+1))); err == nil {
		t.Fatalf("ParseRequest accepted more than %d bytes", MaxRequestBytes)
	}
	if _, err := ParseResult([]byte(`{}`), MaxResultBytes+1); err == nil {
		t.Fatalf("ParseResult accepted configured cap %d", MaxResultBytes+1)
	}
	if _, err := ParseUnsignedResult([]byte(`{}`), MaxResultBytes+1); err == nil {
		t.Fatalf("ParseUnsignedResult accepted configured cap %d", MaxResultBytes+1)
	}
	if _, err := ParseResult([]byte(`{}`), MinResultBytes-1); err == nil {
		t.Fatalf("ParseResult accepted configured cap %d", MinResultBytes-1)
	}

	identity := scorerTestRequest().Scorer
	identity.Version = "v" + strings.Repeat("1", 59) + ".0.0"
	if got := len(identity.Version); got != 64 {
		t.Fatalf("boundary scorer version length = %d, want 64", got)
	}
	if err := identity.Validate(); err != nil {
		t.Fatalf("64-byte scorer version rejected: %v", err)
	}
	identity.Version = "v" + strings.Repeat("1", 60) + ".0.0"
	if err := identity.Validate(); err == nil {
		t.Fatal("65-byte scorer version accepted")
	}
}

func scorerTestPair(t *testing.T, fill byte) identity.KeyPair {
	t.Helper()
	pair, err := identity.FromSeed(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func scorerTestRequest() Request {
	return Request{
		Kind: RequestKind, Protocol: envelope.Protocol, ProtocolVersion: envelope.ProtocolVersion,
		EventID: "pyhk-2030", EventEpoch: "1", AttemptID: "33333333-3333-4333-8333-333333333333",
		ActorID: "42", TeamID: "22222222-2222-4222-8222-222222222222",
		TeamProposalDigest: strings.Repeat("1", 64), ConfigDigest: strings.Repeat("2", 64),
		SubmissionEnvelopeDigest: strings.Repeat("3", 64), ReservationReceiptDigest: strings.Repeat("4", 64),
		Reservation:     statepointer.Pointer{Sequence: 5, JournalEventDigest: strings.Repeat("5", 64)},
		SourceCreatedAt: "2030-06-01T02:01:00Z", AcceptedAt: "2030-06-01T02:05:00Z",
		PullRequest: envelope.PullRequest{
			Number: 7, ID: "700", BaseRepositoryID: "123456789", BaseRef: "main",
			HeadRepositoryID: "987654321", HeadOwner: "participant", HeadRef: "event-submission",
			HeadSHA: strings.Repeat("6", 40),
		},
		Bundle: Bundle{Path: "submission.eventctl", MediaType: BundleMediaType, SizeBytes: 2048,
			SHA256: strings.Repeat("7", 64), EnvelopeSHA256: strings.Repeat("8", 64),
			CiphertextSize: 1024, CiphertextSHA256: strings.Repeat("9", 64)},
		Scorer:     Identity{ID: "reference_scorer", Version: "v1.2.3", PolicyDigest: strings.Repeat("a", 64)},
		Provenance: Provenance, IssuedAt: "2030-06-01T02:00:00Z", ExpiresAt: "2030-06-01T02:15:00Z",
	}
}

func scorerTestExpected(public identity.Public) Expected {
	request := scorerTestRequest()
	return Expected{
		EventID: request.EventID, EventEpoch: request.EventEpoch, BaseRepositoryID: request.PullRequest.BaseRepositoryID,
		BaseRef: request.PullRequest.BaseRef, ConfigDigest: request.ConfigDigest, Scorer: request.Scorer,
		ResultKey: public, MaximumResultBytes: MaxResultBytes, MaximumCiphertextBytes: 47_000_000,
		CurrentState: statepointer.Pointer{Sequence: 9, JournalEventDigest: strings.Repeat("b", 64)},
		Now:          time.Date(2030, 6, 2, 4, 0, 0, 0, time.UTC),
	}
}

func FuzzParseScorerArtifacts(f *testing.F) {
	f.Add([]byte(`{}`))
	requestRaw, _ := canonical.Marshal(scorerTestRequest())
	f.Add(requestRaw)
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseRequest(raw)
		_, _ = ParseResult(raw, MaxResultBytes)
		_, _ = ParseUnsignedResult(raw, MaxResultBytes)
	})
}
