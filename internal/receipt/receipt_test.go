package receipt

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
	"github.com/pythonhk/eventctl/internal/statepointer"
)

func TestSignedReceiptExactTransportBoundary(t *testing.T) {
	pair := receiptTestPair(t, 29)
	claim := receiptTestClaim()
	claim.EventID = "e" + strings.Repeat("1", 62)
	claim.BaseRepositoryID = "18446744073709551615"
	claim.ActorID = "18446744073709551615"
	claim.Operation = "submission.finalize"
	claim.RequestKind = "scorer_result"
	claim.Outcome = "failed"
	reason := "r" + strings.Repeat("1", 63)
	claim.ReasonCode = &reason
	claim.QuotaCharged = false
	claim.StateBefore.Sequence = statepointer.MaxSequenceV1 - 1
	claim.StateAfter.Sequence = statepointer.MaxSequenceV1
	claim.ScorerResultDigest = claim.RequestDocumentDigest
	reservationDigest := strings.Repeat("9", 64)
	claim.ReservationReceiptDigest = &reservationDigest
	expected := SignExpected{
		EventID: claim.EventID, EventEpoch: claim.EventEpoch,
		BaseRepositoryID: claim.BaseRepositoryID, ConfigDigest: claim.ConfigDigest,
		SigningKey: pair.Public, CurrentState: claim.StateAfter,
	}
	document, err := SignCommitted(claim, expected, pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := canonical.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != MaxSignedBytes {
		t.Fatalf("worst-case signed receipt is %d bytes, want %d", len(raw), MaxSignedBytes)
	}
	if base64.StdEncoding.EncodedLen(len(raw)) != MaxPaddedBase64Chars || base64.StdEncoding.EncodedLen(len(raw)+1) != MaxPaddedBase64Chars {
		t.Fatalf("padded base64 limit does not cover the bounded document and one terminal LF")
	}

	withLF := append(append([]byte(nil), raw...), '\n')
	if _, err := Verify(withLF, Expected{
		EventID: claim.EventID, EventEpoch: claim.EventEpoch,
		BaseRepositoryID: claim.BaseRepositoryID, ConfigDigest: claim.ConfigDigest,
		SigningKey: pair.Public, CurrentState: claim.StateAfter,
	}); err != nil {
		t.Fatalf("boundary signed receipt with one framing LF did not round-trip: %v", err)
	}
	overLimit := append(append([]byte(nil), raw...), ' ')
	if _, err := Parse(overLimit); err == nil {
		t.Fatal("accepted a signed receipt above the raw document limit")
	}
	wrongFraming := append(append([]byte(nil), raw...), '\r')
	if _, err := Parse(wrongFraming); err == nil {
		t.Fatal("accepted over-limit signed receipt framing other than one terminal LF")
	}
}

func TestCommittedClaimKeepsGenericDocumentLimit(t *testing.T) {
	claimRaw, err := canonical.Marshal(receiptTestClaim())
	if err != nil {
		t.Fatal(err)
	}
	if len(claimRaw) >= MaxSignedBytesWithLF {
		t.Fatalf("claim fixture unexpectedly too large: %d bytes", len(claimRaw))
	}
	claimRaw = append(claimRaw, bytes.Repeat([]byte{' '}, MaxSignedBytesWithLF-len(claimRaw))...)
	if _, err := ParseCommittedClaim(claimRaw); err != nil {
		t.Fatalf("committed claim incorrectly inherited signed-receipt limit: %v", err)
	}
}

func TestSignCommittedVerifyGolden(t *testing.T) {
	pair := receiptTestPair(t, 7)
	claim := receiptTestClaim()
	expected := receiptSignExpected(pair, claim.StateAfter)
	document, err := SignCommitted(claim, expected, pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := canonical.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(raw, Expected{
		EventID: claim.EventID, EventEpoch: claim.EventEpoch, SigningKey: pair.Public,
		BaseRepositoryID: claim.BaseRepositoryID, ConfigDigest: claim.ConfigDigest,
		CurrentState: expected.CurrentState, Now: time.Date(2030, 6, 1, 3, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verified.Document, document) {
		t.Fatalf("verified document differs: %#v", verified.Document)
	}
	const wantDocumentDigest = "2cc2bbd85d30bde5d71520a12c756899c66f81972bb74679d52f248cb381e33d"
	if verified.DocumentDigest != wantDocumentDigest {
		t.Fatalf("document digest = %s, want %s", verified.DocumentDigest, wantDocumentDigest)
	}
	if err := document.ValidateSourceWindow("2030-06-01T01:55:00Z", "2030-06-01T02:05:00Z"); err != nil {
		t.Fatalf("ValidateSourceWindow() error = %v", err)
	}

	retry, err := SignCommitted(claim, expected, pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	retryRaw, _ := canonical.Marshal(retry)
	if !bytes.Equal(raw, retryRaw) {
		t.Fatal("deterministic retry produced different signed receipt bytes")
	}
}

func TestReceiptRejectsTamperingAndUncommittedClaims(t *testing.T) {
	pair := receiptTestPair(t, 7)
	claim := receiptTestClaim()
	expected := receiptSignExpected(pair, claim.StateAfter)
	document, err := SignCommitted(claim, expected, pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := canonical.Marshal(document)

	t.Run("tampered signed actor", func(t *testing.T) {
		tampered := document
		tampered.ActorID = "43"
		tamperedRaw, _ := canonical.Marshal(tampered)
		if _, err := Verify(tamperedRaw, Expected{EventID: claim.EventID, EventEpoch: claim.EventEpoch, BaseRepositoryID: claim.BaseRepositoryID, ConfigDigest: claim.ConfigDigest, SigningKey: pair.Public, CurrentState: claim.StateAfter}); err == nil {
			t.Fatal("Verify() accepted tampered receipt")
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		withUnknown := append([]byte(`{"unknown":true,`), raw[1:]...)
		if _, err := Parse(withUnknown); err == nil {
			t.Fatal("Parse() accepted unknown field")
		}
	})

	t.Run("future state", func(t *testing.T) {
		current := statepointer.Pointer{Sequence: claim.StateAfter.Sequence - 1, JournalEventDigest: claim.StateBefore.JournalEventDigest}
		if _, err := Verify(raw, Expected{EventID: claim.EventID, EventEpoch: claim.EventEpoch, BaseRepositoryID: claim.BaseRepositoryID, ConfigDigest: claim.ConfigDigest, SigningKey: pair.Public, CurrentState: current}); err == nil {
			t.Fatal("Verify() accepted receipt ahead of protected state")
		}
	})

	t.Run("older state without authenticated membership", func(t *testing.T) {
		later := statepointer.Pointer{Sequence: 9, JournalEventDigest: strings.Repeat("9", 64)}
		laterSignExpected := receiptSignExpected(pair, later)
		if _, err := SignCommitted(claim, laterSignExpected, pair.Private); err == nil {
			t.Fatal("SignCommitted() accepted state 5/f against trusted state 9/9")
		}
		if _, err := Verify(raw, Expected{EventID: claim.EventID, EventEpoch: claim.EventEpoch, BaseRepositoryID: claim.BaseRepositoryID, ConfigDigest: claim.ConfigDigest, SigningKey: pair.Public, CurrentState: later}); err == nil {
			t.Fatal("Verify() accepted state 5/f against trusted state 9/9")
		}
	})

	t.Run("same sequence different digest", func(t *testing.T) {
		current := statepointer.Pointer{Sequence: claim.StateAfter.Sequence, JournalEventDigest: strings.Repeat("9", 64)}
		if _, err := SignCommitted(claim, receiptSignExpected(pair, current), pair.Private); err == nil {
			t.Fatal("SignCommitted() accepted a different digest at the trusted sequence")
		}
		if _, err := Verify(raw, Expected{EventID: claim.EventID, EventEpoch: claim.EventEpoch, BaseRepositoryID: claim.BaseRepositoryID, ConfigDigest: claim.ConfigDigest, SigningKey: pair.Public, CurrentState: current}); err == nil {
			t.Fatal("Verify() accepted a different digest at the trusted sequence")
		}
	})

	t.Run("wrong signer", func(t *testing.T) {
		wrong := receiptTestPair(t, 9)
		if _, err := Verify(raw, Expected{EventID: claim.EventID, EventEpoch: claim.EventEpoch, BaseRepositoryID: claim.BaseRepositoryID, ConfigDigest: claim.ConfigDigest, SigningKey: wrong.Public, CurrentState: claim.StateAfter}); err == nil {
			t.Fatal("Verify() accepted wrong configured signer")
		}
	})

	t.Run("wrong repository", func(t *testing.T) {
		context := Expected{EventID: claim.EventID, EventEpoch: claim.EventEpoch, BaseRepositoryID: "987654321", ConfigDigest: claim.ConfigDigest, SigningKey: pair.Public, CurrentState: claim.StateAfter}
		if _, err := Verify(raw, context); err == nil {
			t.Fatal("Verify() accepted a receipt for another repository")
		}
	})

	t.Run("wrong archived config", func(t *testing.T) {
		context := Expected{EventID: claim.EventID, EventEpoch: claim.EventEpoch, BaseRepositoryID: claim.BaseRepositoryID, ConfigDigest: strings.Repeat("0", 64), SigningKey: pair.Public, CurrentState: claim.StateAfter}
		if _, err := Verify(raw, context); err == nil {
			t.Fatal("Verify() accepted a receipt under another config")
		}
	})

	t.Run("pre-commit claim", func(t *testing.T) {
		uncommitted := claim
		uncommitted.CommitStatus = "rejected"
		if _, err := SignCommitted(uncommitted, expected, pair.Private); err == nil {
			t.Fatal("SignCommitted() signed a rejected claim")
		}
	})

	t.Run("source after commit", func(t *testing.T) {
		invalid := claim
		invalid.SourceCreatedAt = "2030-06-01T02:01:00Z"
		if _, err := SignCommitted(invalid, expected, pair.Private); err == nil {
			t.Fatal("SignCommitted() accepted source time after commit")
		}
	})

	t.Run("submission without quota charge", func(t *testing.T) {
		invalid := claim
		invalid.QuotaCharged = false
		if _, err := SignCommitted(invalid, expected, pair.Private); err == nil {
			t.Fatal("SignCommitted() accepted uncharged submission reservation")
		}
	})

	t.Run("valid registration shape", func(t *testing.T) {
		valid := claim
		valid.Operation = "participant.register"
		valid.RequestKind = envelope.RegistrationKind
		valid.QuotaCharged = false
		valid.TeamID = nil
		valid.AttemptID = nil
		if _, err := SignCommitted(valid, expected, pair.Private); err != nil {
			t.Fatalf("SignCommitted() rejected a valid registration claim: %v", err)
		}
	})

	t.Run("valid team shape", func(t *testing.T) {
		valid := claim
		valid.Operation = "team.propose"
		valid.RequestKind = "team_proposal"
		valid.QuotaCharged = false
		valid.AttemptID = nil
		if _, err := SignCommitted(valid, expected, pair.Private); err != nil {
			t.Fatalf("SignCommitted() rejected a valid team claim: %v", err)
		}
	})

	t.Run("registration carries team", func(t *testing.T) {
		invalid := claim
		invalid.Operation = "participant.register"
		invalid.RequestKind = envelope.RegistrationKind
		invalid.QuotaCharged = false
		invalid.AttemptID = nil
		if _, err := SignCommitted(invalid, expected, pair.Private); err == nil {
			t.Fatal("SignCommitted() accepted a registration claim with team_id")
		}
	})

	t.Run("team operation omits team", func(t *testing.T) {
		invalid := claim
		invalid.Operation = "team.propose"
		invalid.RequestKind = "team_proposal"
		invalid.QuotaCharged = false
		invalid.TeamID = nil
		invalid.AttemptID = nil
		if _, err := SignCommitted(invalid, expected, pair.Private); err == nil {
			t.Fatal("SignCommitted() accepted a team claim without team_id")
		}
	})
}

func TestCommittedReceiptOperationShapes(t *testing.T) {
	pair := receiptTestPair(t, 17)
	base := receiptTestClaim()
	expected := receiptSignExpected(pair, base.StateAfter)
	teamID := "22222222-2222-4222-8222-222222222222"
	attemptID := "33333333-3333-4333-8333-333333333333"
	resultDigest := *base.RequestDocumentDigest
	reservationDigest := strings.Repeat("9", 64)
	reasonCode := "judge_timeout"

	registration := base
	registration.Operation = "participant.register"
	registration.RequestKind = envelope.RegistrationKind
	registration.TeamID = nil
	registration.AttemptID = nil
	registration.QuotaCharged = false

	teamProposal := base
	teamProposal.Operation = "team.propose"
	teamProposal.RequestKind = "team_proposal"
	teamProposal.TeamID = &teamID
	teamProposal.AttemptID = nil
	teamProposal.QuotaCharged = false

	teamConsent := teamProposal
	teamConsent.Operation = "team.consent"
	teamConsent.RequestKind = "team_consent"

	submission := base

	scorerResult := base
	scorerResult.Operation = "submission.finalize"
	scorerResult.RequestKind = "scorer_result"
	scorerResult.TeamID = &teamID
	scorerResult.AttemptID = &attemptID
	scorerResult.QuotaCharged = false
	scorerResult.ScorerResultDigest = &resultDigest
	scorerResult.ReservationReceiptDigest = &reservationDigest

	failedScorerResult := scorerResult
	failedScorerResult.Outcome = "failed"
	failedScorerResult.ReasonCode = &reasonCode

	tests := []struct {
		name  string
		claim CommittedClaim
		valid bool
	}{
		{"registration", registration, true},
		{"registration without request document digest", mutateClaim(registration, func(value *CommittedClaim) { value.RequestDocumentDigest = nil }), false},
		{"registration with team", mutateClaim(registration, func(value *CommittedClaim) { value.TeamID = &teamID }), false},
		{"registration with attempt", mutateClaim(registration, func(value *CommittedClaim) { value.AttemptID = &attemptID }), false},
		{"team proposal", teamProposal, true},
		{"team consent", teamConsent, true},
		{"team without request document digest", mutateClaim(teamProposal, func(value *CommittedClaim) { value.RequestDocumentDigest = nil }), false},
		{"team without team", mutateClaim(teamProposal, func(value *CommittedClaim) { value.TeamID = nil }), false},
		{"team with attempt", mutateClaim(teamProposal, func(value *CommittedClaim) { value.AttemptID = &attemptID }), false},
		{"submission", submission, true},
		{"submission without request document digest", mutateClaim(submission, func(value *CommittedClaim) { value.RequestDocumentDigest = nil }), false},
		{"submission without team", mutateClaim(submission, func(value *CommittedClaim) { value.TeamID = nil }), false},
		{"submission without attempt", mutateClaim(submission, func(value *CommittedClaim) { value.AttemptID = nil }), false},
		{"submission without quota", mutateClaim(submission, func(value *CommittedClaim) { value.QuotaCharged = false }), false},
		{"participant with scorer digest", mutateClaim(submission, func(value *CommittedClaim) { value.ScorerResultDigest = &resultDigest }), false},
		{"failed participant", mutateClaim(submission, func(value *CommittedClaim) { value.Outcome = "failed"; value.ReasonCode = &reasonCode }), false},
		{"scorer result", scorerResult, true},
		{"failed scorer result", failedScorerResult, true},
		{"scorer result without request document digest", mutateClaim(scorerResult, func(value *CommittedClaim) { value.RequestDocumentDigest = nil }), false},
		{"scorer result without team", mutateClaim(scorerResult, func(value *CommittedClaim) { value.TeamID = nil }), false},
		{"scorer result without attempt", mutateClaim(scorerResult, func(value *CommittedClaim) { value.AttemptID = nil }), false},
		{"scorer result charging quota", mutateClaim(scorerResult, func(value *CommittedClaim) { value.QuotaCharged = true }), false},
		{"scorer result without result digest", mutateClaim(scorerResult, func(value *CommittedClaim) { value.ScorerResultDigest = nil }), false},
		{"scorer result with wrong result digest", mutateClaim(scorerResult, func(value *CommittedClaim) { wrong := strings.Repeat("8", 64); value.ScorerResultDigest = &wrong }), false},
		{"scorer result without reservation digest", mutateClaim(scorerResult, func(value *CommittedClaim) { value.ReservationReceiptDigest = nil }), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := SignCommitted(test.claim, expected, pair.Private)
			if test.valid && err != nil {
				t.Fatalf("SignCommitted() rejected valid claim: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("SignCommitted() accepted invalid claim")
			}
		})
	}
}

func TestSubmissionCancellationReceiptContract(t *testing.T) {
	pair := receiptTestPair(t, 23)
	base := receiptTestClaim()
	reasonCode := "organizer_cancelled"
	reservationDigest := strings.Repeat("9", 64)
	claim := base
	claim.Operation = CancellationOperation
	claim.RequestKind = CancellationKind
	claim.RequestDocumentDigest = nil
	claim.Outcome = "failed"
	claim.ReasonCode = &reasonCode
	claim.QuotaCharged = false
	claim.ReservationReceiptDigest = &reservationDigest
	claim.SourceCreatedAt = claim.IssuedAt
	const canonicalCancellation = `{"attempt_id":"33333333-3333-4333-8333-333333333333","reason_code":"organizer_cancelled","reservation_receipt_digest":"9999999999999999999999999999999999999999999999999999999999999999"}`
	const requestDigest = "4695b99bc6a8bc85ccf117206fe36549c560ae717230e2d23220f274c8f213c5"
	derivedDigest, err := cancellationRequestDigest(*claim.AttemptID, reservationDigest, reasonCode)
	if err != nil {
		t.Fatal(err)
	}
	if derivedDigest != requestDigest || envelope.Digest([]byte(canonicalCancellation)) != requestDigest {
		t.Fatalf("cancellation request digest = %q, want no-LF canonical digest %q", derivedDigest, requestDigest)
	}
	claim.RequestDigest = requestDigest
	requestDigestWithLF := envelope.Digest(append([]byte(canonicalCancellation), '\n'))

	document, err := SignCommitted(claim, receiptSignExpected(pair, claim.StateAfter), pair.Private)
	if err != nil {
		t.Fatalf("SignCommitted() rejected the exact cancellation operation/request pair: %v", err)
	}
	raw, err := canonical.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"request_document_digest":null`)) {
		t.Fatalf("signed cancellation receipt does not encode a null request_document_digest: %s", raw)
	}
	if _, err := Verify(raw, Expected{
		EventID: claim.EventID, EventEpoch: claim.EventEpoch,
		BaseRepositoryID: claim.BaseRepositoryID, ConfigDigest: claim.ConfigDigest,
		SigningKey: pair.Public, CurrentState: claim.StateAfter,
	}); err != nil {
		t.Fatalf("Verify() rejected the signed cancellation receipt: %v", err)
	}

	tests := []struct {
		name      string
		mutate    func(*CommittedClaim)
		wantError string
	}{
		{"cancellation operation with scorer result kind", func(value *CommittedClaim) { value.RequestKind = "scorer_result" }, "operation/request_kind binding"},
		{"finalization operation with cancellation kind", func(value *CommittedClaim) { value.Operation = "submission.finalize" }, "operation/request_kind binding"},
		{"request document digest", func(value *CommittedClaim) { value.RequestDocumentDigest = base.RequestDocumentDigest }, "cancellation receipt"},
		{"accepted outcome", func(value *CommittedClaim) { value.Outcome = "accepted"; value.ReasonCode = nil }, "cancellation receipt"},
		{"missing reason", func(value *CommittedClaim) { value.ReasonCode = nil }, "requires a bounded reason_code"},
		{"invalid reason", func(value *CommittedClaim) { invalid := "Organizer-Cancelled"; value.ReasonCode = &invalid }, "requires a bounded reason_code"},
		{"changed reason without matching digest", func(value *CommittedClaim) { changed := "manual_cancel"; value.ReasonCode = &changed }, "request_digest does not bind"},
		{"trailing LF request digest", func(value *CommittedClaim) { value.RequestDigest = requestDigestWithLF }, "request_digest does not bind"},
		{"source time before commit", func(value *CommittedClaim) { value.SourceCreatedAt = "2030-06-01T01:59:59Z" }, "source_created_at must equal"},
		{"quota charge", func(value *CommittedClaim) { value.QuotaCharged = true }, "cancellation receipt"},
		{"missing team", func(value *CommittedClaim) { value.TeamID = nil }, "cancellation receipt"},
		{"missing attempt", func(value *CommittedClaim) { value.AttemptID = nil }, "cancellation receipt"},
		{"scorer result digest", func(value *CommittedClaim) { value.ScorerResultDigest = base.RequestDocumentDigest }, "cancellation receipt"},
		{"missing reservation receipt digest", func(value *CommittedClaim) { value.ReservationReceiptDigest = nil }, "cancellation receipt"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := claim
			test.mutate(&invalid)
			_, err := SignCommitted(invalid, receiptSignExpected(pair, invalid.StateAfter), pair.Private)
			if err == nil {
				t.Fatal("SignCommitted() accepted an invalid cancellation claim")
			}
			if !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("SignCommitted() error = %q, want it to contain %q", err, test.wantError)
			}
		})
	}
}

func mutateClaim(claim CommittedClaim, mutate func(*CommittedClaim)) CommittedClaim {
	mutate(&claim)
	return claim
}

func receiptTestPair(t *testing.T, fill byte) identity.KeyPair {
	t.Helper()
	pair, err := identity.FromSeed(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func receiptTestClaim() CommittedClaim {
	teamID := "22222222-2222-4222-8222-222222222222"
	attemptID := "33333333-3333-4333-8333-333333333333"
	requestDocumentDigest := strings.Repeat("d", 64)
	return CommittedClaim{
		Kind: ClaimKind, Protocol: envelope.Protocol, ProtocolVersion: envelope.ProtocolVersion,
		EventID: "pyhk-2030", EventEpoch: "1", BaseRepositoryID: "123456789",
		ConfigDigest: strings.Repeat("a", 64), CommitStatus: "receipt_pending",
		Operation: "submission.reserve", ReceiptID: "11111111-1111-4111-8111-111111111111",
		OperationID: "11111111-1111-4111-8111-111111111111",
		RequestKind: envelope.SubmissionKind, ReplayKey: strings.Repeat("b", 64),
		RequestDigest: strings.Repeat("c", 64), RequestDocumentDigest: &requestDocumentDigest,
		ActorID: "42", TeamID: &teamID, AttemptID: &attemptID, Outcome: "accepted",
		QuotaCharged:    true,
		StateBefore:     statepointer.Pointer{Sequence: 4, JournalEventDigest: strings.Repeat("e", 64)},
		StateAfter:      statepointer.Pointer{Sequence: 5, JournalEventDigest: strings.Repeat("f", 64)},
		SourceCreatedAt: "2030-06-01T01:59:00Z", IssuedAt: "2030-06-01T02:00:00Z",
	}
}

func receiptSignExpected(pair identity.KeyPair, current statepointer.Pointer) SignExpected {
	return SignExpected{
		EventID: "pyhk-2030", EventEpoch: "1", BaseRepositoryID: "123456789",
		ConfigDigest: strings.Repeat("a", 64), SigningKey: pair.Public, CurrentState: current,
	}
}

func FuzzParseReceipt(f *testing.F) {
	f.Add([]byte(`{}`))
	pair, _ := identity.FromSeed(bytes.Repeat([]byte{7}, 32))
	document, err := SignCommitted(receiptTestClaim(), receiptSignExpected(pair, receiptTestClaim().StateAfter), pair.Private)
	if err == nil {
		raw, _ := canonical.Marshal(document)
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = Parse(raw)
	})
}
