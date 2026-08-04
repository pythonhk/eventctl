package envelope

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pythonhk/eventctl/internal/identity"
)

const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testPair(t *testing.T, fill byte) identity.KeyPair {
	t.Helper()
	pair, err := identity.GenerateFrom(bytes.NewReader(bytes.Repeat([]byte{fill}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func registrationParams() RegistrationParams {
	issued := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	return RegistrationParams{
		EventID: "summer-data-2026", EventEpoch: "1", OperationID: "123e4567-e89b-42d3-a456-426614174000",
		ActorID: "42", KeyEpoch: "1", BaseRepository: Repository{ID: "123456789", Owner: "pythonhk", Name: "event"},
		ConfigDigest: testDigest, TermsDigest: strings.Repeat("a", 64), IssuedAt: issued, ExpiresAt: issued.Add(15 * time.Minute),
	}
}

func TestRegistrationRoundTripAndExpectedContext(t *testing.T) {
	t.Parallel()
	pair := testPair(t, 3)
	raw, err := NewRegistration(registrationParams(), pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	expected := Expected{EventID: "summer-data-2026", EventEpoch: "1", RepositoryID: "123456789", ActorID: "42", ConfigDigest: testDigest, Now: registrationParams().IssuedAt.Add(time.Minute)}
	verified, err := VerifyRegistration(raw, expected)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Document.ParticipantKey != pair.Public {
		t.Fatal("participant key mismatch")
	}
	if err := verified.Fingerprint.Validate(); err != nil {
		t.Fatal(err)
	}
	expected.ActorID = "43"
	if _, err := VerifyRegistration(raw, expected); err == nil {
		t.Fatal("accepted wrong trusted actor")
	}
}

func TestRegistrationMutationAndUnknownFieldFail(t *testing.T) {
	t.Parallel()
	pair := testPair(t, 4)
	raw, err := NewRegistration(registrationParams(), pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	mutated := bytes.Replace(raw, []byte(`"actor_id":"42"`), []byte(`"actor_id":"43"`), 1)
	if _, err := VerifyRegistration(mutated, Expected{}); err == nil {
		t.Fatal("accepted mutated actor")
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown"] = true
	withUnknown, _ := json.Marshal(object)
	if _, err := VerifyRegistration(withUnknown, Expected{}); err == nil {
		t.Fatal("accepted unknown field")
	}
}

func TestReplayClassificationConflictsAcrossChangedIntent(t *testing.T) {
	t.Parallel()
	first, err := NewFingerprint("registration_request", "summer-data-2026", "123e4567-e89b-42d3-a456-426614174000", strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	if first.ReplayKey != "593f0bd3b4c189f58c59677cb9a4d66f7ddb202f9cf57b107d65a8dc8a36d95e" {
		t.Fatalf("replay key = %q", first.ReplayKey)
	}
	if got, err := ClassifyReplay(&first, first); err != nil || got != ReplayDuplicate {
		t.Fatalf("duplicate = %q, %v", got, err)
	}
	second := first
	second.RequestDigest = strings.Repeat("2", 64)
	if got, err := ClassifyReplay(&first, second); err != nil || got != ReplayConflict {
		t.Fatalf("conflict = %q, %v", got, err)
	}
}

func TestRequestIDGeneration(t *testing.T) {
	t.Parallel()
	requestID, err := NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	if !IsUUID(requestID) {
		t.Fatalf("request ID = %q", requestID)
	}
}

func TestRegistrationValidityUsesTrustedSourceTime(t *testing.T) {
	t.Parallel()
	pair := testPair(t, 17)
	params := registrationParams()
	params.IssuedAt = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	params.ExpiresAt = params.IssuedAt.Add(30 * time.Minute)
	raw, err := NewRegistration(params, pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	// A controller may process this durable source much later; the verifier's
	// Now is the immutable GitHub source creation time, not processing time.
	if _, err := VerifyRegistration(raw, Expected{Now: params.IssuedAt.Add(10 * time.Minute)}); err != nil {
		t.Fatalf("valid delayed source was rejected: %v", err)
	}
	if _, err := VerifyRegistration(raw, Expected{Now: params.IssuedAt.Add(-time.Second)}); err == nil {
		t.Fatal("pre-issued source time was accepted")
	}
	if _, err := VerifyRegistration(raw, Expected{Now: params.ExpiresAt.Add(time.Second)}); err == nil {
		t.Fatal("post-expiry source time was accepted")
	}
}
