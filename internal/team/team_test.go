package team

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
)

func pair(t *testing.T, fill byte) identity.KeyPair {
	t.Helper()
	p, err := identity.GenerateFrom(bytes.NewReader(bytes.Repeat([]byte{fill}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func registry(t *testing.T, entries []identity.RegistryEntry) identity.Registry {
	t.Helper()
	raw, _ := json.Marshal(identity.Registry{Schema: identity.RegistrySchema, Identities: entries})
	r, err := identity.ParseRegistry(raw)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestUnanimousTeamRequiresEveryMemberIncludingProposer(t *testing.T) {
	t.Parallel()
	a2, a10 := pair(t, 2), pair(t, 10)
	r := registry(t, []identity.RegistryEntry{{ActorID: "2", KeyEpoch: "1", Identity: a2.Public}, {ActorID: "10", KeyEpoch: "1", Identity: a10.Public}})
	issued := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	proposal, err := NewProposal(ProposalParams{EventID: "summer-data-2026", EventEpoch: "1", OperationID: "10000000-0000-4000-8000-000000000001", TeamID: "11000000-0000-4000-8000-000000000001", ProposerActorID: "2", KeyEpoch: "1", MemberActorIDs: []string{"10", "2"}, BaseRepository: envelope.Repository{ID: "9001", Owner: "pythonhk", Name: "event"}, ConfigDigest: strings.Repeat("a", 64), IssuedAt: issued, ExpiresAt: issued.Add(15 * time.Minute)}, a2.Private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyProposal(proposal, envelope.Expected{Now: issued.Add(time.Minute)}, 15*time.Minute, r)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Document.MemberActorIDs[0] != "2" || verified.Document.MemberActorIDs[1] != "10" {
		t.Fatalf("not numeric sort: %#v", verified.Document.MemberActorIDs)
	}
	c2, err := NewConsent(proposal, ConsentParams{OperationID: "20000000-0000-4000-8000-000000000002", ActorID: "2", KeyEpoch: "1", IssuedAt: issued, ExpiresAt: issued.Add(15 * time.Minute)}, a2.Private, r)
	if err != nil {
		t.Fatal(err)
	}
	c10, err := NewConsent(proposal, ConsentParams{OperationID: "30000000-0000-4000-8000-000000000003", ActorID: "10", KeyEpoch: "1", IssuedAt: issued, ExpiresAt: issued.Add(15 * time.Minute)}, a10.Private, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyUnanimous(proposal, [][]byte{c10}, envelope.Expected{Now: issued.Add(time.Minute)}, 15*time.Minute, r); err == nil {
		t.Fatal("accepted missing proposer consent")
	}
	candidate, err := VerifyUnanimous(proposal, [][]byte{c10, c2}, envelope.Expected{Now: issued.Add(time.Minute)}, 15*time.Minute, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.ConsentRequests) != 2 {
		t.Fatalf("candidate %#v", candidate)
	}
}

func TestProposalRejectsAttackerKeyForTrustedActor(t *testing.T) {
	t.Parallel()
	attacker, victim := pair(t, 1), pair(t, 2)
	issued := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	r := registry(t, []identity.RegistryEntry{{ActorID: "1", KeyEpoch: "1", Identity: victim.Public}})
	proposal, err := NewProposal(ProposalParams{EventID: "summer-data-2026", EventEpoch: "1", OperationID: "40000000-0000-4000-8000-000000000004", TeamID: "41000000-0000-4000-8000-000000000004", ProposerActorID: "1", MemberActorIDs: []string{"1"}, BaseRepository: envelope.Repository{ID: "9", Owner: "pythonhk", Name: "event"}, ConfigDigest: strings.Repeat("b", 64), IssuedAt: issued, ExpiresAt: issued.Add(time.Minute)}, attacker.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyProposal(proposal, envelope.Expected{}, 15*time.Minute, r); err == nil {
		t.Fatal("accepted attacker key")
	}
}

func TestDefaultSevenDayProposalWindow(t *testing.T) {
	t.Parallel()
	proposer := pair(t, 11)
	r := registry(t, []identity.RegistryEntry{{ActorID: "11", KeyEpoch: "1", Identity: proposer.Public}})
	issued := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	proposal, err := NewProposal(ProposalParams{
		EventID: "summer-data-2026", EventEpoch: "1",
		OperationID: "50000000-0000-4000-8000-000000000005", TeamID: "51000000-0000-4000-8000-000000000005",
		ProposerActorID: "11", KeyEpoch: "1", MemberActorIDs: []string{"11"},
		BaseRepository: envelope.Repository{ID: "9", Owner: "pythonhk", Name: "event"},
		ConfigDigest:   strings.Repeat("c", 64), IssuedAt: issued, ExpiresAt: issued.Add(7 * 24 * time.Hour),
	}, proposer.Private)
	if err != nil {
		t.Fatalf("create default seven-day proposal: %v", err)
	}
	if _, err := VerifyProposal(proposal, envelope.Expected{Now: issued.Add(time.Minute)}, 7*24*time.Hour, r); err != nil {
		t.Fatalf("verify default seven-day proposal: %v", err)
	}
	consent, err := NewConsent(proposal, ConsentParams{
		OperationID: "52000000-0000-4000-8000-000000000005", ActorID: "11", KeyEpoch: "1",
		IssuedAt: issued, ExpiresAt: issued.Add(7 * 24 * time.Hour),
	}, proposer.Private, r)
	if err != nil {
		t.Fatalf("create default seven-day consent: %v", err)
	}
	if _, err := VerifyConsent(proposal, consent, envelope.Expected{Now: issued.Add(time.Minute)}, 7*24*time.Hour, r); err != nil {
		t.Fatalf("verify default seven-day consent: %v", err)
	}
}

func TestTeamVerificationRejectsInvalidOrExceededConfiguredTTL(t *testing.T) {
	t.Parallel()
	proposer := pair(t, 12)
	r := registry(t, []identity.RegistryEntry{{ActorID: "12", KeyEpoch: "1", Identity: proposer.Public}})
	issued := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	base := ProposalParams{
		EventID: "summer-data-2026", EventEpoch: "1",
		OperationID: "60000000-0000-4000-8000-000000000006", TeamID: "61000000-0000-4000-8000-000000000006",
		ProposerActorID: "12", KeyEpoch: "1", MemberActorIDs: []string{"12"},
		BaseRepository: envelope.Repository{ID: "9", Owner: "pythonhk", Name: "event"},
		ConfigDigest:   strings.Repeat("d", 64), IssuedAt: issued,
	}

	overConfigured := base
	overConfigured.ExpiresAt = issued.Add(30 * time.Minute)
	proposal, err := NewProposal(overConfigured, proposer.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyProposal(proposal, envelope.Expected{Now: issued.Add(time.Minute)}, 15*time.Minute, r); err == nil {
		t.Fatal("accepted proposal above the signed config TTL")
	}
	if _, err := VerifyProposal(proposal, envelope.Expected{Now: issued.Add(time.Minute)}, MaxProposalTTL+time.Second, r); err == nil {
		t.Fatal("accepted an out-of-protocol configured proposal TTL")
	}

	compliant := base
	compliant.OperationID = "62000000-0000-4000-8000-000000000006"
	compliant.TeamID = "63000000-0000-4000-8000-000000000006"
	compliant.ExpiresAt = issued.Add(15 * time.Minute)
	proposal, err = NewProposal(compliant, proposer.Private)
	if err != nil {
		t.Fatal(err)
	}
	consent, err := NewConsent(proposal, ConsentParams{
		OperationID: "64000000-0000-4000-8000-000000000006", ActorID: "12", KeyEpoch: "1",
		IssuedAt: issued, ExpiresAt: issued.Add(30 * time.Minute),
	}, proposer.Private, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyConsent(proposal, consent, envelope.Expected{Now: issued.Add(time.Minute)}, 15*time.Minute, r); err == nil {
		t.Fatal("accepted consent above the signed config TTL")
	}
}
