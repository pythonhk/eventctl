package config

import (
	"bytes"
	"sort"
	"testing"
	"time"

	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
)

func deterministicPair(t *testing.T, value byte) identity.KeyPair {
	t.Helper()
	pair, err := identity.GenerateFrom(bytes.NewReader(bytes.Repeat([]byte{value}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func delegationFixture(t *testing.T, signers ...identity.Public) Delegation {
	t.Helper()
	keys := make([]DelegatedKey, len(signers))
	for index, signer := range signers {
		keys[index] = DelegatedKey{Algorithm: signer.Algorithm, KeyID: signer.KeyID, PublicKey: signer.PublicKey, Role: "event_config_signer"}
	}
	sort.Slice(keys, func(left, right int) bool { return keys[left].KeyID < keys[right].KeyID })
	return Delegation{
		Kind: DelegationKind, Protocol: envelope.Protocol, ProtocolVersion: envelope.ProtocolVersion,
		EventID: "example-event-2026", EventEpoch: "1",
		BaseRepository:  envelope.Repository{ID: "123", Owner: "pythonhk", Name: "example-event-2026"},
		DelegationEpoch: 1, PreviousDelegationDigest: nil,
		ValidFrom: "2026-08-04T00:00:00Z", ExpiresAt: "2027-08-04T00:00:00Z",
		Threshold: len(keys), Keys: keys,
	}
}

func TestRootDelegationVerifiesDistinctConfigSigner(t *testing.T) {
	t.Parallel()
	root := deterministicPair(t, 21)
	signer := deterministicPair(t, 22)
	if root.Public.KeyID == signer.Public.KeyID {
		t.Fatal("test root and delegated signer unexpectedly match")
	}
	delegation, err := SignDelegation(delegationFixture(t, signer.Public), root.Private)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	delegationVerification, err := VerifyDelegation(delegation, []identity.Public{root.Public}, delegation.EventID, delegation.BaseRepository.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if delegationVerification.Authority.Threshold != 1 || delegationVerification.Authority.Keys[0] != signer.Public {
		t.Fatalf("derived authority = %#v", delegationVerification.Authority)
	}
	event := validEvent(t)
	event.DelegationDigest = delegationVerification.Digest
	event.Signatures = nil
	event, err = Sign(event, signer.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyWithDelegation(event, delegation, []identity.Public{root.Public}, event.EventID, event.BaseRepository.ID, now); err != nil {
		t.Fatal(err)
	}
}

func TestTwoRootDelegationAssemblyVerifiesSignedConfig(t *testing.T) {
	t.Parallel()
	firstRoot := deterministicPair(t, 23)
	secondRoot := deterministicPair(t, 24)
	signer := deterministicPair(t, 25)
	if firstRoot.Public.KeyID == signer.Public.KeyID || secondRoot.Public.KeyID == signer.Public.KeyID {
		t.Fatal("test roots and delegated signer unexpectedly match")
	}

	delegation, err := SignDelegation(delegationFixture(t, signer.Public), firstRoot.Private)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDelegationRootSignature(delegation, firstRoot.Public); err != nil {
		t.Fatalf("verify first independently assembled root signature: %v", err)
	}
	delegation, err = SignDelegation(delegation, secondRoot.Private)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDelegationRootSignature(delegation, secondRoot.Public); err != nil {
		t.Fatalf("verify second independently assembled root signature: %v", err)
	}

	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	roots := []identity.Public{firstRoot.Public, secondRoot.Public}
	delegationVerification, err := VerifyDelegation(delegation, roots, delegation.EventID, delegation.BaseRepository.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(delegationVerification.RootKeyIDs) != 2 {
		t.Fatalf("verified root count = %d, want 2", len(delegationVerification.RootKeyIDs))
	}

	event := validEvent(t)
	event.DelegationDigest = delegationVerification.Digest
	event.Signatures = nil
	event, err = Sign(event, signer.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyWithDelegation(event, delegation, roots, event.EventID, event.BaseRepository.ID, now); err != nil {
		t.Fatal(err)
	}
}

func TestDelegationRejectsSubstitutionExpiryAndInsufficientThreshold(t *testing.T) {
	t.Parallel()
	root := deterministicPair(t, 31)
	first := deterministicPair(t, 32)
	second := deterministicPair(t, 33)
	delegation, err := SignDelegation(delegationFixture(t, first.Public, second.Public), root.Private)
	if err != nil {
		t.Fatal(err)
	}
	inside := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if _, err := VerifyDelegation(delegation, []identity.Public{root.Public}, delegation.EventID, delegation.BaseRepository.ID, time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("accepted expired delegation")
	}
	substituted := delegation
	substituted.Threshold = 1
	if _, err := VerifyDelegation(substituted, []identity.Public{root.Public}, substituted.EventID, substituted.BaseRepository.ID, inside); err == nil {
		t.Fatal("accepted threshold substitution under old root signature")
	}
	verification, err := VerifyDelegation(delegation, []identity.Public{root.Public}, delegation.EventID, delegation.BaseRepository.ID, inside)
	if err != nil {
		t.Fatal(err)
	}
	event := validEvent(t)
	event.DelegationDigest = verification.Digest
	event.Signatures = nil
	event, err = Sign(event, first.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyWithDelegation(event, delegation, []identity.Public{root.Public}, event.EventID, event.BaseRepository.ID, inside); err == nil {
		t.Fatal("accepted config below delegated threshold")
	}
}
