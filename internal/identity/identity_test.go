package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func deterministicPair(t *testing.T, fill byte) KeyPair {
	t.Helper()
	pair, err := GenerateFrom(bytes.NewReader(bytes.Repeat([]byte{fill}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func TestGenerateRoundTripAndSign(t *testing.T) {
	t.Parallel()
	pair := deterministicPair(t, 7)
	raw, err := MarshalPrivate(pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePrivate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Public != pair.Public {
		t.Fatalf("parsed public = %#v, want %#v", parsed.Public, pair.Public)
	}
	message := []byte("eventctl protocol test")
	signature, err := Sign(parsed.Private, message)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(parsed.Public, message, signature); err != nil {
		t.Fatal(err)
	}
	if err := Verify(parsed.Public, append(message, '!'), signature); err == nil {
		t.Fatal("Verify unexpectedly accepted a mutated message")
	}
}

func TestKeyIDUsesRawHexAndAlgorithmDomain(t *testing.T) {
	t.Parallel()
	pair := deterministicPair(t, 4)
	if len(pair.Public.KeyID) != 64 || strings.Contains(pair.Public.KeyID, ":") {
		t.Fatalf("key ID = %q", pair.Public.KeyID)
	}
	if !IsDigest(pair.Public.KeyID) {
		t.Fatalf("key ID is not a digest: %q", pair.Public.KeyID)
	}
}

func TestPublicRejectsNoncanonicalEncodingAndMismatchedID(t *testing.T) {
	t.Parallel()
	pair := deterministicPair(t, 9)
	bad := pair.Public
	bad.PublicKey += "="
	if err := bad.Validate(); err == nil {
		t.Fatal("Validate accepted padded base64url")
	}
	bad = pair.Public
	bad.KeyID = strings.Repeat("0", 64)
	if err := bad.Validate(); err == nil {
		t.Fatal("Validate accepted a mismatched key ID")
	}
}

func TestParsePrivateRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	pair := deterministicPair(t, 5)
	raw, err := json.Marshal(pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...)
	if _, err := ParsePrivate(withUnknown); err == nil {
		t.Fatal("ParsePrivate accepted an unknown field")
	}
}

func TestRegistryRequiresSortedUniqueTrustedBindings(t *testing.T) {
	t.Parallel()
	first, second := deterministicPair(t, 1), deterministicPair(t, 2)
	registry := Registry{Schema: RegistrySchema, Identities: []RegistryEntry{
		{ActorID: "2", KeyEpoch: "1", Identity: first.Public},
		{ActorID: "10", KeyEpoch: "1", Identity: second.Public},
	}}
	raw, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRegistry(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := parsed.Resolve("10", "1"); !ok || got != second.Public {
		t.Fatalf("Resolve = %#v, %v", got, ok)
	}
	registry.Identities[0], registry.Identities[1] = registry.Identities[1], registry.Identities[0]
	raw, err = json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRegistry(raw); err == nil {
		t.Fatal("ParseRegistry accepted unsorted identities")
	}
}

func TestRegistryRejectsAmbiguousActiveBindings(t *testing.T) {
	t.Parallel()
	first, second := deterministicPair(t, 11), deterministicPair(t, 12)
	for name, entries := range map[string][]RegistryEntry{
		"same actor has multiple active epochs": {
			{ActorID: "2", KeyEpoch: "1", Identity: first.Public},
			{ActorID: "2", KeyEpoch: "2", Identity: second.Public},
		},
		"same key belongs to multiple actors": {
			{ActorID: "2", KeyEpoch: "1", Identity: first.Public},
			{ActorID: "10", KeyEpoch: "1", Identity: first.Public},
		},
	} {
		t.Run(name, func(t *testing.T) {
			registry := Registry{Schema: RegistrySchema, Identities: entries}
			if err := registry.Validate(); err == nil {
				t.Fatalf("Registry.Validate accepted ambiguous bindings: %#v", entries)
			}
		})
	}
}

func TestSignatureEncodingValidationDoesNotAuthenticate(t *testing.T) {
	t.Parallel()
	pair := deterministicPair(t, 13)
	signature := Signature{
		Algorithm: Algorithm,
		KeyID:     pair.Public.KeyID,
		Value:     base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	if err := signature.ValidateEncoding(); err != nil {
		t.Fatalf("structurally valid signature rejected: %v", err)
	}
	if err := Verify(pair.Public, []byte("not signed"), signature); err == nil {
		t.Fatal("encoding validation authenticated a cryptographically invalid signature")
	}
}
