package config

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
)

const (
	DelegationKind          = "config_delegation"
	DelegationSigningDomain = "config_delegation"
)

type DelegatedKey struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Role      string `json:"role"`
}

func (key DelegatedKey) Public() identity.Public {
	return identity.Public{Algorithm: key.Algorithm, KeyID: key.KeyID, PublicKey: key.PublicKey}
}

type Delegation struct {
	Kind                     string               `json:"kind"`
	Protocol                 string               `json:"protocol"`
	ProtocolVersion          int                  `json:"protocol_version"`
	EventID                  string               `json:"event_id"`
	EventEpoch               string               `json:"event_epoch"`
	BaseRepository           envelope.Repository  `json:"base_repository"`
	DelegationEpoch          uint64               `json:"delegation_epoch"`
	PreviousDelegationDigest *string              `json:"previous_delegation_digest"`
	ValidFrom                string               `json:"valid_from"`
	ExpiresAt                string               `json:"expires_at"`
	Threshold                int                  `json:"threshold"`
	Keys                     []DelegatedKey       `json:"keys"`
	Signatures               []identity.Signature `json:"signatures"`
}

type unsignedDelegation struct {
	Kind                     string              `json:"kind"`
	Protocol                 string              `json:"protocol"`
	ProtocolVersion          int                 `json:"protocol_version"`
	EventID                  string              `json:"event_id"`
	EventEpoch               string              `json:"event_epoch"`
	BaseRepository           envelope.Repository `json:"base_repository"`
	DelegationEpoch          uint64              `json:"delegation_epoch"`
	PreviousDelegationDigest *string             `json:"previous_delegation_digest"`
	ValidFrom                string              `json:"valid_from"`
	ExpiresAt                string              `json:"expires_at"`
	Threshold                int                 `json:"threshold"`
	Keys                     []DelegatedKey      `json:"keys"`
}

type DelegationVerification struct {
	Digest     string
	Authority  Authority
	RootKeyIDs []string
	Delegation Delegation
}

func ParseDelegation(raw []byte) (Delegation, error) {
	return parseDelegation(raw, true)
}

func ParseUnsignedDelegation(raw []byte) (Delegation, error) {
	return parseDelegation(raw, false)
}

func parseDelegation(raw []byte, requireSignatures bool) (Delegation, error) {
	if len(raw) > MaxBytes {
		return Delegation{}, errors.New("config delegation exceeds 1 MiB")
	}
	var delegation Delegation
	if err := canonical.StrictUnmarshal(raw, &delegation); err != nil {
		return Delegation{}, fmt.Errorf("decode config delegation: %w", err)
	}
	if err := delegation.validate(requireSignatures); err != nil {
		return Delegation{}, err
	}
	return delegation, nil
}

func (delegation Delegation) validate(requireSignatures bool) error {
	if delegation.Kind != DelegationKind || delegation.Protocol != envelope.Protocol || delegation.ProtocolVersion != envelope.ProtocolVersion || !envelope.IsEventID(delegation.EventID) || delegation.EventEpoch != "1" || delegation.DelegationEpoch != 1 || delegation.PreviousDelegationDigest != nil {
		return errors.New("config delegation v1 discriminator/epoch is invalid")
	}
	if err := envelope.ValidateRepository(delegation.BaseRepository); err != nil {
		return err
	}
	validFrom, err := envelope.ParseTimestamp(delegation.ValidFrom)
	if err != nil {
		return err
	}
	expires, err := envelope.ParseTimestamp(delegation.ExpiresAt)
	if err != nil || !expires.After(validFrom) {
		return errors.New("config delegation validity window is invalid")
	}
	if delegation.Threshold < 1 || delegation.Threshold > 16 || len(delegation.Keys) < delegation.Threshold || len(delegation.Keys) > 16 {
		return errors.New("config delegation threshold/key count is invalid")
	}
	for index, key := range delegation.Keys {
		if key.Role != "event_config_signer" {
			return errors.New("delegated key role is invalid")
		}
		if err := key.Public().Validate(); err != nil {
			return fmt.Errorf("delegated key %d: %w", index, err)
		}
		if index > 0 && delegation.Keys[index-1].KeyID >= key.KeyID {
			return errors.New("delegated keys must be strictly sorted by key_id")
		}
	}
	if (requireSignatures && len(delegation.Signatures) < 1) || len(delegation.Signatures) > 16 {
		return errors.New("config delegation must contain 1 to 16 root signatures")
	}
	for index, signature := range delegation.Signatures {
		if signature.Algorithm != identity.Algorithm || !identity.IsDigest(signature.KeyID) {
			return errors.New("config delegation signature is invalid")
		}
		if index > 0 && delegation.Signatures[index-1].KeyID >= signature.KeyID {
			return errors.New("config delegation signatures must be strictly sorted by key_id")
		}
	}
	return nil
}

func delegationUnsigned(value Delegation) unsignedDelegation {
	return unsignedDelegation{
		value.Kind, value.Protocol, value.ProtocolVersion, value.EventID, value.EventEpoch,
		value.BaseRepository, value.DelegationEpoch, value.PreviousDelegationDigest,
		value.ValidFrom, value.ExpiresAt, value.Threshold, value.Keys,
	}
}

// SignDelegation appends or replaces one explicit organizer-root signature.
func SignDelegation(delegation Delegation, root identity.Private) (Delegation, error) {
	if err := delegation.validate(false); err != nil {
		return Delegation{}, err
	}
	signature, err := envelope.Sign(DelegationSigningDomain, delegationUnsigned(delegation), root)
	if err != nil {
		return Delegation{}, err
	}
	remaining := make([]identity.Signature, 0, len(delegation.Signatures)+1)
	for _, existing := range delegation.Signatures {
		if existing.KeyID != signature.KeyID {
			remaining = append(remaining, existing)
		}
	}
	delegation.Signatures = append(remaining, signature)
	sort.Slice(delegation.Signatures, func(left, right int) bool {
		return delegation.Signatures[left].KeyID < delegation.Signatures[right].KeyID
	})
	if err := delegation.validate(true); err != nil {
		return Delegation{}, err
	}
	return delegation, nil
}

// VerifyDelegationRootSignature verifies one named root signature without
// claiming that a multi-root delegation's complete trust set was supplied.
// It is used while independently assembling root signatures.
func VerifyDelegationRootSignature(delegation Delegation, root identity.Public) error {
	if err := delegation.validate(true); err != nil {
		return err
	}
	if err := root.Validate(); err != nil {
		return err
	}
	for _, signature := range delegation.Signatures {
		if signature.KeyID == root.KeyID {
			return envelope.Verify(DelegationSigningDomain, delegationUnsigned(delegation), signature, root)
		}
	}
	return errors.New("delegation has no signature from the supplied organizer root")
}

// VerifyDelegation requires the exact supplied organizer-root set to have
// signed the delegation, then derives the only config authority callers may
// pin in protected genesis.
func VerifyDelegation(delegation Delegation, roots []identity.Public, expectedEventID, expectedRepositoryID string, now time.Time) (DelegationVerification, error) {
	if err := delegation.validate(true); err != nil {
		return DelegationVerification{}, err
	}
	if len(roots) < 1 || len(roots) > 16 {
		return DelegationVerification{}, errors.New("explicit organizer root set must contain 1 to 16 keys")
	}
	if expectedEventID == "" || expectedRepositoryID == "" || delegation.EventID != expectedEventID || delegation.BaseRepository.ID != expectedRepositoryID {
		return DelegationVerification{}, errors.New("config delegation does not match expected event/repository")
	}
	validFrom, _ := envelope.ParseTimestamp(delegation.ValidFrom)
	expires, _ := envelope.ParseTimestamp(delegation.ExpiresAt)
	if !now.IsZero() && (now.UTC().Before(validFrom) || now.UTC().After(expires)) {
		return DelegationVerification{}, errors.New("config delegation is outside its validity window")
	}
	rootByID := make(map[string]identity.Public, len(roots))
	for _, root := range roots {
		if err := root.Validate(); err != nil {
			return DelegationVerification{}, fmt.Errorf("organizer root: %w", err)
		}
		if _, duplicate := rootByID[root.KeyID]; duplicate {
			return DelegationVerification{}, errors.New("duplicate organizer root key")
		}
		rootByID[root.KeyID] = root
	}
	verifiedRoots := make(map[string]struct{}, len(delegation.Signatures))
	for _, signature := range delegation.Signatures {
		root, ok := rootByID[signature.KeyID]
		if !ok {
			return DelegationVerification{}, errors.New("delegation contains a signature outside the explicit organizer root set")
		}
		if err := envelope.Verify(DelegationSigningDomain, delegationUnsigned(delegation), signature, root); err != nil {
			return DelegationVerification{}, err
		}
		verifiedRoots[signature.KeyID] = struct{}{}
	}
	if len(verifiedRoots) != len(rootByID) {
		return DelegationVerification{}, errors.New("not every explicit organizer root signed the delegation")
	}
	authority := Authority{Threshold: delegation.Threshold, Keys: make([]identity.Public, len(delegation.Keys))}
	for index, key := range delegation.Keys {
		authority.Keys[index] = key.Public()
	}
	digest, err := envelope.DocumentDigest(delegation)
	if err != nil {
		return DelegationVerification{}, err
	}
	rootIDs := make([]string, 0, len(verifiedRoots))
	for keyID := range verifiedRoots {
		rootIDs = append(rootIDs, keyID)
	}
	sort.Strings(rootIDs)
	return DelegationVerification{Digest: digest, Authority: authority, RootKeyIDs: rootIDs, Delegation: delegation}, nil
}

func VerifyWithDelegation(event Event, delegation Delegation, roots []identity.Public, expectedEventID, expectedRepositoryID string, now time.Time) (Verification, DelegationVerification, error) {
	delegationVerification, err := VerifyDelegation(delegation, roots, expectedEventID, expectedRepositoryID, now)
	if err != nil {
		return Verification{}, DelegationVerification{}, err
	}
	if event.EventID != delegation.EventID || event.EventEpoch != delegation.EventEpoch || event.BaseRepository != delegation.BaseRepository || event.DelegationEpoch != delegation.DelegationEpoch || event.DelegationDigest != delegationVerification.Digest {
		return Verification{}, DelegationVerification{}, errors.New("event config does not bind the verified config delegation")
	}
	verification, err := Verify(event, delegationVerification.Authority.Keys, delegationVerification.Authority.Threshold, now)
	if err != nil {
		return Verification{}, DelegationVerification{}, err
	}
	return verification, delegationVerification, nil
}
