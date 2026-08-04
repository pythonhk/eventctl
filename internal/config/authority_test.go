package config

import (
	"strings"
	"testing"
	"time"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
	"github.com/pythonhk/eventctl/internal/statepointer"
)

func TestArchivedConfigUsesSourceTimeAfterQueueDelayAndCurrentAuthorities(t *testing.T) {
	t.Parallel()
	signer := deterministicPair(t, 41)
	event := validEvent(t)
	event.DelegationDigest = strings.Repeat("a", 64)
	event.Signatures = nil
	var err error
	event, err = Sign(event, signer.Private)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := Digest(event)
	if err != nil {
		t.Fatal(err)
	}
	genesis := Genesis{
		SchemaVersion: 1, EventID: event.EventID, EventEpoch: event.EventEpoch,
		BaseRepositoryID: event.BaseRepository.ID, ConfigDigest: digest,
		GenesisDelegationDigest:   event.DelegationDigest,
		ConfigDelegationValidFrom: "2026-08-15T00:00:00Z",
		ConfigDelegationExpiresAt: "2027-07-01T00:00:00Z",
		ConfigAuthority:           Authority{Threshold: 1, Keys: []identity.Public{signer.Public}},
		ReceiptAuthority:          event.Receipts.SigningKey,
		CreatedAt:                 "2026-08-04T00:00:00Z", OperationID: "00000000-0000-4000-8000-000000000001",
		OrganizerActorID:                   "42",
		TeamMinimumSize:                    event.Teams.MinimumSize,
		TeamMaximumSize:                    event.Teams.MaximumSize,
		TeamMaximumProposalsPerParticipant: event.Teams.MaximumProposalsPerParticipant,
		SubmissionQuota:                    event.Submissions.MaximumAttemptsPerTeam,
		SubmissionMaximumTotalAttempts:     event.Submissions.MaximumTotalAttempts,
		Writer:                             Writer{AppSlug: "pythonhk-event-state-writer", InstallationID: "1", Provenance: "local_bootstrap"},
	}
	meta := StateMeta{
		Kind: "state_meta_view", Protocol: envelope.Protocol, ProtocolVersion: envelope.ProtocolVersion,
		EventID: event.EventID, EventEpoch: event.EventEpoch, BaseRepositoryID: event.BaseRepository.ID,
		ConfigDigest: digest, ConfigAuthorityDigest: event.DelegationDigest,
		ReceiptAuthority: event.Receipts.SigningKey, Sequence: 9, JournalEventDigest: strings.Repeat("c", 64),
		LifecyclePhase: "frozen", Enabled: true, DisabledReason: nil,
	}
	unsupportedMeta := meta
	unsupportedMeta.EventEpoch = "2"
	unsupportedRaw, err := canonical.Marshal(unsupportedMeta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStateMeta(unsupportedRaw); err == nil {
		t.Fatal("accepted unsupported protected-state event epoch")
	}
	beyondLifetime := meta
	beyondLifetime.Sequence = statepointer.MaxSequenceV1 + 1
	beyondLifetimeRaw, err := canonical.Marshal(beyondLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStateMeta(beyondLifetimeRaw); err == nil {
		t.Fatal("accepted protected state beyond the v1 lifetime bound")
	}
	if err := VerifyAuthorityState(genesis, beyondLifetime); err == nil {
		t.Fatal("trusted protected state beyond the v1 lifetime bound")
	}
	sourceCreatedAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if _, err := VerifyAdoptedConfig(event, genesis, meta, sourceCreatedAt); err != nil {
		t.Fatalf("current config valid at trusted source time failed after queue delay: %v", err)
	}
	wrongProvenance := genesis
	wrongProvenance.Writer.Provenance = "workflow_dispatch"
	if err := wrongProvenance.Validate(); err == nil {
		t.Fatal("accepted non-local genesis bootstrap provenance")
	}
	beforeDelegation := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	if _, err := VerifyAdoptedConfig(event, genesis, meta, beforeDelegation); err == nil {
		t.Fatal("accepted source before protected delegation validity")
	}
	afterDelegation := time.Date(2027, 7, 15, 0, 0, 0, 0, time.UTC)
	if _, err := VerifyAdoptedConfig(event, genesis, meta, afterDelegation); err == nil {
		t.Fatal("accepted source after protected delegation validity")
	}
	processedAfterExpiry := time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := VerifyAdoptedConfig(event, genesis, meta, processedAfterExpiry); err == nil {
		t.Fatal("config validity unexpectedly ignored the supplied verification time")
	}
	if _, err := VerifyArchivedConfig(event, genesis, meta, sourceCreatedAt); err != nil {
		t.Fatalf("historical accepted config failed: %v", err)
	}
	for name, mutate := range map[string]func(*Genesis){
		"minimum team size":    func(value *Genesis) { value.TeamMinimumSize++ },
		"maximum team size":    func(value *Genesis) { value.TeamMaximumSize++ },
		"proposal limit":       func(value *Genesis) { value.TeamMaximumProposalsPerParticipant++ },
		"per-team quota":       func(value *Genesis) { value.SubmissionQuota++ },
		"global attempt limit": func(value *Genesis) { value.SubmissionMaximumTotalAttempts++ },
	} {
		t.Run("policy mismatch "+name, func(t *testing.T) {
			mismatched := genesis
			mutate(&mismatched)
			if _, err := VerifyWithAuthority(event, mismatched, sourceCreatedAt); err == nil {
				t.Fatalf("accepted genesis/config %s mismatch", name)
			}
		})
	}
	changed := meta
	changed.ConfigDigest = strings.Repeat("d", 64)
	if _, err := VerifyArchivedConfig(event, genesis, changed, sourceCreatedAt); err == nil {
		t.Fatal("accepted superseded current config digest")
	}
}
