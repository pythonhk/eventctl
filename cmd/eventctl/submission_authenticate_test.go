package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/config"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
)

type submissionAuthenticationFixture struct {
	configPath    string
	authorityPath string
	stateMetaPath string
	registryPath  string
	requestPath   string
	sourceTime    time.Time
	request       envelope.Submission
	verified      envelope.VerifiedSubmission
	docDigest     string
}

func TestSubmissionAuthenticateRequestWorksAfterLifecycleClosureWithoutMutableInputs(t *testing.T) {
	fixture := newSubmissionAuthenticationFixture(t)
	outPath := filepath.Join(t.TempDir(), "authenticated.json")
	args := fixture.commandArgs(outPath, fixture.request.ActorID, fixture.requestPath)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exit := run(args, &stdout, &stderr)
	if exit != 0 || stderr.String() != "" {
		t.Fatalf("run exit=%d stderr=%q stdout=%q", exit, stderr.String(), stdout.String())
	}
	var response struct {
		OutputVersion string         `json:"output_version"`
		OK            bool           `json:"ok"`
		Command       string         `json:"command"`
		Result        requestSummary `json:"result"`
		Error         *errorObject   `json:"error"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	wantSummary := requestSummary{
		Path: outPath, Kind: envelope.SubmissionKind,
		RequestDigest:  fixture.verified.Fingerprint.RequestDigest,
		DocumentDigest: fixture.docDigest,
		ReplayKey:      fixture.verified.Fingerprint.ReplayKey,
	}
	if response.OutputVersion != outputVersion || !response.OK || response.Command != "submission.authenticate-request" || response.Error != nil || response.Result != wantSummary {
		t.Fatalf("response = %#v, want result %#v", response, wantSummary)
	}

	artifactRaw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct {
		Status         string              `json:"status"`
		Kind           string              `json:"kind"`
		RequestDigest  string              `json:"request_digest"`
		DocumentDigest string              `json:"document_digest"`
		ReplayKey      string              `json:"replay_key"`
		Document       envelope.Submission `json:"document"`
	}
	if err := canonical.StrictUnmarshal(artifactRaw, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.Status != "verified" || artifact.Kind != envelope.SubmissionKind || artifact.RequestDigest != fixture.verified.Fingerprint.RequestDigest || artifact.DocumentDigest != fixture.docDigest || artifact.ReplayKey != fixture.verified.Fingerprint.ReplayKey || artifact.Document != fixture.request {
		t.Fatalf("authenticated artifact = %#v", artifact)
	}
}

func TestSubmissionAuthenticateRequestRejectsWrongActorAndForgedDocument(t *testing.T) {
	fixture := newSubmissionAuthenticationFixture(t)
	directory := t.TempDir()

	forged := fixture.request
	forged.PullRequest.HeadSHA = strings.Repeat("b", 40)
	forgedPath := filepath.Join(directory, "forged.json")
	writeCanonicalFixture(t, forgedPath, forged)

	for name, test := range map[string]struct {
		actorID     string
		requestPath string
	}{
		"wrong trusted actor": {actorID: "43", requestPath: fixture.requestPath},
		"forged signed field": {actorID: fixture.request.ActorID, requestPath: forgedPath},
	} {
		t.Run(name, func(t *testing.T) {
			outPath := filepath.Join(directory, strings.ReplaceAll(name, " ", "-")+".out.json")
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exit := run(fixture.commandArgs(outPath, test.actorID, test.requestPath), &stdout, &stderr)
			if exit != 3 || stderr.String() != "" {
				t.Fatalf("run exit=%d stderr=%q stdout=%q", exit, stderr.String(), stdout.String())
			}
			var response struct {
				OK      bool         `json:"ok"`
				Command string       `json:"command"`
				Error   *errorObject `json:"error"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.OK || response.Command != "submission" || response.Error == nil || response.Error.Code != "verification_failed" || !strings.Contains(response.Error.Message, "authenticate submission request") {
				t.Fatalf("failure response = %#v", response)
			}
			if _, err := os.Stat(outPath); !os.IsNotExist(err) {
				t.Fatalf("rejected request created output: %v", err)
			}
		})
	}
}

func (fixture submissionAuthenticationFixture) commandArgs(outPath, actorID, requestPath string) []string {
	return []string{
		"submission", "authenticate-request",
		"--config", fixture.configPath,
		"--authority", fixture.authorityPath,
		"--state-meta", fixture.stateMetaPath,
		"--registry", fixture.registryPath,
		"--request", requestPath,
		"--expect-actor-id", actorID,
		"--source-time", fixture.sourceTime.Format(time.RFC3339),
		"--out", outPath,
	}
}

func newSubmissionAuthenticationFixture(t *testing.T) submissionAuthenticationFixture {
	t.Helper()
	configSigner := deterministicCLIKeyPair(t, 31)
	receiptSigner := deterministicCLIKeyPair(t, 32)
	scorerSigner := deterministicCLIKeyPair(t, 33)
	participant := deterministicCLIKeyPair(t, 34)
	hybridIdentity, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	externalJudgeURL := "https://judge.example.invalid/v1/score"
	event := config.Event{
		Kind: config.Kind, Protocol: envelope.Protocol, ProtocolVersion: envelope.ProtocolVersion,
		EventID: "replay-event-2026", EventEpoch: "1",
		BaseRepository: envelope.Repository{ID: "123", Owner: "pythonhk", Name: "replay-event-2026"},
		ConfigEpoch:    1, DelegationEpoch: 1, DelegationDigest: strings.Repeat("a", 64),
		IssuedAt: "2026-08-01T00:00:00Z", ExpiresAt: "2027-08-01T00:00:00Z",
		InitialState: config.InitialState{Phase: "draft", Enabled: false, DisabledReason: "template_not_bootstrapped"},
		Registration: config.Registration{MaximumParticipants: 20, RequestTTLSeconds: 1800, TermsDigest: strings.Repeat("1", 64), KeyAlgorithm: identity.Algorithm, KeyRotationPolicy: "unsupported"},
		Teams:        config.Teams{MinimumSize: 2, MaximumSize: 5, MaximumProposalsPerParticipant: 1, ProposalTTLSeconds: 604800, MembershipLockPhase: "submissions_open"},
		Submissions: config.Submissions{
			BaseRef: "main", MaximumAttemptsPerTeam: 10, MaximumTotalAttempts: 100,
			MaximumCiphertextBytes: 47_000_000, MaximumPlaintextBytes: 42_000_000,
			MaximumFileBytes: 20_000_000, MaximumPlaintextFiles: 4096,
			EnvelopeTTLSeconds: 1800, DeliveryMode: envelope.SubmissionDeliveryMode,
			FailedConsumeQuota: true, AllowedExtensions: []string{".csv"},
			Encryption: config.Encryption{
				Algorithm: "age-hybrid-mlkem768-x25519", RecipientEpoch: "1",
				Recipients: []config.Recipient{{RecipientID: "primary_judge", PublicKey: hybridIdentity.Recipient().String()}},
			},
		},
		Scoring: config.Scoring{
			Mode: "external_judge", ScorerID: "example_scorer", ScorerVersion: "v1.0.0",
			PolicyDigest: strings.Repeat("2", 64), MaximumResultBytes: 65536,
			ResultKey: scorerSigner.Public, ExternalJudgeURL: &externalJudgeURL,
		},
		State: config.State{
			Branch: "event-state", Public: true, WriterAppSlug: "pythonhk-event-state-writer",
			WriterConcurrencyGroup: "event-state-writer", JournalFormat: "hash-linked-json-v1",
		},
		Receipts: config.Receipts{SigningKey: receiptSigner.Public},
	}
	event, err = config.Sign(event, configSigner.Private)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := config.Digest(event)
	if err != nil {
		t.Fatal(err)
	}

	authority := config.Genesis{
		SchemaVersion: 1, EventID: event.EventID, EventEpoch: event.EventEpoch,
		BaseRepositoryID: event.BaseRepository.ID, ConfigDigest: digest,
		GenesisDelegationDigest:            event.DelegationDigest,
		ConfigDelegationValidFrom:          "2026-08-01T00:00:00Z",
		ConfigDelegationExpiresAt:          "2027-08-01T00:00:00Z",
		ConfigAuthority:                    config.Authority{Threshold: 1, Keys: []identity.Public{configSigner.Public}},
		ReceiptAuthority:                   event.Receipts.SigningKey,
		CreatedAt:                          "2026-08-01T00:00:00Z",
		OperationID:                        "10000000-0000-4000-8000-000000000001",
		OrganizerActorID:                   "42",
		TeamMinimumSize:                    event.Teams.MinimumSize,
		TeamMaximumSize:                    event.Teams.MaximumSize,
		TeamMaximumProposalsPerParticipant: event.Teams.MaximumProposalsPerParticipant,
		SubmissionQuota:                    event.Submissions.MaximumAttemptsPerTeam,
		SubmissionMaximumTotalAttempts:     event.Submissions.MaximumTotalAttempts,
		Writer: config.Writer{
			AppSlug: "pythonhk-event-state-writer", InstallationID: "1", Provenance: "local_bootstrap",
		},
	}
	disabledReason := "event_closed"
	stateMeta := config.StateMeta{
		Kind: "state_meta_view", Protocol: envelope.Protocol, ProtocolVersion: envelope.ProtocolVersion,
		EventID: event.EventID, EventEpoch: event.EventEpoch, BaseRepositoryID: event.BaseRepository.ID,
		ConfigDigest: digest, ConfigAuthorityDigest: event.DelegationDigest,
		ReceiptAuthority: event.Receipts.SigningKey, Sequence: 10,
		JournalEventDigest: strings.Repeat("c", 64), LifecyclePhase: "closed",
		Enabled: false, DisabledReason: &disabledReason,
	}
	registry := identity.Registry{
		Schema:     identity.RegistrySchema,
		Identities: []identity.RegistryEntry{{ActorID: "84", KeyEpoch: "1", Identity: participant.Public}},
	}
	sourceTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	requestRaw, err := envelope.NewSubmission(envelope.SubmissionParams{
		EventID: event.EventID, EventEpoch: event.EventEpoch,
		RequestID: "20000000-0000-4000-8000-000000000002",
		AttemptID: "30000000-0000-4000-8000-000000000003",
		ActorID:   "84", KeyEpoch: "1",
		TeamID:             "40000000-0000-4000-8000-000000000004",
		TeamProposalDigest: strings.Repeat("d", 64),
		Metadata: envelope.PRMetadata{
			Kind: "github_pr_metadata", ActorID: "84", PullRequestAuthorID: "84",
			BaseRepository: event.BaseRepository,
			PullRequest: envelope.PullRequest{
				Number: 7, ID: "700", BaseRepositoryID: event.BaseRepository.ID, BaseRef: "main",
				HeadRepositoryID: "456", HeadOwner: "participant", HeadRef: "attempt-one",
				HeadSHA: strings.Repeat("e", 40),
			},
		},
		ConfigDigest: digest, IssuedAt: sourceTime.Add(-time.Minute),
		ExpiresAt: sourceTime.Add(14 * time.Minute),
		Bundle: envelope.BundleReference{
			Path: "submission.eventctl", SizeBytes: 2048, SHA256: strings.Repeat("3", 64),
			EnvelopeSHA256: strings.Repeat("4", 64), CiphertextSize: 1024,
			CiphertextSHA256: strings.Repeat("5", 64), Format: envelope.SubmissionBundleFormat,
		},
	}, participant.Private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := envelope.VerifySubmission(requestRaw, envelope.Expected{
		EventID: event.EventID, EventEpoch: event.EventEpoch, RepositoryID: event.BaseRepository.ID,
		ActorID: "84", ConfigDigest: digest, Now: sourceTime,
	}, 1800*time.Second, registry)
	if err != nil {
		t.Fatal(err)
	}
	docDigest, err := envelope.DocumentDigest(verified.Document)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	configPath := filepath.Join(directory, "event.yaml")
	configRaw, err := config.MarshalYAML(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	authorityPath := filepath.Join(directory, "genesis.json")
	stateMetaPath := filepath.Join(directory, "state-meta.json")
	registryPath := filepath.Join(directory, "registry.json")
	requestPath := filepath.Join(directory, "request.json")
	writeCanonicalFixture(t, authorityPath, authority)
	writeCanonicalFixture(t, stateMetaPath, stateMeta)
	writeCanonicalFixture(t, registryPath, registry)
	if err := os.WriteFile(requestPath, append(requestRaw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	return submissionAuthenticationFixture{
		configPath: configPath, authorityPath: authorityPath, stateMetaPath: stateMetaPath,
		registryPath: registryPath, requestPath: requestPath, sourceTime: sourceTime,
		request: verified.Document, verified: verified, docDigest: docDigest,
	}
}

func deterministicCLIKeyPair(t *testing.T, fill byte) identity.KeyPair {
	t.Helper()
	pair, err := identity.FromSeed(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func writeCanonicalFixture(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := canonical.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
