package envelope

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pythonhk/eventctl/internal/identity"
)

func TestSubmissionBindsActorPRHeadAndBundle(t *testing.T) {
	t.Parallel()
	pair := testPair(t, 12)
	issued := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	metadata := PRMetadata{
		Kind: "github_pr_metadata", ActorID: "42", PullRequestAuthorID: "42",
		BaseRepository: Repository{ID: "100", Owner: "pythonhk", Name: "event"},
		PullRequest:    PullRequest{Number: 7, ID: "700", BaseRepositoryID: "100", BaseRef: "main", HeadRepositoryID: "200", HeadOwner: "participant", HeadRef: "attempt-one", HeadSHA: strings.Repeat("a", 40)},
	}
	bundle := BundleReference{Path: "submission.eventctl", SizeBytes: 1000, SHA256: strings.Repeat("1", 64), EnvelopeSHA256: strings.Repeat("2", 64), CiphertextSize: 800, CiphertextSHA256: strings.Repeat("3", 64), Format: SubmissionBundleFormat}
	params := SubmissionParams{EventID: "summer-data-2026", EventEpoch: "1", RequestID: "10000000-0000-4000-8000-000000000001", AttemptID: "20000000-0000-4000-8000-000000000002", ActorID: "42", KeyEpoch: "1", TeamID: "30000000-0000-4000-8000-000000000003", TeamProposalDigest: strings.Repeat("5", 64), Metadata: metadata, ConfigDigest: strings.Repeat("4", 64), IssuedAt: issued, ExpiresAt: issued.Add(15 * time.Minute), Bundle: bundle}
	raw, err := NewSubmission(params, pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	registryRaw, _ := json.Marshal(identity.Registry{Schema: identity.RegistrySchema, Identities: []identity.RegistryEntry{{ActorID: "42", KeyEpoch: "1", Identity: pair.Public}}})
	registry, err := identity.ParseRegistry(registryRaw)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySubmission(raw, Expected{EventID: "summer-data-2026", EventEpoch: "1", RepositoryID: "100", ActorID: "42", ConfigDigest: strings.Repeat("4", 64), Now: issued.Add(time.Minute)}, 15*time.Minute, registry)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Document.PullRequest.HeadSHA != metadata.PullRequest.HeadSHA || verified.Document.Bundle.SHA256 != bundle.SHA256 {
		t.Fatal("binding lost")
	}
	mutated := bytes.Replace(raw, []byte(metadata.PullRequest.HeadSHA), []byte(strings.Repeat("b", 40)), 1)
	if _, err := VerifySubmission(mutated, Expected{}, 15*time.Minute, registry); err == nil {
		t.Fatal("accepted mutated head SHA")
	}
	params.ExpiresAt = issued.Add(15*time.Minute + time.Second)
	overConfiguredTTL, err := NewSubmission(params, pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySubmission(overConfiguredTTL, Expected{Now: issued.Add(time.Minute)}, 15*time.Minute, registry); err == nil {
		t.Fatal("submission above the signed config TTL was accepted")
	}
}

func TestPRMetadataRejectsAddressMismatch(t *testing.T) {
	t.Parallel()
	metadata := PRMetadata{Kind: "github_pr_metadata", ActorID: "1", PullRequestAuthorID: "1", BaseRepository: Repository{ID: "1", Owner: "pythonhk", Name: "event"}, PullRequest: PullRequest{Number: 1, ID: "10", BaseRepositoryID: "2", BaseRef: "main", HeadRepositoryID: "3", HeadOwner: "u", HeadRef: "branch", HeadSHA: strings.Repeat("a", 40)}}
	raw, _ := json.Marshal(metadata)
	if _, err := ParsePRMetadata(raw); err == nil {
		t.Fatal("accepted mismatched base repository")
	}
}
