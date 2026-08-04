package envelope

import (
	"strings"
	"testing"
)

func TestPackRecordPlaintextTransportBoundary(t *testing.T) {
	t.Parallel()
	record := PackRecord{
		Kind: PackRecordKind, Protocol: Protocol, ProtocolVersion: ProtocolVersion,
		EventID: "example-event-2026", EventEpoch: "1",
		RequestID: "11111111-1111-4111-8111-111111111111",
		AttemptID: "22222222-2222-4222-8222-222222222222",
		ActorID:   "42", KeyID: strings.Repeat("1", 64), KeyEpoch: "1",
		TeamID:             "33333333-3333-4333-8333-333333333333",
		TeamProposalDigest: strings.Repeat("2", 64), BaseRepositoryID: "123",
		ConfigDigest: strings.Repeat("3", 64), RecipientEpoch: "1",
		RecipientKeyIDs:     []string{strings.Repeat("4", 64)},
		InnerManifestSHA256: strings.Repeat("5", 64), FileCount: MaxSubmissionFilesV1,
		PlaintextSize: 42_000_000,
		Bundle: PackRecordBundle{
			Path: "submission.eventctl", Format: SubmissionBundleFormat,
			SizeBytes: 48_000_000, SHA256: strings.Repeat("6", 64),
			EnvelopeSHA256: strings.Repeat("7", 64), CiphertextSize: 47_000_000,
			CiphertextSHA256: strings.Repeat("8", 64),
		},
		CreatedAt: "2026-08-04T00:00:00Z",
	}
	if err := record.Validate(); err != nil {
		t.Fatalf("42,000,000-byte plaintext boundary rejected: %v", err)
	}
	record.FileCount++
	if err := record.Validate(); err == nil {
		t.Fatal("pack record accepted 4,097 files")
	}
	record.FileCount = MaxSubmissionFilesV1
	record.PlaintextSize++
	if err := record.Validate(); err == nil {
		t.Fatal("pack record accepted plaintext above 42,000,000-byte cap")
	}
}
