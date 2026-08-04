package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"filippo.io/age"
	"github.com/pythonhk/eventctl/internal/bundle"
	"github.com/pythonhk/eventctl/internal/config"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
	"github.com/pythonhk/eventctl/internal/keystore"
	"github.com/pythonhk/eventctl/internal/receipt"
	organizerrecipient "github.com/pythonhk/eventctl/internal/recipient"
	"github.com/pythonhk/eventctl/internal/team"
)

func runSubmission(args []string, stderr io.Writer) (any, error) {
	if len(args) == 0 {
		return nil, usageError("usage: eventctl submission pack|inspect|verify|prepare|verify-request|decrypt-verify")
	}
	switch args[0] {
	case "pack":
		return submissionPack(args[1:], stderr)
	case "inspect":
		return submissionInspect(args[1:])
	case "verify":
		return submissionVerifyPublic(args[1:])
	case "prepare":
		return submissionPrepare(args[1:], stderr)
	case "verify-request":
		return submissionVerifyRequest(args[1:])
	case "decrypt-verify":
		return submissionDecryptVerify(args[1:], stderr)
	default:
		return nil, usageError("usage: eventctl submission pack|inspect|verify|prepare|verify-request|decrypt-verify")
	}
}

func submissionPack(args []string, stderr io.Writer) (any, error) {
	flags := newFlagSet("submission pack")
	configPath := flags.String("config", "", "signed event config")
	authority := flags.String("authority", "", "protected genesis")
	stateMeta := flags.String("state-meta", "", "protected current state metadata")
	registryPath := flags.String("registry", "", "trusted identity registry")
	teamsPath := flags.String("teams", "", "protected current teams view")
	teamID := flags.String("team-id", "", "active team UUIDv4")
	keyPath := flags.String("key", "", "encrypted participant key")
	passFile := flags.String("passphrase-file", "", "passphrase file or -")
	actorID := flags.String("actor-id", "", "numeric GitHub actor ID")
	attemptID := flags.String("attempt-id", "", "UUIDv4 (generated if omitted)")
	requestID := flags.String("request-id", "", "UUIDv4 (generated if omitted)")
	source := flags.String("source", "", "submission source directory")
	bundleOut := flags.String("bundle-out", "", "must be submission.eventctl")
	recordOut := flags.String("record-out", "", "local pack record output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authority == "" || *stateMeta == "" || *registryPath == "" || *teamsPath == "" || *teamID == "" || *keyPath == "" || *actorID == "" || *source == "" || *bundleOut == "" || *recordOut == "" {
		return nil, usageError("usage: eventctl submission pack --config PATH --authority PATH --state-meta PATH --registry PATH --teams PATH --team-id UUID --key PATH --actor-id ID --source DIR --bundle-out submission.eventctl --record-out PATH [--passphrase-file PATH|-] [--attempt-id UUID] [--request-id UUID]")
	}
	if filepath.Base(filepath.Clean(*bundleOut)) != "submission.eventctl" {
		return nil, invalidError("--bundle-out file name must be submission.eventctl", nil)
	}
	event, digest, meta, err := loadTrustedContext(*configPath, *authority, *stateMeta, time.Now().UTC())
	if err != nil {
		return nil, verificationError("verify event trust context", err)
	}
	if err := requirePhase(meta, "submissions_open"); err != nil {
		return nil, verificationError("submissions are not open", err)
	}
	registry, err := loadRegistry(*registryPath)
	if err != nil {
		return nil, verificationError("load identity registry", err)
	}
	pair, err := loadPrivate(*keyPath, *passFile, stderr)
	if err != nil {
		return nil, verificationError("decrypt participant key", err)
	}
	keyEpoch, err := resolveKeyEpoch(registry, *actorID, pair.Public)
	if err != nil {
		return nil, verificationError("resolve active registration", err)
	}
	teamsRaw, err := readBounded(*teamsPath, 16<<20)
	if err != nil {
		return nil, ioError("read protected teams view", err)
	}
	teamsView, err := team.ParseTeamsView(teamsRaw)
	if err != nil {
		return nil, verificationError("validate protected teams view", err)
	}
	if teamsView.EventID != event.EventID || teamsView.EventEpoch != event.EventEpoch || teamsView.ConfigDigest != digest || teamsView.Sequence != meta.Sequence || teamsView.JournalEventDigest != meta.JournalEventDigest {
		return nil, verificationError("protected teams view does not match trusted current state", nil)
	}
	activeTeam, ok := teamsView.FindActiveTeam(*teamID)
	if !ok {
		return nil, verificationError("team is not active in protected current state", nil)
	}
	if !containsActor(activeTeam.MemberActorIDs, *actorID) {
		return nil, verificationError("submission actor is not a team member", nil)
	}
	if *attemptID == "" {
		*attemptID, err = envelope.NewRequestID()
		if err != nil {
			return nil, err
		}
	}
	if *requestID == "" {
		*requestID, err = envelope.NewRequestID()
		if err != nil {
			return nil, err
		}
	}
	if err := validateSourceExtensions(*source, event.Submissions.AllowedExtensions); err != nil {
		return nil, invalidError("validate source extensions", err)
	}
	recipients := make([]*age.HybridRecipient, 0, len(event.Submissions.Encryption.Recipients))
	for _, configured := range event.Submissions.Encryption.Recipients {
		recipient, parseErr := age.ParseHybridRecipient(configured.PublicKey)
		if parseErr != nil {
			return nil, verificationError("parse trusted hybrid recipient", parseErr)
		}
		recipients = append(recipients, recipient)
	}
	privateKey, _, err := identity.SigningKey(pair.Private)
	if err != nil {
		return nil, err
	}
	issued := time.Now().UTC().Truncate(time.Second)
	limits := bundleLimits(event)
	packed, err := bundle.PackDirectory(context.Background(), bundle.PackOptions{SourceDir: *source, OutputPath: *bundleOut, Binding: bundle.Binding{EventID: event.EventID, EventEpoch: event.EventEpoch, RequestID: *requestID, AttemptID: *attemptID, ActorID: *actorID, KeyID: pair.Public.KeyID, KeyEpoch: keyEpoch, TeamID: activeTeam.TeamID, TeamProposalDigest: activeTeam.ProposalDigest, BaseRepositoryID: event.BaseRepository.ID, ConfigDigest: digest, IssuedAt: formatTimestamp(issued), ExpiresAt: formatTimestamp(issued.Add(time.Duration(event.Submissions.EnvelopeTTLSeconds) * time.Second)), RecipientEpoch: event.Submissions.Encryption.RecipientEpoch}, Recipients: recipients, SigningKey: privateKey, Limits: limits})
	if err != nil {
		return nil, invalidError("pack encrypted submission", err)
	}
	record := packRecordFrom(packed, issued)
	if err := record.Validate(); err != nil {
		return nil, verificationError("validate generated pack record", err)
	}
	if err := writeCanonical(*recordOut, record, 0o600); err != nil {
		return nil, ioError("write pack record", err)
	}
	return struct {
		Bundle         string `json:"bundle"`
		Record         string `json:"record"`
		BundleSHA256   string `json:"bundle_sha256"`
		EnvelopeSHA256 string `json:"envelope_sha256"`
		AttemptID      string `json:"attempt_id"`
		RequestID      string `json:"request_id"`
	}{*bundleOut, *recordOut, packed.BundleSHA256, packed.EnvelopeSHA256, *attemptID, *requestID}, nil
}

func submissionInspect(args []string) (any, error) {
	flags := newFlagSet("submission inspect")
	path := flags.String("bundle", "", "encrypted bundle")
	out := flags.String("out", "", "normalized inspection output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *path == "" || *out == "" {
		return nil, usageError("usage: eventctl submission inspect --bundle PATH --out PATH")
	}
	inspection, err := bundle.Inspect(context.Background(), *path, bundle.DefaultLimits())
	if err != nil {
		return nil, verificationError("inspect bundle", err)
	}
	result := struct {
		Status         string          `json:"status"`
		Kind           string          `json:"kind"`
		EnvelopeDigest string          `json:"envelope_digest"`
		BundleDigest   string          `json:"bundle_digest"`
		BundleSize     uint64          `json:"bundle_size"`
		Envelope       bundle.Envelope `json:"envelope"`
	}{"inspected", bundle.EnvelopeKind, inspection.EnvelopeSHA256, inspection.BundleSHA256, inspection.BundleSize, inspection.Envelope}
	if err := writeCanonical(*out, result, 0o644); err != nil {
		return nil, ioError("write bundle inspection", err)
	}
	return result, nil
}

func submissionPrepare(args []string, stderr io.Writer) (any, error) {
	flags := newFlagSet("submission prepare")
	configPath := flags.String("config", "", "signed event config")
	authority := flags.String("authority", "", "protected genesis")
	stateMeta := flags.String("state-meta", "", "protected current state metadata")
	registryPath := flags.String("registry", "", "trusted identity registry")
	keyPath := flags.String("key", "", "encrypted participant key")
	passFile := flags.String("passphrase-file", "", "passphrase file or -")
	actorID := flags.String("actor-id", "", "numeric GitHub actor ID")
	metadataPath := flags.String("metadata", "", "bounded GitHub PR metadata JSON")
	bundlePath := flags.String("bundle", "", "encrypted bundle (submission.eventctl)")
	recordPath := flags.String("record", "", "local pack record")
	out := flags.String("out", "", "signed submission request output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authority == "" || *stateMeta == "" || *registryPath == "" || *keyPath == "" || *actorID == "" || *metadataPath == "" || *bundlePath == "" || *recordPath == "" || *out == "" {
		return nil, usageError("usage: eventctl submission prepare --config PATH --authority PATH --state-meta PATH --registry PATH --key PATH --actor-id ID --metadata PATH --bundle submission.eventctl --record PATH --out PATH [--passphrase-file PATH|-]")
	}
	if filepath.Base(filepath.Clean(*bundlePath)) != "submission.eventctl" {
		return nil, invalidError("--bundle file name must be submission.eventctl", nil)
	}
	event, digest, meta, err := loadTrustedContext(*configPath, *authority, *stateMeta, time.Now().UTC())
	if err != nil {
		return nil, verificationError("verify event trust context", err)
	}
	if err := requirePhase(meta, "submissions_open"); err != nil {
		return nil, verificationError("submissions are not open", err)
	}
	registry, err := loadRegistry(*registryPath)
	if err != nil {
		return nil, verificationError("load identity registry", err)
	}
	pair, err := loadPrivate(*keyPath, *passFile, stderr)
	if err != nil {
		return nil, verificationError("decrypt participant key", err)
	}
	keyEpoch, err := resolveKeyEpoch(registry, *actorID, pair.Public)
	if err != nil {
		return nil, verificationError("resolve active registration", err)
	}
	metadataRaw, err := readBounded(*metadataPath, 64*1024)
	if err != nil {
		return nil, ioError("read PR metadata", err)
	}
	metadata, err := envelope.ParsePRMetadata(metadataRaw)
	if err != nil {
		return nil, invalidError("validate PR metadata", err)
	}
	if metadata.ActorID != *actorID || metadata.PullRequest.BaseRef != event.Submissions.BaseRef {
		return nil, verificationError("PR metadata does not match actor/configured base ref", nil)
	}
	recordRaw, err := readBounded(*recordPath, envelope.MaxDocumentBytes)
	if err != nil {
		return nil, ioError("read pack record", err)
	}
	record, err := envelope.ParsePackRecord(recordRaw)
	if err != nil {
		return nil, verificationError("validate pack record", err)
	}
	inspection, err := bundle.AuthenticatePublic(context.Background(), *bundlePath, pair.Public, bundleLimits(event))
	if err != nil {
		return nil, verificationError("inspect committed bundle", err)
	}
	if err := compareRecordInspection(record, inspection); err != nil {
		return nil, verificationError("pack record/bundle mismatch", err)
	}
	if err := compareConfiguredRecipients(inspection.Envelope, event); err != nil {
		return nil, verificationError("bundle recipient policy mismatch", err)
	}
	if record.EventID != event.EventID || record.EventEpoch != event.EventEpoch || record.BaseRepositoryID != event.BaseRepository.ID || record.ConfigDigest != digest || record.ActorID != *actorID || record.KeyID != pair.Public.KeyID || record.KeyEpoch != keyEpoch {
		return nil, verificationError("pack record does not match trusted actor/config", nil)
	}
	issued := time.Now().UTC().Truncate(time.Second)
	envelopeTTL := time.Duration(event.Submissions.EnvelopeTTLSeconds) * time.Second
	reference := envelope.BundleReference{Path: "submission.eventctl", SizeBytes: record.Bundle.SizeBytes, SHA256: record.Bundle.SHA256, EnvelopeSHA256: record.Bundle.EnvelopeSHA256, CiphertextSize: record.Bundle.CiphertextSize, CiphertextSHA256: record.Bundle.CiphertextSHA256, Format: envelope.SubmissionBundleFormat}
	raw, err := envelope.NewSubmission(envelope.SubmissionParams{EventID: event.EventID, EventEpoch: event.EventEpoch, RequestID: record.RequestID, AttemptID: record.AttemptID, ActorID: *actorID, KeyEpoch: keyEpoch, TeamID: record.TeamID, TeamProposalDigest: record.TeamProposalDigest, Metadata: metadata, ConfigDigest: digest, IssuedAt: issued, ExpiresAt: issued.Add(envelopeTTL), Bundle: reference}, pair.Private)
	if err != nil {
		return nil, invalidError("create submission request", err)
	}
	verified, err := envelope.VerifySubmission(raw, envelope.Expected{EventID: event.EventID, EventEpoch: event.EventEpoch, RepositoryID: event.BaseRepository.ID, ActorID: *actorID, ConfigDigest: digest, Now: issued}, envelopeTTL, registry)
	if err != nil {
		return nil, verificationError("self-verify submission request", err)
	}
	if err := writeExclusive(*out, append(raw, '\n'), 0o644); err != nil {
		return nil, ioError("write submission request", err)
	}
	docDigest, _ := envelope.DocumentDigest(verified.Document)
	return requestSummary{*out, envelope.SubmissionKind, verified.Fingerprint.RequestDigest, docDigest, verified.Fingerprint.ReplayKey}, nil
}

func submissionVerifyRequest(args []string) (any, error) {
	flags := newFlagSet("submission verify-request")
	configPath := flags.String("config", "", "signed event config")
	authority := flags.String("authority", "", "protected genesis")
	stateMeta := flags.String("state-meta", "", "protected current state metadata")
	registryPath := flags.String("registry", "", "trusted identity registry")
	requestPath := flags.String("request", "", "signed submission request")
	metadataPath := flags.String("metadata", "", "fresh GitHub PR metadata")
	bundlePath := flags.String("bundle", "", "bundle fetched at exact head SHA")
	actorID := flags.String("expect-actor-id", "", "trusted workflow actor ID")
	sourceTimeText := flags.String("source-time", "", "trusted immutable GitHub source creation time")
	out := flags.String("out", "", "normalized verification output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authority == "" || *stateMeta == "" || *registryPath == "" || *requestPath == "" || *metadataPath == "" || *bundlePath == "" || *actorID == "" || *sourceTimeText == "" || *out == "" {
		return nil, usageError("usage: eventctl submission verify-request --config PATH --authority PATH --state-meta PATH --registry PATH --request PATH --metadata PATH --bundle PATH --expect-actor-id ID --source-time RFC3339 --out PATH")
	}
	sourceTime, err := parseTrustedSourceTime(*sourceTimeText)
	if err != nil {
		return nil, invalidError("validate trusted source time", err)
	}
	event, digest, meta, err := loadTrustedContext(*configPath, *authority, *stateMeta, sourceTime)
	if err != nil {
		return nil, verificationError("verify event trust context", err)
	}
	if err := requirePhase(meta, "submissions_open"); err != nil {
		return nil, verificationError("submissions are not open", err)
	}
	registry, err := loadRegistry(*registryPath)
	if err != nil {
		return nil, verificationError("load identity registry", err)
	}
	requestRaw, err := readBounded(*requestPath, envelope.MaxDocumentBytes)
	if err != nil {
		return nil, ioError("read submission request", err)
	}
	envelopeTTL := time.Duration(event.Submissions.EnvelopeTTLSeconds) * time.Second
	verified, err := envelope.VerifySubmission(requestRaw, envelope.Expected{EventID: event.EventID, EventEpoch: event.EventEpoch, RepositoryID: event.BaseRepository.ID, ActorID: *actorID, ConfigDigest: digest, Now: sourceTime}, envelopeTTL, registry)
	if err != nil {
		return nil, verificationError("verify submission request", err)
	}
	metadataRaw, err := readBounded(*metadataPath, 64*1024)
	if err != nil {
		return nil, ioError("read PR metadata", err)
	}
	metadata, err := envelope.ParsePRMetadata(metadataRaw)
	if err != nil {
		return nil, verificationError("validate PR metadata", err)
	}
	if metadata != verified.Document.MetadataEquivalent() || metadata.PullRequest.BaseRef != event.Submissions.BaseRef {
		return nil, verificationError("fresh PR metadata does not match signed request", nil)
	}
	trustedBundleSigner, ok := registry.Resolve(verified.Document.ActorID, verified.Document.KeyEpoch)
	if !ok || trustedBundleSigner.KeyID != verified.Document.KeyID {
		return nil, verificationError("bundle signer is not the verified submission signer", nil)
	}
	inspection, err := bundle.AuthenticatePublic(context.Background(), *bundlePath, trustedBundleSigner, bundleLimits(event))
	if err != nil {
		return nil, verificationError("inspect fetched bundle", err)
	}
	if err := compareSubmissionInspection(verified.Document, inspection); err != nil {
		return nil, verificationError("submission request/bundle mismatch", err)
	}
	if err := compareConfiguredRecipients(inspection.Envelope, event); err != nil {
		return nil, verificationError("bundle recipient policy mismatch", err)
	}
	docDigest, _ := envelope.DocumentDigest(verified.Document)
	normalized := normalizedRequest{"verified", envelope.SubmissionKind, verified.Fingerprint.RequestDigest, docDigest, verified.Fingerprint.ReplayKey, verified.Document}
	if err := writeCanonical(*out, normalized, 0o644); err != nil {
		return nil, ioError("write verified submission", err)
	}
	return requestSummary{*out, envelope.SubmissionKind, verified.Fingerprint.RequestDigest, docDigest, verified.Fingerprint.ReplayKey}, nil
}

func submissionDecryptVerify(args []string, stderr io.Writer) (any, error) {
	if runtime.GOOS != "linux" {
		return nil, verificationError("submission decryption is supported only on Linux", bundle.ErrExtractionUnsupported)
	}
	flags := newFlagSet("submission decrypt-verify")
	configPath := flags.String("config", "", "signed event config")
	authority := flags.String("authority", "", "protected genesis")
	stateMeta := flags.String("state-meta", "", "protected current state metadata")
	registryPath := flags.String("registry", "", "trusted identity registry")
	requestPath := flags.String("request", "", "signed post-push submission request")
	acceptancePath := flags.String("acceptance", "", "organizer-signed accepted submission receipt")
	bundlePath := flags.String("bundle", "", "encrypted bundle")
	recordPath := flags.String("record", "", "optional local pack record")
	var identityPaths stringList
	flags.Var(&identityPaths, "identity", "encrypted organizer hybrid identity (repeat for every configured recipient)")
	passFile := flags.String("passphrase-file", "", "identity passphrase file or -")
	expectActorID := flags.String("expect-actor-id", "", "optional trusted actor ID")
	expectAttemptID := flags.String("expect-attempt-id", "", "optional trusted attempt UUID")
	outDir := flags.String("out-dir", "", "new private plaintext directory")
	out := flags.String("out", "", "private normalized verification output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authority == "" || *stateMeta == "" || *registryPath == "" || *requestPath == "" || *acceptancePath == "" || *bundlePath == "" || len(identityPaths) == 0 || *outDir == "" || *out == "" {
		return nil, usageError("usage: eventctl submission decrypt-verify --config ARCHIVED_PATH --authority PATH --state-meta PATH --registry PATH --request PATH --acceptance RECEIPT --bundle PATH --identity PATH [--identity PATH ...] --out-dir PRIVATE_DIR --out PATH [--record PATH] [--passphrase-file PATH|-] [--expect-actor-id ID] [--expect-attempt-id UUID]")
	}
	if filepath.Base(filepath.Clean(*bundlePath)) != "submission.eventctl" {
		return nil, invalidError("--bundle file name must be submission.eventctl", nil)
	}
	parent := filepath.Dir(filepath.Clean(*outDir))
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, invalidError("--out-dir parent must be an existing private directory with no group/other permissions", err)
	}
	genesis, currentMeta, err := loadAuthorityState(*authority, *stateMeta)
	if err != nil {
		return nil, verificationError("verify protected genesis/current-state authorities", err)
	}
	if err := requireOneOfPhases(currentMeta, "submissions_open", "frozen"); err != nil {
		return nil, verificationError("scoring is not allowed in the current phase", err)
	}
	acceptanceRaw, err := readBounded(*acceptancePath, envelope.MaxDocumentBytes)
	if err != nil {
		return nil, ioError("read accepted submission receipt", err)
	}
	parsedAcceptance, err := receipt.Parse(acceptanceRaw)
	if err != nil {
		return nil, verificationError("validate accepted submission receipt", err)
	}
	sourceCreatedAt, err := envelope.ParseTimestamp(parsedAcceptance.SourceCreatedAt)
	if err != nil {
		return nil, verificationError("validate accepted receipt source time", err)
	}
	event, digest, err := loadArchivedConfig(*configPath, genesis, currentMeta, sourceCreatedAt)
	if err != nil {
		return nil, verificationError("verify archived accepted config", err)
	}
	if parsedAcceptance.ConfigDigest != digest || parsedAcceptance.BaseRepositoryID != event.BaseRepository.ID {
		return nil, verificationError("accepted receipt does not bind archived config/repository", nil)
	}
	verifiedAcceptance, err := receipt.Verify(acceptanceRaw, receipt.Expected{
		EventID: event.EventID, EventEpoch: event.EventEpoch,
		BaseRepositoryID: event.BaseRepository.ID, ConfigDigest: digest,
		SigningKey: event.Receipts.SigningKey, CurrentState: currentPointer(currentMeta), Now: time.Now().UTC(),
	})
	if err != nil {
		return nil, verificationError("verify accepted submission receipt", err)
	}
	registry, err := loadRegistry(*registryPath)
	if err != nil {
		return nil, verificationError("load identity registry", err)
	}
	requestRaw, err := readBounded(*requestPath, envelope.MaxDocumentBytes)
	if err != nil {
		return nil, ioError("read submission request", err)
	}
	verifiedRequest, err := envelope.VerifySubmission(requestRaw, envelope.Expected{
		EventID: event.EventID, EventEpoch: event.EventEpoch, RepositoryID: event.BaseRepository.ID,
		ActorID: *expectActorID, ConfigDigest: digest, Now: time.Time{},
	}, time.Duration(event.Submissions.EnvelopeTTLSeconds)*time.Second, registry)
	if err != nil {
		return nil, verificationError("verify signed submission request", err)
	}
	if *expectAttemptID != "" && verifiedRequest.Document.AttemptID != *expectAttemptID {
		return nil, verificationError("submission attempt does not match trusted reservation", nil)
	}
	requestDocumentDigest, err := envelope.DocumentDigest(verifiedRequest.Document)
	if err != nil {
		return nil, err
	}
	acceptance := verifiedAcceptance.Document
	if acceptance.RequestKind != envelope.SubmissionKind || acceptance.Outcome != "accepted" || !acceptance.QuotaCharged || acceptance.ReasonCode != nil || acceptance.OperationID != verifiedRequest.Document.RequestID || acceptance.ReplayKey != verifiedRequest.Fingerprint.ReplayKey || acceptance.RequestDigest != verifiedRequest.Fingerprint.RequestDigest || acceptance.RequestDocumentDigest != requestDocumentDigest || acceptance.ActorID != verifiedRequest.Document.ActorID || acceptance.TeamID == nil || *acceptance.TeamID != verifiedRequest.Document.TeamID || acceptance.AttemptID == nil || *acceptance.AttemptID != verifiedRequest.Document.AttemptID {
		return nil, verificationError("accepted receipt does not bind the exact submission reservation", nil)
	}
	if err := acceptance.ValidateSourceWindow(verifiedRequest.Document.IssuedAt, verifiedRequest.Document.ExpiresAt); err != nil {
		return nil, verificationError("accepted source time is outside signed submission window", err)
	}
	trustedPublic, ok := registry.Resolve(verifiedRequest.Document.ActorID, verifiedRequest.Document.KeyEpoch)
	if !ok || trustedPublic.KeyID != verifiedRequest.Document.KeyID {
		return nil, verificationError("submission signer is not active in trusted registry", nil)
	}
	verificationKey, err := identity.VerificationKey(trustedPublic)
	if err != nil {
		return nil, verificationError("decode trusted verification key", err)
	}
	passphrase, err := readPassphrase(*passFile, "Recipient identity passphrase: ", false, stderr)
	if err != nil {
		return nil, invalidError("read recipient passphrase", err)
	}
	expectedRecipientIDs, err := configuredRecipientFingerprints(event)
	if err != nil {
		clear(passphrase)
		return nil, verificationError("derive trusted recipient policy", err)
	}
	decryptionIdentities := make([]*age.HybridIdentity, 0, len(identityPaths))
	identityFingerprints := make([]string, 0, len(identityPaths))
	for _, identityPath := range identityPaths {
		decryptionIdentity, loadErr := organizerrecipient.LoadIdentity(context.Background(), identityPath, passphrase, keystore.DefaultLimits())
		if loadErr != nil {
			clear(passphrase)
			return nil, verificationError("decrypt organizer identity", loadErr)
		}
		publicRecipient, describeErr := organizerrecipient.Describe(decryptionIdentity)
		if describeErr != nil {
			clear(passphrase)
			return nil, verificationError("validate organizer identity", describeErr)
		}
		decryptionIdentities = append(decryptionIdentities, decryptionIdentity)
		identityFingerprints = append(identityFingerprints, publicRecipient.Fingerprint)
	}
	clear(passphrase)
	if !matchesConfiguredIdentitySet(identityFingerprints, expectedRecipientIDs) {
		return nil, verificationError("organizer identity set does not exactly match every configured recipient", nil)
	}
	verifiedBundle, err := bundle.DecryptToDirectory(context.Background(), *bundlePath, *outDir, decryptionIdentities, verificationKey, bundleLimits(event), event.Submissions.AllowedExtensions)
	if err != nil {
		return nil, verificationError("authenticate and decrypt bundle", err)
	}
	inspection := bundle.Inspection{Envelope: verifiedBundle.Envelope, EnvelopeSHA256: verifiedBundle.EnvelopeSHA256, BundleSize: verifiedBundle.BundleSize, BundleSHA256: verifiedBundle.BundleSHA256}
	if err := compareSubmissionInspection(verifiedRequest.Document, inspection); err != nil {
		_ = os.RemoveAll(*outDir)
		return nil, verificationError("signed request/decrypted bundle mismatch", err)
	}
	if err := compareConfiguredRecipients(verifiedBundle.Envelope, event); err != nil {
		_ = os.RemoveAll(*outDir)
		return nil, verificationError("decrypted bundle recipient policy mismatch", err)
	}
	if *recordPath != "" {
		recordRaw, readErr := readBounded(*recordPath, envelope.MaxDocumentBytes)
		if readErr != nil {
			_ = os.RemoveAll(*outDir)
			return nil, ioError("read pack record", readErr)
		}
		record, parseErr := envelope.ParsePackRecord(recordRaw)
		if parseErr != nil {
			_ = os.RemoveAll(*outDir)
			return nil, verificationError("pack record/decrypted bundle mismatch", parseErr)
		}
		if compareErr := compareRecordInspection(record, inspection); compareErr != nil {
			_ = os.RemoveAll(*outDir)
			return nil, verificationError("pack record/decrypted bundle mismatch", compareErr)
		}
	}
	result := struct {
		Status           string          `json:"status"`
		Kind             string          `json:"kind"`
		RequestDigest    string          `json:"request_digest"`
		DocumentDigest   string          `json:"document_digest"`
		BundleDigest     string          `json:"bundle_digest"`
		EnvelopeDigest   string          `json:"envelope_digest"`
		ManifestDigest   string          `json:"manifest_digest"`
		AcceptanceDigest string          `json:"acceptance_digest"`
		OutputDirectory  string          `json:"output_directory"`
		Envelope         bundle.Envelope `json:"envelope"`
		Manifest         bundle.Manifest `json:"manifest"`
	}{"verified", "decrypted_submission_bundle", verifiedRequest.Fingerprint.RequestDigest, requestDocumentDigest, verifiedBundle.BundleSHA256, verifiedBundle.EnvelopeSHA256, verifiedBundle.Envelope.InnerManifestSHA256, verifiedAcceptance.DocumentDigest, *outDir, verifiedBundle.Envelope, verifiedBundle.Manifest}
	if err := writeCanonical(*out, result, 0o600); err != nil {
		_ = os.RemoveAll(*outDir)
		return nil, ioError("write private decryption result", err)
	}
	return struct {
		Path            string `json:"path"`
		OutputDirectory string `json:"output_directory"`
		AttemptID       string `json:"attempt_id"`
		BundleDigest    string `json:"bundle_digest"`
	}{*out, *outDir, verifiedRequest.Document.AttemptID, verifiedBundle.BundleSHA256}, nil
}

func bundleLimits(event config.Event) bundle.Limits {
	return bundle.Limits{MaxCiphertextBytes: event.Submissions.MaximumCiphertextBytes, MaxEnvelopeBytes: 256 * 1024, MaxPlaintextBytes: event.Submissions.MaximumPlaintextBytes, MaxFileBytes: event.Submissions.MaximumFileBytes, MaxFiles: uint32(event.Submissions.MaximumPlaintextFiles), MaxManifestBytes: 4 * 1024 * 1024, MaxRecipients: uint32(len(event.Submissions.Encryption.Recipients)), MaxTotalFileBytes: event.Submissions.MaximumPlaintextBytes, MaxValidity: time.Duration(event.Submissions.EnvelopeTTLSeconds) * time.Second}
}
func packRecordFrom(packed bundle.Packed, created time.Time) envelope.PackRecord {
	e := packed.Envelope
	return envelope.PackRecord{Kind: envelope.PackRecordKind, Protocol: envelope.Protocol, ProtocolVersion: envelope.ProtocolVersion, EventID: e.EventID, EventEpoch: e.EventEpoch, RequestID: e.RequestID, AttemptID: e.AttemptID, ActorID: e.ActorID, KeyID: e.KeyID, KeyEpoch: e.KeyEpoch, TeamID: e.TeamID, TeamProposalDigest: e.TeamProposalDigest, BaseRepositoryID: e.BaseRepositoryID, ConfigDigest: e.ConfigDigest, RecipientEpoch: e.RecipientEpoch, RecipientKeyIDs: append([]string(nil), e.RecipientKeyIDs...), InnerManifestSHA256: e.InnerManifestSHA256, FileCount: e.FileCount, PlaintextSize: e.PlaintextSize, Bundle: envelope.PackRecordBundle{Path: "submission.eventctl", Format: envelope.SubmissionBundleFormat, SizeBytes: packed.BundleSize, SHA256: packed.BundleSHA256, EnvelopeSHA256: packed.EnvelopeSHA256, CiphertextSize: e.CiphertextSize, CiphertextSHA256: e.CiphertextSHA256}, CreatedAt: formatTimestamp(created)}
}
func compareRecordInspection(r envelope.PackRecord, i bundle.Inspection) error {
	e := i.Envelope
	if r.Bundle.SizeBytes != i.BundleSize || r.Bundle.SHA256 != i.BundleSHA256 || r.Bundle.EnvelopeSHA256 != i.EnvelopeSHA256 || r.Bundle.CiphertextSize != e.CiphertextSize || r.Bundle.CiphertextSHA256 != e.CiphertextSHA256 || r.EventID != e.EventID || r.EventEpoch != e.EventEpoch || r.RequestID != e.RequestID || r.AttemptID != e.AttemptID || r.ActorID != e.ActorID || r.KeyID != e.KeyID || r.KeyEpoch != e.KeyEpoch || r.TeamID != e.TeamID || r.TeamProposalDigest != e.TeamProposalDigest || r.BaseRepositoryID != e.BaseRepositoryID || r.ConfigDigest != e.ConfigDigest || r.RecipientEpoch != e.RecipientEpoch || !equalStrings(r.RecipientKeyIDs, e.RecipientKeyIDs) || r.InnerManifestSHA256 != e.InnerManifestSHA256 || r.FileCount != e.FileCount || r.PlaintextSize != e.PlaintextSize {
		return errors.New("record differs from inspected bundle")
	}
	return nil
}

func compareConfiguredRecipients(envelopeValue bundle.Envelope, event config.Event) error {
	expected, err := configuredRecipientFingerprints(event)
	if err != nil {
		return err
	}
	if envelopeValue.RecipientEpoch != event.Submissions.Encryption.RecipientEpoch || !equalStrings(envelopeValue.RecipientKeyIDs, expected) {
		return errors.New("bundle recipient epoch or exact recipient set differs from signed config")
	}
	return nil
}

func configuredRecipientFingerprints(event config.Event) ([]string, error) {
	fingerprints := make([]string, 0, len(event.Submissions.Encryption.Recipients))
	for _, configured := range event.Submissions.Encryption.Recipients {
		recipient, err := age.ParseHybridRecipient(configured.PublicKey)
		if err != nil {
			return nil, err
		}
		fingerprint, err := bundle.HybridRecipientFingerprint(recipient)
		if err != nil {
			return nil, err
		}
		fingerprints = append(fingerprints, fingerprint)
	}
	sort.Strings(fingerprints)
	for index := 1; index < len(fingerprints); index++ {
		if fingerprints[index-1] == fingerprints[index] {
			return nil, errors.New("signed config contains duplicate recipient public keys")
		}
	}
	return fingerprints, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func matchesConfiguredIdentitySet(supplied, expected []string) bool {
	ordered := append([]string(nil), supplied...)
	sort.Strings(ordered)
	return equalStrings(ordered, expected)
}
func compareSubmissionInspection(s envelope.Submission, i bundle.Inspection) error {
	e := i.Envelope
	if s.Bundle.SizeBytes != i.BundleSize || s.Bundle.SHA256 != i.BundleSHA256 || s.Bundle.EnvelopeSHA256 != i.EnvelopeSHA256 || s.Bundle.CiphertextSize != e.CiphertextSize || s.Bundle.CiphertextSHA256 != e.CiphertextSHA256 || s.EventID != e.EventID || s.EventEpoch != e.EventEpoch || s.RequestID != e.RequestID || s.AttemptID != e.AttemptID || s.ActorID != e.ActorID || s.KeyID != e.KeyID || s.KeyEpoch != e.KeyEpoch || s.TeamID != e.TeamID || s.TeamProposalDigest != e.TeamProposalDigest || s.BaseRepository.ID != e.BaseRepositoryID || s.ConfigDigest != e.ConfigDigest {
		return errors.New("signed request differs from inspected bundle")
	}
	return nil
}
func validateSourceExtensions(root string, allowed []string) error {
	set := map[string]struct{}{}
	for _, ext := range allowed {
		set[ext] = struct{}{}
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return errors.New("source contains a symlink")
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("source contains a special file")
		}
		extension := filepath.Ext(entry.Name())
		if _, ok := set[extension]; !ok {
			return errors.New("source contains a disallowed extension: " + extension)
		}
		return nil
	})
}
func formatTimestamp(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}
func containsActor(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
