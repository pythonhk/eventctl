package main

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"filippo.io/age"
	"github.com/pythonhk/eventctl/internal/bundle"
	"github.com/pythonhk/eventctl/internal/config"
	"github.com/pythonhk/eventctl/internal/envelope"
)

type normalizedPublicBundle struct {
	Status         string              `json:"status"`
	Kind           string              `json:"kind"`
	EnvelopeDigest string              `json:"envelope_digest"`
	BundleDigest   string              `json:"bundle_digest"`
	BundleSize     uint64              `json:"bundle_size"`
	Envelope       bundle.Envelope     `json:"envelope"`
	Record         envelope.PackRecord `json:"record"`
}

func submissionVerifyPublic(args []string) (any, error) {
	flags := newFlagSet("submission verify")
	configPath := flags.String("config", "", "signed event config")
	authorityPath := flags.String("authority", "", "protected genesis authority")
	statePath := flags.String("state-meta", "", "protected current state metadata")
	registryPath := flags.String("registry", "", "protected public identity registry")
	bundlePath := flags.String("bundle", "", "encrypted submission bundle")
	recordPath := flags.String("record", "", "local submission pack record")
	out := flags.String("out", "", "normalized public verification output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authorityPath == "" || *statePath == "" || *registryPath == "" || *bundlePath == "" || *recordPath == "" || *out == "" {
		return nil, usageError("usage: eventctl submission verify --config PATH --authority PATH --state-meta PATH --registry PATH --bundle submission.eventctl --record PATH --out PATH")
	}
	if filepath.Base(filepath.Clean(*bundlePath)) != "submission.eventctl" {
		return nil, invalidError("--bundle file name must be submission.eventctl", nil)
	}
	event, digest, _, err := loadTrustedContext(*configPath, *authorityPath, *statePath, time.Now().UTC())
	if err != nil {
		return nil, verificationError("verify event trust context", err)
	}
	registry, err := loadRegistry(*registryPath)
	if err != nil {
		return nil, verificationError("load identity registry", err)
	}
	recordRaw, err := readBounded(*recordPath, envelope.MaxDocumentBytes)
	if err != nil {
		return nil, ioError("read pack record", err)
	}
	record, err := envelope.ParsePackRecord(recordRaw)
	if err != nil {
		return nil, verificationError("validate pack record", err)
	}
	registered, ok := registry.Resolve(record.ActorID, record.KeyEpoch)
	if !ok || registered.KeyID != record.KeyID {
		return nil, verificationError("pack record signer is not registered", nil)
	}
	inspection, err := bundle.AuthenticatePublic(context.Background(), *bundlePath, registered, bundleLimits(event))
	if err != nil {
		return nil, verificationError("authenticate public bundle envelope", err)
	}
	if err := compareRecordInspection(record, inspection); err != nil {
		return nil, verificationError("pack record/bundle mismatch", err)
	}
	if !slices.Equal(record.RecipientKeyIDs, inspection.Envelope.RecipientKeyIDs) || record.CreatedAt != inspection.Envelope.IssuedAt {
		return nil, verificationError("pack record recipient/timestamp differs from authenticated envelope", nil)
	}
	configuredRecipientIDs, err := configuredHybridRecipientIDs(event.Submissions.Encryption.Recipients)
	if err != nil {
		return nil, verificationError("derive configured recipient fingerprints", err)
	}
	e := inspection.Envelope
	if e.EventID != event.EventID || e.EventEpoch != event.EventEpoch || e.BaseRepositoryID != event.BaseRepository.ID || e.ConfigDigest != digest || e.RecipientEpoch != event.Submissions.Encryption.RecipientEpoch || !slices.Equal(e.RecipientKeyIDs, configuredRecipientIDs) {
		return nil, verificationError("authenticated bundle does not match trusted event/config recipient set", nil)
	}
	if err := envelope.ValidateWindowWithin(e.IssuedAt, e.ExpiresAt, time.Now().UTC(), time.Duration(event.Submissions.EnvelopeTTLSeconds)*time.Second); err != nil {
		return nil, verificationError("bundle validity window", err)
	}
	normalized := normalizedPublicBundle{"verified", bundle.EnvelopeKind, inspection.EnvelopeSHA256, inspection.BundleSHA256, inspection.BundleSize, inspection.Envelope, record}
	if err := writeCanonical(*out, normalized, 0o644); err != nil {
		return nil, ioError("write verified public bundle", err)
	}
	return struct {
		Path           string `json:"path"`
		Kind           string `json:"kind"`
		BundleDigest   string `json:"bundle_digest"`
		EnvelopeDigest string `json:"envelope_digest"`
		ActorID        string `json:"actor_id"`
		AttemptID      string `json:"attempt_id"`
	}{*out, bundle.EnvelopeKind, inspection.BundleSHA256, inspection.EnvelopeSHA256, e.ActorID, e.AttemptID}, nil
}

func configuredHybridRecipientIDs(configured []config.Recipient) ([]string, error) {
	ids := make([]string, 0, len(configured))
	for _, configuredRecipient := range configured {
		encoded := configuredRecipient.PublicKey
		recipient, err := age.ParseHybridRecipient(encoded)
		if err != nil || recipient.String() != encoded {
			return nil, errors.New("configured hybrid recipient is invalid")
		}
		fingerprint, err := bundle.HybridRecipientFingerprint(recipient)
		if err != nil {
			return nil, err
		}
		ids = append(ids, fingerprint)
	}
	sort.Strings(ids)
	for index := 1; index < len(ids); index++ {
		if ids[index-1] == ids[index] {
			return nil, errors.New("configured recipient fingerprints are duplicated")
		}
	}
	return ids, nil
}
