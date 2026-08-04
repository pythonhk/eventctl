package envelope

import (
	"errors"
	"fmt"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/identity"
)

const PackRecordKind = "submission_pack_record"

type PackRecordBundle struct {
	Path             string `json:"path"`
	Format           string `json:"format"`
	SizeBytes        uint64 `json:"size_bytes"`
	SHA256           string `json:"sha256"`
	EnvelopeSHA256   string `json:"envelope_sha256"`
	CiphertextSize   uint64 `json:"ciphertext_size"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
}

type PackRecord struct {
	Kind                string           `json:"kind"`
	Protocol            string           `json:"protocol"`
	ProtocolVersion     int              `json:"protocol_version"`
	EventID             string           `json:"event_id"`
	EventEpoch          string           `json:"event_epoch"`
	RequestID           string           `json:"request_id"`
	AttemptID           string           `json:"attempt_id"`
	ActorID             string           `json:"actor_id"`
	KeyID               string           `json:"key_id"`
	KeyEpoch            string           `json:"key_epoch"`
	TeamID              string           `json:"team_id"`
	TeamProposalDigest  string           `json:"team_proposal_digest"`
	BaseRepositoryID    string           `json:"base_repository_id"`
	ConfigDigest        string           `json:"config_digest"`
	RecipientEpoch      string           `json:"recipient_epoch"`
	RecipientKeyIDs     []string         `json:"recipient_key_ids"`
	InnerManifestSHA256 string           `json:"inner_manifest_sha256"`
	FileCount           uint32           `json:"file_count"`
	PlaintextSize       uint64           `json:"plaintext_size"`
	Bundle              PackRecordBundle `json:"bundle"`
	CreatedAt           string           `json:"created_at"`
}

func ParsePackRecord(raw []byte) (PackRecord, error) {
	if len(raw) > MaxDocumentBytes {
		return PackRecord{}, errors.New("pack record exceeds 1 MiB")
	}
	var record PackRecord
	if err := canonical.StrictUnmarshal(raw, &record); err != nil {
		return PackRecord{}, fmt.Errorf("decode pack record: %w", err)
	}
	if err := record.Validate(); err != nil {
		return PackRecord{}, err
	}
	return record, nil
}

func (r PackRecord) Validate() error {
	if r.Kind != PackRecordKind || r.Protocol != Protocol || r.ProtocolVersion != ProtocolVersion {
		return errors.New("pack record protocol discriminator is invalid")
	}
	if !IsEventID(r.EventID) || identity.ValidateDecimal(r.EventEpoch, "event_epoch") != nil || !IsUUID(r.RequestID) || !IsUUID(r.AttemptID) || identity.ValidateDecimal(r.ActorID, "actor_id") != nil || !IsDigest(r.KeyID) || identity.ValidateDecimal(r.KeyEpoch, "key_epoch") != nil || !IsUUID(r.TeamID) || !IsDigest(r.TeamProposalDigest) || ValidateRepositoryID(r.BaseRepositoryID) != nil || !IsDigest(r.ConfigDigest) || identity.ValidateDecimal(r.RecipientEpoch, "recipient_epoch") != nil {
		return errors.New("pack record binding is invalid")
	}
	if len(r.RecipientKeyIDs) < 1 || len(r.RecipientKeyIDs) > 32 {
		return errors.New("pack record recipient count is invalid")
	}
	for index, keyID := range r.RecipientKeyIDs {
		if !IsDigest(keyID) {
			return errors.New("recipient fingerprint is invalid")
		}
		if index > 0 && r.RecipientKeyIDs[index-1] >= keyID {
			return errors.New("recipient fingerprints must be strictly sorted")
		}
	}
	if !IsDigest(r.InnerManifestSHA256) || r.FileCount < 1 || r.FileCount > MaxSubmissionFilesV1 || r.PlaintextSize < 1 || r.PlaintextSize > 42_000_000 {
		return errors.New("pack record manifest summary is invalid")
	}
	if r.Bundle.Path != "submission.eventctl" || r.Bundle.Format != SubmissionBundleFormat || r.Bundle.SizeBytes < 1 || r.Bundle.SizeBytes > 48_000_000 || !IsDigest(r.Bundle.SHA256) || !IsDigest(r.Bundle.EnvelopeSHA256) || r.Bundle.CiphertextSize < 1 || r.Bundle.CiphertextSize > 47_000_000 || r.Bundle.CiphertextSize >= r.Bundle.SizeBytes || !IsDigest(r.Bundle.CiphertextSHA256) {
		return errors.New("pack record bundle summary is invalid")
	}
	if _, err := ParseTimestamp(r.CreatedAt); err != nil {
		return err
	}
	return nil
}
