package envelope

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/identity"
)

const (
	SubmissionKind         = "submission_envelope"
	SubmissionDomain       = "submission_envelope"
	SubmissionDeliveryMode = "signed_pr_comment_after_push"
	SubmissionBundleFormat = "eventctl-encrypted-bundle-v1"
)

// PullRequest is the full fork address and immutable head object seal.
type PullRequest struct {
	Number           uint64 `json:"number"`
	ID               string `json:"id"`
	BaseRepositoryID string `json:"base_repository_id"`
	BaseRef          string `json:"base_ref"`
	HeadRepositoryID string `json:"head_repository_id"`
	HeadOwner        string `json:"head_owner"`
	HeadRef          string `json:"head_ref"`
	HeadSHA          string `json:"head_sha"`
}

// PRMetadata is the bounded transport document supplied after resolving a PR
// through GitHub's API. eventctl never performs the GitHub lookup itself.
type PRMetadata struct {
	Kind                string      `json:"kind"`
	ActorID             string      `json:"actor_id"`
	PullRequestAuthorID string      `json:"pull_request_author_id"`
	BaseRepository      Repository  `json:"base_repository"`
	PullRequest         PullRequest `json:"pull_request"`
}

// BundleReference binds the exact committed encrypted bundle and its public
// envelope/ciphertext digests.
type BundleReference struct {
	Path             string `json:"path"`
	SizeBytes        uint64 `json:"size_bytes"`
	SHA256           string `json:"sha256"`
	EnvelopeSHA256   string `json:"envelope_sha256"`
	CiphertextSize   uint64 `json:"ciphertext_size"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
	Format           string `json:"format"`
}

// Submission is the actor-bound post-push submission request.
type Submission struct {
	Kind               string             `json:"kind"`
	Protocol           string             `json:"protocol"`
	ProtocolVersion    int                `json:"protocol_version"`
	EventID            string             `json:"event_id"`
	EventEpoch         string             `json:"event_epoch"`
	RequestID          string             `json:"request_id"`
	AttemptID          string             `json:"attempt_id"`
	ActorID            string             `json:"actor_id"`
	KeyID              string             `json:"key_id"`
	KeyEpoch           string             `json:"key_epoch"`
	TeamID             string             `json:"team_id"`
	TeamProposalDigest string             `json:"team_proposal_digest"`
	BaseRepository     Repository         `json:"base_repository"`
	PullRequest        PullRequest        `json:"pull_request"`
	ConfigDigest       string             `json:"config_digest"`
	IssuedAt           string             `json:"issued_at"`
	ExpiresAt          string             `json:"expires_at"`
	DeliveryMode       string             `json:"delivery_mode"`
	Bundle             BundleReference    `json:"bundle"`
	Signature          identity.Signature `json:"signature"`
}

// ValidateUntrustedStructure validates the concrete submission schema and
// internal field relationships without authenticating its signature, trusted
// actor/config context, GitHub metadata freshness, or current validity window.
func (value Submission) ValidateUntrustedStructure() error {
	if err := validateSubmission(value, time.Time{}); err != nil {
		return err
	}
	if err := value.Signature.ValidateEncoding(); err != nil {
		return err
	}
	if value.Signature.KeyID != value.KeyID {
		return errors.New("signature.key_id does not match key_id")
	}
	return nil
}

type submissionUnsigned struct {
	Kind               string          `json:"kind"`
	Protocol           string          `json:"protocol"`
	ProtocolVersion    int             `json:"protocol_version"`
	EventID            string          `json:"event_id"`
	EventEpoch         string          `json:"event_epoch"`
	RequestID          string          `json:"request_id"`
	AttemptID          string          `json:"attempt_id"`
	ActorID            string          `json:"actor_id"`
	KeyID              string          `json:"key_id"`
	KeyEpoch           string          `json:"key_epoch"`
	TeamID             string          `json:"team_id"`
	TeamProposalDigest string          `json:"team_proposal_digest"`
	BaseRepository     Repository      `json:"base_repository"`
	PullRequest        PullRequest     `json:"pull_request"`
	ConfigDigest       string          `json:"config_digest"`
	IssuedAt           string          `json:"issued_at"`
	ExpiresAt          string          `json:"expires_at"`
	DeliveryMode       string          `json:"delivery_mode"`
	Bundle             BundleReference `json:"bundle"`
}

type SubmissionParams struct {
	EventID            string
	EventEpoch         string
	RequestID          string
	AttemptID          string
	ActorID            string
	KeyEpoch           string
	TeamID             string
	TeamProposalDigest string
	Metadata           PRMetadata
	ConfigDigest       string
	IssuedAt           time.Time
	ExpiresAt          time.Time
	Bundle             BundleReference
}

type VerifiedSubmission struct {
	Document    Submission
	Fingerprint Fingerprint
}

// MetadataEquivalent reconstructs the exact bounded transport metadata bound
// by a verified submission for comparison with a fresh GitHub API lookup.
func (submission Submission) MetadataEquivalent() PRMetadata {
	return PRMetadata{Kind: "github_pr_metadata", ActorID: submission.ActorID, PullRequestAuthorID: submission.ActorID, BaseRepository: submission.BaseRepository, PullRequest: submission.PullRequest}
}

// NewSubmission creates the post-push request. The caller must populate Bundle
// from a successful structural inspection of the committed bundle.
func NewSubmission(params SubmissionParams, private identity.Private) ([]byte, error) {
	pair, err := parsePrivate(private)
	if err != nil {
		return nil, err
	}
	if params.RequestID == "" {
		params.RequestID, err = NewRequestID()
		if err != nil {
			return nil, err
		}
	}
	if params.KeyEpoch == "" {
		params.KeyEpoch = "1"
	}
	if params.Metadata.Kind != "github_pr_metadata" || params.Metadata.ActorID != params.ActorID || params.Metadata.PullRequestAuthorID != params.ActorID {
		return nil, errors.New("PR metadata actor and author must match submission actor")
	}
	submission := Submission{
		Kind: SubmissionKind, Protocol: Protocol, ProtocolVersion: ProtocolVersion,
		EventID: params.EventID, EventEpoch: params.EventEpoch, RequestID: params.RequestID, AttemptID: params.AttemptID,
		ActorID: params.ActorID, KeyID: pair.Public.KeyID, KeyEpoch: params.KeyEpoch, TeamID: params.TeamID, TeamProposalDigest: params.TeamProposalDigest,
		BaseRepository: params.Metadata.BaseRepository, PullRequest: params.Metadata.PullRequest,
		ConfigDigest: params.ConfigDigest, IssuedAt: formatTime(params.IssuedAt), ExpiresAt: formatTime(params.ExpiresAt),
		DeliveryMode: SubmissionDeliveryMode, Bundle: params.Bundle,
	}
	if err := validateSubmission(submission, time.Time{}); err != nil {
		return nil, err
	}
	submission.Signature, err = Sign(SubmissionDomain, unsignedSubmission(submission), pair.Private)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(submission)
}

// VerifySubmission authenticates a post-push request with the exact registered
// key. The intake must additionally fetch the head SHA, inspect the referenced
// bundle, and cross-check every bundle binding before state admission.
func VerifySubmission(raw []byte, expected Expected, registry identity.Registry) (VerifiedSubmission, error) {
	if len(raw) > MaxDocumentBytes {
		return VerifiedSubmission{}, errors.New("submission document exceeds 1 MiB")
	}
	var submission Submission
	if err := canonical.StrictUnmarshal(raw, &submission); err != nil {
		return VerifiedSubmission{}, fmt.Errorf("decode submission: %w", err)
	}
	if err := validateSubmission(submission, expected.Now); err != nil {
		return VerifiedSubmission{}, err
	}
	if err := compareExpected(submission.EventID, submission.EventEpoch, submission.BaseRepository.ID, submission.ActorID, submission.ConfigDigest, submission.KeyEpoch, submission.KeyID, expected); err != nil {
		return VerifiedSubmission{}, err
	}
	trusted, ok := registry.Resolve(submission.ActorID, submission.KeyEpoch)
	if !ok || trusted.KeyID != submission.KeyID {
		return VerifiedSubmission{}, errors.New("submission signer does not match trusted registration")
	}
	if err := Verify(SubmissionDomain, unsignedSubmission(submission), submission.Signature, trusted); err != nil {
		return VerifiedSubmission{}, err
	}
	intentDigest, err := SigningDigest(SubmissionDomain, unsignedSubmission(submission))
	if err != nil {
		return VerifiedSubmission{}, err
	}
	fingerprint, err := NewFingerprint(SubmissionDomain, submission.EventID, submission.RequestID, intentDigest)
	if err != nil {
		return VerifiedSubmission{}, err
	}
	return VerifiedSubmission{Document: submission, Fingerprint: fingerprint}, nil
}

func ParsePRMetadata(raw []byte) (PRMetadata, error) {
	if len(raw) > 64*1024 {
		return PRMetadata{}, errors.New("PR metadata exceeds 64 KiB")
	}
	var metadata PRMetadata
	if err := canonical.StrictUnmarshal(raw, &metadata); err != nil {
		return PRMetadata{}, fmt.Errorf("decode PR metadata: %w", err)
	}
	if err := ValidateRepository(metadata.BaseRepository); err != nil {
		return PRMetadata{}, err
	}
	if metadata.Kind != "github_pr_metadata" {
		return PRMetadata{}, errors.New("PR metadata kind is invalid")
	}
	if err := identity.ValidateDecimal(metadata.ActorID, "actor_id"); err != nil {
		return PRMetadata{}, err
	}
	if metadata.PullRequestAuthorID != metadata.ActorID {
		return PRMetadata{}, errors.New("v1 requires actor_id to equal pull_request_author_id")
	}
	if err := validatePullRequest(metadata.PullRequest); err != nil {
		return PRMetadata{}, err
	}
	if metadata.BaseRepository.ID != metadata.PullRequest.BaseRepositoryID {
		return PRMetadata{}, errors.New("PR base_repository_id does not match base_repository.id")
	}
	return metadata, nil
}

func validateSubmission(value Submission, now time.Time) error {
	if value.Kind != SubmissionKind || value.Protocol != Protocol || value.ProtocolVersion != ProtocolVersion || value.DeliveryMode != SubmissionDeliveryMode {
		return errors.New("submission protocol discriminator is invalid")
	}
	if !IsEventID(value.EventID) || !IsUUID(value.RequestID) || !IsUUID(value.AttemptID) || !IsUUID(value.TeamID) {
		return errors.New("submission event/request/attempt/team identifier is invalid")
	}
	if err := identity.ValidateDecimal(value.EventEpoch, "event_epoch"); err != nil {
		return err
	}
	if err := identity.ValidateDecimal(value.ActorID, "actor_id"); err != nil {
		return err
	}
	if err := identity.ValidateDecimal(value.KeyEpoch, "key_epoch"); err != nil {
		return err
	}
	if !IsDigest(value.KeyID) || !IsDigest(value.ConfigDigest) || !IsDigest(value.TeamProposalDigest) {
		return errors.New("submission key_id/config_digest is invalid")
	}
	if err := ValidateRepository(value.BaseRepository); err != nil {
		return err
	}
	if err := validatePullRequest(value.PullRequest); err != nil {
		return err
	}
	if value.PullRequest.BaseRepositoryID != value.BaseRepository.ID {
		return errors.New("pull_request.base_repository_id does not match base_repository.id")
	}
	if err := validateBundleReference(value.Bundle); err != nil {
		return err
	}
	return ValidateWindow(value.IssuedAt, value.ExpiresAt, now)
}

func validatePullRequest(value PullRequest) error {
	if value.Number == 0 {
		return errors.New("pull request number must be positive")
	}
	if err := identity.ValidateDecimal(value.ID, "pull_request.id"); err != nil {
		return err
	}
	if err := ValidateRepositoryID(value.BaseRepositoryID); err != nil {
		return err
	}
	if err := ValidateRef(value.BaseRef); err != nil {
		return fmt.Errorf("base_ref: %w", err)
	}
	if err := identity.ValidateDecimal(value.HeadRepositoryID, "head_repository_id"); err != nil {
		return err
	}
	if !ownerPattern.MatchString(value.HeadOwner) || len(value.HeadOwner) > 39 {
		return errors.New("head_owner is invalid")
	}
	if err := ValidateRef(value.HeadRef); err != nil {
		return err
	}
	if !IsGitOID(value.HeadSHA) {
		return errors.New("head_sha must be a lower-case Git SHA-1 or SHA-256 object ID")
	}
	return nil
}

func validateBundleReference(value BundleReference) error {
	clean := filepath.ToSlash(filepath.Clean(value.Path))
	if value.Path != "submission.eventctl" || clean != value.Path || filepath.IsAbs(value.Path) || strings.Contains(clean, "..") {
		return errors.New("bundle.path must be exactly submission.eventctl")
	}
	if value.SizeBytes == 0 || value.SizeBytes > 48_000_000 {
		return errors.New("bundle.size_bytes is outside the allowed range")
	}
	if value.CiphertextSize == 0 || value.CiphertextSize > 47_000_000 || value.CiphertextSize >= value.SizeBytes {
		return errors.New("bundle.ciphertext_size is outside the allowed range")
	}
	if !IsDigest(value.SHA256) || !IsDigest(value.EnvelopeSHA256) || !IsDigest(value.CiphertextSHA256) {
		return errors.New("bundle digests must be raw lower-case SHA-256 hex")
	}
	if value.Format != SubmissionBundleFormat {
		return errors.New("bundle format is unsupported")
	}
	return nil
}

func unsignedSubmission(v Submission) submissionUnsigned {
	return submissionUnsigned{v.Kind, v.Protocol, v.ProtocolVersion, v.EventID, v.EventEpoch, v.RequestID, v.AttemptID, v.ActorID, v.KeyID, v.KeyEpoch, v.TeamID, v.TeamProposalDigest, v.BaseRepository, v.PullRequest, v.ConfigDigest, v.IssuedAt, v.ExpiresAt, v.DeliveryMode, v.Bundle}
}
