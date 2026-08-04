package main

import (
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/config"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
	"github.com/pythonhk/eventctl/internal/team"
)

func runTeam(args []string, stderr io.Writer) (any, error) {
	if len(args) == 0 {
		return nil, usageError("usage: eventctl team propose|consent|verify")
	}
	switch args[0] {
	case "propose":
		return teamPropose(args[1:], stderr)
	case "consent":
		return teamConsent(args[1:], stderr)
	case "verify":
		return teamVerify(args[1:])
	default:
		return nil, usageError("usage: eventctl team propose|consent|verify")
	}
}

type teamTrustFlags struct{ configPath, authority, stateMeta, registry string }

func addTeamTrustFlags(flags interface {
	String(string, string, string) *string
}) teamTrustFlags {
	return teamTrustFlags{*flags.String("config", "", "signed event config"), *flags.String("authority", "", "protected genesis"), *flags.String("state-meta", "", "protected current state metadata"), *flags.String("registry", "", "trusted identity registry")}
}

func teamPropose(args []string, stderr io.Writer) (any, error) {
	flags := newFlagSet("team propose")
	configPath := flags.String("config", "", "signed event config")
	authority := flags.String("authority", "", "protected genesis")
	stateMeta := flags.String("state-meta", "", "protected current state metadata")
	registryPath := flags.String("registry", "", "trusted identity registry")
	keyPath := flags.String("key", "", "encrypted participant key")
	passFile := flags.String("passphrase-file", "", "passphrase file or -")
	actorID := flags.String("actor-id", "", "numeric GitHub actor ID")
	membersPath := flags.String("members", "", "JSON array of numeric actor IDs")
	teamID := flags.String("team-id", "", "UUIDv4 (generated if omitted)")
	requestID := flags.String("request-id", "", "UUIDv4 (generated if omitted)")
	out := flags.String("out", "", "team proposal output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authority == "" || *stateMeta == "" || *registryPath == "" || *keyPath == "" || *actorID == "" || *membersPath == "" || *out == "" {
		return nil, usageError("usage: eventctl team propose --config PATH --authority PATH --state-meta PATH --registry PATH --key PATH --actor-id ID --members PATH --out PATH [--passphrase-file PATH|-] [--team-id UUID] [--request-id UUID]")
	}
	event, digest, meta, err := loadTrustedContext(*configPath, *authority, *stateMeta, time.Now().UTC())
	if err != nil {
		return nil, verificationError("verify event trust context", err)
	}
	if err := requirePhase(meta, "formation_open"); err != nil {
		return nil, verificationError("team formation is not open", err)
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
	members, err := loadMembers(*membersPath)
	if err != nil {
		return nil, invalidError("load team members", err)
	}
	if uint64(len(members)) < event.Teams.MinimumSize || uint64(len(members)) > event.Teams.MaximumSize {
		return nil, invalidError("team size is outside configured bounds", nil)
	}
	issued := time.Now().UTC().Truncate(time.Second)
	proposalTTL := time.Duration(event.Teams.ProposalTTLSeconds) * time.Second
	raw, err := team.NewProposal(team.ProposalParams{EventID: event.EventID, EventEpoch: event.EventEpoch, OperationID: *requestID, TeamID: *teamID, ProposerActorID: *actorID, KeyEpoch: keyEpoch, MemberActorIDs: members, BaseRepository: event.BaseRepository, ConfigDigest: digest, IssuedAt: issued, ExpiresAt: issued.Add(proposalTTL)}, pair.Private)
	if err != nil {
		return nil, invalidError("create team proposal", err)
	}
	verified, err := team.VerifyProposal(raw, envelope.Expected{EventID: event.EventID, EventEpoch: event.EventEpoch, RepositoryID: event.BaseRepository.ID, ActorID: *actorID, ConfigDigest: digest, Now: issued}, proposalTTL, registry)
	if err != nil {
		return nil, verificationError("self-verify team proposal", err)
	}
	if err := writeExclusive(*out, append(raw, '\n'), 0o644); err != nil {
		return nil, ioError("write team proposal", err)
	}
	docDigest, err := envelope.DocumentDigest(verified.Document)
	if err != nil {
		return nil, err
	}
	return requestSummary{*out, team.ProposalKind, verified.Fingerprint.RequestDigest, docDigest, verified.Fingerprint.ReplayKey}, nil
}

func teamConsent(args []string, stderr io.Writer) (any, error) {
	flags := newFlagSet("team consent")
	configPath := flags.String("config", "", "signed event config")
	authority := flags.String("authority", "", "protected genesis")
	stateMeta := flags.String("state-meta", "", "protected current state metadata")
	registryPath := flags.String("registry", "", "trusted identity registry")
	proposalPath := flags.String("proposal", "", "raw team proposal")
	keyPath := flags.String("key", "", "encrypted participant key")
	passFile := flags.String("passphrase-file", "", "passphrase file or -")
	actorID := flags.String("actor-id", "", "numeric GitHub actor ID")
	requestID := flags.String("request-id", "", "UUIDv4 (generated if omitted)")
	out := flags.String("out", "", "team consent output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authority == "" || *stateMeta == "" || *registryPath == "" || *proposalPath == "" || *keyPath == "" || *actorID == "" || *out == "" {
		return nil, usageError("usage: eventctl team consent --config PATH --authority PATH --state-meta PATH --registry PATH --proposal PATH --key PATH --actor-id ID --out PATH [--passphrase-file PATH|-] [--request-id UUID]")
	}
	event, _, meta, err := loadTrustedContext(*configPath, *authority, *stateMeta, time.Now().UTC())
	if err != nil {
		return nil, verificationError("verify event trust context", err)
	}
	if err := requirePhase(meta, "formation_open"); err != nil {
		return nil, verificationError("team formation is not open", err)
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
	proposalRaw, err := readBounded(*proposalPath, envelope.MaxDocumentBytes)
	if err != nil {
		return nil, ioError("read team proposal", err)
	}
	issued := time.Now().UTC().Truncate(time.Second)
	proposalTTL := time.Duration(event.Teams.ProposalTTLSeconds) * time.Second
	raw, err := team.NewConsent(proposalRaw, team.ConsentParams{OperationID: *requestID, ActorID: *actorID, KeyEpoch: keyEpoch, IssuedAt: issued, ExpiresAt: issued.Add(proposalTTL)}, pair.Private, registry)
	if err != nil {
		return nil, invalidError("create team consent", err)
	}
	verified, err := team.VerifyConsent(proposalRaw, raw, envelope.Expected{EventID: event.EventID, EventEpoch: event.EventEpoch, RepositoryID: event.BaseRepository.ID, ConfigDigest: meta.ConfigDigest, Now: issued}, proposalTTL, registry)
	if err != nil {
		return nil, verificationError("self-verify team consent", err)
	}
	if err := writeExclusive(*out, append(raw, '\n'), 0o644); err != nil {
		return nil, ioError("write team consent", err)
	}
	docDigest, err := envelope.DocumentDigest(verified.Document)
	if err != nil {
		return nil, err
	}
	return requestSummary{*out, team.ConsentKind, verified.Fingerprint.RequestDigest, docDigest, verified.Fingerprint.ReplayKey}, nil
}

func teamVerify(args []string) (any, error) {
	flags := newFlagSet("team verify")
	configPath := flags.String("config", "", "signed event config")
	authority := flags.String("authority", "", "protected genesis")
	stateMeta := flags.String("state-meta", "", "protected current state metadata")
	registryPath := flags.String("registry", "", "trusted identity registry")
	requestPath := flags.String("request", "", "proposal or consent request")
	proposalPath := flags.String("proposal", "", "verified proposal output, required for consent")
	sourceTimeText := flags.String("source-time", "", "trusted immutable GitHub source creation time")
	out := flags.String("out", "", "normalized verification output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authority == "" || *stateMeta == "" || *registryPath == "" || *requestPath == "" || *sourceTimeText == "" || *out == "" {
		return nil, usageError("usage: eventctl team verify --config PATH --authority PATH --state-meta PATH --registry PATH --request PATH --source-time RFC3339 [--proposal VERIFIED_PROPOSAL] --out PATH")
	}
	sourceTime, err := parseTrustedSourceTime(*sourceTimeText)
	if err != nil {
		return nil, invalidError("validate trusted source time", err)
	}
	event, digest, meta, err := loadTrustedContext(*configPath, *authority, *stateMeta, sourceTime)
	if err != nil {
		return nil, verificationError("verify event trust context", err)
	}
	if err := requirePhase(meta, "formation_open"); err != nil {
		return nil, verificationError("team formation is not open", err)
	}
	registry, err := loadRegistry(*registryPath)
	if err != nil {
		return nil, verificationError("load identity registry", err)
	}
	requestRaw, err := readBounded(*requestPath, envelope.MaxDocumentBytes)
	if err != nil {
		return nil, ioError("read team request", err)
	}
	kind, err := documentKind(requestRaw)
	if err != nil {
		return nil, invalidError("read team request kind", err)
	}
	expected := envelope.Expected{EventID: event.EventID, EventEpoch: event.EventEpoch, RepositoryID: event.BaseRepository.ID, ConfigDigest: digest, Now: sourceTime}
	proposalTTL := time.Duration(event.Teams.ProposalTTLSeconds) * time.Second
	var normalized normalizedRequest
	switch kind {
	case team.ProposalKind:
		verified, verifyErr := team.VerifyProposal(requestRaw, expected, proposalTTL, registry)
		if verifyErr != nil {
			return nil, verificationError("verify team proposal", verifyErr)
		}
		docDigest, _ := envelope.DocumentDigest(verified.Document)
		normalized = normalizedRequest{"verified", kind, verified.Fingerprint.RequestDigest, docDigest, verified.Fingerprint.ReplayKey, verified.Document}
	case team.ConsentKind:
		if *proposalPath == "" {
			return nil, usageError("team consent verification requires --proposal VERIFIED_PROPOSAL")
		}
		proposalRaw, loadErr := loadVerifiedProposal(*proposalPath)
		if loadErr != nil {
			return nil, verificationError("load verified team proposal", loadErr)
		}
		verified, verifyErr := team.VerifyConsent(proposalRaw, requestRaw, expected, proposalTTL, registry)
		if verifyErr != nil {
			return nil, verificationError("verify team consent", verifyErr)
		}
		docDigest, _ := envelope.DocumentDigest(verified.Document)
		normalized = normalizedRequest{"verified", kind, verified.Fingerprint.RequestDigest, docDigest, verified.Fingerprint.ReplayKey, verified.Document}
	default:
		return nil, invalidError("unsupported team request kind", errors.New(kind))
	}
	if err := writeCanonical(*out, normalized, 0o644); err != nil {
		return nil, ioError("write verified team request", err)
	}
	return requestSummary{*out, normalized.Kind, normalized.RequestDigest, normalized.DocumentDigest, normalized.ReplayKey}, nil
}

func loadRegistry(path string) (identity.Registry, error) {
	raw, err := readBounded(path, config.MaxBytes)
	if err != nil {
		return identity.Registry{}, err
	}
	return identity.ParseRegistry(raw)
}
func resolveKeyEpoch(registry identity.Registry, actorID string, public identity.Public) (string, error) {
	epoch := ""
	for _, entry := range registry.Identities {
		if entry.ActorID == actorID && entry.Identity == public {
			if epoch != "" {
				return "", errors.New("multiple registry epochs match key")
			}
			epoch = entry.KeyEpoch
		}
	}
	if epoch == "" {
		return "", errors.New("signing key is not the actor's trusted registration")
	}
	return epoch, nil
}
func loadMembers(path string) ([]string, error) {
	raw, err := readBounded(path, 64*1024)
	if err != nil {
		return nil, err
	}
	var members []string
	if err := canonical.StrictUnmarshal(raw, &members); err != nil {
		return nil, err
	}
	if len(members) == 0 {
		return nil, errors.New("members array is empty")
	}
	return members, nil
}
func documentKind(raw []byte) (string, error) {
	var object map[string]json.RawMessage
	if err := canonical.StrictUnmarshal(raw, &object); err != nil {
		return "", err
	}
	value, ok := object["kind"]
	if !ok {
		return "", errors.New("missing kind")
	}
	var kind string
	if err := canonical.StrictUnmarshal(value, &kind); err != nil {
		return "", err
	}
	return kind, nil
}
func loadVerifiedProposal(path string) ([]byte, error) {
	raw, err := readBounded(path, envelope.MaxDocumentBytes*2)
	if err != nil {
		return nil, err
	}
	var normalized struct {
		Status         string        `json:"status"`
		Kind           string        `json:"kind"`
		RequestDigest  string        `json:"request_digest"`
		DocumentDigest string        `json:"document_digest"`
		ReplayKey      string        `json:"replay_key"`
		Document       team.Proposal `json:"document"`
	}
	if err := canonical.StrictUnmarshal(raw, &normalized); err != nil {
		return nil, err
	}
	if normalized.Status != "verified" || normalized.Kind != team.ProposalKind {
		return nil, errors.New("file is not a verified team proposal")
	}
	docDigest, err := envelope.DocumentDigest(normalized.Document)
	if err != nil || docDigest != normalized.DocumentDigest {
		return nil, errors.New("verified proposal document digest mismatch")
	}
	return canonical.Marshal(normalized.Document)
}
