//go:build e2e

package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/suite"

	"github.com/pythonhk/eventctl/internal/protocol"
	"github.com/pythonhk/eventctl/internal/stream"
)

type response struct {
	OK      bool            `json:"ok"`
	Command string          `json:"command"`
	Result  json.RawMessage `json:"result"`
	Error   string          `json:"error"`
}

type keyResult struct {
	SigningPrivate   string `json:"signing_private_key"`
	SigningPublic    string `json:"signing_public_key"`
	RecipientPrivate string `json:"recipient_private_key"`
	RecipientPublic  string `json:"recipient_public_key"`
}

type eventSuite struct {
	suite.Suite
	root       string
	work       string
	binary     string
	coverage   string
	passphrase string
	binding    string
	input      string
	metadata   string
	organizer  keyResult
	memberOne  keyResult
	memberTwo  keyResult
	proposal   string
	consentOne string
	consentTwo string
	stream     string
}

func TestEventctl(t *testing.T) { suite.Run(t, new(eventSuite)) }

func (s *eventSuite) SetupSuite() {
	_, currentFile, _, ok := runtime.Caller(0)
	s.Require().True(ok)
	s.root = filepath.Clean(filepath.Join(filepath.Dir(currentFile), "../.."))
	s.work = s.T().TempDir()
	s.binary = filepath.Join(s.work, "eventctl")
	s.coverage = os.Getenv("GOCOVERDIR")
	if s.coverage == "" {
		s.coverage = filepath.Join(s.work, "coverage")
	}
	s.Require().NoError(os.MkdirAll(s.coverage, 0o755))
	build := exec.Command("go", "build", "-cover", "-coverpkg=./...", "-o", s.binary, "./cmd/eventctl")
	build.Dir = s.root
	build.Env = append(os.Environ(), "GOCOVERDIR="+s.coverage)
	output, err := build.CombinedOutput()
	s.Require().NoError(err, string(output))
	s.passphrase = filepath.Join(s.work, "passphrase.txt")
	s.Require().NoError(os.WriteFile(s.passphrase, []byte("correct horse battery staple\n"), 0o600))
	s.binding = filepath.Join(s.work, "binding.json")
	s.writeJSON(s.binding, map[string]any{
		"event_id": "pycon-hk-2026", "event_epoch": 1, "request_id": "request-001", "attempt_id": "attempt-001", "actor_id": "100", "key_epoch": 1,
		"team_id": "team-001", "team_proposal_digest": "team-digest-001", "base_repository_id": 12345, "config_digest": "config-digest-001",
		"issued_at": "2026-08-07T09:00:00Z", "expires_at": "2026-08-08T09:00:00Z",
	})
	s.input = filepath.Join(s.work, "judge.log")
	s.metadata = filepath.Join(s.work, "metadata.json")
	s.Require().NoError(os.WriteFile(s.input, []byte("private judge output\n"), 0o600))
	s.Require().NoError(os.WriteFile(s.metadata, []byte(`{"language":"python","attempt":1}`), 0o600))
	s.organizer = s.keyGen("organizer")
	s.memberOne = s.keyGen("member-one")
	s.memberTwo = s.keyGen("member-two")
}

func (s *eventSuite) TearDownSuite() {
	entries, err := os.ReadDir(s.coverage)
	s.Require().NoError(err)
	meta, counters := false, false
	for _, entry := range entries {
		meta = meta || strings.HasPrefix(entry.Name(), "covmeta.")
		counters = counters || strings.HasPrefix(entry.Name(), "covcounters.")
	}
	s.Require().True(meta, "instrumented binary did not emit covmeta")
	s.Require().True(counters, "instrumented binary did not emit covcounters")
}

func (s *eventSuite) TestVersionDoctorAndHelp() {
	value := s.success("version")
	s.Require().JSONEq(`{"version":"0.1.0","commit":"dev","protocol":"eventctl/v1"}`, string(value.Result))
	doctor := s.successWithEnv(map[string]string{"EVENTCTL_EVENT_ID": "weekend-1", "EVENTCTL_EVENT_EPOCH": "2"}, "doctor")
	s.Contains(string(doctor.Result), `"event_id":"weekend-1"`)
	s.Contains(string(doctor.Result), `"event_epoch":2`)
	s.raw(0, "--help")
	s.failureWithEnv(map[string]string{"EVENTCTL_EVENT_EPOCH": "0"}, "doctor")
	s.failureWithEnv(map[string]string{"EVENTCTL_EVENT_EPOCH": "not-an-int"}, "doctor")
}

func (s *eventSuite) TestKeyGenerationFailures() {
	s.failure("key-gen", "--out", filepath.Join(s.work, "missing-pass"))
	empty := filepath.Join(s.work, "empty-pass")
	s.Require().NoError(os.WriteFile(empty, nil, 0o600))
	s.failure("key-gen", "--out", filepath.Join(s.work, "empty-key"), "--passphrase-file", empty)
	s.failure("key-gen", "--out", filepath.Join(s.work, "organizer"), "--passphrase-file", s.passphrase)
	badPass := filepath.Join(s.work, "wrong-pass")
	s.Require().NoError(os.WriteFile(badPass, []byte("wrong\n"), 0o600))
	s.failure("sigcrypt", "--input", s.input, "--output", filepath.Join(s.work, "bad-pass.stream"), "--context", s.binding, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", badPass, "--enc-public-key", s.memberOne.RecipientPublic)
}

func (s *eventSuite) TestCommandInputErrors() {
	identity := filepath.Join(s.work, "command-errors-identity.json")
	s.success("identity", "register", "--context", s.binding, "--actor-id", "100", "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", identity)
	s.failure("identity", "register", "--context", s.binding, "--actor-id", "100", "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", identity)
	s.failure("identity", "verify", "--context", filepath.Join(s.work, "missing-context"), "--input", identity, "--ver-public-key", s.organizer.SigningPublic)
	proposal := filepath.Join(s.work, "command-errors-proposal.json")
	s.success("team", "register", "--context", s.binding, "--team-id", "team-001", "--member", "200", "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", proposal)
	s.failure("team", "register", "--context", s.binding, "--team-id", "team-001", "--member", "200", "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", proposal)
	s.failure("team", "register", "--context", s.binding, "--team-id", "wrong-team", "--member", "200", "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "wrong-team.json"))
	fileAsDirectory := filepath.Join(s.work, "not-a-directory")
	s.Require().NoError(os.WriteFile(fileAsDirectory, []byte("file"), 0o600))
	s.failure("key-gen", "--out", fileAsDirectory, "--passphrase-file", s.passphrase)
	s.failure("sigcrypt", "--input", s.input, "--output", filepath.Join(s.work, "missing-pass.stream"), "--context", s.binding, "--sig-private-key", s.organizer.SigningPrivate)
	s.failure("sigcrypt", "--input", s.input, "--output", filepath.Join(s.work, "missing-signing.stream"), "--context", s.binding, "--sig-private-key", filepath.Join(s.work, "missing-signing"), "--passphrase-file", s.passphrase, "--enc-public-key", s.memberOne.RecipientPublic)
	s.failure("sigcrypt", "--input", filepath.Join(s.work, "missing-input"), "--output", filepath.Join(s.work, "missing-input.stream"), "--context", s.binding, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", s.memberOne.RecipientPublic)
	s.failure("sigcrypt", "--input", s.input, "--output", filepath.Join(s.work, "bad-context.stream"), "--context", filepath.Join(s.work, "missing-context"), "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", s.memberOne.RecipientPublic)

	s.failure("decverify", "--input", s.input, "--output", filepath.Join(s.work, "missing-context.log"), "--context", filepath.Join(s.work, "missing-context"), "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	s.failure("decverify", "--input", s.input, "--output", filepath.Join(s.work, "missing-signer.log"), "--context", s.binding, "--ver-public-key", filepath.Join(s.work, "missing-signer"), "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	s.failure("decverify", "--input", s.input, "--output", filepath.Join(s.work, "missing-pass.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate)
	s.failure("decverify", "--input", s.input, "--output", filepath.Join(s.work, "missing-recipient.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", filepath.Join(s.work, "missing-recipient"), "--passphrase-file", s.passphrase)
	s.failure("decverify", "--input", filepath.Join(s.work, "missing-stream"), "--output", filepath.Join(s.work, "missing-stream.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)

	s.failure("identity", "register", "--context", filepath.Join(s.work, "missing-context"), "--actor-id", "100", "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "identity-missing-context.json"))
	s.failure("identity", "register", "--context", s.binding, "--actor-id", "100", "--sig-private-key", filepath.Join(s.work, "missing-signing"), "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "identity-missing-signing.json"))
	s.failure("identity", "register", "--context", s.binding, "--actor-id", "100", "--sig-private-key", s.organizer.SigningPrivate, "--output", filepath.Join(s.work, "identity-missing-pass.json"))
	s.failure("identity", "verify", "--context", s.binding, "--input", filepath.Join(s.work, "missing-identity.json"), "--ver-public-key", s.organizer.SigningPublic)
	s.failure("identity", "verify", "--context", s.binding, "--input", identity, "--ver-public-key", filepath.Join(s.work, "missing-public"))

	s.failure("team", "register", "--context", filepath.Join(s.work, "missing-context"), "--team-id", "team-001", "--member", "200", "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "team-missing-context.json"))
	s.failure("team", "register", "--context", s.binding, "--team-id", "team-001", "--member", "200", "--sig-private-key", filepath.Join(s.work, "missing-signing"), "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "team-missing-signing.json"))
	s.failure("team", "register", "--context", s.binding, "--team-id", "team-001", "--member", "200", "--sig-private-key", s.organizer.SigningPrivate, "--output", filepath.Join(s.work, "team-missing-pass.json"))
	s.failure("team", "consent", "--proposal", filepath.Join(s.work, "missing-proposal.json"), "--actor-id", "200", "--sig-private-key", s.memberOne.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "consent-missing-proposal.json"))
	s.failure("team", "consent", "--proposal", proposal, "--actor-id", "200", "--sig-private-key", filepath.Join(s.work, "missing-signing"), "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "consent-missing-signing.json"))
	s.failure("team", "consent", "--proposal", proposal, "--actor-id", "200", "--sig-private-key", s.memberOne.SigningPrivate, "--output", filepath.Join(s.work, "consent-missing-pass.json"))
	consent := filepath.Join(s.work, "command-errors-consent.json")
	s.success("team", "consent", "--proposal", proposal, "--actor-id", "200", "--sig-private-key", s.memberOne.SigningPrivate, "--passphrase-file", s.passphrase, "--output", consent)
	s.failure("team", "consent", "--proposal", proposal, "--actor-id", "200", "--sig-private-key", s.memberOne.SigningPrivate, "--passphrase-file", s.passphrase, "--output", consent)
	s.failure("team", "verify", "--proposal", filepath.Join(s.work, "missing-proposal.json"), "--consent", s.consentOne)
	s.failure("team", "verify", "--proposal", proposal, "--consent", filepath.Join(s.work, "missing-consent.json"))

	s.failure("submission", "prepare", "--context", s.binding, "--input", filepath.Join(s.work, "missing-input"), "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "missing-input.json"))
	s.failure("submission", "prepare", "--context", s.binding, "--input", s.input, "--sig-private-key", filepath.Join(s.work, "missing-signing"), "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "missing-signing.json"))
	s.failure("submission", "prepare", "--context", s.binding, "--input", s.input, "--sig-private-key", s.organizer.SigningPrivate, "--output", filepath.Join(s.work, "missing-pass.json"))
}

func (s *eventSuite) TestBindingValidation() {
	base := map[string]any{
		"event_id": "pycon-hk-2026", "event_epoch": 1, "request_id": "request-001", "attempt_id": "attempt-001", "actor_id": "100", "key_epoch": 1,
		"team_id": "team-001", "team_proposal_digest": "team-digest-001", "base_repository_id": 12345, "config_digest": "config-digest-001",
		"issued_at": "2026-08-07T09:00:00Z", "expires_at": "2026-08-08T09:00:00Z",
	}
	variants := []map[string]any{
		{"event_id": ""}, {"event_epoch": 0}, {"issued_at": "bad-time"}, {"expires_at": "bad-time"}, {"expires_at": "2026-08-06T09:00:00Z"},
	}
	for index, change := range variants {
		value := make(map[string]any, len(base))
		for key, item := range base {
			value[key] = item
		}
		for key, item := range change {
			value[key] = item
		}
		path := filepath.Join(s.work, fmt.Sprintf("invalid-binding-%d.json", index))
		s.writeJSON(path, value)
		s.failure("submission", "prepare", "--context", path, "--input", s.input, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, fmt.Sprintf("invalid-binding-%d.out", index)))
	}
	invalidJSON := filepath.Join(s.work, "invalid-json.context")
	s.Require().NoError(os.WriteFile(invalidJSON, []byte("{"), 0o600))
	s.failure("submission", "prepare", "--context", invalidJSON, "--input", s.input, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "invalid-json.out"))
	trailing := filepath.Join(s.work, "trailing.context")
	s.Require().NoError(os.WriteFile(trailing, append(mustJSON(map[string]any{"event_id": "x"}), []byte("{}")...), 0o600))
	s.failure("submission", "prepare", "--context", trailing, "--input", s.input, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "trailing.out"))
	unknown := filepath.Join(s.work, "unknown.context")
	unknownValue := make(map[string]any, len(base)+1)
	for key, item := range base {
		unknownValue[key] = item
	}
	unknownValue["unexpected"] = true
	s.writeJSON(unknown, unknownValue)
	s.failure("submission", "prepare", "--context", unknown, "--input", s.input, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "unknown.out"))
}

func (s *eventSuite) TestMalformedKeyDocuments() {
	wrongPass := filepath.Join(s.work, "wrong-recipient-pass.txt")
	s.Require().NoError(os.WriteFile(wrongPass, []byte("wrong\n"), 0o600))
	s.failure("decverify", "--input", filepath.Join(s.work, "missing-stream"), "--output", filepath.Join(s.work, "wrong-recipient-pass.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", wrongPass)
	badSigningJSON := filepath.Join(s.work, "bad-signing-json.age")
	s.writeAge(badSigningJSON, []byte("not JSON"))
	s.failure("sigcrypt", "--input", s.input, "--output", filepath.Join(s.work, "bad-signing-json.stream"), "--context", s.binding, "--sig-private-key", badSigningJSON, "--passphrase-file", s.passphrase, "--enc-public-key", s.memberOne.RecipientPublic)
	badSigningBase64 := filepath.Join(s.work, "bad-signing-base64.age")
	s.writeAge(badSigningBase64, mustJSON(map[string]any{"kind": "signing-private", "algorithm": "ed25519", "key_id": "bad", "private_key": "!"}))
	s.failure("sigcrypt", "--input", s.input, "--output", filepath.Join(s.work, "bad-signing-base64.stream"), "--context", s.binding, "--sig-private-key", badSigningBase64, "--passphrase-file", s.passphrase, "--enc-public-key", s.memberOne.RecipientPublic)
	zeroKey := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize))
	badSigningMetadata := filepath.Join(s.work, "bad-signing-metadata.age")
	s.writeAge(badSigningMetadata, mustJSON(map[string]any{"kind": "wrong", "algorithm": "wrong", "key_id": "wrong", "private_key": zeroKey}))
	s.failure("sigcrypt", "--input", s.input, "--output", filepath.Join(s.work, "bad-signing-metadata.stream"), "--context", s.binding, "--sig-private-key", badSigningMetadata, "--passphrase-file", s.passphrase, "--enc-public-key", s.memberOne.RecipientPublic)

	badSigningPublicMetadata := filepath.Join(s.work, "bad-signing-public-metadata.json")
	s.writeJSON(badSigningPublicMetadata, map[string]any{"kind": "wrong", "algorithm": "wrong", "key_id": "wrong", "public_key": "!"})
	s.failure("decverify", "--input", filepath.Join(s.work, "missing-stream"), "--output", filepath.Join(s.work, "bad-signing-public-metadata.log"), "--context", s.binding, "--ver-public-key", badSigningPublicMetadata, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	badSigningPublicBase64 := filepath.Join(s.work, "bad-signing-public-base64.json")
	s.writeJSON(badSigningPublicBase64, map[string]any{"kind": "signing-public", "algorithm": "ed25519", "key_id": "bad", "public_key": "!"})
	s.failure("decverify", "--input", filepath.Join(s.work, "missing-stream"), "--output", filepath.Join(s.work, "bad-signing-public-base64.log"), "--context", s.binding, "--ver-public-key", badSigningPublicBase64, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	badSigningPublicFingerprint := filepath.Join(s.work, "bad-signing-public-fingerprint.json")
	publicData, err := os.ReadFile(s.organizer.SigningPublic)
	s.Require().NoError(err)
	publicData = bytes.Replace(publicData, []byte(`"key_id": "`), []byte(`"key_id": "bad-`), 1)
	s.Require().NoError(os.WriteFile(badSigningPublicFingerprint, publicData, 0o600))
	s.failure("decverify", "--input", filepath.Join(s.work, "missing-stream"), "--output", filepath.Join(s.work, "bad-signing-public-fingerprint.log"), "--context", s.binding, "--ver-public-key", badSigningPublicFingerprint, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)

	badRecipientMetadata := filepath.Join(s.work, "bad-recipient-metadata.json")
	s.writeJSON(badRecipientMetadata, map[string]any{"kind": "wrong", "algorithm": "wrong", "key_id": "wrong", "public_key": "bad"})
	s.failure("sigcrypt", "--input", s.input, "--output", filepath.Join(s.work, "bad-recipient-metadata.stream"), "--context", s.binding, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", badRecipientMetadata)
	badRecipientParse := filepath.Join(s.work, "bad-recipient-parse.json")
	s.writeJSON(badRecipientParse, map[string]any{"kind": "recipient-public", "algorithm": "age-hybrid-mlkem768-x25519", "key_id": "bad", "public_key": "bad"})
	s.failure("sigcrypt", "--input", s.input, "--output", filepath.Join(s.work, "bad-recipient-parse.stream"), "--context", s.binding, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", badRecipientParse)
	badRecipientFingerprint := filepath.Join(s.work, "bad-recipient-fingerprint.json")
	recipientData, err := os.ReadFile(s.memberOne.RecipientPublic)
	s.Require().NoError(err)
	recipientData = bytes.Replace(recipientData, []byte(`"key_id": "`), []byte(`"key_id": "bad-`), 1)
	s.Require().NoError(os.WriteFile(badRecipientFingerprint, recipientData, 0o600))
	s.failure("sigcrypt", "--input", s.input, "--output", filepath.Join(s.work, "bad-recipient-fingerprint.stream"), "--context", s.binding, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", badRecipientFingerprint)

	badRecipientJSON := filepath.Join(s.work, "bad-recipient-json.age")
	s.writeAge(badRecipientJSON, []byte("not JSON"))
	s.failure("decverify", "--input", filepath.Join(s.work, "missing-stream"), "--output", filepath.Join(s.work, "bad-recipient-json.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", badRecipientJSON, "--passphrase-file", s.passphrase)
	badRecipientPrivateMetadata := filepath.Join(s.work, "bad-recipient-private-metadata.age")
	s.writeAge(badRecipientPrivateMetadata, mustJSON(map[string]any{"kind": "wrong", "algorithm": "wrong", "key_id": "wrong", "identity": "bad"}))
	s.failure("decverify", "--input", filepath.Join(s.work, "missing-stream"), "--output", filepath.Join(s.work, "bad-recipient-private-metadata.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", badRecipientPrivateMetadata, "--passphrase-file", s.passphrase)
	badRecipientPrivateParse := filepath.Join(s.work, "bad-recipient-private-parse.age")
	s.writeAge(badRecipientPrivateParse, mustJSON(map[string]any{"kind": "recipient-private", "algorithm": "age-hybrid-mlkem768-x25519", "key_id": "bad", "identity": "bad"}))
	s.failure("decverify", "--input", filepath.Join(s.work, "missing-stream"), "--output", filepath.Join(s.work, "bad-recipient-private-parse.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", badRecipientPrivateParse, "--passphrase-file", s.passphrase)
	identity, err := age.GenerateHybridIdentity()
	s.Require().NoError(err)
	badRecipientPrivateFingerprint := filepath.Join(s.work, "bad-recipient-private-fingerprint.age")
	s.writeAge(badRecipientPrivateFingerprint, mustJSON(map[string]any{"kind": "recipient-private", "algorithm": "age-hybrid-mlkem768-x25519", "key_id": "bad", "identity": identity.String()}))
	s.failure("decverify", "--input", filepath.Join(s.work, "missing-stream"), "--output", filepath.Join(s.work, "bad-recipient-private-fingerprint.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", badRecipientPrivateFingerprint, "--passphrase-file", s.passphrase)
}

func (s *eventSuite) TestIdentityAndTeamLifecycle() {
	identity := filepath.Join(s.work, "identity.json")
	s.success("identity", "register", "--context", s.binding, "--actor-id", "100", "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", identity)
	s.success("identity", "verify", "--context", s.binding, "--input", identity, "--ver-public-key", s.organizer.SigningPublic)
	identityTampered := filepath.Join(s.work, "identity-tampered.json")
	data, err := os.ReadFile(identity)
	s.Require().NoError(err)
	data = bytes.Replace(data, []byte(`"actor_id": "100"`), []byte(`"actor_id": "999"`), 1)
	s.Require().NoError(os.WriteFile(identityTampered, data, 0o600))
	s.failure("identity", "verify", "--context", s.binding, "--input", identityTampered, "--ver-public-key", s.organizer.SigningPublic)
	s.failure("identity", "verify", "--context", s.binding, "--input", identity, "--ver-public-key", s.memberOne.SigningPublic)
	identityKind := filepath.Join(s.work, "identity-kind.json")
	kindData, err := os.ReadFile(identity)
	s.Require().NoError(err)
	kindData = bytes.Replace(kindData, []byte("identity-registration"), []byte("wrong"), 1)
	s.Require().NoError(os.WriteFile(identityKind, kindData, 0o600))
	s.failure("identity", "verify", "--context", s.binding, "--input", identityKind, "--ver-public-key", s.organizer.SigningPublic)
	identityBadSignature := filepath.Join(s.work, "identity-bad-signature.json")
	var identityValue map[string]any
	s.Require().NoError(json.Unmarshal(data, &identityValue))
	identitySignature := identityValue["signature"].(map[string]any)
	identitySignature["value"] = "!"
	s.writeJSON(identityBadSignature, identityValue)
	s.failure("identity", "verify", "--context", s.binding, "--input", identityBadSignature, "--ver-public-key", s.organizer.SigningPublic)
	identityBadSigner := filepath.Join(s.work, "identity-bad-signer.json")
	var identitySignerValue map[string]any
	s.Require().NoError(json.Unmarshal(data, &identitySignerValue))
	identitySigner := identitySignerValue["signer"].(map[string]any)
	identitySigner["public_key"] = "!"
	s.writeJSON(identityBadSigner, identitySignerValue)
	s.failure("identity", "verify", "--context", s.binding, "--input", identityBadSigner, "--ver-public-key", s.organizer.SigningPublic)

	s.proposal = filepath.Join(s.work, "proposal.json")
	s.success("team", "register", "--context", s.binding, "--team-id", "team-001", "--member", "200", "--member", " 300 ", "--member", "200", "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", s.proposal)
	s.consentOne = filepath.Join(s.work, "consent-one.json")
	s.consentTwo = filepath.Join(s.work, "consent-two.json")
	s.success("team", "consent", "--proposal", s.proposal, "--actor-id", "200", "--sig-private-key", s.memberOne.SigningPrivate, "--passphrase-file", s.passphrase, "--output", s.consentOne)
	s.success("team", "consent", "--proposal", s.proposal, "--actor-id", "300", "--sig-private-key", s.memberTwo.SigningPrivate, "--passphrase-file", s.passphrase, "--output", s.consentTwo)
	verified := s.success("team", "verify", "--proposal", s.proposal, "--consent", s.consentOne, "--consent", s.consentTwo)
	s.Contains(string(verified.Result), `"verified":true`)
	s.failure("team", "verify", "--proposal", s.proposal, "--consent", s.consentOne)
	s.failure("team", "verify", "--proposal", s.proposal, "--consent", s.consentOne, "--consent", s.consentOne)
	s.failure("team", "verify", "--proposal", s.proposal)
	badActor := filepath.Join(s.work, "bad-actor-consent.json")
	s.failure("team", "consent", "--proposal", s.proposal, "--actor-id", "999", "--sig-private-key", s.memberOne.SigningPrivate, "--passphrase-file", s.passphrase, "--output", badActor)
	s.failure("team", "register", "--context", s.binding, "--team-id", "team-001", "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "empty-team.json"))
	proposalKind := filepath.Join(s.work, "proposal-kind.json")
	proposalData, err := os.ReadFile(s.proposal)
	s.Require().NoError(err)
	proposalData = bytes.Replace(proposalData, []byte("team-proposal"), []byte("wrong"), 1)
	s.Require().NoError(os.WriteFile(proposalKind, proposalData, 0o600))
	s.failure("team", "verify", "--proposal", proposalKind, "--consent", s.consentOne, "--consent", s.consentTwo)
	proposalBadSignature := filepath.Join(s.work, "proposal-bad-signature.json")
	proposalData, err = os.ReadFile(s.proposal)
	s.Require().NoError(err)
	proposalData = bytes.Replace(proposalData, []byte(`"200"`), []byte(`"999"`), 1)
	s.Require().NoError(os.WriteFile(proposalBadSignature, proposalData, 0o600))
	s.failure("team", "verify", "--proposal", proposalBadSignature, "--consent", s.consentOne, "--consent", s.consentTwo)
	proposalBadSigner := filepath.Join(s.work, "proposal-bad-signer.json")
	var proposalValue map[string]any
	s.Require().NoError(json.Unmarshal(proposalData, &proposalValue))
	proposalSigner := proposalValue["signer"].(map[string]any)
	proposalSigner["public_key"] = "!"
	s.writeJSON(proposalBadSigner, proposalValue)
	s.failure("team", "verify", "--proposal", proposalBadSigner, "--consent", s.consentOne, "--consent", s.consentTwo)
	consentUnknown := filepath.Join(s.work, "consent-unknown.json")
	consentData, err := os.ReadFile(s.consentOne)
	s.Require().NoError(err)
	consentData = bytes.Replace(consentData, []byte(`"actor_id": "200"`), []byte(`"actor_id": "999"`), 1)
	s.Require().NoError(os.WriteFile(consentUnknown, consentData, 0o600))
	s.failure("team", "verify", "--proposal", s.proposal, "--consent", consentUnknown, "--consent", s.consentTwo)
	consentBadSignature := filepath.Join(s.work, "consent-bad-signature.json")
	consentData, err = os.ReadFile(s.consentOne)
	s.Require().NoError(err)
	consentData = bytes.Replace(consentData, []byte(`"value": "`), []byte(`"value": "%`), 1)
	s.Require().NoError(os.WriteFile(consentBadSignature, consentData, 0o600))
	s.failure("team", "verify", "--proposal", s.proposal, "--consent", consentBadSignature, "--consent", s.consentTwo)
}

func (s *eventSuite) TestStreamRoundTripAndRejection() {
	s.stream = filepath.Join(s.work, "judge.log.eventctl")
	value := s.success("sigcrypt", "--input", s.input, "--output", s.stream, "--context", s.binding, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", s.memberOne.RecipientPublic, "--enc-public-key", s.memberTwo.RecipientPublic, "--enc-public-key", s.memberOne.RecipientPublic)
	s.Contains(string(value.Result), `"recipient_count":2`)
	s.failure("sigcrypt", "--input", s.input, "--output", s.stream, "--context", s.binding, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", s.memberOne.RecipientPublic)
	plainOne := filepath.Join(s.work, "plain-one.log")
	s.success("decverify", "--input", s.stream, "--output", plainOne, "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	plain, err := os.ReadFile(plainOne)
	s.Require().NoError(err)
	s.Equal([]byte("private judge output\n"), plain)
	plainTwo := filepath.Join(s.work, "plain-two.log")
	s.success("decverify", "--input", s.stream, "--output", plainTwo, "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberTwo.RecipientPrivate, "--passphrase-file", s.passphrase)
	s.failure("decverify", "--input", s.stream, "--output", plainOne, "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	s.failure("decverify", "--input", s.stream, "--output", filepath.Join(s.work, "wrong-recipient.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.organizer.RecipientPrivate, "--passphrase-file", s.passphrase)
	s.failure("decverify", "--input", s.stream, "--output", filepath.Join(s.work, "wrong-signer.log"), "--context", s.binding, "--ver-public-key", s.memberOne.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	wrongBinding := filepath.Join(s.work, "wrong-binding.json")
	data, err := os.ReadFile(s.binding)
	s.Require().NoError(err)
	data = bytes.Replace(data, []byte("pycon-hk-2026"), []byte("pycon-hk-other"), 1)
	s.Require().NoError(os.WriteFile(wrongBinding, data, 0o600))
	s.failure("decverify", "--input", s.stream, "--output", filepath.Join(s.work, "wrong-binding.log"), "--context", wrongBinding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	tampered := filepath.Join(s.work, "tampered.stream")
	data, err = os.ReadFile(s.stream)
	s.Require().NoError(err)
	data[len(data)-1] ^= 1
	s.Require().NoError(os.WriteFile(tampered, data, 0o600))
	s.failure("decverify", "--input", tampered, "--output", filepath.Join(s.work, "tampered.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	s.failure("sigcrypt", "--input", s.input, "--output", filepath.Join(s.work, "no-recipient.stream"), "--context", s.binding, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase)
	s.failure("sigcrypt", "--input", s.input, "--output", filepath.Join(s.work, "bad-recipient.stream"), "--context", s.binding, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", s.input)
	badPublic := filepath.Join(s.work, "bad-public.json")
	s.Require().NoError(os.WriteFile(badPublic, []byte(`{"kind":"recipient-public","algorithm":"age-hybrid-mlkem768-x25519","key_id":"bad","public_key":"bad"}`), 0o600))
	s.failure("decverify", "--input", s.stream, "--output", filepath.Join(s.work, "bad-key.log"), "--context", s.binding, "--ver-public-key", badPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	invalidMagic := filepath.Join(s.work, "invalid-magic.stream")
	s.Require().NoError(os.WriteFile(invalidMagic, []byte("invalid"), 0o600))
	s.failure("decverify", "--input", invalidMagic, "--output", filepath.Join(s.work, "invalid-magic.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	invalidSize := filepath.Join(s.work, "invalid-size.stream")
	s.writeRawStream(invalidSize, 64<<20+1, nil)
	s.failure("decverify", "--input", invalidSize, "--output", filepath.Join(s.work, "invalid-size.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	invalidJSON := filepath.Join(s.work, "invalid-header-json.stream")
	s.writeRawStream(invalidJSON, 1, []byte("{"))
	s.failure("decverify", "--input", invalidJSON, "--output", filepath.Join(s.work, "invalid-header-json.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	wrongSignerHeader := filepath.Join(s.work, "wrong-signer-header.stream")
	s.writeCustomStream(wrongSignerHeader, s.memberOne.SigningPrivate, s.organizerPublic(), []byte("private judge output\n"), int64(len("private judge output\n")), "")
	s.failure("decverify", "--input", wrongSignerHeader, "--output", filepath.Join(s.work, "wrong-signer-header.log"), "--context", s.binding, "--ver-public-key", s.memberOne.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	sizeMismatch := filepath.Join(s.work, "size-mismatch.stream")
	s.writeCustomStream(sizeMismatch, s.organizer.SigningPrivate, s.organizerPublic(), []byte("private judge output\n"), int64(len("private judge output\n")+1), "")
	s.failure("decverify", "--input", sizeMismatch, "--output", filepath.Join(s.work, "size-mismatch.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	digestMismatch := filepath.Join(s.work, "digest-mismatch.stream")
	s.writeCustomStream(digestMismatch, s.organizer.SigningPrivate, s.organizerPublic(), []byte("private judge output\n"), int64(len("private judge output\n")), strings.Repeat("0", 64))
	s.failure("decverify", "--input", digestMismatch, "--output", filepath.Join(s.work, "digest-mismatch.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	truncated := filepath.Join(s.work, "truncated.stream")
	s.writeCustomStream(truncated, s.organizer.SigningPrivate, s.organizerPublic(), []byte("private judge output\n"), int64(len("private judge output\n")), "")
	truncatedData, err := os.ReadFile(truncated)
	s.Require().NoError(err)
	s.Require().NoError(os.WriteFile(truncated, truncatedData[:len(truncatedData)-1], 0o600))
	s.failure("decverify", "--input", truncated, "--output", filepath.Join(s.work, "truncated.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
	decryptFailure := filepath.Join(s.work, "decrypt-failure.stream")
	s.writeCustomStream(decryptFailure, s.organizer.SigningPrivate, s.organizerPublic(), []byte("private judge output\n"), int64(len("private judge output\n")), "")
	decryptData, err := os.ReadFile(decryptFailure)
	s.Require().NoError(err)
	headerLength := int(binary.BigEndian.Uint32(decryptData[8:12]))
	decryptData = append(decryptData[:12+headerLength], []byte("not an age stream")...)
	s.Require().NoError(os.WriteFile(decryptFailure, decryptData, 0o600))
	s.failure("decverify", "--input", decryptFailure, "--output", filepath.Join(s.work, "decrypt-failure.log"), "--context", s.binding, "--ver-public-key", s.organizer.SigningPublic, "--dec-private-key", s.memberOne.RecipientPrivate, "--passphrase-file", s.passphrase)
}

func (s *eventSuite) TestSubmissionPreparation() {
	withMetadata := filepath.Join(s.work, "submission-with-metadata.json")
	s.success("submission", "prepare", "--context", s.binding, "--input", s.input, "--metadata", s.metadata, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", withMetadata)
	withoutMetadata := filepath.Join(s.work, "submission-without-metadata.json")
	s.success("submission", "prepare", "--context", s.binding, "--input", s.input, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", withoutMetadata)
	s.failure("submission", "prepare", "--context", s.binding, "--input", s.input, "--metadata", filepath.Join(s.work, "missing-metadata"), "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "missing-metadata-submission.json"))
	s.failure("submission", "prepare", "--context", s.binding, "--input", s.input, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", withMetadata)
	invalidContext := filepath.Join(s.work, "invalid-context.json")
	s.Require().NoError(os.WriteFile(invalidContext, []byte(`{"event_id":"missing"}`), 0o600))
	s.failure("submission", "prepare", "--context", invalidContext, "--input", s.input, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "invalid-submission.json"))
	large := filepath.Join(s.work, "large-input.bin")
	s.Require().NoError(os.WriteFile(large, nil, 0o600))
	s.Require().NoError(os.Truncate(large, 64<<20+1))
	s.failure("submission", "prepare", "--context", s.binding, "--input", large, "--sig-private-key", s.organizer.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "large-submission.json"))
}

func (s *eventSuite) keyGen(name string) keyResult {
	directory := filepath.Join(s.work, name)
	result := s.success("key-gen", "--out", directory, "--passphrase-file", s.passphrase)
	var value keyResult
	s.Require().NoError(json.Unmarshal(result.Result, &value))
	return value
}

func (s *eventSuite) success(args ...string) response { return s.invoke(true, nil, args...) }

func (s *eventSuite) successWithEnv(values map[string]string, args ...string) response {
	return s.invoke(true, values, args...)
}

func (s *eventSuite) failure(args ...string) response { return s.invoke(false, nil, args...) }

func (s *eventSuite) failureWithEnv(values map[string]string, args ...string) response {
	return s.invoke(false, values, args...)
}

func (s *eventSuite) invoke(wantSuccess bool, values map[string]string, args ...string) response {
	command := exec.Command(s.binary, args...)
	command.Env = append(os.Environ(), "GOCOVERDIR="+s.coverage)
	for key, value := range values {
		command.Env = append(command.Env, key+"="+value)
	}
	output, err := command.CombinedOutput()
	if wantSuccess {
		s.Require().NoError(err, "%s\n%s", strings.Join(args, " "), output)
	} else {
		s.Require().Error(err, "%s unexpectedly succeeded\n%s", strings.Join(args, " "), output)
	}
	var value response
	s.Require().NoError(json.Unmarshal(bytes.TrimSpace(output), &value), "%s", output)
	s.Equal(wantSuccess, value.OK, "%s", output)
	if !wantSuccess {
		s.NotEmpty(value.Error)
	}
	return value
}

func (s *eventSuite) raw(expectedExit int, args ...string) []byte {
	command := exec.Command(s.binary, args...)
	command.Env = append(os.Environ(), "GOCOVERDIR="+s.coverage)
	output, err := command.CombinedOutput()
	if expectedExit == 0 {
		s.Require().NoError(err, "%s\n%s", strings.Join(args, " "), output)
	} else {
		s.Require().Error(err)
	}
	return output
}

func (s *eventSuite) writeJSON(path string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	s.Require().NoError(err)
	s.Require().NoError(os.WriteFile(path, append(data, '\n'), 0o600))
}

func (s *eventSuite) writeAge(path string, plaintext []byte) {
	recipient, err := age.NewScryptRecipient("correct horse battery staple")
	s.Require().NoError(err)
	var output bytes.Buffer
	writer, err := age.Encrypt(&output, recipient)
	s.Require().NoError(err)
	_, err = writer.Write(plaintext)
	s.Require().NoError(err)
	s.Require().NoError(writer.Close())
	s.Require().NoError(os.WriteFile(path, output.Bytes(), 0o600))
}

func (s *eventSuite) writeRawStream(path string, headerSize uint32, header []byte) {
	data := make([]byte, 12+len(header))
	copy(data, []byte{'E', 'V', 'T', 'C', 'T', 'L', 1, 0})
	binary.BigEndian.PutUint32(data[8:12], headerSize)
	copy(data[12:], header)
	s.Require().NoError(os.WriteFile(path, data, 0o600))
}

func (s *eventSuite) organizerPublic() protocol.SigningPublic {
	public, err := protocol.LoadSigningPublic(s.organizer.SigningPublic)
	s.Require().NoError(err)
	return public
}

func (s *eventSuite) writeCustomStream(path, signingPath string, headerSigner protocol.SigningPublic, payload []byte, payloadSize int64, payloadDigest string) {
	binding, err := protocol.ReadBinding(s.binding)
	s.Require().NoError(err)
	key, err := protocol.LoadSigningPrivate(signingPath, "correct horse battery staple")
	s.Require().NoError(err)
	recipient, err := protocol.LoadRecipientPublic(s.memberOne.RecipientPublic)
	s.Require().NoError(err)
	parsedRecipient, err := age.ParseHybridRecipient(recipient.PublicKey)
	s.Require().NoError(err)
	digest := sha256.Sum256(payload)
	if payloadDigest == "" {
		payloadDigest = fmt.Sprintf("%x", digest[:])
	}
	unsigned := stream.Header{Protocol: protocol.Protocol, Binding: binding, Signer: headerSigner, RecipientKeyIDs: []string{recipient.KeyID}, PayloadSize: payloadSize, PayloadSHA256: payloadDigest}
	unsigned.Signature = protocol.Sign("stream.sigcrypt", unsigned, key)
	header, err := json.Marshal(unsigned)
	s.Require().NoError(err)
	var encrypted bytes.Buffer
	writer, err := age.Encrypt(&encrypted, parsedRecipient)
	s.Require().NoError(err)
	_, err = writer.Write(payload)
	s.Require().NoError(err)
	s.Require().NoError(writer.Close())
	container := make([]byte, 12+len(header)+encrypted.Len())
	copy(container, []byte{'E', 'V', 'T', 'C', 'T', 'L', 1, 0})
	binary.BigEndian.PutUint32(container[8:12], uint32(len(header)))
	copy(container[12:], header)
	copy(container[12+len(header):], encrypted.Bytes())
	s.Require().NoError(os.WriteFile(path, container, 0o600))
}

func mustJSON(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}
