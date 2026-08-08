//go:build e2e

package e2e

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/suite"
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
	SigningKeyID     string `json:"signing_key_id"`
	RecipientKeyID   string `json:"recipient_key_id"`
}

type streamEventReference struct {
	EventID       string `json:"event_id"`
	EventEpoch    int    `json:"event_epoch"`
	RepositoryID  string `json:"repository_id"`
	BindingSHA256 string `json:"binding_sha256"`
}

type streamBinding struct {
	Version    int                  `json:"v"`
	Kind       string               `json:"kind"`
	Event      streamEventReference `json:"event"`
	Purpose    string               `json:"purpose"`
	TeamID     string               `json:"team_id"`
	AttemptID  string               `json:"attempt_id"`
	ArtifactID string               `json:"artifact_id"`
}

type streamSigningPublic struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	PublicKey string `json:"public"`
}

type streamSignature struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Value     string `json:"value"`
}

type streamHeader struct {
	Protocol        string              `json:"protocol"`
	Binding         streamBinding       `json:"binding"`
	Signer          streamSigningPublic `json:"signer"`
	RecipientKeyIDs []string            `json:"recipient_key_ids"`
	PayloadSize     int64               `json:"payload_size"`
	PayloadSHA256   string              `json:"payload_sha256"`
	Signature       streamSignature     `json:"signature"`
}

type eventSuite struct {
	suite.Suite
	root               string
	work               string
	binary             string
	coverage           string
	passphrase         string
	event              string
	registry           string
	submissionRegistry string
	bundle             string
	metadata           string
	captain            keyResult
	teammate           keyResult
	outsider           keyResult
	captainReg         string
	teammateReg        string
	proposal           string
	captainConsent     string
	teammateConsent    string
	teamVerification   string
	teamID             string
	attemptID          string
	submission         string
	streamBinding      string
	stream             string
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
	buildOutput, err := build.CombinedOutput()
	s.Require().NoError(err, string(buildOutput))

	s.passphrase = filepath.Join(s.work, "passphrase.txt")
	s.Require().NoError(os.WriteFile(s.passphrase, []byte("correct horse battery staple\n"), 0o600))
	s.event = filepath.Join(s.work, "event.json")
	s.writeJSON(s.event, map[string]any{
		"v":             2,
		"kind":          "event-binding",
		"protocol":      "eventctl/v2",
		"event_id":      "pycon-hk-2026",
		"event_epoch":   1,
		"repository_id": "12345",
		"valid_from":    "2026-01-01T00:00:00Z",
		"valid_until":   "2030-01-01T00:00:00Z",
		"terms_sha256":  strings.Repeat("a", 64),
		"ttl_seconds":   map[string]any{"registration": 604800, "team": 604800, "submission": 86400},
		"limits":        map[string]any{"team_min": 1, "team_max": 5, "attempts_per_team": 10, "attempts_total": 200},
	})
	s.bundle = filepath.Join(s.work, "exploit-package.zip")
	s.metadata = filepath.Join(s.work, "metadata.json")
	s.Require().NoError(os.WriteFile(s.bundle, []byte("safe exploit package\n"), 0o600))
	s.Require().NoError(os.WriteFile(s.metadata, []byte(`{"lab":1,"language":"python"}`), 0o600))

	s.captain = s.keyGen("captain")
	s.teammate = s.keyGen("teammate")
	s.outsider = s.keyGen("outsider")
	s.captainReg = s.register("100", "10000000-0000-4000-8000-000000000001", s.captain)
	s.teammateReg = s.register("200", "20000000-0000-4000-8000-000000000002", s.teammate)
	s.registry = filepath.Join(s.work, "registry.json")
	identities := s.verifiedIdentities(s.captainReg, s.teammateReg)
	s.writeRegistry(s.registry, "formation_open", identities, nil, nil)
	s.teamID = "30000000-0000-4000-8000-000000000003"
	s.attemptID = "40000000-0000-4000-8000-000000000004"
	s.proposal = filepath.Join(s.work, "proposal.json")
	s.success("team", "propose", "--event", s.event, "--registry", s.registry, "--team-id", s.teamID, "--actor-id", "100", "--member", "100", "--member", "200", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", s.proposal)
	s.captainConsent = filepath.Join(s.work, "captain-consent.json")
	s.teammateConsent = filepath.Join(s.work, "teammate-consent.json")
	s.success("team", "consent", "--event", s.event, "--registry", s.registry, "--proposal", s.proposal, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", s.captainConsent)
	s.success("team", "consent", "--event", s.event, "--registry", s.registry, "--proposal", s.proposal, "--actor-id", "200", "--sig-private-key", s.teammate.SigningPrivate, "--passphrase-file", s.passphrase, "--output", s.teammateConsent)
	s.teamVerification = filepath.Join(s.work, "team-verification.json")
	s.success("team", "verify", "--event", s.event, "--registry", s.registry, "--proposal", s.proposal, "--proposal-source-time", s.issuedAt(s.proposal), "--consent", s.captainConsent, "--consent", s.teammateConsent, "--consent-source-time", "100="+s.issuedAt(s.captainConsent), "--consent-source-time", "200="+s.issuedAt(s.teammateConsent), "--output", s.teamVerification)
	s.submissionRegistry = filepath.Join(s.work, "submission-registry.json")
	verification := s.readObject(s.teamVerification)
	s.writeRegistry(s.submissionRegistry, "submissions_open", identities, []any{map[string]any{"team_id": verification["team_id"], "proposal_sha256": verification["proposal_sha256"], "members": verification["members"]}}, nil)
	s.submission = filepath.Join(s.work, "submission.json")
	s.success("submission", "prepare", "--event", s.event, "--input", s.bundle, "--metadata", s.metadata, "--team-id", s.teamID, "--attempt-id", s.attemptID, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", s.submission)
	s.streamBinding = filepath.Join(s.work, "stream-binding.json")
	s.writeJSON(s.streamBinding, map[string]any{
		"v":           2,
		"kind":        "stream-binding",
		"event":       s.readObject(s.captainReg)["event"],
		"purpose":     "judge-log",
		"team_id":     s.teamID,
		"attempt_id":  s.attemptID,
		"artifact_id": "run-1",
	})
	judgeLog := filepath.Join(s.work, "judge.log")
	s.Require().NoError(os.WriteFile(judgeLog, []byte("private judge output\n"), 0o600))
	s.stream = filepath.Join(s.work, "judge.log.eventctl")
	s.success("sigcrypt", "--input", judgeLog, "--output", s.stream, "--context", s.streamBinding, "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", s.captain.RecipientPublic, "--enc-public-key", s.teammate.RecipientPublic, "--enc-public-key", s.captain.RecipientPublic)
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

func (s *eventSuite) TestVersionDoctorAndEventBinding() {
	version := s.success("version")
	s.Contains(string(version.Result), `"protocol":"eventctl/v2"`)
	defaultDoctor := s.successWithEnv(map[string]string{"EVENTCTL_EVENT_ID": "weekend-1", "EVENTCTL_EVENT_EPOCH": "2"}, "doctor")
	s.Contains(string(defaultDoctor.Result), `"event_id":"weekend-1"`)
	eventDoctor := s.success("doctor", "--event", s.event)
	s.Contains(string(eventDoctor.Result), `"repository_id":"12345"`)
	registryDoctor := s.success("doctor", "--event", s.event, "--registry", s.submissionRegistry)
	s.Contains(string(registryDoctor.Result), `"phase":"submissions_open"`)
	s.failure("doctor", "--registry", s.registry)
	s.failure("doctor", "--event", s.event, "--registry", filepath.Join(s.work, "missing-registry.json"))
	s.failureWithEnv(map[string]string{"EVENTCTL_EVENT_EPOCH": "0"}, "doctor")
	s.failureWithEnv(map[string]string{"EVENTCTL_EVENT_EPOCH": "not-a-number"}, "doctor")
	s.raw(0, "--help")
}

func (s *eventSuite) TestPublicBindingAndJSONFailures() {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"discriminator", func(value map[string]any) { value["kind"] = "wrong" }},
		{"event-identity", func(value map[string]any) { value["event_id"] = "NO" }},
		{"valid-from", func(value map[string]any) { value["valid_from"] = "not-a-time" }},
		{"valid-until", func(value map[string]any) { value["valid_until"] = "2025-01-01T00:00:00Z" }},
		{"ttl", func(value map[string]any) { value["ttl_seconds"].(map[string]any)["team"] = 0 }},
		{"limits", func(value map[string]any) { value["limits"].(map[string]any)["team_max"] = 0 }},
	}
	for _, test := range cases {
		s.Run(test.name, func() {
			path := filepath.Join(s.work, "bad-event-"+test.name+".json")
			value := s.copyObject(s.event)
			test.mutate(value)
			s.writeJSON(path, value)
			s.failure("doctor", "--event", path)
		})
	}

	s.failure("doctor", "--event", filepath.Join(s.work, "missing-event.json"))
	s.failure("doctor", "--event", s.work)

	tooLarge := filepath.Join(s.work, "too-large-event.json")
	file, err := os.Create(tooLarge)
	s.Require().NoError(err)
	s.Require().NoError(file.Truncate((64 << 20) + 1))
	s.Require().NoError(file.Close())
	s.failure("doctor", "--event", tooLarge)

	for name, data := range map[string][]byte{
		"empty":           nil,
		"invalid":         []byte("{"),
		"key":             []byte(`{"event"`),
		"invalid-key":     []byte(`{"event`),
		"primitive":       []byte("1"),
		"nested-object":   []byte(`{"event":{`),
		"nested-array":    []byte(`{"items":[`),
		"invalid-element": []byte(`{"items":[}`),
		"invalid-array":   []byte(`{"items":[1,]}`),
		"duplicate":       []byte(`{"v":2,"v":2}`),
		"trailing":        append(bytes.TrimSpace(s.readBytes(s.event)), []byte("\n{}")...),
		"unknown":         append(bytes.TrimSuffix(bytes.TrimSpace(s.readBytes(s.event)), []byte("}")), []byte(`,"unexpected":true}`)...),
	} {
		path := filepath.Join(s.work, "bad-json-"+name+".json")
		s.Require().NoError(os.WriteFile(path, data, 0o600))
		s.failure("doctor", "--event", path)
	}

	for name, mutate := range map[string]func(map[string]any){
		"invalid-reference": func(value map[string]any) {
			value["event"].(map[string]any)["event_id"] = "bad"
		},
		"mismatched-reference": func(value map[string]any) {
			value["event"].(map[string]any)["binding_sha256"] = strings.Repeat("b", 64)
		},
	} {
		path := filepath.Join(s.work, "bad-registration-event-"+name+".json")
		value := s.copyObject(s.captainReg)
		mutate(value)
		s.writeJSON(path, value)
		s.failure("identity", "verify", "--event", s.event, "--input", path, "--expect-actor-id", "100", "--source-time", s.issuedAt(s.captainReg), "--output", filepath.Join(s.work, "bad-registration-event-"+name+".verified.json"))
	}
}

func (s *eventSuite) TestCommandInputFailures() {
	missingPassphrase := filepath.Join(s.work, "missing-passphrase.txt")
	fileOutput := filepath.Join(s.work, "not-a-directory")
	s.Require().NoError(os.WriteFile(fileOutput, []byte("file"), 0o600))
	s.failure("key-gen", "--out", filepath.Join(s.work, "missing-passphrase-key"), "--passphrase-file", missingPassphrase)
	s.failure("key-gen", "--out", filepath.Join(s.work, "captain"), "--passphrase-file", s.passphrase)
	s.failure("key-gen", "--out", fileOutput, "--passphrase-file", s.passphrase)

	badRecipientPublic := filepath.Join(s.work, "bad-recipient.public.json")
	s.writeJSON(badRecipientPublic, map[string]any{"alg": "wrong", "kid": strings.Repeat("a", 64), "recipient": "wrong"})
	badSigningPublic := filepath.Join(s.work, "bad-signing.public.json")
	s.writeJSON(badSigningPublic, map[string]any{"alg": "wrong", "kid": strings.Repeat("a", 64), "public": "wrong"})
	badSigningPrivate := filepath.Join(s.work, "bad-signing.private.age")
	s.writePassphraseEncrypted(badSigningPrivate, []byte(`{"kind":"wrong"}`))
	badRecipientPrivate := filepath.Join(s.work, "bad-recipient.private.age")
	s.writePassphraseEncrypted(badRecipientPrivate, []byte(`{"kind":"wrong"}`))

	missingStreamBinding := filepath.Join(s.work, "missing-stream-binding.json")
	s.failure("sigcrypt", "--input", s.bundle, "--output", filepath.Join(s.work, "missing-context.eventctl"), "--context", missingStreamBinding, "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", s.captain.RecipientPublic)
	s.failure("sigcrypt", "--input", s.bundle, "--output", filepath.Join(s.work, "missing-pass.eventctl"), "--context", s.streamBinding, "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", missingPassphrase, "--enc-public-key", s.captain.RecipientPublic)
	s.failure("sigcrypt", "--input", s.bundle, "--output", filepath.Join(s.work, "missing-signing.eventctl"), "--context", s.streamBinding, "--sig-private-key", filepath.Join(s.work, "missing-signing.private.age"), "--passphrase-file", s.passphrase, "--enc-public-key", s.captain.RecipientPublic)
	s.failure("sigcrypt", "--input", s.bundle, "--output", filepath.Join(s.work, "bad-signing.eventctl"), "--context", s.streamBinding, "--sig-private-key", badSigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", s.captain.RecipientPublic)
	s.failure("sigcrypt", "--input", s.bundle, "--output", filepath.Join(s.work, "bad-recipient.eventctl"), "--context", s.streamBinding, "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", badRecipientPublic)
	s.failure("sigcrypt", "--input", filepath.Join(s.work, "missing-input"), "--output", filepath.Join(s.work, "missing-input.eventctl"), "--context", s.streamBinding, "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", s.captain.RecipientPublic)
	s.failure("sigcrypt", "--input", s.bundle, "--output", s.stream, "--context", s.streamBinding, "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", s.captain.RecipientPublic)

	s.failure("decverify", "--input", s.stream, "--output", filepath.Join(s.work, "missing-decrypt-context"), "--context", missingStreamBinding, "--ver-public-key", s.captain.SigningPublic, "--dec-private-key", s.captain.RecipientPrivate, "--passphrase-file", s.passphrase)
	s.failure("decverify", "--input", s.stream, "--output", filepath.Join(s.work, "missing-public"), "--context", s.streamBinding, "--ver-public-key", filepath.Join(s.work, "missing-signing.public.json"), "--dec-private-key", s.captain.RecipientPrivate, "--passphrase-file", s.passphrase)
	s.failure("decverify", "--input", s.stream, "--output", filepath.Join(s.work, "bad-public"), "--context", s.streamBinding, "--ver-public-key", badSigningPublic, "--dec-private-key", s.captain.RecipientPrivate, "--passphrase-file", s.passphrase)
	s.failure("decverify", "--input", s.stream, "--output", filepath.Join(s.work, "missing-decrypt-pass"), "--context", s.streamBinding, "--ver-public-key", s.captain.SigningPublic, "--dec-private-key", s.captain.RecipientPrivate, "--passphrase-file", missingPassphrase)
	s.failure("decverify", "--input", s.stream, "--output", filepath.Join(s.work, "missing-recipient"), "--context", s.streamBinding, "--ver-public-key", s.captain.SigningPublic, "--dec-private-key", filepath.Join(s.work, "missing-recipient.private.age"), "--passphrase-file", s.passphrase)
	s.failure("decverify", "--input", s.stream, "--output", filepath.Join(s.work, "bad-recipient"), "--context", s.streamBinding, "--ver-public-key", s.captain.SigningPublic, "--dec-private-key", badRecipientPrivate, "--passphrase-file", s.passphrase)
	s.failure("decverify", "--input", filepath.Join(s.work, "missing-encrypted-stream"), "--output", filepath.Join(s.work, "missing-encrypted-output"), "--context", s.streamBinding, "--ver-public-key", s.captain.SigningPublic, "--dec-private-key", s.captain.RecipientPrivate, "--passphrase-file", s.passphrase)

	s.identityCommandFailures(missingPassphrase, badSigningPrivate, badRecipientPublic)
	s.teamCommandFailures(missingPassphrase, badSigningPrivate)
	s.submissionCommandFailures(missingPassphrase, badSigningPrivate)
}

func (s *eventSuite) TestKeyMaterialRejections() {
	invalidCiphertext := filepath.Join(s.work, "invalid-ciphertext.age")
	s.Require().NoError(os.WriteFile(invalidCiphertext, []byte("not an age file"), 0o600))
	corruptCiphertext := filepath.Join(s.work, "corrupt-ciphertext.age")
	corrupt := append([]byte(nil), s.readBytes(s.captain.SigningPrivate)...)
	corrupt[len(corrupt)-1] ^= 1
	s.Require().NoError(os.WriteFile(corruptCiphertext, corrupt, 0o600))
	invalidJSON := filepath.Join(s.work, "invalid-json.age")
	s.writePassphraseEncrypted(invalidJSON, []byte("{"))
	_, private, err := ed25519.GenerateKey(nil)
	s.Require().NoError(err)
	metadataMismatch := filepath.Join(s.work, "metadata-mismatch-signing.age")
	s.writePassphraseEncrypted(metadataMismatch, []byte(`{"kind":"wrong","alg":"Ed25519","kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","private":"`+base64.RawURLEncoding.EncodeToString(private)+`"}`))

	register := func(signingPath, recipientPath, output string) {
		s.failure("identity", "register", "--event", s.event, "--actor-id", "100", "--registration-id", "50000000-0000-4000-8000-000000000005", "--sig-private-key", signingPath, "--recipient-public-key", recipientPath, "--passphrase-file", s.passphrase, "--output", output)
	}
	register(invalidCiphertext, s.captain.RecipientPublic, filepath.Join(s.work, "invalid-signing-cipher.json"))
	register(corruptCiphertext, s.captain.RecipientPublic, filepath.Join(s.work, "corrupt-signing-cipher.json"))
	register(invalidJSON, s.captain.RecipientPublic, filepath.Join(s.work, "invalid-signing-json.json"))
	register(metadataMismatch, s.captain.RecipientPublic, filepath.Join(s.work, "invalid-signing-metadata.json"))

	badRecipientParse := filepath.Join(s.work, "bad-recipient-parse.json")
	s.writeJSON(badRecipientParse, map[string]any{"alg": "age-hybrid-mlkem768-x25519", "kid": strings.Repeat("a", 64), "recipient": "not-a-recipient"})
	recipientIdentity, err := age.GenerateHybridIdentity()
	s.Require().NoError(err)
	badRecipientFingerprint := filepath.Join(s.work, "bad-recipient-fingerprint.json")
	s.writeJSON(badRecipientFingerprint, map[string]any{"alg": "age-hybrid-mlkem768-x25519", "kid": strings.Repeat("a", 64), "recipient": recipientIdentity.Recipient().String()})
	register(s.captain.SigningPrivate, badRecipientParse, filepath.Join(s.work, "invalid-recipient-parse.json"))
	register(s.captain.SigningPrivate, badRecipientFingerprint, filepath.Join(s.work, "invalid-recipient-fingerprint.json"))
	badSigningFingerprint := filepath.Join(s.work, "bad-signing-fingerprint.json")
	s.writeJSON(badSigningFingerprint, map[string]any{"alg": "Ed25519", "kid": strings.Repeat("a", 64), "public": base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))})
	s.failure("decverify", "--input", s.stream, "--output", filepath.Join(s.work, "invalid-signing-fingerprint.log"), "--context", s.streamBinding, "--ver-public-key", badSigningFingerprint, "--dec-private-key", s.captain.RecipientPrivate, "--passphrase-file", s.passphrase)

	recipientMetadata := filepath.Join(s.work, "recipient-metadata.age")
	s.writePassphraseEncrypted(recipientMetadata, []byte(`{"kind":"wrong"}`))
	recipientParse := filepath.Join(s.work, "recipient-parse.age")
	s.writePassphraseEncrypted(recipientParse, []byte(`{"kind":"recipient-private","alg":"age-hybrid-mlkem768-x25519","kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","identity":"not-an-identity"}`))
	recipientFingerprint := filepath.Join(s.work, "recipient-fingerprint.age")
	s.writePassphraseEncrypted(recipientFingerprint, []byte(`{"kind":"recipient-private","alg":"age-hybrid-mlkem768-x25519","kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","identity":"`+recipientIdentity.String()+`"}`))
	decrypt := func(recipientPath, output string) {
		s.failure("decverify", "--input", s.stream, "--output", output, "--context", s.streamBinding, "--ver-public-key", s.captain.SigningPublic, "--dec-private-key", recipientPath, "--passphrase-file", s.passphrase)
	}
	decrypt(invalidCiphertext, filepath.Join(s.work, "invalid-recipient-cipher.log"))
	decrypt(invalidJSON, filepath.Join(s.work, "invalid-recipient-json.log"))
	decrypt(recipientMetadata, filepath.Join(s.work, "invalid-recipient-metadata.log"))
	decrypt(recipientParse, filepath.Join(s.work, "invalid-recipient-parse.log"))
	decrypt(recipientFingerprint, filepath.Join(s.work, "invalid-recipient-fingerprint.log"))
}

func (s *eventSuite) TestRequestWindowRejections() {
	registrationEvent := filepath.Join(s.work, "registration-window-event.json")
	registrationBinding := s.copyObject(s.event)
	registrationBinding["ttl_seconds"].(map[string]any)["registration"] = 200000000
	s.writeJSON(registrationEvent, registrationBinding)
	s.failure("identity", "register", "--event", registrationEvent, "--actor-id", "100", "--registration-id", "50000000-0000-4000-8000-000000000005", "--sig-private-key", s.captain.SigningPrivate, "--recipient-public-key", s.captain.RecipientPublic, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "registration-window.json"))

	submissionEvent := filepath.Join(s.work, "submission-window-event.json")
	submissionBinding := s.copyObject(s.event)
	submissionBinding["ttl_seconds"].(map[string]any)["submission"] = 200000000
	s.writeJSON(submissionEvent, submissionBinding)
	s.failure("submission", "prepare", "--event", submissionEvent, "--input", s.bundle, "--team-id", s.teamID, "--attempt-id", "50000000-0000-4000-8000-000000000005", "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "submission-window.json"))

	teamEvent := filepath.Join(s.work, "team-window-event.json")
	teamBinding := s.copyObject(s.event)
	teamBinding["ttl_seconds"].(map[string]any)["team"] = 200000000
	s.writeJSON(teamEvent, teamBinding)
	registration := filepath.Join(s.work, "team-window-registration.json")
	s.success("identity", "register", "--event", teamEvent, "--actor-id", "100", "--registration-id", "60000000-0000-4000-8000-000000000006", "--sig-private-key", s.captain.SigningPrivate, "--recipient-public-key", s.captain.RecipientPublic, "--passphrase-file", s.passphrase, "--output", registration)
	verified := filepath.Join(s.work, "team-window-identity.json")
	s.success("identity", "verify", "--event", teamEvent, "--input", registration, "--expect-actor-id", "100", "--source-time", s.issuedAt(registration), "--output", verified)
	registry := filepath.Join(s.work, "team-window-registry.json")
	s.writeJSON(registry, map[string]any{"v": 2, "kind": "event-registry", "event": s.readObject(registration)["event"], "revision": 0, "phase": "formation_open", "enabled": true, "disabled_reason": "", "identities": []any{s.readObject(verified)}, "teams": []any{}, "attempts": []any{}})
	s.failure("team", "propose", "--event", teamEvent, "--registry", registry, "--team-id", "50000000-0000-4000-8000-000000000005", "--actor-id", "100", "--member", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "team-window.json"))
}

func (s *eventSuite) identityCommandFailures(missingPassphrase, badSigningPrivate, badRecipientPublic string) {
	output := filepath.Join(s.work, "identity-command-output.json")
	s.failure("identity", "register", "--event", s.event, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--recipient-public-key", s.captain.RecipientPublic, "--passphrase-file", missingPassphrase, "--output", output)
	s.failure("identity", "register", "--event", s.event, "--actor-id", "100", "--sig-private-key", filepath.Join(s.work, "missing-signing.private.age"), "--recipient-public-key", s.captain.RecipientPublic, "--passphrase-file", s.passphrase, "--output", output)
	s.failure("identity", "register", "--event", s.event, "--actor-id", "100", "--sig-private-key", badSigningPrivate, "--recipient-public-key", s.captain.RecipientPublic, "--passphrase-file", s.passphrase, "--output", output)
	s.failure("identity", "register", "--event", s.event, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--recipient-public-key", filepath.Join(s.work, "missing-recipient.public.json"), "--passphrase-file", s.passphrase, "--output", output)
	s.failure("identity", "register", "--event", s.event, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--recipient-public-key", badRecipientPublic, "--passphrase-file", s.passphrase, "--output", output)
	s.failure("identity", "register", "--event", s.event, "--actor-id", "0", "--sig-private-key", s.captain.SigningPrivate, "--recipient-public-key", s.captain.RecipientPublic, "--passphrase-file", s.passphrase, "--output", output)
	s.failure("identity", "register", "--event", s.event, "--actor-id", "100", "--key-epoch", "0", "--sig-private-key", s.captain.SigningPrivate, "--recipient-public-key", s.captain.RecipientPublic, "--passphrase-file", s.passphrase, "--output", output)
	s.failure("identity", "register", "--event", s.event, "--actor-id", "100", "--registration-id", "not-a-uuid", "--sig-private-key", s.captain.SigningPrivate, "--recipient-public-key", s.captain.RecipientPublic, "--passphrase-file", s.passphrase, "--output", output)

	generated := filepath.Join(s.work, "generated-registration.json")
	s.success("identity", "register", "--event", s.event, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--recipient-public-key", s.captain.RecipientPublic, "--passphrase-file", s.passphrase, "--output", generated)
	s.failure("identity", "register", "--event", s.event, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--recipient-public-key", s.captain.RecipientPublic, "--passphrase-file", s.passphrase, "--output", generated)

	s.failure("identity", "verify", "--event", filepath.Join(s.work, "missing-event.json"), "--input", s.captainReg, "--expect-actor-id", "100", "--source-time", s.issuedAt(s.captainReg), "--output", output)
	s.failure("identity", "verify", "--event", s.event, "--input", filepath.Join(s.work, "missing-registration.json"), "--expect-actor-id", "100", "--source-time", s.issuedAt(s.captainReg), "--output", output)
	s.Require().NoError(os.WriteFile(output, []byte("already exists"), 0o600))
	s.failure("identity", "verify", "--event", s.event, "--input", s.captainReg, "--expect-actor-id", "100", "--source-time", s.issuedAt(s.captainReg), "--output", output)
}

func (s *eventSuite) teamCommandFailures(missingPassphrase, badSigningPrivate string) {
	output := filepath.Join(s.work, "team-command-output.json")
	s.failure("team", "propose", "--event", filepath.Join(s.work, "missing-event.json"), "--registry", s.registry, "--actor-id", "100", "--member", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", output)
	s.failure("team", "propose", "--event", s.event, "--registry", filepath.Join(s.work, "missing-registry.json"), "--actor-id", "100", "--member", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", output)
	s.failure("team", "propose", "--event", s.event, "--registry", s.registry, "--actor-id", "100", "--member", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", missingPassphrase, "--output", output)
	s.failure("team", "propose", "--event", s.event, "--registry", s.registry, "--actor-id", "100", "--member", "100", "--sig-private-key", badSigningPrivate, "--passphrase-file", s.passphrase, "--output", output)

	s.failure("team", "consent", "--event", filepath.Join(s.work, "missing-event.json"), "--registry", s.registry, "--proposal", s.proposal, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", output)
	s.failure("team", "consent", "--event", s.event, "--registry", filepath.Join(s.work, "missing-registry.json"), "--proposal", s.proposal, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", output)
	s.failure("team", "consent", "--event", s.event, "--registry", s.registry, "--proposal", filepath.Join(s.work, "missing-proposal.json"), "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", output)
	s.failure("team", "consent", "--event", s.event, "--registry", s.registry, "--proposal", s.proposal, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", missingPassphrase, "--output", output)
	s.failure("team", "consent", "--event", s.event, "--registry", s.registry, "--proposal", s.proposal, "--actor-id", "100", "--sig-private-key", badSigningPrivate, "--passphrase-file", s.passphrase, "--output", output)

	s.failure("team", "verify", "--event", filepath.Join(s.work, "missing-event.json"), "--registry", s.registry, "--proposal", s.proposal, "--proposal-source-time", s.issuedAt(s.proposal), "--consent", s.captainConsent, "--output", output)
	s.failure("team", "verify", "--event", s.event, "--registry", filepath.Join(s.work, "missing-registry.json"), "--proposal", s.proposal, "--proposal-source-time", s.issuedAt(s.proposal), "--consent", s.captainConsent, "--output", output)
	s.failure("team", "verify", "--event", s.event, "--registry", s.registry, "--proposal", filepath.Join(s.work, "missing-proposal.json"), "--proposal-source-time", s.issuedAt(s.proposal), "--consent", s.captainConsent, "--output", output)
	s.failure("team", "verify", "--event", s.event, "--registry", s.registry, "--proposal", s.proposal, "--proposal-source-time", s.issuedAt(s.proposal), "--output", output)
	s.failure("team", "verify", "--event", s.event, "--registry", s.registry, "--proposal", s.proposal, "--proposal-source-time", s.issuedAt(s.proposal), "--consent", filepath.Join(s.work, "missing-consent.json"), "--output", output)
	s.Require().NoError(os.WriteFile(output, []byte("already exists"), 0o600))
	s.failure("team", "verify", "--event", s.event, "--registry", s.registry, "--proposal", s.proposal, "--proposal-source-time", s.issuedAt(s.proposal), "--consent", s.captainConsent, "--consent", s.teammateConsent, "--consent-source-time", "100="+s.issuedAt(s.captainConsent), "--consent-source-time", "200="+s.issuedAt(s.teammateConsent), "--output", output)
}

func (s *eventSuite) submissionCommandFailures(missingPassphrase, badSigningPrivate string) {
	output := filepath.Join(s.work, "submission-command-output.json")
	s.failure("submission", "prepare", "--event", filepath.Join(s.work, "missing-event.json"), "--input", s.bundle, "--team-id", s.teamID, "--attempt-id", s.attemptID, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", output)
	s.failure("submission", "prepare", "--event", s.event, "--input", filepath.Join(s.work, "missing-bundle"), "--team-id", s.teamID, "--attempt-id", s.attemptID, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", output)
	s.failure("submission", "prepare", "--event", s.event, "--input", s.bundle, "--metadata", filepath.Join(s.work, "missing-metadata"), "--team-id", s.teamID, "--attempt-id", s.attemptID, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", output)
	s.failure("submission", "prepare", "--event", s.event, "--input", s.bundle, "--team-id", s.teamID, "--attempt-id", s.attemptID, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", missingPassphrase, "--output", output)
	s.failure("submission", "prepare", "--event", s.event, "--input", s.bundle, "--team-id", s.teamID, "--attempt-id", s.attemptID, "--actor-id", "100", "--sig-private-key", badSigningPrivate, "--passphrase-file", s.passphrase, "--output", output)

	s.failure("submission", "verify", "--event", filepath.Join(s.work, "missing-event.json"), "--registry", s.registry, "--request", s.submission, "--bundle", s.bundle, "--expect-actor-id", "100", "--source-time", s.issuedAt(s.submission), "--output", output)
	s.failure("submission", "verify", "--event", s.event, "--registry", filepath.Join(s.work, "missing-registry.json"), "--request", s.submission, "--bundle", s.bundle, "--expect-actor-id", "100", "--source-time", s.issuedAt(s.submission), "--output", output)
	s.failure("submission", "verify", "--event", s.event, "--registry", s.submissionRegistry, "--request", filepath.Join(s.work, "missing-submission.json"), "--bundle", s.bundle, "--expect-actor-id", "100", "--source-time", s.issuedAt(s.submission), "--output", output)
	s.failure("submission", "verify", "--event", s.event, "--registry", s.submissionRegistry, "--request", s.submission, "--bundle", filepath.Join(s.work, "missing-bundle"), "--expect-actor-id", "100", "--source-time", s.issuedAt(s.submission), "--output", output)
	s.failure("submission", "verify", "--event", s.event, "--registry", s.submissionRegistry, "--request", s.submission, "--bundle", s.bundle, "--metadata", filepath.Join(s.work, "missing-metadata"), "--expect-actor-id", "100", "--source-time", s.issuedAt(s.submission), "--output", output)
	s.Require().NoError(os.WriteFile(output, []byte("already exists"), 0o600))
	s.failure("submission", "verify", "--event", s.event, "--registry", s.submissionRegistry, "--request", s.submission, "--bundle", s.bundle, "--metadata", s.metadata, "--expect-actor-id", "100", "--source-time", s.issuedAt(s.submission), "--output", output)
}

func (s *eventSuite) TestIdentityRegistrationAndVerification() {
	verified := filepath.Join(s.work, "captain-verified.json")
	s.success("identity", "verify", "--event", s.event, "--input", s.captainReg, "--expect-actor-id", "100", "--source-time", s.issuedAt(s.captainReg), "--output", verified)
	s.failure("identity", "verify", "--event", s.event, "--input", s.captainReg, "--expect-actor-id", "200", "--source-time", s.issuedAt(s.captainReg), "--output", filepath.Join(s.work, "wrong-actor.json"))
	s.failure("identity", "verify", "--event", s.event, "--input", s.captainReg, "--expect-actor-id", "100", "--source-time", "2031-01-01T00:00:00Z", "--output", filepath.Join(s.work, "expired.json"))
	bad := filepath.Join(s.work, "bad-registration.json")
	data, err := os.ReadFile(s.captainReg)
	s.Require().NoError(err)
	data = bytes.Replace(data, []byte(`"actor_id":"100"`), []byte(`"actor_id":"999"`), 1)
	s.Require().NoError(os.WriteFile(bad, data, 0o600))
	s.failure("identity", "verify", "--event", s.event, "--input", bad, "--expect-actor-id", "999", "--source-time", s.issuedAt(s.captainReg), "--output", filepath.Join(s.work, "bad-signature.json"))
}

func (s *eventSuite) TestIdentityAndRegistryRejections() {
	identityCases := map[string]func(map[string]any){
		"identity": func(value map[string]any) {
			value["v"] = 1
		},
		"invalid-reference": func(value map[string]any) {
			value["event"].(map[string]any)["event_id"] = "A"
		},
		"window": func(value map[string]any) {
			value["expires_at"] = value["issued_at"]
		},
		"issued-at": func(value map[string]any) {
			value["issued_at"] = "not-a-time"
		},
		"signing-key": func(value map[string]any) {
			value["signing_key"].(map[string]any)["alg"] = "wrong"
		},
		"recipient-key": func(value map[string]any) {
			value["recipient_key"].(map[string]any)["alg"] = "wrong"
		},
		"signature-metadata": func(value map[string]any) {
			value["signature"].(map[string]any)["alg"] = "wrong"
		},
		"signature-encoding": func(value map[string]any) {
			value["signature"].(map[string]any)["value"] = "!"
		},
		"signature": func(value map[string]any) {
			value["actor_id"] = "999"
		},
	}
	for name, mutate := range identityCases {
		path := filepath.Join(s.work, "rejected-identity-"+name+".json")
		value := s.copyObject(s.captainReg)
		mutate(value)
		s.writeJSON(path, value)
		actorID := "100"
		if name == "signature" {
			actorID = "999"
		}
		s.failure(s.identityVerifyArgs(path, actorID, s.issuedAt(s.captainReg), filepath.Join(s.work, "rejected-identity-"+name+".verified.json"))...)
	}
	s.failure(s.identityVerifyArgs(s.captainReg, "100", "not-a-time", filepath.Join(s.work, "rejected-identity-time.verified.json"))...)

	registryCases := map[string]func(map[string]any){
		"discriminator": func(value map[string]any) {
			value["kind"] = "wrong"
		},
		"invalid-reference": func(value map[string]any) {
			value["event"].(map[string]any)["event_id"] = "A"
		},
		"empty": func(value map[string]any) {
			value["identities"] = []any{}
		},
		"identity": func(value map[string]any) {
			value["identities"].([]any)[0].(map[string]any)["actor_id"] = "0"
		},
		"signing-key": func(value map[string]any) {
			value["identities"].([]any)[0].(map[string]any)["signing_key"].(map[string]any)["alg"] = "wrong"
		},
		"recipient-key": func(value map[string]any) {
			value["identities"].([]any)[0].(map[string]any)["recipient_key"].(map[string]any)["recipient"] = "wrong"
		},
		"sorted": func(value map[string]any) {
			identities := value["identities"].([]any)
			value["identities"] = []any{identities[1], identities[0]}
		},
		"duplicate": func(value map[string]any) {
			identities := value["identities"].([]any)
			identities[1].(map[string]any)["actor_id"] = identities[0].(map[string]any)["actor_id"]
		},
	}
	for name, mutate := range registryCases {
		path := filepath.Join(s.work, "rejected-registry-"+name+".json")
		value := s.copyObject(s.registry)
		mutate(value)
		s.writeJSON(path, value)
		s.failure(s.teamProposeArgs(path, "50000000-0000-4000-8000-000000000005", "100", s.captain.SigningPrivate, filepath.Join(s.work, "rejected-registry-"+name+".proposal.json"), "100")...)
	}

	s.failure(s.teamProposeArgs(s.registry, "50000000-0000-4000-8000-000000000005", "999", s.captain.SigningPrivate, filepath.Join(s.work, "missing-proposer.proposal.json"), "999")...)
	s.failure(s.teamProposeArgs(s.registry, "50000000-0000-4000-8000-000000000005", "100", s.captain.SigningPrivate, filepath.Join(s.work, "missing-member.proposal.json"), "100", "999")...)
	s.failure(s.teamProposeArgs(s.registry, "not-a-uuid", "100", s.captain.SigningPrivate, filepath.Join(s.work, "bad-id.proposal.json"), "100")...)
	s.failure(s.teamProposeArgs(s.registry, "50000000-0000-4000-8000-000000000005", "100", s.captain.SigningPrivate, filepath.Join(s.work, "captain-not-member.proposal.json"), "200")...)

	generated := filepath.Join(s.work, "generated-team.proposal.json")
	s.success(s.teamProposeArgs(s.registry, "", "100", s.captain.SigningPrivate, generated, "100", "200")...)
	s.failure(s.teamProposeArgs(s.registry, "50000000-0000-4000-8000-000000000005", "100", s.captain.SigningPrivate, generated, "100")...)
}

func (s *eventSuite) TestRegistryBoundTeamLifecycle() {
	verified := filepath.Join(s.work, "team-verified.json")
	s.success("team", "verify", "--event", s.event, "--registry", s.registry, "--proposal", s.proposal, "--proposal-source-time", s.issuedAt(s.proposal), "--consent", s.captainConsent, "--consent", s.teammateConsent, "--consent-source-time", "100="+s.issuedAt(s.captainConsent), "--consent-source-time", "200="+s.issuedAt(s.teammateConsent), "--output", verified)
	s.failure("team", "verify", "--event", s.event, "--registry", s.registry, "--proposal", s.proposal, "--proposal-source-time", s.issuedAt(s.proposal), "--consent", s.captainConsent, "--consent-source-time", "100="+s.issuedAt(s.captainConsent), "--output", filepath.Join(s.work, "missing-consent.json"))
	s.failure("team", "propose", "--event", s.event, "--registry", s.registry, "--team-id", "50000000-0000-4000-8000-000000000005", "--actor-id", "100", "--member", "100", "--sig-private-key", s.outsider.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "wrong-key-proposal.json"))
	s.failure("team", "consent", "--event", s.event, "--registry", s.registry, "--proposal", s.proposal, "--actor-id", "200", "--sig-private-key", s.outsider.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "wrong-key-consent.json"))
}

func (s *eventSuite) TestRegistryStateRejections() {
	registryCases := map[string]func(map[string]any){
		"phase": func(value map[string]any) {
			value["phase"] = "wrong"
		},
		"enabled-reason": func(value map[string]any) {
			value["disabled_reason"] = "wrong"
		},
		"disabled-reason": func(value map[string]any) {
			value["enabled"] = false
		},
		"team": func(value map[string]any) {
			value["teams"].([]any)[0].(map[string]any)["team_id"] = "wrong"
		},
		"teams-sorted": func(value map[string]any) {
			team := value["teams"].([]any)[0]
			value["teams"] = []any{team, team}
		},
		"team-member": func(value map[string]any) {
			value["teams"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)["actor_id"] = "999"
		},
		"team-members-sorted": func(value map[string]any) {
			members := value["teams"].([]any)[0].(map[string]any)["members"].([]any)
			value["teams"].([]any)[0].(map[string]any)["members"] = []any{members[1], members[0]}
		},
		"team-member-reused": func(value map[string]any) {
			team := value["teams"].([]any)[0].(map[string]any)
			duplicate := s.copyValue(team)
			duplicate["team_id"] = "50000000-0000-4000-8000-000000000005"
			value["teams"] = []any{team, duplicate}
		},
		"attempt": func(value map[string]any) {
			value["attempts"] = []any{map[string]any{"attempt_id": "wrong"}}
		},
		"attempts-sorted": func(value map[string]any) {
			attempt := s.attemptRecord("40000000-0000-4000-8000-000000000004")
			value["attempts"] = []any{attempt, attempt}
		},
		"attempt-member": func(value map[string]any) {
			attempt := s.attemptRecord("40000000-0000-4000-8000-000000000004")
			attempt["actor_id"] = "999"
			value["attempts"] = []any{attempt}
		},
	}
	for name, mutate := range registryCases {
		path := filepath.Join(s.work, "rejected-state-"+name+".json")
		value := s.copyObject(s.submissionRegistry)
		mutate(value)
		s.writeJSON(path, value)
		s.failure(s.teamProposeArgs(path, "50000000-0000-4000-8000-000000000005", "100", s.captain.SigningPrivate, filepath.Join(s.work, "rejected-state-"+name+".proposal.json"), "100")...)
	}
}

func (s *eventSuite) TestRegistryPhaseMembershipAndReplayRejections() {
	disabled := filepath.Join(s.work, "disabled-registry.json")
	disabledValue := s.copyObject(s.registry)
	disabledValue["enabled"] = false
	disabledValue["disabled_reason"] = "maintenance"
	s.writeJSON(disabled, disabledValue)
	s.failure(s.teamProposeArgs(disabled, "50000000-0000-4000-8000-000000000005", "100", s.captain.SigningPrivate, filepath.Join(s.work, "disabled.proposal.json"), "100")...)
	s.failure(s.teamConsentArgs(disabled, s.proposal, "100", s.captain.SigningPrivate, filepath.Join(s.work, "disabled.consent.json"))...)
	s.failure(s.teamVerifyArgsWithRegistry(disabled, s.proposal, s.issuedAt(s.proposal), filepath.Join(s.work, "disabled.verified.json"), []string{s.captainConsent, s.teammateConsent}, []string{"100=" + s.issuedAt(s.captainConsent), "200=" + s.issuedAt(s.teammateConsent)})...)
	s.failure(s.submissionVerifyArgsWithRegistry(s.registry, s.submission, s.bundle, s.metadata, "100", s.issuedAt(s.submission), filepath.Join(s.work, "formation-submission.json"))...)

	activeFormation := filepath.Join(s.work, "active-formation-registry.json")
	activeFormationValue := s.copyObject(s.submissionRegistry)
	activeFormationValue["phase"] = "formation_open"
	s.writeJSON(activeFormation, activeFormationValue)
	s.failure(s.teamProposeArgs(activeFormation, s.teamID, "100", s.captain.SigningPrivate, filepath.Join(s.work, "active-team-id.proposal.json"), "100", "200")...)
	s.failure(s.teamProposeArgs(activeFormation, "50000000-0000-4000-8000-000000000005", "100", s.captain.SigningPrivate, filepath.Join(s.work, "active-member.proposal.json"), "100")...)
	s.failure(s.teamConsentArgs(activeFormation, s.proposal, "100", s.captain.SigningPrivate, filepath.Join(s.work, "active-team.consent.json"))...)
	s.failure(s.teamVerifyArgsWithRegistry(activeFormation, s.proposal, s.issuedAt(s.proposal), filepath.Join(s.work, "active-team.verified.json"), []string{s.captainConsent, s.teammateConsent}, []string{"100=" + s.issuedAt(s.captainConsent), "200=" + s.issuedAt(s.teammateConsent)})...)

	missingTeam := filepath.Join(s.work, "missing-team-registry.json")
	missingTeamValue := s.copyObject(s.submissionRegistry)
	missingTeamValue["teams"] = []any{}
	s.writeJSON(missingTeam, missingTeamValue)
	s.failure(s.submissionVerifyArgsWithRegistry(missingTeam, s.submission, s.bundle, s.metadata, "100", s.issuedAt(s.submission), filepath.Join(s.work, "missing-team-submission.json"))...)

	replayed := filepath.Join(s.work, "replayed-attempt-registry.json")
	replayedValue := s.copyObject(s.submissionRegistry)
	replayedValue["attempts"] = []any{s.attemptRecord(s.attemptID)}
	s.writeJSON(replayed, replayedValue)
	s.failure(s.submissionVerifyArgsWithRegistry(replayed, s.submission, s.bundle, s.metadata, "100", s.issuedAt(s.submission), filepath.Join(s.work, "replayed-submission.json"))...)

	perTeam := filepath.Join(s.work, "per-team-quota-registry.json")
	perTeamValue := s.copyObject(s.submissionRegistry)
	attempts := make([]any, 0, 10)
	for index := range 10 {
		attempts = append(attempts, s.attemptRecord(fmt.Sprintf("%08x-0000-4000-8000-%012x", 0x41000000+index, index)))
	}
	perTeamValue["attempts"] = attempts
	s.writeJSON(perTeam, perTeamValue)
	s.failure(s.submissionVerifyArgsWithRegistry(perTeam, s.submission, s.bundle, s.metadata, "100", s.issuedAt(s.submission), filepath.Join(s.work, "per-team-submission.json"))...)

	total := filepath.Join(s.work, "total-quota-registry.json")
	totalValue := s.copyObject(s.submissionRegistry)
	attempts = make([]any, 0, 200)
	for index := range 200 {
		attempts = append(attempts, s.attemptRecord(fmt.Sprintf("%08x-0000-4000-8000-%012x", 0x42000000+index, index)))
	}
	totalValue["attempts"] = attempts
	s.writeJSON(total, totalValue)
	s.failure(s.submissionVerifyArgsWithRegistry(total, s.submission, s.bundle, s.metadata, "100", s.issuedAt(s.submission), filepath.Join(s.work, "total-submission.json"))...)
}

func (s *eventSuite) TestTeamAndSubmissionRejections() {
	proposalCases := map[string]func(map[string]any){
		"identity": func(value map[string]any) {
			value["v"] = 1
		},
		"invalid-reference": func(value map[string]any) {
			value["event"].(map[string]any)["event_id"] = "A"
		},
		"size": func(value map[string]any) {
			value["members"] = []any{}
		},
		"window": func(value map[string]any) {
			value["expires_at"] = value["issued_at"]
		},
		"member": func(value map[string]any) {
			value["members"].([]any)[0].(map[string]any)["signing_kid"] = strings.Repeat("b", 64)
		},
		"sorted": func(value map[string]any) {
			members := value["members"].([]any)
			value["members"] = []any{members[1], members[0]}
		},
		"proposer": func(value map[string]any) {
			value["proposer"].(map[string]any)["actor_id"] = "999"
		},
		"signature": func(value map[string]any) {
			value["signature"].(map[string]any)["alg"] = "wrong"
		},
	}
	for name, mutate := range proposalCases {
		path := filepath.Join(s.work, "rejected-proposal-"+name+".json")
		value := s.copyObject(s.proposal)
		mutate(value)
		s.writeJSON(path, value)
		s.failure(s.teamConsentArgs(s.registry, path, "100", s.captain.SigningPrivate, filepath.Join(s.work, "rejected-proposal-"+name+".consent.json"))...)
	}
	s.failure(s.teamConsentArgs(s.registry, s.proposal, "999", s.captain.SigningPrivate, filepath.Join(s.work, "missing-consenter.consent.json"))...)

	consentOutput := filepath.Join(s.work, "existing-consent.json")
	s.Require().NoError(os.WriteFile(consentOutput, []byte("already exists"), 0o600))
	s.failure(s.teamConsentArgs(s.registry, s.proposal, "100", s.captain.SigningPrivate, consentOutput)...)

	validTimes := []string{"100=" + s.issuedAt(s.captainConsent), "200=" + s.issuedAt(s.teammateConsent)}
	s.failure(s.teamVerifyArgs(s.proposal, "not-a-time", filepath.Join(s.work, "bad-proposal-time.json"), []string{s.captainConsent, s.teammateConsent}, validTimes)...)
	s.failure(s.teamVerifyArgs(filepath.Join(s.work, "rejected-proposal-identity.json"), s.issuedAt(s.proposal), filepath.Join(s.work, "bad-proposal.json"), []string{s.captainConsent, s.teammateConsent}, validTimes)...)
	s.failure(s.teamVerifyArgs(s.proposal, s.issuedAt(s.proposal), filepath.Join(s.work, "duplicate-consent.json"), []string{s.captainConsent, s.captainConsent}, []string{"100=" + s.issuedAt(s.captainConsent), "999=" + s.issuedAt(s.captainConsent)})...)
	s.failure(s.teamVerifyArgs(s.proposal, s.issuedAt(s.proposal), filepath.Join(s.work, "missing-consent-time.json"), []string{s.captainConsent, s.teammateConsent}, []string{"100=" + s.issuedAt(s.captainConsent), "999=" + s.issuedAt(s.captainConsent)})...)
	s.failure(s.teamVerifyArgs(s.proposal, s.issuedAt(s.proposal), filepath.Join(s.work, "bad-consent-time.json"), []string{s.captainConsent, s.teammateConsent}, []string{"100=not-a-time", "200=" + s.issuedAt(s.teammateConsent)})...)

	consentCases := map[string]func(map[string]any){
		"identity": func(value map[string]any) {
			value["v"] = 1
		},
		"invalid-reference": func(value map[string]any) {
			value["event"].(map[string]any)["event_id"] = "A"
		},
		"window": func(value map[string]any) {
			value["expires_at"] = value["issued_at"]
		},
		"signer": func(value map[string]any) {
			value["key_epoch"] = 2
		},
		"signature-metadata": func(value map[string]any) {
			value["signature"].(map[string]any)["alg"] = "wrong"
		},
		"signature-encoding": func(value map[string]any) {
			value["signature"].(map[string]any)["value"] = "!"
		},
	}
	for name, mutate := range consentCases {
		path := filepath.Join(s.work, "rejected-consent-"+name+".json")
		value := s.copyObject(s.captainConsent)
		mutate(value)
		s.writeJSON(path, value)
		s.failure(s.teamVerifyArgs(s.proposal, s.issuedAt(s.proposal), filepath.Join(s.work, "rejected-consent-"+name+".verified.json"), []string{path, s.teammateConsent}, validTimes)...)
	}

	prepareOutput := filepath.Join(s.work, "existing-submission.json")
	s.Require().NoError(os.WriteFile(prepareOutput, []byte("already exists"), 0o600))
	s.failure("submission", "prepare", "--event", s.event, "--input", s.bundle, "--metadata", s.metadata, "--team-id", s.teamID, "--attempt-id", "50000000-0000-4000-8000-000000000005", "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", prepareOutput)
	s.failure("submission", "prepare", "--event", s.event, "--input", s.bundle, "--team-id", "not-a-uuid", "--attempt-id", s.attemptID, "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "bad-submission-identity.json"))

	submissionCases := map[string]func(map[string]any){
		"identity": func(value map[string]any) {
			value["v"] = 1
		},
		"invalid-reference": func(value map[string]any) {
			value["event"].(map[string]any)["event_id"] = "A"
		},
		"window": func(value map[string]any) {
			value["expires_at"] = value["issued_at"]
		},
		"signer": func(value map[string]any) {
			value["key_epoch"] = 2
		},
		"signature": func(value map[string]any) {
			value["signature"].(map[string]any)["alg"] = "wrong"
		},
	}
	for name, mutate := range submissionCases {
		path := filepath.Join(s.work, "rejected-submission-"+name+".json")
		value := s.copyObject(s.submission)
		mutate(value)
		s.writeJSON(path, value)
		s.failure(s.submissionVerifyArgs(path, s.bundle, s.metadata, "100", s.issuedAt(s.submission), filepath.Join(s.work, "rejected-submission-"+name+".verified.json"))...)
	}
	s.failure(s.submissionVerifyArgs(s.submission, s.bundle, s.metadata, "100", "not-a-time", filepath.Join(s.work, "bad-submission-time.verified.json"))...)
	s.failure(s.submissionVerifyArgs(s.submission, s.bundle, "", "100", s.issuedAt(s.submission), filepath.Join(s.work, "missing-submission-metadata.verified.json"))...)
}

func (s *eventSuite) TestSubmissionVerification() {
	verified := filepath.Join(s.work, "submission-verified.json")
	s.success("submission", "verify", "--event", s.event, "--registry", s.submissionRegistry, "--request", s.submission, "--bundle", s.bundle, "--metadata", s.metadata, "--expect-actor-id", "100", "--source-time", s.issuedAt(s.submission), "--output", verified)
	s.failure("submission", "verify", "--event", s.event, "--registry", s.submissionRegistry, "--request", s.submission, "--bundle", s.bundle, "--metadata", s.metadata, "--expect-actor-id", "200", "--source-time", s.issuedAt(s.submission), "--output", filepath.Join(s.work, "wrong-submitter.json"))
	tampered := filepath.Join(s.work, "tampered-bundle.zip")
	s.Require().NoError(os.WriteFile(tampered, []byte("tampered"), 0o600))
	s.failure("submission", "verify", "--event", s.event, "--registry", s.submissionRegistry, "--request", s.submission, "--bundle", tampered, "--metadata", s.metadata, "--expect-actor-id", "100", "--source-time", s.issuedAt(s.submission), "--output", filepath.Join(s.work, "tampered-submission.json"))
}

func (s *eventSuite) TestSignedEncryptedStream() {
	for _, member := range []keyResult{s.captain, s.teammate} {
		plain := filepath.Join(s.work, member.SigningKeyID+".log")
		s.success("decverify", "--input", s.stream, "--output", plain, "--context", s.streamBinding, "--ver-public-key", s.captain.SigningPublic, "--dec-private-key", member.RecipientPrivate, "--passphrase-file", s.passphrase)
		data, err := os.ReadFile(plain)
		s.Require().NoError(err)
		s.Equal([]byte("private judge output\n"), data)
	}
	s.failure("decverify", "--input", s.stream, "--output", filepath.Join(s.work, "outsider.log"), "--context", s.streamBinding, "--ver-public-key", s.captain.SigningPublic, "--dec-private-key", s.outsider.RecipientPrivate, "--passphrase-file", s.passphrase)
	wrongContext := filepath.Join(s.work, "wrong-stream-binding.json")
	wrong := s.readObject(s.streamBinding)
	wrong["artifact_id"] = "different-run"
	s.writeJSON(wrongContext, wrong)
	s.failure("decverify", "--input", s.stream, "--output", filepath.Join(s.work, "wrong-context.log"), "--context", wrongContext, "--ver-public-key", s.captain.SigningPublic, "--dec-private-key", s.captain.RecipientPrivate, "--passphrase-file", s.passphrase)
}

func (s *eventSuite) TestStreamEnvelopeRejections() {
	badBinding := filepath.Join(s.work, "bad-stream-binding.json")
	value := s.copyObject(s.streamBinding)
	value["purpose"] = ""
	s.writeJSON(badBinding, value)
	s.failure("sigcrypt", "--input", s.bundle, "--output", filepath.Join(s.work, "bad-binding.eventctl"), "--context", badBinding, "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase, "--enc-public-key", s.captain.RecipientPublic)

	invalidMagic := filepath.Join(s.work, "invalid-magic.eventctl")
	s.Require().NoError(os.WriteFile(invalidMagic, []byte("not an eventctl stream"), 0o600))
	s.failure(s.decverifyArgs(invalidMagic, filepath.Join(s.work, "invalid-magic.log"))...)

	invalidSize := filepath.Join(s.work, "invalid-size.eventctl")
	s.writeRawStream(invalidSize, uint32((64<<20)+1), nil, nil)
	s.failure(s.decverifyArgs(invalidSize, filepath.Join(s.work, "invalid-size.log"))...)

	invalidHeader := filepath.Join(s.work, "invalid-header.eventctl")
	s.writeRawStream(invalidHeader, 1, []byte("{"), nil)
	s.failure(s.decverifyArgs(invalidHeader, filepath.Join(s.work, "invalid-header.log"))...)

	invalidSignature := filepath.Join(s.work, "invalid-signature.eventctl")
	s.mutateStream(invalidSignature, func(header map[string]any) {
		header["signature"].(map[string]any)["value"] = "!"
	}, func(payload []byte) []byte { return payload })
	s.failure(s.decverifyArgs(invalidSignature, filepath.Join(s.work, "invalid-signature.log"))...)

	invalidCiphertext := filepath.Join(s.work, "invalid-stream-ciphertext.eventctl")
	s.mutateStream(invalidCiphertext, func(map[string]any) {}, func([]byte) []byte { return []byte("not an age payload") })
	s.failure(s.decverifyArgs(invalidCiphertext, filepath.Join(s.work, "invalid-stream-ciphertext.log"))...)

	tamperedCiphertext := filepath.Join(s.work, "tampered-stream-ciphertext.eventctl")
	s.mutateStream(tamperedCiphertext, func(map[string]any) {}, func(payload []byte) []byte {
		copy := append([]byte(nil), payload...)
		copy[len(copy)-1] ^= 1
		return copy
	})
	s.failure(s.decverifyArgs(tamperedCiphertext, filepath.Join(s.work, "tampered-stream-ciphertext.log"))...)

	wrongSigner := filepath.Join(s.work, "wrong-header-signer.eventctl")
	s.writeSignedStream(wrongSigner, func(header *streamHeader) {
		header.Signer.KeyID = strings.Repeat("b", 64)
	})
	s.failure(s.decverifyArgs(wrongSigner, filepath.Join(s.work, "wrong-header-signer.log"))...)

	wrongSize := filepath.Join(s.work, "wrong-header-size.eventctl")
	s.writeSignedStream(wrongSize, func(header *streamHeader) {
		header.PayloadSize++
	})
	s.failure(s.decverifyArgs(wrongSize, filepath.Join(s.work, "wrong-header-size.log"))...)

	wrongDigest := filepath.Join(s.work, "wrong-header-digest.eventctl")
	s.writeSignedStream(wrongDigest, func(header *streamHeader) {
		header.PayloadSHA256 = strings.Repeat("b", 64)
	})
	s.failure(s.decverifyArgs(wrongDigest, filepath.Join(s.work, "wrong-header-digest.log"))...)
	s.failure(s.decverifyArgs(s.stream, s.stream)...)

}

func (s *eventSuite) TestInputFailures() {
	s.failure("key-gen", "--out", filepath.Join(s.work, "no-passphrase"))
	empty := filepath.Join(s.work, "empty-passphrase.txt")
	s.Require().NoError(os.WriteFile(empty, nil, 0o600))
	s.failure("key-gen", "--out", filepath.Join(s.work, "empty-passphrase"), "--passphrase-file", empty)
	s.failure("identity", "register", "--event", filepath.Join(s.work, "missing-event.json"), "--actor-id", "100", "--sig-private-key", s.captain.SigningPrivate, "--recipient-public-key", s.captain.RecipientPublic, "--passphrase-file", s.passphrase, "--output", filepath.Join(s.work, "missing-event-registration.json"))
	s.failure("team", "verify", "--event", s.event, "--registry", s.registry, "--proposal", s.proposal, "--proposal-source-time", s.issuedAt(s.proposal), "--consent", s.captainConsent, "--consent-source-time", "wrong", "--output", filepath.Join(s.work, "bad-consent-time.json"))
	s.failure("sigcrypt", "--input", s.bundle, "--output", filepath.Join(s.work, "no-recipients.eventctl"), "--context", s.streamBinding, "--sig-private-key", s.captain.SigningPrivate, "--passphrase-file", s.passphrase)
}

func (s *eventSuite) keyGen(name string) keyResult {
	directory := filepath.Join(s.work, name)
	result := s.success("key-gen", "--out", directory, "--passphrase-file", s.passphrase)
	var value keyResult
	s.Require().NoError(json.Unmarshal(result.Result, &value))
	return value
}

func (s *eventSuite) register(actorID, registrationID string, key keyResult) string {
	request := filepath.Join(s.work, actorID+".registration.json")
	s.success("identity", "register", "--event", s.event, "--actor-id", actorID, "--registration-id", registrationID, "--sig-private-key", key.SigningPrivate, "--recipient-public-key", key.RecipientPublic, "--passphrase-file", s.passphrase, "--output", request)
	return request
}

func (s *eventSuite) verifiedIdentities(registrations ...string) []any {
	identities := make([]any, 0, len(registrations))
	for _, registration := range registrations {
		verified := filepath.Join(s.work, filepath.Base(registration)+".verified.json")
		actorID := s.readObject(registration)["actor_id"].(string)
		s.success("identity", "verify", "--event", s.event, "--input", registration, "--expect-actor-id", actorID, "--source-time", s.issuedAt(registration), "--output", verified)
		identities = append(identities, s.readObject(verified))
	}
	return identities
}

func (s *eventSuite) writeRegistry(path, phase string, identities, teams, attempts []any) {
	s.writeJSON(path, map[string]any{"v": 2, "kind": "event-registry", "event": s.readObject(s.captainReg)["event"], "revision": 0, "phase": phase, "enabled": true, "disabled_reason": "", "identities": identities, "teams": teams, "attempts": attempts})
}

func (s *eventSuite) issuedAt(path string) string { return s.readObject(path)["issued_at"].(string) }

func (s *eventSuite) readObject(path string) map[string]any {
	data := s.readBytes(path)
	var value map[string]any
	s.Require().NoError(json.Unmarshal(data, &value))
	return value
}

func (s *eventSuite) copyObject(path string) map[string]any {
	return s.copyValue(s.readObject(path))
}

func (s *eventSuite) copyValue(value map[string]any) map[string]any {
	data, err := json.Marshal(value)
	s.Require().NoError(err)
	var copy map[string]any
	s.Require().NoError(json.Unmarshal(data, &copy))
	return copy
}

func (s *eventSuite) readBytes(path string) []byte {
	data, err := os.ReadFile(path)
	s.Require().NoError(err)
	return data
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
	data, err := json.Marshal(value)
	s.Require().NoError(err)
	s.Require().NoError(os.WriteFile(path, append(data, '\n'), 0o600))
}

func (s *eventSuite) writePassphraseEncrypted(path string, data []byte) {
	passphrase := strings.TrimSpace(string(s.readBytes(s.passphrase)))
	recipient, err := age.NewScryptRecipient(passphrase)
	s.Require().NoError(err)
	var encrypted bytes.Buffer
	writer, err := age.Encrypt(&encrypted, recipient)
	s.Require().NoError(err)
	_, err = writer.Write(data)
	s.Require().NoError(err)
	s.Require().NoError(writer.Close())
	s.Require().NoError(os.WriteFile(path, encrypted.Bytes(), 0o600))
}

func (s *eventSuite) identityVerifyArgs(input, actorID, sourceTime, output string) []string {
	return []string{"identity", "verify", "--event", s.event, "--input", input, "--expect-actor-id", actorID, "--source-time", sourceTime, "--output", output}
}

func (s *eventSuite) teamProposeArgs(registry, teamID, actorID, signingPath, output string, members ...string) []string {
	args := []string{"team", "propose", "--event", s.event, "--registry", registry}
	if teamID != "" {
		args = append(args, "--team-id", teamID)
	}
	args = append(args, "--actor-id", actorID)
	for _, member := range members {
		args = append(args, "--member", member)
	}
	return append(args, "--sig-private-key", signingPath, "--passphrase-file", s.passphrase, "--output", output)
}

func (s *eventSuite) teamConsentArgs(registry, proposal, actorID, signingPath, output string) []string {
	return []string{"team", "consent", "--event", s.event, "--registry", registry, "--proposal", proposal, "--actor-id", actorID, "--sig-private-key", signingPath, "--passphrase-file", s.passphrase, "--output", output}
}

func (s *eventSuite) teamVerifyArgs(proposal, proposalTime, output string, consents, consentTimes []string) []string {
	return s.teamVerifyArgsWithRegistry(s.registry, proposal, proposalTime, output, consents, consentTimes)
}

func (s *eventSuite) teamVerifyArgsWithRegistry(registry, proposal, proposalTime, output string, consents, consentTimes []string) []string {
	args := []string{"team", "verify", "--event", s.event, "--registry", registry, "--proposal", proposal, "--proposal-source-time", proposalTime}
	for _, consent := range consents {
		args = append(args, "--consent", consent)
	}
	for _, consentTime := range consentTimes {
		args = append(args, "--consent-source-time", consentTime)
	}
	return append(args, "--output", output)
}

func (s *eventSuite) submissionVerifyArgs(request, bundle, metadata, actorID, sourceTime, output string) []string {
	return s.submissionVerifyArgsWithRegistry(s.submissionRegistry, request, bundle, metadata, actorID, sourceTime, output)
}

func (s *eventSuite) submissionVerifyArgsWithRegistry(registry, request, bundle, metadata, actorID, sourceTime, output string) []string {
	args := []string{"submission", "verify", "--event", s.event, "--registry", registry, "--request", request, "--bundle", bundle}
	if metadata != "" {
		args = append(args, "--metadata", metadata)
	}
	return append(args, "--expect-actor-id", actorID, "--source-time", sourceTime, "--output", output)
}

func (s *eventSuite) attemptRecord(attemptID string) map[string]any {
	return map[string]any{"attempt_id": attemptID, "team_id": s.teamID, "actor_id": "100", "submission_sha256": strings.Repeat("a", 64), "payload_sha256": strings.Repeat("b", 64)}
}

func (s *eventSuite) decverifyArgs(input, output string) []string {
	return []string{"decverify", "--input", input, "--output", output, "--context", s.streamBinding, "--ver-public-key", s.captain.SigningPublic, "--dec-private-key", s.captain.RecipientPrivate, "--passphrase-file", s.passphrase}
}

func (s *eventSuite) writeRawStream(path string, headerSize uint32, header, payload []byte) {
	data := make([]byte, 12+len(header)+len(payload))
	copy(data, []byte{'E', 'V', 'T', 'C', 'T', 'L', 1, 0})
	binary.BigEndian.PutUint32(data[8:12], headerSize)
	copy(data[12:], header)
	copy(data[12+len(header):], payload)
	s.Require().NoError(os.WriteFile(path, data, 0o600))
}

func (s *eventSuite) mutateStream(path string, mutateHeader func(map[string]any), mutatePayload func([]byte) []byte) {
	data := s.readBytes(s.stream)
	headerSize := binary.BigEndian.Uint32(data[8:12])
	headerEnd := 12 + int(headerSize)
	var header map[string]any
	s.Require().NoError(json.Unmarshal(data[12:headerEnd], &header))
	mutateHeader(header)
	headerData, err := json.Marshal(header)
	s.Require().NoError(err)
	s.writeRawStream(path, uint32(len(headerData)), headerData, mutatePayload(data[headerEnd:]))
}

func (s *eventSuite) writeSignedStream(path string, mutate func(*streamHeader)) {
	data := s.readBytes(s.stream)
	headerSize := binary.BigEndian.Uint32(data[8:12])
	headerEnd := 12 + int(headerSize)
	var header streamHeader
	s.Require().NoError(json.Unmarshal(data[12:headerEnd], &header))
	mutate(&header)
	unsigned := header
	unsigned.Signature = streamSignature{}
	unsignedData, err := json.Marshal(unsigned)
	s.Require().NoError(err)
	message := append([]byte("eventctl:eventctl/v2:stream.sigcrypt\x00"), append(unsignedData, '\n')...)
	private := s.readSigningPrivate()
	header.Signature = streamSignature{Algorithm: "Ed25519", KeyID: s.captain.SigningKeyID, Value: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))}
	headerData, err := json.Marshal(header)
	s.Require().NoError(err)
	s.writeRawStream(path, uint32(len(headerData)), headerData, data[headerEnd:])
}

func (s *eventSuite) readSigningPrivate() ed25519.PrivateKey {
	identity, err := age.NewScryptIdentity(strings.TrimSpace(string(s.readBytes(s.passphrase))))
	s.Require().NoError(err)
	reader, err := age.Decrypt(bytes.NewReader(s.readBytes(s.captain.SigningPrivate)), identity)
	s.Require().NoError(err)
	plain, err := io.ReadAll(reader)
	s.Require().NoError(err)
	var value struct {
		PrivateKey string `json:"private"`
	}
	s.Require().NoError(json.Unmarshal(plain, &value))
	private, err := base64.RawURLEncoding.DecodeString(value.PrivateKey)
	s.Require().NoError(err)
	return ed25519.PrivateKey(private)
}
