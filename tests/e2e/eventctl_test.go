//go:build e2e

package e2e

import (
	"archive/tar"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/suite"
)

type cliResponse struct {
	OK      bool            `json:"ok"`
	Command string          `json:"command"`
	Result  json.RawMessage `json:"result"`
	Error   string          `json:"error"`
}

type keyPaths struct {
	SignaturePrivate  string `json:"signature_private_key"`
	SignaturePublic   string `json:"signature_public_key"`
	EncryptionPrivate string `json:"encryption_private_key"`
	EncryptionPublic  string `json:"encryption_public_key"`
}

type artifactResult struct {
	Output         string `json:"output"`
	SHA256         string `json:"sha256"`
	TeamID         string `json:"team_id"`
	AttemptID      string `json:"attempt_id"`
	FileCount      int    `json:"file_count"`
	RecipientCount int    `json:"recipient_count"`
}

type manifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type manifest struct {
	Protocol            string         `json:"protocol"`
	Kind                string         `json:"kind"`
	EventID             string         `json:"event_id,omitempty"`
	GitHubID            string         `json:"github_id,omitempty"`
	TeamID              string         `json:"team_id,omitempty"`
	TeamName            string         `json:"team_name,omitempty"`
	Members             []string       `json:"members,omitempty"`
	FormationSHA256     string         `json:"formation_sha256,omitempty"`
	AttemptID           string         `json:"attempt_id,omitempty"`
	Files               []manifestFile `json:"files"`
	SigningPublicKey    string         `json:"signing_public_key"`
	EncryptionPublicKey string         `json:"encryption_public_key,omitempty"`
	Signature           string         `json:"signature,omitempty"`
}

type rawTarEntry struct {
	Name string
	Data []byte
	Type byte
}

type eventSuite struct {
	suite.Suite
	root     string
	work     string
	binary   string
	coverage string
	alice    keyPaths
	bob      keyPaths
	outsider keyPaths
	input    string
	log      string
}

func TestEventctl(t *testing.T) { suite.Run(t, new(eventSuite)) }

func (s *eventSuite) SetupSuite() {
	_, file, _, ok := runtime.Caller(0)
	s.Require().True(ok)
	s.root = filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
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

	s.alice = s.keyGen("alice")
	s.bob = s.keyGen("bob")
	s.outsider = s.keyGen("outsider")
	s.input = s.write("exploit.whl", "wheel payload\n")
	s.log = s.write("judge.log", "private judge output\n")
}

func (s *eventSuite) TearDownSuite() {
	entries, err := os.ReadDir(s.coverage)
	s.Require().NoError(err)
	metadata, counters := false, false
	for _, entry := range entries {
		metadata = metadata || strings.HasPrefix(entry.Name(), "covmeta.")
		counters = counters || strings.HasPrefix(entry.Name(), "covcounters.")
	}
	s.True(metadata, "instrumented binary did not emit covmeta")
	s.True(counters, "instrumented binary did not emit covcounters")
}

func (s *eventSuite) TestVersionAndDoctor() {
	version := s.success("version")
	s.Contains(string(version.Result), `"protocol":"eventctl/v3"`)
	s.Contains(string(version.Result), `"version":"0.3.0-dev"`)

	doctor := s.successWithEnv(map[string]string{"EVENTCTL_EVENT_ID": "pythonhk/event-smoke"}, "doctor")
	s.Contains(string(doctor.Result), `"event_id":"pythonhk/event-smoke"`)
	s.Contains(string(doctor.Result), `"signature":"Ed25519"`)
	s.success("doctor")
	s.failureWithEnv(map[string]string{"EVENTCTL_EVENT_ID": "not-a-repository"}, "doctor")
	s.failure("doctor", "--unexpected")
	s.raw(0, "--help")
	s.raw(0, "team", "--help")
}

func (s *eventSuite) TestKeyGenerationFilesArePlainAndExclusive() {
	for _, file := range []struct {
		path string
		mode os.FileMode
	}{
		{s.alice.SignaturePrivate, 0o600},
		{s.alice.SignaturePublic, 0o644},
		{s.alice.EncryptionPrivate, 0o600},
		{s.alice.EncryptionPublic, 0o644},
	} {
		info, err := os.Stat(file.path)
		s.Require().NoError(err)
		s.Equal(file.mode, info.Mode().Perm())
	}
	s.Contains(string(s.read(s.alice.SignaturePrivate)), "BEGIN PRIVATE KEY")
	s.Contains(string(s.read(s.alice.EncryptionPrivate)), "AGE-SECRET-KEY")
	s.failure("key-gen", "--out", filepath.Join(s.work, "alice"))
	s.failure("key-gen")
	blocked := s.write("blocked", "not a directory")
	s.failure("key-gen", "--out", blocked)
}

func (s *eventSuite) TestSoloTeamActivatesFromFormationOnly() {
	formation, result := s.form("solo.tar", "Solo & Politics", "100", s.alice, "100")
	s.NotEmpty(result.TeamID)
	s.Empty(result.AttemptID)
	s.Equal(0, result.FileCount)
	entries := s.tarEntries(formation)
	s.Len(entries, 1)
	member := s.manifest(formation)
	s.Equal("eventctl/v3", member.Protocol)
	s.Equal("team-formation", member.Kind)
	s.Equal("pythonhk/event-smoke", member.EventID)
	s.Equal("100", member.GitHubID)
	s.Equal(result.TeamID, member.TeamID)
	s.Equal("Solo & Politics", member.TeamName)
	s.Equal([]string{"100"}, member.Members)
	s.NotEmpty(member.SigningPublicKey)
	s.NotEmpty(member.EncryptionPublicKey)
	s.NotEmpty(member.Signature)

	s.failure("team", "key", "--formation", formation, "--github-id", "100", "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", filepath.Join(s.work, "duplicate-key.tar"))
	s.failure("team", "form", "--event-id", "pythonhk/event-smoke", "--team-name", "missing initiator", "--github-id", "100", "--member", "200", "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", filepath.Join(s.work, "missing-initiator.tar"))
	s.failure("team", "form", "--event-id", "pythonhk/event-smoke", "--team-name", "duplicate", "--github-id", "100", "--member", "100", "--member", "100", "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", filepath.Join(s.work, "duplicate-member.tar"))
	s.failure("team", "form", "--event-id", "bad", "--team-name", "bad event", "--github-id", "100", "--member", "100", "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", filepath.Join(s.work, "bad-event.tar"))
	s.failure("team", "form", "--event-id", "pythonhk/event-smoke", "--team-name", " ", "--github-id", "100", "--member", "100", "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", filepath.Join(s.work, "empty-name.tar"))
}

func (s *eventSuite) TestMultiMemberKeyProofAndTampering() {
	formation, result := s.form("multi.tar", "The Peers", "100", s.alice, "200", "100")
	base := s.manifest(formation)
	s.Equal([]string{"100", "200"}, base.Members)

	key := filepath.Join(s.work, "bob-key.tar")
	response := s.success("team", "key", "--formation", formation, "--github-id", "200", "--sig-priv-key", s.bob.SignaturePrivate, "--enc-pub-key", s.bob.EncryptionPublic, "--out", key)
	var keyResult artifactResult
	s.Require().NoError(json.Unmarshal(response.Result, &keyResult))
	s.Equal(result.TeamID, keyResult.TeamID)
	proof := s.manifest(key)
	s.Equal("team-key", proof.Kind)
	s.Equal("200", proof.GitHubID)
	s.Equal(result.TeamID, proof.TeamID)
	s.Equal(result.SHA256, proof.FormationSHA256)
	s.NotEmpty(proof.EncryptionPublicKey)

	s.failure("team", "key", "--formation", formation, "--github-id", "300", "--sig-priv-key", s.outsider.SignaturePrivate, "--enc-pub-key", s.outsider.EncryptionPublic, "--out", filepath.Join(s.work, "outsider-key.tar"))
	s.failure("team", "key", "--formation", filepath.Join(s.work, "missing.tar"), "--github-id", "200", "--sig-priv-key", s.bob.SignaturePrivate, "--enc-pub-key", s.bob.EncryptionPublic, "--out", filepath.Join(s.work, "missing-key.tar"))

	entries := s.tarEntries(formation)
	var changed map[string]any
	s.Require().NoError(json.Unmarshal(entries["manifest.json"], &changed))
	changed["team_name"] = "Changed after signing"
	entries["manifest.json"], _ = json.Marshal(changed)
	tampered := filepath.Join(s.work, "tampered-formation.tar")
	s.writeTar(tampered, entries)
	s.failure("team", "key", "--formation", tampered, "--github-id", "200", "--sig-priv-key", s.bob.SignaturePrivate, "--enc-pub-key", s.bob.EncryptionPublic, "--out", filepath.Join(s.work, "tampered-key.tar"))

	invalid := s.write("invalid-formation.tar", "not a tar")
	s.failure("team", "key", "--formation", invalid, "--github-id", "200", "--sig-priv-key", s.bob.SignaturePrivate, "--enc-pub-key", s.bob.EncryptionPublic, "--out", filepath.Join(s.work, "invalid-key.tar"))
}

func (s *eventSuite) TestSubmissionPreparation() {
	_, team := s.form("submission-team.tar", "Submitters", "100", s.alice, "100")
	second := s.write("evidence.txt", "evidence\n")
	output := filepath.Join(s.work, "submission.tar")
	response := s.success("submission", "prepare", "--event-id", "pythonhk/event-smoke", "--github-id", "100", "--team-id", team.TeamID, "--input", second, "--input", s.input, "--sig-priv-key", s.alice.SignaturePrivate, "--out", output)
	var result artifactResult
	s.Require().NoError(json.Unmarshal(response.Result, &result))
	s.Equal(team.TeamID, result.TeamID)
	s.NotEmpty(result.AttemptID)
	s.Equal(2, result.FileCount)
	manifest := s.manifest(output)
	s.Equal("submission", manifest.Kind)
	s.Equal(result.AttemptID, manifest.AttemptID)
	s.Equal([]string{"files/evidence.txt", "files/exploit.whl"}, []string{manifest.Files[0].Path, manifest.Files[1].Path})
	firstDigest := result.SHA256
	s.Require().NoError(os.WriteFile(s.input, []byte("revised wheel payload\n"), 0o600))
	response = s.success("submission", "prepare", "--event-id", "pythonhk/event-smoke", "--github-id", "100", "--team-id", team.TeamID, "--input", s.input, "--sig-priv-key", s.alice.SignaturePrivate, "--out", output)
	s.Require().NoError(json.Unmarshal(response.Result, &result))
	s.NotEqual(firstDigest, result.SHA256)

	s.failure("submission", "prepare", "--event-id", "pythonhk/event-smoke", "--github-id", "100", "--team-id", team.TeamID, "--sig-priv-key", s.alice.SignaturePrivate, "--out", filepath.Join(s.work, "no-input.tar"))
	s.failure("submission", "prepare", "--event-id", "pythonhk/event-smoke", "--github-id", "no", "--team-id", team.TeamID, "--input", s.input, "--sig-priv-key", s.alice.SignaturePrivate, "--out", filepath.Join(s.work, "bad-actor.tar"))
	s.failure("submission", "prepare", "--event-id", "pythonhk/event-smoke", "--github-id", "100", "--team-id", "not-a-uuid", "--input", s.input, "--sig-priv-key", s.alice.SignaturePrivate, "--out", filepath.Join(s.work, "bad-team.tar"))
	badKey := s.write("bad-signing-key.pem", "not a key")
	s.failure("submission", "prepare", "--event-id", "pythonhk/event-smoke", "--github-id", "100", "--team-id", team.TeamID, "--input", s.input, "--sig-priv-key", badKey, "--out", filepath.Join(s.work, "bad-key.tar"))
	s.failure("submission", "prepare", "--event-id", "pythonhk/event-smoke", "--github-id", "100", "--team-id", team.TeamID, "--input", s.work, "--sig-priv-key", s.alice.SignaturePrivate, "--out", filepath.Join(s.work, "directory-input.tar"))
}

func (s *eventSuite) TestEncryptedFeedbackForEveryMember() {
	secondLog := s.write("details.log", "more private output\n")
	feedback := filepath.Join(s.work, "feedback.tar")
	response := s.success("sigcrypt", "--input", s.log, "--input", secondLog, "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--enc-pub-key", s.bob.EncryptionPublic, "--enc-pub-key", s.alice.EncryptionPublic, "--out", feedback)
	var result artifactResult
	s.Require().NoError(json.Unmarshal(response.Result, &result))
	s.Equal(2, result.FileCount)
	s.Equal(2, result.RecipientCount)
	entries := s.tarEntries(feedback)
	s.ElementsMatch([]string{"manifest.json", "payload.age"}, sortedKeys(entries))
	s.Equal("feedback", s.manifest(feedback).Kind)

	for name, keys := range map[string]keyPaths{"alice": s.alice, "bob": s.bob} {
		output := filepath.Join(s.work, name+"-feedback")
		s.success("decverify", "--input", feedback, "--out-dir", output, "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", keys.EncryptionPrivate)
		s.Equal("private judge output\n", string(s.read(filepath.Join(output, "judge.log"))))
		s.Equal("more private output\n", string(s.read(filepath.Join(output, "details.log"))))
	}
	s.failure("decverify", "--input", feedback, "--out-dir", filepath.Join(s.work, "outsider-feedback"), "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", s.outsider.EncryptionPrivate)
	s.failure("decverify", "--input", feedback, "--out-dir", filepath.Join(s.work, "wrong-signer"), "--sig-pub-key", s.bob.SignaturePublic, "--enc-priv-key", s.alice.EncryptionPrivate)
	nonempty := filepath.Join(s.work, "nonempty")
	s.Require().NoError(os.MkdirAll(nonempty, 0o700))
	s.write(filepath.Join("nonempty", "already.txt"), "present")
	s.failure("decverify", "--input", feedback, "--out-dir", nonempty, "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", s.alice.EncryptionPrivate)

	s.failure("sigcrypt", "--input", s.log, "--sig-priv-key", s.alice.SignaturePrivate, "--out", filepath.Join(s.work, "no-recipient.tar"))
	s.failure("sigcrypt", "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", filepath.Join(s.work, "no-input.tar"))
	badRecipient := s.write("bad-recipient.pub", "not an age recipient")
	s.failure("sigcrypt", "--input", s.log, "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", badRecipient, "--out", filepath.Join(s.work, "bad-recipient.tar"))

	tampered := s.tarEntries(feedback)
	var changed map[string]any
	s.Require().NoError(json.Unmarshal(tampered["manifest.json"], &changed))
	changed["signature"] = "bad"
	tampered["manifest.json"], _ = json.Marshal(changed)
	tamperedFeedback := filepath.Join(s.work, "tampered-feedback.tar")
	s.writeTar(tamperedFeedback, tampered)
	s.failure("decverify", "--input", tamperedFeedback, "--out-dir", filepath.Join(s.work, "tampered-output"), "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", s.alice.EncryptionPrivate)
}

func (s *eventSuite) TestCommandAndKeyFailurePaths() {
	formation, team := s.form("command-formation.tar", "Command Paths", "100", s.alice, "100", "200")
	feedback := s.signedFeedback("command-feedback.tar", s.innerTar(rawTarEntry{Name: "files/result.log", Data: []byte("result\n")}))
	missing := filepath.Join(s.work, "missing-key")
	badPrivate := s.write("bad-private.pem", "not a PEM")
	badPrivateDER := s.pem("bad-private-der.pem", "PRIVATE KEY", []byte("not PKCS8"))
	otherPrivate := s.ecdsaPrivate("other-private.pem")
	badPublic := s.write("bad-public.pem", "not a PEM")
	badPublicDER := s.pem("bad-public-der.pem", "PUBLIC KEY", []byte("not PKIX"))
	otherPublic := s.ecdsaPublic("other-public.pem")
	badRecipient := s.write("bad-recipient-for-command.pub", "not an age recipient")
	badIdentity := s.write("bad-identity.key", "not an age identity")

	s.failure("team", "form", "--event-id", "pythonhk/event-smoke", "--team-name", "missing signing", "--github-id", "100", "--member", "100", "--sig-priv-key", missing, "--enc-pub-key", s.alice.EncryptionPublic, "--out", filepath.Join(s.work, "missing-signing.tar"))
	s.failure("team", "form", "--event-id", "pythonhk/event-smoke", "--team-name", "missing recipient", "--github-id", "100", "--member", "100", "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", missing, "--out", filepath.Join(s.work, "missing-recipient.tar"))
	s.failure("team", "form", "--event-id", "pythonhk/event-smoke", "--team-name", "bad recipient", "--github-id", "100", "--member", "100", "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", badRecipient, "--out", filepath.Join(s.work, "bad-recipient.tar"))
	s.failure("team", "form", "--event-id", "pythonhk/event-smoke", "--team-name", "directory output", "--github-id", "100", "--member", "100", "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", s.work)
	blockedOutput := s.write("output-obstacle", "not a directory")
	s.failure("team", "form", "--event-id", "pythonhk/event-smoke", "--team-name", "blocked output", "--github-id", "100", "--member", "100", "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", filepath.Join(blockedOutput, "formation.tar"))

	s.failure("team", "key", "--formation", formation, "--github-id", "200", "--sig-priv-key", missing, "--enc-pub-key", s.bob.EncryptionPublic, "--out", filepath.Join(s.work, "missing-team-key.tar"))
	s.failure("team", "key", "--formation", formation, "--github-id", "200", "--sig-priv-key", s.bob.SignaturePrivate, "--enc-pub-key", badRecipient, "--out", filepath.Join(s.work, "bad-team-key.tar"))
	s.failure("team", "key", "--formation", formation, "--github-id", "200", "--sig-priv-key", s.bob.SignaturePrivate, "--enc-pub-key", s.bob.EncryptionPublic, "--out", s.work)

	for index, private := range []string{badPrivate, badPrivateDER, otherPrivate} {
		s.failure("submission", "prepare", "--event-id", "pythonhk/event-smoke", "--github-id", "100", "--team-id", team.TeamID, "--input", s.input, "--sig-priv-key", private, "--out", filepath.Join(s.work, "bad-private-"+string(rune('a'+index))+".tar"))
	}
	s.failure("sigcrypt", "--input", s.log, "--sig-priv-key", badPrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", filepath.Join(s.work, "bad-sigcrypt-private.tar"))
	s.failure("sigcrypt", "--input", s.log, "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", s.work)

	for index, public := range []string{missing, badPublic, badPublicDER, otherPublic} {
		s.failure("decverify", "--input", feedback, "--out-dir", filepath.Join(s.work, "bad-public-output-"+string(rune('a'+index))), "--sig-pub-key", public, "--enc-priv-key", s.alice.EncryptionPrivate)
	}
	s.failure("decverify", "--input", feedback, "--out-dir", filepath.Join(s.work, "missing-identity-output"), "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", missing)
	s.failure("decverify", "--input", feedback, "--out-dir", filepath.Join(s.work, "bad-identity-output"), "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", badIdentity)
	s.failure("decverify", "--input", missing, "--out-dir", filepath.Join(s.work, "missing-feedback-output"), "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", s.alice.EncryptionPrivate)

	large := s.write("large-input.bin", "")
	s.Require().NoError(os.Truncate(large, 64<<20+1))
	s.failure("submission", "prepare", "--event-id", "pythonhk/event-smoke", "--github-id", "100", "--team-id", team.TeamID, "--input", large, "--sig-priv-key", s.alice.SignaturePrivate, "--out", filepath.Join(s.work, "large-input.tar"))
	duplicateOne := s.write(filepath.Join("one", "same.txt"), "one")
	duplicateTwo := s.write(filepath.Join("two", "same.txt"), "two")
	s.failure("submission", "prepare", "--event-id", "pythonhk/event-smoke", "--github-id", "100", "--team-id", team.TeamID, "--input", duplicateOne, "--input", duplicateTwo, "--sig-priv-key", s.alice.SignaturePrivate, "--out", filepath.Join(s.work, "duplicate-input.tar"))
	backslash := s.write("unsafe\\name.txt", "unsafe")
	s.failure("submission", "prepare", "--event-id", "pythonhk/event-smoke", "--github-id", "100", "--team-id", team.TeamID, "--input", backslash, "--sig-priv-key", s.alice.SignaturePrivate, "--out", filepath.Join(s.work, "unsafe-input.tar"))
	s.failure("sigcrypt", "--input", backslash, "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", filepath.Join(s.work, "unsafe-feedback.tar"))

	s.failure("team", "form", "--event-id", "pythonhk/event-smoke", "--team-name", "missing member", "--github-id", "100", "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", filepath.Join(s.work, "no-member.tar"))
	s.failure("team", "form", "--event-id", "pythonhk/event-smoke", "--team-name", "bad member", "--github-id", "100", "--member", "0", "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", filepath.Join(s.work, "bad-member.tar"))
	s.failure("team", "form", "--event-id", "pythonhk/event-smoke", "--team-name", "line\nbreak", "--github-id", "100", "--member", "100", "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", filepath.Join(s.work, "control-name.tar"))
	s.success("team", "form", "--event-id", "pythonhk/event-smoke", "--team-name", "different lengths", "--github-id", "100", "--member", "100", "--member", "9", "--sig-priv-key", s.alice.SignaturePrivate, "--enc-pub-key", s.alice.EncryptionPublic, "--out", filepath.Join(s.work, "sorted-members.tar"))
}

func (s *eventSuite) TestArtifactReaderRejectsMalformedRequests() {
	formation, team := s.form("reader-formation.tar", "Reader Paths", "100", s.alice, "100", "200")
	key := filepath.Join(s.work, "reader-key.tar")
	s.success("team", "key", "--formation", formation, "--github-id", "200", "--sig-priv-key", s.bob.SignaturePrivate, "--enc-pub-key", s.bob.EncryptionPublic, "--out", key)
	submission := filepath.Join(s.work, "reader-submission.tar")
	s.success("submission", "prepare", "--event-id", "pythonhk/event-smoke", "--github-id", "100", "--team-id", team.TeamID, "--input", s.input, "--sig-priv-key", s.alice.SignaturePrivate, "--out", submission)
	feedback := s.signedFeedback("reader-feedback.tar", s.innerTar(rawTarEntry{Name: "files/result.log", Data: []byte("result\n")}))

	fail := func(file string) {
		s.failure("team", "key", "--formation", file, "--github-id", "200", "--sig-priv-key", s.bob.SignaturePrivate, "--enc-pub-key", s.bob.EncryptionPublic, "--out", filepath.Join(s.work, "rejected-"+filepath.Base(file)))
	}
	fail(s.writeRawTar("no-manifest.tar", rawTarEntry{Name: "note.txt", Data: []byte("missing")}))
	fail(s.write("malformed-header.tar", strings.Repeat("x", 512)))
	fail(s.writeRawTar("unsafe-name.tar", rawTarEntry{Name: "../outside", Data: []byte("unsafe")}))
	fail(s.writeRawTar("directory-entry.tar", rawTarEntry{Name: "folder", Type: tar.TypeDir}))
	fail(s.writeRawTar("duplicate-entry.tar", rawTarEntry{Name: "manifest.json", Data: []byte("{}")}, rawTarEntry{Name: "manifest.json", Data: []byte("{}")}))
	fail(s.writeTruncatedTar("truncated-entry.tar"))
	fail(s.writeOversizedHeaderTar("oversized-entry.tar"))

	fail(s.replaceManifest("invalid-json.tar", formation, []byte("{")))
	fail(s.mutateManifest("unknown-field.tar", formation, func(value map[string]any) { value["unexpected"] = true }))
	fail(s.replaceManifest("trailing-json.tar", formation, append(s.tarEntries(formation)["manifest.json"], []byte("{}")...)))
	fail(s.mutateManifest("wrong-protocol.tar", formation, func(value map[string]any) { value["protocol"] = "eventctl/v2" }))
	fail(s.mutateManifest("invalid-public-key.tar", formation, func(value map[string]any) { value["signing_public_key"] = "not a key" }))
	fail(s.mutateManifest("unknown-kind.tar", formation, func(value map[string]any) { value["kind"] = "unknown" }))
	fail(s.mutateManifest("unsorted-members.tar", formation, func(value map[string]any) { value["members"] = []string{"100", "9"} }))
	fail(s.mutateManifest("bad-formation-encryption.tar", formation, func(value map[string]any) { value["encryption_public_key"] = "not age" }))
	fail(s.mutateManifest("bad-formation-fields.tar", formation, func(value map[string]any) { value["formation_sha256"] = strings.Repeat("a", 64) }))
	fail(s.mutateManifest("bad-key-fields.tar", key, func(value map[string]any) { value["formation_sha256"] = "bad" }))
	fail(s.mutateManifest("bad-key-identity.tar", key, func(value map[string]any) { value["team_id"] = "bad" }))
	fail(s.mutateManifest("bad-key-encryption.tar", key, func(value map[string]any) { value["encryption_public_key"] = "not age" }))
	fail(s.mutateManifest("bad-submission-identity.tar", submission, func(value map[string]any) { value["attempt_id"] = "bad" }))
	fail(s.mutateManifest("bad-submission-files.tar", submission, func(value map[string]any) {
		value["files"] = []any{map[string]any{"path": "other", "sha256": strings.Repeat("a", 64), "size": 1}}
	}))
	fail(s.mutateManifest("bad-feedback-identity.tar", feedback, func(value map[string]any) { value["event_id"] = "pythonhk/event-smoke" }))
	fail(s.mutateManifest("bad-feedback-files.tar", feedback, func(value map[string]any) { value["files"] = []any{} }))

	entries := s.tarEntries(submission)
	entries["files/extra.txt"] = []byte("extra")
	s.writeTar(filepath.Join(s.work, "submission-extra-entry.tar"), entries)
	fail(filepath.Join(s.work, "submission-extra-entry.tar"))
	entries = s.tarEntries(submission)
	for name := range entries {
		if strings.HasPrefix(name, "files/") {
			delete(entries, name)
			break
		}
	}
	entries["files/replacement.txt"] = []byte("replacement")
	s.writeTar(filepath.Join(s.work, "submission-missing-entry.tar"), entries)
	fail(filepath.Join(s.work, "submission-missing-entry.tar"))
	entries = s.tarEntries(submission)
	for name := range entries {
		if strings.HasPrefix(name, "files/") {
			entries[name] = []byte("short")
		}
	}
	s.writeTar(filepath.Join(s.work, "submission-wrong-size.tar"), entries)
	fail(filepath.Join(s.work, "submission-wrong-size.tar"))
	entries = s.tarEntries(submission)
	for name, data := range entries {
		if strings.HasPrefix(name, "files/") {
			entries[name] = append([]byte(nil), data...)
			entries[name][0] ^= 1
		}
	}
	s.writeTar(filepath.Join(s.work, "submission-wrong-digest.tar"), entries)
	fail(filepath.Join(s.work, "submission-wrong-digest.tar"))
	entries = s.tarEntries(feedback)
	entries["unexpected"] = []byte("extra")
	s.writeTar(filepath.Join(s.work, "feedback-extra-entry.tar"), entries)
	fail(filepath.Join(s.work, "feedback-extra-entry.tar"))
	entries = s.tarEntries(feedback)
	delete(entries, "payload.age")
	entries["unexpected"] = []byte("missing")
	s.writeTar(filepath.Join(s.work, "feedback-missing-payload.tar"), entries)
	fail(filepath.Join(s.work, "feedback-missing-payload.tar"))
	entries = s.tarEntries(feedback)
	entries["payload.age"][0] ^= 1
	s.writeTar(filepath.Join(s.work, "feedback-wrong-digest.tar"), entries)
	fail(filepath.Join(s.work, "feedback-wrong-digest.tar"))

	s.failure("team", "key", "--formation", submission, "--github-id", "200", "--sig-priv-key", s.bob.SignaturePrivate, "--enc-pub-key", s.bob.EncryptionPublic, "--out", filepath.Join(s.work, "submission-is-not-formation.tar"))
}

func (s *eventSuite) TestSignedFeedbackPayloadFailures() {
	validPayload := s.innerTar(rawTarEntry{Name: "files/result.log", Data: []byte("result\n")})
	normal := s.signedFeedback("payload-normal.tar", validPayload)
	formation, _ := s.form("payload-formation.tar", "Not Feedback", "100", s.alice, "100")
	s.failure("decverify", "--input", formation, "--out-dir", filepath.Join(s.work, "not-feedback"), "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", s.alice.EncryptionPrivate)

	tampered := s.resignFeedbackPayload("payload-late-tamper.tar", normal, func(payload []byte) { payload[len(payload)-1] ^= 1 })
	s.failure("decverify", "--input", tampered, "--out-dir", filepath.Join(s.work, "late-tamper"), "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", s.alice.EncryptionPrivate)
	nonTar := s.signedFeedback("payload-not-tar.tar", []byte("not a tar"))
	s.failure("decverify", "--input", nonTar, "--out-dir", filepath.Join(s.work, "not-tar"), "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", s.alice.EncryptionPrivate)
	empty := s.signedFeedback("payload-empty.tar", s.innerTar())
	s.failure("decverify", "--input", empty, "--out-dir", filepath.Join(s.work, "empty-payload"), "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", s.alice.EncryptionPrivate)
	unsafe := s.signedFeedback("payload-unsafe.tar", s.innerTar(rawTarEntry{Name: "not-files", Data: []byte("unsafe")}))
	s.failure("decverify", "--input", unsafe, "--out-dir", filepath.Join(s.work, "unsafe-payload"), "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", s.alice.EncryptionPrivate)
	nested := s.signedFeedback("payload-nested.tar", s.innerTar(rawTarEntry{Name: "files/nested/result.log", Data: []byte("nested")}))
	s.failure("decverify", "--input", nested, "--out-dir", filepath.Join(s.work, "nested-payload"), "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", s.alice.EncryptionPrivate)

	blocked := s.write("feedback-output-obstacle", "not a directory")
	s.failure("decverify", "--input", normal, "--out-dir", filepath.Join(blocked, "output"), "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", s.alice.EncryptionPrivate)
	readonly := filepath.Join(s.work, "readonly-feedback-output")
	s.Require().NoError(os.MkdirAll(readonly, 0o500))
	s.Require().NoError(os.Chmod(readonly, 0o500))
	s.failure("decverify", "--input", normal, "--out-dir", readonly, "--sig-pub-key", s.alice.SignaturePublic, "--enc-priv-key", s.alice.EncryptionPrivate)
	s.Require().NoError(os.Chmod(readonly, 0o700))
}

func (s *eventSuite) keyGen(name string) keyPaths {
	response := s.success("key-gen", "--out", filepath.Join(s.work, name))
	var result keyPaths
	s.Require().NoError(json.Unmarshal(response.Result, &result))
	return result
}

func (s *eventSuite) form(name, teamName, githubID string, keys keyPaths, members ...string) (string, artifactResult) {
	output := filepath.Join(s.work, name)
	arguments := []string{"team", "form", "--event-id", "pythonhk/event-smoke", "--team-name", teamName, "--github-id", githubID}
	for _, member := range members {
		arguments = append(arguments, "--member", member)
	}
	arguments = append(arguments, "--sig-priv-key", keys.SignaturePrivate, "--enc-pub-key", keys.EncryptionPublic, "--out", output)
	response := s.success(arguments...)
	var result artifactResult
	s.Require().NoError(json.Unmarshal(response.Result, &result))
	return output, result
}

func (s *eventSuite) success(arguments ...string) cliResponse {
	code, output := s.raw(-1, arguments...)
	s.Equal(0, code, string(output))
	var response cliResponse
	s.Require().NoError(json.Unmarshal(output, &response), string(output))
	s.True(response.OK, response.Error)
	return response
}

func (s *eventSuite) successWithEnv(values map[string]string, arguments ...string) cliResponse {
	command := exec.Command(s.binary, arguments...)
	command.Dir = s.work
	command.Env = append(os.Environ(), "GOCOVERDIR="+s.coverage)
	for key, value := range values {
		command.Env = append(command.Env, key+"="+value)
	}
	output, err := command.CombinedOutput()
	s.Require().NoError(err, string(output))
	var response cliResponse
	s.Require().NoError(json.Unmarshal(output, &response), string(output))
	s.True(response.OK, response.Error)
	return response
}

func (s *eventSuite) failure(arguments ...string) {
	code, output := s.raw(-1, arguments...)
	s.NotEqual(0, code, string(output))
	var response cliResponse
	s.Require().NoError(json.Unmarshal(output, &response), string(output))
	s.False(response.OK)
	s.NotEmpty(response.Error)
}

func (s *eventSuite) failureWithEnv(values map[string]string, arguments ...string) {
	command := exec.Command(s.binary, arguments...)
	command.Dir = s.work
	command.Env = append(os.Environ(), "GOCOVERDIR="+s.coverage)
	for key, value := range values {
		command.Env = append(command.Env, key+"="+value)
	}
	output, err := command.CombinedOutput()
	s.Require().Error(err, string(output))
	var response cliResponse
	s.Require().NoError(json.Unmarshal(output, &response), string(output))
	s.False(response.OK)
}

func (s *eventSuite) raw(expected int, arguments ...string) (int, []byte) {
	command := exec.Command(s.binary, arguments...)
	command.Dir = s.work
	command.Env = append(os.Environ(), "GOCOVERDIR="+s.coverage)
	output, err := command.CombinedOutput()
	code := 0
	if err != nil {
		var exitError *exec.ExitError
		s.Require().ErrorAs(err, &exitError)
		code = exitError.ExitCode()
	}
	if expected >= 0 {
		s.Equal(expected, code, string(output))
	}
	return code, output
}

func (s *eventSuite) write(name, content string) string {
	file := filepath.Join(s.work, name)
	s.Require().NoError(os.MkdirAll(filepath.Dir(file), 0o755))
	s.Require().NoError(os.WriteFile(file, []byte(content), 0o600))
	return file
}

func (s *eventSuite) read(file string) []byte {
	data, err := os.ReadFile(file)
	s.Require().NoError(err)
	return data
}

func (s *eventSuite) manifest(file string) manifest {
	entries := s.tarEntries(file)
	var value manifest
	s.Require().NoError(json.Unmarshal(entries["manifest.json"], &value))
	return value
}

func (s *eventSuite) tarEntries(file string) map[string][]byte {
	reader := tar.NewReader(bytes.NewReader(s.read(file)))
	entries := map[string][]byte{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return entries
		}
		s.Require().NoError(err)
		data, err := io.ReadAll(reader)
		s.Require().NoError(err)
		entries[header.Name] = data
	}
}

func (s *eventSuite) writeTar(file string, entries map[string][]byte) {
	names := sortedKeys(entries)
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, name := range names {
		data := entries[name]
		s.Require().NoError(writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}))
		_, err := writer.Write(data)
		s.Require().NoError(err)
	}
	s.Require().NoError(writer.Close())
	s.Require().NoError(os.WriteFile(file, output.Bytes(), 0o600))
}

func (s *eventSuite) writeRawTar(name string, entries ...rawTarEntry) string {
	file := filepath.Join(s.work, name)
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, entry := range entries {
		typeFlag := entry.Type
		if typeFlag == 0 {
			typeFlag = tar.TypeReg
		}
		header := &tar.Header{Name: entry.Name, Mode: 0o644, Size: int64(len(entry.Data)), Typeflag: typeFlag}
		if typeFlag == tar.TypeDir {
			header.Size = 0
		}
		s.Require().NoError(writer.WriteHeader(header))
		if len(entry.Data) != 0 {
			_, err := writer.Write(entry.Data)
			s.Require().NoError(err)
		}
	}
	s.Require().NoError(writer.Close())
	s.Require().NoError(os.WriteFile(file, output.Bytes(), 0o600))
	return file
}

func (s *eventSuite) writeTruncatedTar(name string) string {
	file := filepath.Join(s.work, name)
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	s.Require().NoError(writer.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o644, Size: 10, Typeflag: tar.TypeReg}))
	_, err := writer.Write([]byte("x"))
	s.Require().NoError(err)
	s.Require().NoError(os.WriteFile(file, output.Bytes(), 0o600))
	return file
}

func (s *eventSuite) writeOversizedHeaderTar(name string) string {
	file := filepath.Join(s.work, name)
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	s.Require().NoError(writer.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o644, Size: 64<<20 + 1, Typeflag: tar.TypeReg}))
	s.Require().NoError(os.WriteFile(file, output.Bytes(), 0o600))
	return file
}

func (s *eventSuite) replaceManifest(name, source string, value []byte) string {
	entries := s.tarEntries(source)
	entries["manifest.json"] = value
	output := filepath.Join(s.work, name)
	s.writeTar(output, entries)
	return output
}

func (s *eventSuite) mutateManifest(name, source string, mutate func(map[string]any)) string {
	entries := s.tarEntries(source)
	var value map[string]any
	s.Require().NoError(json.Unmarshal(entries["manifest.json"], &value))
	mutate(value)
	entries["manifest.json"] = s.json(value)
	output := filepath.Join(s.work, name)
	s.writeTar(output, entries)
	return output
}

func (s *eventSuite) innerTar(entries ...rawTarEntry) []byte {
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, entry := range entries {
		typeFlag := entry.Type
		if typeFlag == 0 {
			typeFlag = tar.TypeReg
		}
		header := &tar.Header{Name: entry.Name, Mode: 0o644, Size: int64(len(entry.Data)), Typeflag: typeFlag}
		s.Require().NoError(writer.WriteHeader(header))
		_, err := writer.Write(entry.Data)
		s.Require().NoError(err)
	}
	s.Require().NoError(writer.Close())
	return output.Bytes()
}

func (s *eventSuite) signedFeedback(name string, payload []byte) string {
	recipient := s.hybridRecipient(s.alice.EncryptionPublic)
	var encrypted bytes.Buffer
	writer, err := age.Encrypt(&encrypted, recipient)
	s.Require().NoError(err)
	_, err = writer.Write(payload)
	s.Require().NoError(err)
	s.Require().NoError(writer.Close())
	return s.writeSignedFeedback(name, encrypted.Bytes())
}

func (s *eventSuite) resignFeedbackPayload(name, source string, mutate func([]byte)) string {
	entries := s.tarEntries(source)
	mutate(entries["payload.age"])
	return s.writeSignedFeedbackEntries(name, entries)
}

func (s *eventSuite) writeSignedFeedback(name string, encrypted []byte) string {
	return s.writeSignedFeedbackEntries(name, map[string][]byte{"payload.age": encrypted})
}

func (s *eventSuite) writeSignedFeedbackEntries(name string, entries map[string][]byte) string {
	payload := entries["payload.age"]
	digest := sha256.Sum256(payload)
	value := manifest{
		Protocol:         "eventctl/v3",
		Kind:             "feedback",
		Files:            []manifestFile{{Path: "payload.age", SHA256: stringHex(digest[:]), Size: int64(len(payload))}},
		SigningPublicKey: string(s.read(s.alice.SignaturePublic)),
	}
	value.Signature = s.signManifest(value)
	entries = cloneEntries(entries)
	entries["manifest.json"] = s.json(value)
	output := filepath.Join(s.work, name)
	s.writeTar(output, entries)
	return output
}

func (s *eventSuite) signManifest(value manifest) string {
	value.Signature = ""
	payload := append([]byte("eventctl/v3\x00feedback\x00"), s.json(value)...)
	signature := ed25519.Sign(s.ed25519Private(s.alice.SignaturePrivate), payload)
	return base64.RawStdEncoding.EncodeToString(signature)
}

func (s *eventSuite) hybridRecipient(file string) age.Recipient {
	value, err := age.ParseHybridRecipient(strings.TrimSpace(string(s.read(file))))
	s.Require().NoError(err)
	return value
}

func (s *eventSuite) ed25519Private(file string) ed25519.PrivateKey {
	block, rest := pem.Decode(s.read(file))
	s.Require().NotNil(block)
	s.Empty(bytes.TrimSpace(rest))
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	s.Require().NoError(err)
	key, ok := parsed.(ed25519.PrivateKey)
	s.Require().True(ok)
	return key
}

func (s *eventSuite) ecdsaPrivate(name string) string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.Require().NoError(err)
	data, err := x509.MarshalPKCS8PrivateKey(key)
	s.Require().NoError(err)
	return s.pem(name, "PRIVATE KEY", data)
}

func (s *eventSuite) ecdsaPublic(name string) string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.Require().NoError(err)
	data, err := x509.MarshalPKIXPublicKey(key.Public())
	s.Require().NoError(err)
	return s.pem(name, "PUBLIC KEY", data)
}

func (s *eventSuite) pem(name, kind string, data []byte) string {
	return s.write(name, string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data})))
}

func (s *eventSuite) json(value any) []byte {
	data, err := json.Marshal(value)
	s.Require().NoError(err)
	return data
}

func cloneEntries(entries map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(entries))
	for name, data := range entries {
		result[name] = append([]byte(nil), data...)
	}
	return result
}

func stringHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(value)*2)
	for index, byteValue := range value {
		encoded[index*2] = alphabet[byteValue>>4]
		encoded[index*2+1] = alphabet[byteValue&0x0f]
	}
	return string(encoded)
}

func sortedKeys(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
