package config

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
	"github.com/pythonhk/eventctl/internal/scorer"
	"github.com/pythonhk/eventctl/internal/team"
)

func configPair(t *testing.T) identity.KeyPair {
	t.Helper()
	pair, err := identity.GenerateFrom(bytes.NewReader(bytes.Repeat([]byte{8}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func validEvent(t *testing.T) Event {
	t.Helper()
	pair := configPair(t)
	receiptPair, err := identity.GenerateFrom(bytes.NewReader(bytes.Repeat([]byte{9}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	hybridIdentity, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	externalURL := "https://judge.example.invalid/v1/score"
	return Event{
		Kind: Kind, Protocol: envelope.Protocol, ProtocolVersion: 1,
		EventID: "example-event-2026", EventEpoch: "1",
		BaseRepository: envelope.Repository{ID: "123", Owner: "pythonhk", Name: "example-event-2026"},
		ConfigEpoch:    1, DelegationEpoch: 1, DelegationDigest: strings.Repeat("1", 64),
		IssuedAt: "2026-08-04T00:00:00Z", ExpiresAt: "2027-08-04T00:00:00Z",
		InitialState: InitialState{Phase: "draft", Enabled: false, DisabledReason: "template_not_bootstrapped"},
		Registration: Registration{MaximumParticipants: 200, RequestTTLSeconds: 1800, TermsDigest: strings.Repeat("2", 64), KeyAlgorithm: "Ed25519", KeyRotationPolicy: "unsupported"},
		Teams:        Teams{MinimumSize: 2, MaximumSize: 5, MaximumProposalsPerParticipant: 1, ProposalTTLSeconds: 604800, MembershipLockPhase: "submissions_open"},
		Submissions: Submissions{
			BaseRef:                "main",
			MaximumAttemptsPerTeam: 10, MaximumTotalAttempts: 100,
			MaximumCiphertextBytes: 47_000_000,
			MaximumPlaintextBytes:  42_000_000, MaximumFileBytes: 20_000_000,
			MaximumPlaintextFiles: 4096, EnvelopeTTLSeconds: 1800,
			DeliveryMode: envelope.SubmissionDeliveryMode, FailedConsumeQuota: true,
			AllowedExtensions: []string{".csv"},
			Encryption:        Encryption{Algorithm: "age-hybrid-mlkem768-x25519", RecipientEpoch: "1", Recipients: []Recipient{{RecipientID: "primary_judge", PublicKey: hybridIdentity.Recipient().String()}}},
		},
		Scoring:    Scoring{Mode: "external_judge", ScorerID: "example_scorer", ScorerVersion: "v1.0.0", PolicyDigest: strings.Repeat("3", 64), MaximumResultBytes: 65536, ResultKey: pair.Public, ExternalJudgeURL: &externalURL},
		State:      State{Branch: "event-state", Public: true, WriterAppSlug: "pythonhk-event-state-writer", WriterConcurrencyGroup: "event-state-writer", JournalFormat: "hash-linked-json-v1"},
		Receipts:   Receipts{SigningKey: receiptPair.Public},
		Signatures: []identity.Signature{{Algorithm: "Ed25519", KeyID: pair.Public.KeyID, Value: strings.Repeat("A", 86)}},
	}
}

func TestDerivedCapacityExactBoundaryAndOverflow(t *testing.T) {
	t.Parallel()
	event := validEvent(t)
	event.Registration.MaximumParticipants = 10
	event.Teams.MinimumSize = 1
	event.Teams.MaximumProposalsPerParticipant = 1
	event.Teams.MaximumSize = 1
	event.Submissions.MaximumTotalAttempts = 999

	capacity, err := DeriveCapacity(event.Registration, event.Teams, event.Submissions)
	if err != nil {
		t.Fatalf("exact v1 capacity boundary rejected: %v", err)
	}
	if capacity.BusinessRecords != MaxDerivedBusinessRecordsV1 || capacity.StateRecords != 4_095 {
		t.Fatalf("derived capacity = %#v, want business=%d state=4095", capacity, MaxDerivedBusinessRecordsV1)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("exact v1 capacity config rejected: %v", err)
	}

	overLimit := event
	overLimit.Registration.MaximumParticipants = 11
	overLimit.Submissions.MaximumTotalAttempts = 998
	if _, err := DeriveCapacity(overLimit.Registration, overLimit.Teams, overLimit.Submissions); err == nil || !strings.Contains(err.Error(), "2029") {
		t.Fatalf("one-over derived capacity did not fail at 2029 records: %v", err)
	}
	if err := overLimit.Validate(); err == nil {
		t.Fatal("validated a config above the v1 derived capacity boundary")
	}

	if _, err := DeriveCapacity(
		Registration{MaximumParticipants: ^uint64(0)},
		Teams{MaximumProposalsPerParticipant: 2, MaximumSize: 2},
		Submissions{MaximumTotalAttempts: 1},
	); err == nil {
		t.Fatal("derived capacity arithmetic wrapped on multiplication")
	}
	if _, err := checkedSum(^uint64(0), 1); err == nil {
		t.Fatal("derived capacity arithmetic wrapped on addition")
	}
}

func TestTeamSizesCannotExceedParticipantCapacity(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*Event){
		"minimum": func(event *Event) {
			event.Registration.MaximumParticipants = 1
			event.Teams.MinimumSize = 2
		},
		"maximum": func(event *Event) {
			event.Registration.MaximumParticipants = 4
			event.Teams.MaximumSize = 5
		},
	} {
		t.Run(name, func(t *testing.T) {
			event := validEvent(t)
			mutate(&event)
			if err := event.Validate(); err == nil {
				t.Fatalf("accepted team %s_size above maximum_participants", name)
			}
		})
	}
}

func TestProposalAndSubmissionCapacityFieldBounds(t *testing.T) {
	t.Parallel()
	teamPolicy := validEvent(t).Teams
	for _, value := range []uint64{1, MaxTeamProposalsPerParticipantV1} {
		teamPolicy.MaximumProposalsPerParticipant = value
		if err := validateTeams(teamPolicy); err != nil {
			t.Fatalf("maximum_proposals_per_participant=%d rejected: %v", value, err)
		}
	}
	for _, value := range []uint64{0, MaxTeamProposalsPerParticipantV1 + 1} {
		teamPolicy.MaximumProposalsPerParticipant = value
		if err := validateTeams(teamPolicy); err == nil {
			t.Fatalf("maximum_proposals_per_participant=%d accepted", value)
		}
	}

	submissionPolicy := validEvent(t).Submissions
	for _, value := range []uint64{submissionPolicy.MaximumAttemptsPerTeam, MaxTotalSubmissionAttemptsV1} {
		submissionPolicy.MaximumTotalAttempts = value
		if err := validateSubmissions(submissionPolicy); err != nil {
			t.Fatalf("maximum_total_attempts=%d rejected: %v", value, err)
		}
	}
	for _, value := range []uint64{0, MaxTotalSubmissionAttemptsV1 + 1} {
		submissionPolicy.MaximumTotalAttempts = value
		if err := validateSubmissions(submissionPolicy); err == nil {
			t.Fatalf("maximum_total_attempts=%d accepted", value)
		}
	}
	submissionPolicy.MaximumTotalAttempts = submissionPolicy.MaximumAttemptsPerTeam - 1
	if err := validateSubmissions(submissionPolicy); err == nil {
		t.Fatal("accepted maximum_attempts_per_team above maximum_total_attempts")
	}
}

func TestTeamProposalTTLBounds(t *testing.T) {
	t.Parallel()
	teamPolicy := validEvent(t).Teams
	for _, value := range []uint64{team.MinProposalTTLSeconds, 604_800, team.MaxProposalTTLSeconds} {
		teamPolicy.ProposalTTLSeconds = value
		if err := validateTeams(teamPolicy); err != nil {
			t.Fatalf("proposal_ttl_seconds=%d rejected: %v", value, err)
		}
	}
	for _, value := range []uint64{team.MinProposalTTLSeconds - 1, team.MaxProposalTTLSeconds + 1} {
		teamPolicy.ProposalTTLSeconds = value
		if err := validateTeams(teamPolicy); err == nil {
			t.Fatalf("proposal_ttl_seconds=%d accepted", value)
		}
	}
}

func TestSubmissionGitTransportLimits(t *testing.T) {
	t.Parallel()
	valid := validEvent(t).Submissions
	valid.MaximumCiphertextBytes = 47_000_000
	valid.MaximumPlaintextBytes = 42_000_000
	valid.MaximumFileBytes = 42_000_000
	if err := validateSubmissions(valid); err != nil {
		t.Fatalf("boundary-valid submission limits: %v", err)
	}
	for name, mutate := range map[string]func(*Submissions){
		"ciphertext": func(value *Submissions) { value.MaximumCiphertextBytes = 47_000_001 },
		"plaintext":  func(value *Submissions) { value.MaximumPlaintextBytes = 42_000_001 },
		"file":       func(value *Submissions) { value.MaximumFileBytes = 42_000_001 },
		"file count": func(value *Submissions) { value.MaximumPlaintextFiles = 4_097 },
		"overhead": func(value *Submissions) {
			value.MaximumCiphertextBytes = 46_194_303
			value.MaximumPlaintextBytes = 42_000_000
			value.MaximumFileBytes = 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := validateSubmissions(candidate); err == nil {
				t.Fatal("accepted limits that can exceed the Git transport budget")
			}
		})
	}
}

func TestRegistrationParticipantCapacity(t *testing.T) {
	t.Parallel()
	valid := validEvent(t).Registration
	valid.MaximumParticipants = identity.MaxRegistryEntries
	if err := validateRegistration(valid); err != nil {
		t.Fatalf("1,000-participant v1 boundary rejected: %v", err)
	}
	valid.MaximumParticipants++
	if err := validateRegistration(valid); err == nil {
		t.Fatal("1,001-participant v1 config accepted")
	}
}

func TestScoringTransportLimits(t *testing.T) {
	t.Parallel()
	valid := validEvent(t).Scoring
	valid.MaximumResultBytes = scorer.MaxResultBytes
	valid.ScorerVersion = "v" + strings.Repeat("1", 59) + ".0.0"
	if got := len(valid.ScorerVersion); got != 64 {
		t.Fatalf("boundary scorer version length = %d, want 64", got)
	}
	if err := validateScoring(valid); err != nil {
		t.Fatalf("boundary-valid scoring limits: %v", err)
	}

	tooLargeResult := valid
	tooLargeResult.MaximumResultBytes = scorer.MaxResultBytes + 1
	if err := validateScoring(tooLargeResult); err == nil {
		t.Fatalf("accepted maximum_result_bytes %d", tooLargeResult.MaximumResultBytes)
	}

	tooLongVersion := valid
	tooLongVersion.ScorerVersion = "v" + strings.Repeat("1", 60) + ".0.0"
	if got := len(tooLongVersion.ScorerVersion); got != 65 {
		t.Fatalf("over-limit scorer version length = %d, want 65", got)
	}
	if err := validateScoring(tooLongVersion); err == nil {
		t.Fatal("accepted 65-byte scorer_version")
	}
}

func TestConfigPublicKeysMustBindKeyIDToPublicKey(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*Event){
		"scoring result":  func(event *Event) { event.Scoring.ResultKey.KeyID = strings.Repeat("f", 64) },
		"receipt signing": func(event *Event) { event.Receipts.SigningKey.KeyID = strings.Repeat("e", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			event := validEvent(t)
			mutate(&event)
			if err := event.Validate(); err == nil {
				t.Fatalf("accepted %s key_id that does not derive from public_key", name)
			}
		})
	}
}

func TestV1RejectsConfigAndEventEpochChanges(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*Event){
		"event epoch":  func(event *Event) { event.EventEpoch = "2" },
		"config epoch": func(event *Event) { event.ConfigEpoch = 2 },
		"previous digest": func(event *Event) {
			digest := strings.Repeat("f", 64)
			event.PreviousConfigDigest = &digest
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validEvent(t)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("accepted a v1 config authority rotation field")
			}
		})
	}
}

func TestExternalJudgeURLRejectsAmbiguousOrSecretBearingForms(t *testing.T) {
	t.Parallel()
	for name, value := range map[string]string{
		"credentials": "https://user:secret@judge.example.invalid/v1/score",
		"fragment":    "https://judge.example.invalid/v1/score#token",
		"query":       "https://judge.example.invalid/v1/score?token=secret",
		"opaque":      "https:judge.example.invalid/v1/score",
		"empty host":  "https:///v1/score",
	} {
		t.Run(name, func(t *testing.T) {
			event := validEvent(t)
			event.Scoring.ExternalJudgeURL = &value
			if err := event.Validate(); err == nil {
				t.Fatalf("accepted unsafe external_judge_url form %q", value)
			}
		})
	}
}

func TestExternalJudgeURLLengthBoundary(t *testing.T) {
	t.Parallel()
	const prefix = "https://judge.example.invalid/"
	boundary := prefix + strings.Repeat("a", MaxExternalJudgeURLBytes-len(prefix))
	if got := len(boundary); got != MaxExternalJudgeURLBytes {
		t.Fatalf("boundary URL length = %d, want %d", got, MaxExternalJudgeURLBytes)
	}
	event := validEvent(t)
	event.Scoring.ExternalJudgeURL = &boundary
	if err := event.Validate(); err != nil {
		t.Fatalf("%d-byte external_judge_url rejected: %v", MaxExternalJudgeURLBytes, err)
	}

	overLimit := boundary + "a"
	event.Scoring.ExternalJudgeURL = &overLimit
	if err := event.Validate(); err == nil {
		t.Fatalf("%d-byte external_judge_url accepted", MaxExternalJudgeURLBytes+1)
	}
}

func TestExternalJudgeURLRequiresPrintableASCIIRFC3986(t *testing.T) {
	t.Parallel()
	for name, value := range map[string]string{
		"unicode path":       "https://judge.example.invalid/café",
		"unicode host":       "https://jüge.example.invalid/score",
		"space":              "https://judge.example.invalid/not canonical",
		"non RFC3986 braces": "https://judge.example.invalid/{score}",
	} {
		t.Run(name, func(t *testing.T) {
			event := validEvent(t)
			event.Scoring.ExternalJudgeURL = &value
			if err := event.Validate(); err == nil {
				t.Fatalf("accepted non-canonical external_judge_url %q", value)
			}
		})
	}

	encodedUnicode := "https://judge.example.invalid/caf%C3%A9"
	event := validEvent(t)
	event.Scoring.ExternalJudgeURL = &encodedUnicode
	if err := event.Validate(); err != nil {
		t.Fatalf("rejected RFC3986 percent-encoded Unicode URL: %v", err)
	}
}

func TestYAMLStrictSignVerifyAndDigest(t *testing.T) {
	t.Parallel()
	event := validEvent(t)
	pair := configPair(t)
	signed, err := Sign(event, pair.Private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalYAML(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("key_id:")) || !bytes.Contains(raw, []byte("public_key:")) || bytes.Contains(raw, []byte("keyid:")) || bytes.Contains(raw, []byte("publickey:")) {
		t.Fatalf("protocol public keys/signatures used non-schema YAML field names:\n%s", raw)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := Verify(parsed, []identity.Public{pair.Public}, 1, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !envelope.IsDigest(verification.Digest) || len(verification.ValidKeyIDs) != 1 {
		t.Fatalf("verification %#v", verification)
	}
}

func TestYAMLRejectsUnknownDuplicateAliasAndMultipleDocs(t *testing.T) {
	t.Parallel()
	raw, err := MarshalYAML(validEvent(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{
		append(append([]byte(nil), raw...), []byte("unknown: true\n")...),
		[]byte("kind: event_config\nkind: again\n"),
		[]byte("kind: &x event_config\nprotocol: *x\n"),
		append(append([]byte(nil), raw...), []byte("---\nkind: second\n")...),
	}
	for _, input := range cases {
		if _, err := Parse(input); err == nil {
			t.Fatalf("Parse accepted invalid YAML: %s", input)
		}
	}
}

func TestYAMLRequiresClosedCapacityFields(t *testing.T) {
	t.Parallel()
	raw, err := MarshalYAML(validEvent(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"maximum_proposals_per_participant", "maximum_total_attempts"} {
		t.Run("missing "+field, func(t *testing.T) {
			without := removeYAMLFieldLine(t, raw, field)
			if _, err := Parse(without); err == nil {
				t.Fatalf("Parse accepted YAML missing required %s", field)
			}
		})
		t.Run("unknown "+field, func(t *testing.T) {
			unknown := bytes.Replace(raw, []byte(field+":"), []byte(field+"_typo:"), 1)
			if bytes.Equal(unknown, raw) {
				t.Fatalf("fixture did not contain %s", field)
			}
			if _, err := Parse(unknown); err == nil {
				t.Fatalf("Parse accepted unknown field derived from %s", field)
			}
		})
	}
}

func removeYAMLFieldLine(t *testing.T, raw []byte, field string) []byte {
	t.Helper()
	lines := bytes.Split(raw, []byte{'\n'})
	for index, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(string(line)), field+":") {
			return bytes.Join(append(lines[:index:index], lines[index+1:]...), []byte{'\n'})
		}
	}
	t.Fatalf("fixture did not contain %s", field)
	return nil
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("kind: event_config\n"))
	f.Add([]byte("a: &x [1]\nb: *x\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxBytes+1 {
			return
		}
		_, _ = Parse(raw)
	})
}
