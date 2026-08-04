package team

import (
	"strings"
	"testing"

	"github.com/pythonhk/eventctl/internal/canonical"
)

func TestParseTeamsViewAndSelectActiveTeam(t *testing.T) {
	t.Parallel()
	activation := uint64(4)
	view := TeamsView{
		Kind: "teams_view", Protocol: "pythonhk.github-native-event", ProtocolVersion: 1,
		EventID: "summer-data-2026", EventEpoch: "1", ConfigDigest: strings.Repeat("1", 64),
		Sequence: 4, JournalEventDigest: strings.Repeat("2", 64),
		Teams: []ViewEntry{{
			TeamID: "123e4567-e89b-42d3-a456-426614174000", ProposalDigest: strings.Repeat("3", 64),
			ProposerActorID: "2", MemberActorIDs: []string{"2", "10"}, Status: "active",
			ProposedAtSequence: 2, ActivatedAtSequence: &activation, ExpiresAt: "2020-01-01T00:00:00Z",
			Consents: []ViewConsent{
				{ActorID: "2", KeyID: strings.Repeat("6", 64), RequestDigest: strings.Repeat("7", 64), RecordedAtSequence: 3},
				{ActorID: "10", KeyID: strings.Repeat("4", 64), RequestDigest: strings.Repeat("5", 64), RecordedAtSequence: 4},
			},
		}},
	}
	raw, err := canonical.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTeamsView(raw)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := parsed.FindActiveTeam(view.Teams[0].TeamID)
	if !ok || entry.ProposalDigest != view.Teams[0].ProposalDigest {
		t.Fatalf("active team selection = %#v, %v", entry, ok)
	}
	view.Teams[0].Consents[0], view.Teams[0].Consents[1] = view.Teams[0].Consents[1], view.Teams[0].Consents[0]
	if err := view.Validate(); err == nil {
		t.Fatal("accepted non-deterministically ordered team consents")
	}
}

func TestTeamsViewRejectsHeaderAndNonUnanimousActiveTeam(t *testing.T) {
	t.Parallel()
	activation := uint64(4)
	view := TeamsView{
		Kind: "teams_view", Protocol: "pythonhk.github-native-event", ProtocolVersion: 1,
		EventID: "summer-data-2026", EventEpoch: "1", ConfigDigest: strings.Repeat("1", 64),
		Sequence: 4, JournalEventDigest: strings.Repeat("2", 64),
		Teams: []ViewEntry{{
			TeamID: "123e4567-e89b-42d3-a456-426614174000", ProposalDigest: strings.Repeat("3", 64),
			ProposerActorID: "2", MemberActorIDs: []string{"2", "10"}, Status: "active",
			ProposedAtSequence: 2, ActivatedAtSequence: &activation, ExpiresAt: "2026-08-05T00:00:00Z",
			Consents: []ViewConsent{{ActorID: "2", KeyID: strings.Repeat("6", 64), RequestDigest: strings.Repeat("7", 64), RecordedAtSequence: 3}},
		}},
	}
	if err := view.Validate(); err == nil {
		t.Fatal("accepted active team without unanimous consent")
	}
	view.Teams = nil
	view.EventEpoch = "2"
	if err := view.Validate(); err == nil {
		t.Fatal("accepted unsupported protected-state event epoch")
	}
	view.EventEpoch = "1"
	view.ConfigDigest = strings.Repeat("A", 64)
	if err := view.Validate(); err == nil {
		t.Fatal("accepted malformed header digest")
	}
}
