package team

import (
	"errors"
	"fmt"
	"sort"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
)

// TeamsView is the protected, materialized team view fetched from the same
// immutable event-state commit as current state metadata and the registry.
type TeamsView struct {
	Kind               string      `json:"kind"`
	Protocol           string      `json:"protocol"`
	ProtocolVersion    int         `json:"protocol_version"`
	EventID            string      `json:"event_id"`
	EventEpoch         string      `json:"event_epoch"`
	ConfigDigest       string      `json:"config_digest"`
	Sequence           uint64      `json:"sequence"`
	JournalEventDigest string      `json:"journal_event_digest"`
	Teams              []ViewEntry `json:"teams"`
}

type ViewEntry struct {
	TeamID              string        `json:"team_id"`
	ProposalDigest      string        `json:"proposal_digest"`
	ProposerActorID     string        `json:"proposer_actor_id"`
	MemberActorIDs      []string      `json:"member_actor_ids"`
	Consents            []ViewConsent `json:"consents"`
	Status              string        `json:"status"`
	ProposedAtSequence  uint64        `json:"proposed_at_sequence"`
	ActivatedAtSequence *uint64       `json:"activated_at_sequence"`
	ExpiresAt           string        `json:"expires_at"`
}

type ViewConsent struct {
	ActorID            string `json:"actor_id"`
	KeyID              string `json:"key_id"`
	RequestDigest      string `json:"request_digest"`
	RecordedAtSequence uint64 `json:"recorded_at_sequence"`
}

// ParseTeamsView strictly validates a bounded protected teams view.
func ParseTeamsView(raw []byte) (TeamsView, error) {
	if len(raw) > 16<<20 {
		return TeamsView{}, errors.New("teams view exceeds 16 MiB")
	}
	var view TeamsView
	if err := canonical.StrictUnmarshal(raw, &view); err != nil {
		return TeamsView{}, fmt.Errorf("decode protected teams view: %w", err)
	}
	if err := view.Validate(); err != nil {
		return TeamsView{}, err
	}
	return view, nil
}

func (view TeamsView) Validate() error {
	if view.Kind != "teams_view" || view.Protocol != envelope.Protocol || view.ProtocolVersion != envelope.ProtocolVersion || !envelope.IsEventID(view.EventID) || view.EventEpoch != "1" || !envelope.IsDigest(view.ConfigDigest) || view.Sequence < 1 || !envelope.IsDigest(view.JournalEventDigest) {
		return errors.New("protected teams view header is invalid")
	}
	if len(view.Teams) > 100000 {
		return errors.New("protected teams view has too many teams")
	}
	for index := range view.Teams {
		if err := view.Teams[index].validate(view.Sequence); err != nil {
			return fmt.Errorf("team %d: %w", index, err)
		}
		if index > 0 && view.Teams[index-1].TeamID >= view.Teams[index].TeamID {
			return errors.New("teams must be strictly sorted by team_id")
		}
	}
	return nil
}

func (entry ViewEntry) validate(viewSequence uint64) error {
	if !envelope.IsUUID(entry.TeamID) || !envelope.IsDigest(entry.ProposalDigest) || identity.ValidateDecimal(entry.ProposerActorID, "proposer_actor_id") != nil || entry.ProposedAtSequence < 1 {
		return errors.New("team identity/proposal fields are invalid")
	}
	if _, err := envelope.ParseTimestamp(entry.ExpiresAt); err != nil {
		return err
	}
	if len(entry.MemberActorIDs) < 1 || len(entry.MemberActorIDs) > 64 || !containsSortedUniqueActors(entry.MemberActorIDs, entry.ProposerActorID) {
		return errors.New("team member_actor_ids are invalid, unsorted, or omit the proposer")
	}
	if len(entry.Consents) > len(entry.MemberActorIDs) {
		return errors.New("team has more consents than members")
	}
	memberSet := make(map[string]struct{}, len(entry.MemberActorIDs))
	for _, actorID := range entry.MemberActorIDs {
		memberSet[actorID] = struct{}{}
	}
	consentingActors := make(map[string]struct{}, len(entry.Consents))
	for index, consent := range entry.Consents {
		if identity.ValidateDecimal(consent.ActorID, "consent actor_id") != nil || !envelope.IsDigest(consent.KeyID) || !envelope.IsDigest(consent.RequestDigest) || consent.RecordedAtSequence < entry.ProposedAtSequence || consent.RecordedAtSequence > viewSequence {
			return errors.New("team consent is invalid")
		}
		if index > 0 && identity.CompareDecimal(entry.Consents[index-1].ActorID, consent.ActorID) >= 0 {
			return errors.New("team consents must be strictly sorted by numeric actor_id")
		}
		if _, ok := memberSet[consent.ActorID]; !ok {
			return errors.New("team consent actor is not a member")
		}
		if _, duplicate := consentingActors[consent.ActorID]; duplicate {
			return errors.New("team has duplicate consent actors")
		}
		consentingActors[consent.ActorID] = struct{}{}
	}
	switch entry.Status {
	case "pending":
		if entry.ActivatedAtSequence != nil {
			return errors.New("pending team has activated_at_sequence")
		}
	case "active":
		if entry.ActivatedAtSequence == nil || *entry.ActivatedAtSequence < entry.ProposedAtSequence || *entry.ActivatedAtSequence > viewSequence || len(entry.Consents) != len(entry.MemberActorIDs) {
			return errors.New("active team lacks unanimous, ordered activation evidence")
		}
		for _, actorID := range entry.MemberActorIDs {
			if _, ok := consentingActors[actorID]; !ok {
				return errors.New("active team consent set does not equal member set")
			}
		}
	case "expired", "conflicted":
		// Terminal teams are never accepted for submission packing.
	default:
		return errors.New("team status is invalid")
	}
	return nil
}

func containsSortedUniqueActors(actorIDs []string, required string) bool {
	found := false
	for index, actorID := range actorIDs {
		if identity.ValidateDecimal(actorID, "member_actor_id") != nil {
			return false
		}
		if index > 0 && identity.CompareDecimal(actorIDs[index-1], actorID) >= 0 {
			return false
		}
		found = found || actorID == required
	}
	return found && sort.SliceIsSorted(actorIDs, func(left, right int) bool {
		return identity.CompareDecimal(actorIDs[left], actorIDs[right]) < 0
	})
}

// FindActiveTeam returns an active team by exact ID.
func (view TeamsView) FindActiveTeam(teamID string) (ViewEntry, bool) {
	index := sort.Search(len(view.Teams), func(index int) bool {
		return view.Teams[index].TeamID >= teamID
	})
	if index == len(view.Teams) || view.Teams[index].TeamID != teamID || view.Teams[index].Status != "active" {
		return ViewEntry{}, false
	}
	return view.Teams[index], true
}
