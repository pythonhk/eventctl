package statepointer

import (
	"strings"
	"testing"
)

func TestPointerV1SequenceBoundary(t *testing.T) {
	t.Parallel()
	digest := strings.Repeat("a", 64)
	if err := (Pointer{Sequence: MaxSequenceV1, JournalEventDigest: digest}).Validate(); err != nil {
		t.Fatalf("maximum v1 sequence rejected: %v", err)
	}
	for _, sequence := range []uint64{0, MaxSequenceV1 + 1} {
		if err := (Pointer{Sequence: sequence, JournalEventDigest: digest}).Validate(); err == nil {
			t.Fatalf("sequence %d accepted", sequence)
		}
	}
}
