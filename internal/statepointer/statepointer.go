// Package statepointer defines the small, hash-linked protected-state pointer
// shared by receipts and isolated-scoring artifacts.
package statepointer

import (
	"errors"

	"github.com/pythonhk/eventctl/internal/envelope"
)

const MaxSequenceV1 uint64 = 4_096

// Pointer names one committed protected-state journal event.
type Pointer struct {
	Sequence           uint64 `json:"sequence"`
	JournalEventDigest string `json:"journal_event_digest"`
}

// Validate rejects the zero/genesis sentinel and malformed journal digests.
func (pointer Pointer) Validate() error {
	if pointer.Sequence < 1 || pointer.Sequence > MaxSequenceV1 {
		return errors.New("state pointer sequence is outside the v1 lifetime bound")
	}
	if !envelope.IsDigest(pointer.JournalEventDigest) {
		return errors.New("state pointer journal_event_digest is invalid")
	}
	return nil
}

// Equal reports exact state-pointer equality.
func (pointer Pointer) Equal(other Pointer) bool {
	return pointer.Sequence == other.Sequence && pointer.JournalEventDigest == other.JournalEventDigest
}

// IsAtOrBefore verifies that pointer does not claim a future state. When both
// pointers name the same sequence, the journal digest must also be identical.
func (pointer Pointer) IsAtOrBefore(current Pointer) error {
	if err := pointer.Validate(); err != nil {
		return err
	}
	if err := current.Validate(); err != nil {
		return err
	}
	if pointer.Sequence > current.Sequence {
		return errors.New("state pointer is ahead of trusted current state")
	}
	if pointer.Sequence == current.Sequence && pointer.JournalEventDigest != current.JournalEventDigest {
		return errors.New("state pointer digest disagrees with trusted current state")
	}
	return nil
}
