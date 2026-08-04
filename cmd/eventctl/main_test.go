package main

import "testing"

func TestCommandNameDoesNotTreatDirectCommandFlagAsSubcommand(t *testing.T) {
	t.Parallel()
	if got := commandName([]string{"doctor", "--out", "doctor.json"}); got != "doctor" {
		t.Fatalf("commandName() = %q, want doctor", got)
	}
	if got := commandName([]string{"submission", "verify", "--out", "verified.json"}); got != "submission.verify" {
		t.Fatalf("commandName() = %q, want submission.verify", got)
	}
}
