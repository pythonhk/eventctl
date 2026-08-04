package main

import (
	"testing"

	"github.com/pythonhk/eventctl/internal/config"
)

func TestScoringControlPhasesAndEmergencyGate(t *testing.T) {
	t.Parallel()
	meta := config.StateMeta{Enabled: true, LifecyclePhase: "submissions_open"}
	if err := requireOneOfPhases(meta, "submissions_open", "frozen"); err != nil {
		t.Fatalf("submissions_open rejected: %v", err)
	}
	meta.LifecyclePhase = "frozen"
	if err := requireOneOfPhases(meta, "submissions_open", "frozen"); err != nil {
		t.Fatalf("frozen drain rejected: %v", err)
	}
	meta.LifecyclePhase = "closed"
	if err := requireOneOfPhases(meta, "submissions_open", "frozen"); err == nil {
		t.Fatal("closed phase allowed scoring")
	}
	meta.LifecyclePhase = "frozen"
	meta.Enabled = false
	if err := requireOneOfPhases(meta, "submissions_open", "frozen"); err == nil {
		t.Fatal("emergency-disabled event allowed scoring")
	}
}
