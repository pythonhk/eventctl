package main

import (
	"fmt"
	"os"
	"time"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/config"
	"github.com/pythonhk/eventctl/internal/envelope"
)

func loadTrustedContext(configPath, authorityPath, statePath string, now time.Time) (config.Event, string, config.StateMeta, error) {
	configRaw, err := readBounded(configPath, config.MaxBytes)
	if err != nil {
		return config.Event{}, "", config.StateMeta{}, err
	}
	event, err := config.Parse(configRaw)
	if err != nil {
		return config.Event{}, "", config.StateMeta{}, err
	}
	authorityRaw, err := readBounded(authorityPath, config.MaxBytes)
	if err != nil {
		return config.Event{}, "", config.StateMeta{}, err
	}
	authority, err := config.ParseAuthority(authorityRaw)
	if err != nil {
		return config.Event{}, "", config.StateMeta{}, err
	}
	stateRaw, err := readBounded(statePath, config.MaxBytes)
	if err != nil {
		return config.Event{}, "", config.StateMeta{}, err
	}
	meta, err := config.ParseStateMeta(stateRaw)
	if err != nil {
		return config.Event{}, "", config.StateMeta{}, err
	}
	verification, err := config.VerifyAdoptedConfig(event, authority, meta, now)
	if err != nil {
		return config.Event{}, "", config.StateMeta{}, err
	}
	return event, verification.Digest, meta, nil
}

func loadAuthorityState(authorityPath, statePath string) (config.Genesis, config.StateMeta, error) {
	authorityRaw, err := readBounded(authorityPath, config.MaxBytes)
	if err != nil {
		return config.Genesis{}, config.StateMeta{}, err
	}
	authority, err := config.ParseAuthority(authorityRaw)
	if err != nil {
		return config.Genesis{}, config.StateMeta{}, err
	}
	stateRaw, err := readBounded(statePath, config.MaxBytes)
	if err != nil {
		return config.Genesis{}, config.StateMeta{}, err
	}
	meta, err := config.ParseStateMeta(stateRaw)
	if err != nil {
		return config.Genesis{}, config.StateMeta{}, err
	}
	if err := config.VerifyAuthorityState(authority, meta); err != nil {
		return config.Genesis{}, config.StateMeta{}, err
	}
	return authority, meta, nil
}

func loadArchivedTrustedContext(configPath, authorityPath, statePath string, sourceCreatedAt time.Time) (config.Event, string, config.StateMeta, error) {
	authority, meta, err := loadAuthorityState(authorityPath, statePath)
	if err != nil {
		return config.Event{}, "", config.StateMeta{}, err
	}
	event, digest, err := loadArchivedConfig(configPath, authority, meta, sourceCreatedAt)
	if err != nil {
		return config.Event{}, "", config.StateMeta{}, err
	}
	return event, digest, meta, nil
}

// loadArchivedConfig authenticates one complete historical config against an
// already loaded genesis/current-state pair. Callers that also consume a
// receipt use the immutable receipt source_created_at as sourceCreatedAt, then
// verify the receipt with the key from this authenticated config. The receipt's
// issued_at is commit time and may legitimately follow config expiry.
func loadArchivedConfig(configPath string, authority config.Genesis, meta config.StateMeta, sourceCreatedAt time.Time) (config.Event, string, error) {
	configRaw, err := readBounded(configPath, config.MaxBytes)
	if err != nil {
		return config.Event{}, "", err
	}
	event, err := config.Parse(configRaw)
	if err != nil {
		return config.Event{}, "", err
	}
	verification, err := config.VerifyArchivedConfig(event, authority, meta, sourceCreatedAt)
	if err != nil {
		return config.Event{}, "", err
	}
	return event, verification.Digest, nil
}

func requirePhase(meta config.StateMeta, phase string) error {
	return requireOneOfPhases(meta, phase)
}

func requireOneOfPhases(meta config.StateMeta, phases ...string) error {
	if !meta.Enabled {
		return fmt.Errorf("event is disabled: %v", meta.DisabledReason)
	}
	for _, phase := range phases {
		if meta.LifecyclePhase == phase {
			return nil
		}
	}
	return fmt.Errorf("event phase is %q, require one of %v", meta.LifecyclePhase, phases)
}

func parseTrustedSourceTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("--source-time is required")
	}
	parsed, err := envelope.ParseTimestamp(value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid --source-time: %w", err)
	}
	return parsed, nil
}

func writeCanonical(path string, value any, mode os.FileMode) error {
	raw, err := canonical.Marshal(value)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeExclusive(path, raw, mode)
}
