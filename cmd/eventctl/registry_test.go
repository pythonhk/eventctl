package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/config"
	"github.com/pythonhk/eventctl/internal/identity"
)

func TestMaximumParticipantRegistryFitsActualLoader(t *testing.T) {
	t.Parallel()
	registry := identity.Registry{
		Schema:     identity.RegistrySchema,
		Identities: make([]identity.RegistryEntry, identity.MaxRegistryEntries),
	}
	const firstTwentyDigitActorID = uint64(10_000_000_000_000_000_000)
	for index := range registry.Identities {
		seed := make([]byte, 32)
		binary.BigEndian.PutUint64(seed[24:], uint64(index+1))
		pair, err := identity.FromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		registry.Identities[index] = identity.RegistryEntry{
			ActorID:  strconv.FormatUint(firstTwentyDigitActorID+uint64(index), 10),
			KeyEpoch: "99999999999999999999",
			Identity: pair.Public,
		}
	}
	raw, err := canonical.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > config.MaxBytes {
		t.Fatalf("worst-case %d-entry registry is %d bytes, loader cap is %d", identity.MaxRegistryEntries, len(raw), config.MaxBytes)
	}
	t.Logf("maximum %d-entry registry uses %d of %d loader bytes", identity.MaxRegistryEntries, len(raw), config.MaxBytes)
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadRegistry(path)
	if err != nil {
		t.Fatalf("loadRegistry rejected maximum-participant fixture (%d bytes): %v", len(raw), err)
	}
	if len(loaded.Identities) != identity.MaxRegistryEntries {
		t.Fatalf("loaded %d identities, want %d", len(loaded.Identities), identity.MaxRegistryEntries)
	}

	registry.Identities = append(registry.Identities, identity.RegistryEntry{
		ActorID:  "10000000000000001000",
		KeyEpoch: "99999999999999999999",
		Identity: registry.Identities[0].Identity,
	})
	if err := registry.Validate(); err == nil {
		t.Fatal("identity registry accepted 1,001 entries")
	}
}
