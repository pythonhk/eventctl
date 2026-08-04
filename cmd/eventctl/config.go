package main

import (
	"io"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/config"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
)

type normalizedConfig struct {
	Status string       `json:"status"`
	Kind   string       `json:"kind"`
	Digest string       `json:"digest"`
	Event  config.Event `json:"event"`
}

type configSummary struct {
	Path           string `json:"path"`
	EventID        string `json:"event_id"`
	EventEpoch     string `json:"event_epoch"`
	RepositoryID   string `json:"repository_id"`
	ConfigEpoch    uint64 `json:"config_epoch"`
	Digest         string `json:"digest"`
	SignatureCount int    `json:"signature_count"`
}

func runConfig(args []string, stderr io.Writer) (any, error) {
	if len(args) == 0 {
		return nil, usageError("usage: eventctl config validate|digest|sign|verify|delegation-sign|delegation-verify")
	}
	switch args[0] {
	case "validate", "digest":
		return configNormalize(args[0], args[1:])
	case "sign":
		return configSign(args[1:], stderr)
	case "verify":
		return configVerify(args[1:])
	case "delegation-sign":
		return configDelegationSign(args[1:], stderr)
	case "delegation-verify":
		return configDelegationVerify(args[1:])
	default:
		return nil, usageError("usage: eventctl config validate|digest|sign|verify|delegation-sign|delegation-verify")
	}
}

func configNormalize(command string, args []string) (any, error) {
	flags := newFlagSet("config " + command)
	path := flags.String("config", "", "event YAML")
	out := flags.String("out", "", "normalized JSON output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *path == "" || *out == "" {
		return nil, usageError("usage: eventctl config " + command + " --config PATH --out PATH")
	}
	raw, err := readBounded(*path, config.MaxBytes)
	if err != nil {
		return nil, ioError("read config", err)
	}
	event, err := config.Parse(raw)
	if err != nil {
		return nil, invalidError("validate config", err)
	}
	digest, err := config.Digest(event)
	if err != nil {
		return nil, err
	}
	normalized := normalizedConfig{"valid", config.Kind, digest, event}
	if err := writeCanonical(*out, normalized, 0o644); err != nil {
		return nil, ioError("write normalized config", err)
	}
	return configSummary{*out, event.EventID, event.EventEpoch, event.BaseRepository.ID, event.ConfigEpoch, digest, len(event.Signatures)}, nil
}

func configSign(args []string, stderr io.Writer) (any, error) {
	flags := newFlagSet("config sign")
	path := flags.String("config", "", "event YAML")
	keyPath := flags.String("key", "", "encrypted signing key")
	out := flags.String("out", "", "signed YAML output")
	passFile := flags.String("passphrase-file", "", "passphrase file or -")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *path == "" || *keyPath == "" || *out == "" {
		return nil, usageError("usage: eventctl config sign --config PATH --key PATH --out PATH [--passphrase-file PATH|-]")
	}
	raw, err := readBounded(*path, config.MaxBytes)
	if err != nil {
		return nil, ioError("read config", err)
	}
	event, err := config.ParseUnsigned(raw)
	if err != nil {
		return nil, invalidError("validate unsigned config", err)
	}
	pair, err := loadPrivate(*keyPath, *passFile, stderr)
	if err != nil {
		return nil, verificationError("decrypt signing key", err)
	}
	event, err = config.Sign(event, pair.Private)
	if err != nil {
		return nil, verificationError("sign config", err)
	}
	encoded, err := config.MarshalYAML(event)
	if err != nil {
		return nil, err
	}
	if err := writeExclusive(*out, encoded, 0o644); err != nil {
		return nil, ioError("write signed config", err)
	}
	digest, err := config.Digest(event)
	if err != nil {
		return nil, err
	}
	return struct {
		Path           string `json:"path"`
		Digest         string `json:"digest"`
		KeyID          string `json:"key_id"`
		SignatureCount int    `json:"signature_count"`
	}{*out, digest, pair.Public.KeyID, len(event.Signatures)}, nil
}

func configVerify(args []string) (any, error) {
	flags := newFlagSet("config verify")
	configPath := flags.String("config", "", "event YAML")
	authorityPath := flags.String("authority", "", "protected genesis JSON")
	statePath := flags.String("state-meta", "", "protected current state metadata JSON")
	delegationPath := flags.String("delegation", "", "signed bootstrap config delegation")
	var rootKeyPaths stringList
	flags.Var(&rootKeyPaths, "root-key", "explicit organizer root public key (repeatable)")
	expectEventID := flags.String("expect-event-id", "", "expected event ID for bootstrap")
	expectRepositoryID := flags.String("expect-repository-id", "", "trusted numeric repository ID for bootstrap")
	sourceTimeText := flags.String("source-time", "", "trusted source or bootstrap verification time")
	out := flags.String("out", "", "normalized JSON output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *sourceTimeText == "" || *out == "" {
		return nil, usageError("usage: eventctl config verify --config PATH --source-time RFC3339 (--authority PATH --state-meta PATH | --delegation PATH --root-key PATH --expect-event-id ID --expect-repository-id ID) --out PATH")
	}
	runtimeMode := *authorityPath != "" || *statePath != ""
	bootstrapMode := *delegationPath != "" || len(rootKeyPaths) != 0 || *expectEventID != "" || *expectRepositoryID != ""
	if runtimeMode == bootstrapMode {
		return nil, usageError("config verify requires exactly one runtime or bootstrap trust mode")
	}
	sourceTime, err := parseTrustedSourceTime(*sourceTimeText)
	if err != nil {
		return nil, invalidError("validate trusted source time", err)
	}
	var event config.Event
	var digest string
	if runtimeMode {
		if *authorityPath == "" || *statePath == "" {
			return nil, usageError("runtime config verify requires --authority, --state-meta, and --source-time")
		}
		event, digest, _, err = loadTrustedContext(*configPath, *authorityPath, *statePath, sourceTime)
		if err != nil {
			return nil, verificationError("verify adopted config", err)
		}
	} else {
		if *delegationPath == "" || len(rootKeyPaths) == 0 || *expectEventID == "" || *expectRepositoryID == "" {
			return nil, usageError("bootstrap config verify requires --delegation, --root-key, --expect-event-id, --expect-repository-id, and --source-time")
		}
		configRaw, err := readBounded(*configPath, config.MaxBytes)
		if err != nil {
			return nil, ioError("read config", err)
		}
		event, err = config.Parse(configRaw)
		if err != nil {
			return nil, invalidError("parse config", err)
		}
		delegation, err := loadDelegation(*delegationPath)
		if err != nil {
			return nil, invalidError("load config delegation", err)
		}
		roots, err := loadPublicKeys(rootKeyPaths)
		if err != nil {
			return nil, invalidError("load organizer root keys", err)
		}
		verification, _, err := config.VerifyWithDelegation(event, delegation, roots, *expectEventID, *expectRepositoryID, sourceTime)
		if err != nil {
			return nil, verificationError("verify config through organizer root delegation", err)
		}
		digest = verification.Digest
	}
	normalized := normalizedConfig{"valid", config.Kind, digest, event}
	if err := writeCanonical(*out, normalized, 0o644); err != nil {
		return nil, ioError("write verified config", err)
	}
	return configSummary{*out, event.EventID, event.EventEpoch, event.BaseRepository.ID, event.ConfigEpoch, digest, len(event.Signatures)}, nil
}

type normalizedDelegation struct {
	Status     string            `json:"status"`
	Kind       string            `json:"kind"`
	Digest     string            `json:"digest"`
	Authority  config.Authority  `json:"authority"`
	RootKeyIDs []string          `json:"root_key_ids"`
	Delegation config.Delegation `json:"delegation"`
}

func configDelegationSign(args []string, stderr io.Writer) (any, error) {
	flags := newFlagSet("config delegation-sign")
	delegationPath := flags.String("delegation", "", "unsigned delegation JSON")
	keyPath := flags.String("key", "", "encrypted organizer root signing key")
	passFile := flags.String("passphrase-file", "", "passphrase file or -")
	out := flags.String("out", "", "signed delegation JSON output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *delegationPath == "" || *keyPath == "" || *out == "" {
		return nil, usageError("usage: eventctl config delegation-sign --delegation PATH --key PATH --out PATH [--passphrase-file PATH|-]")
	}
	raw, err := readBounded(*delegationPath, config.MaxBytes)
	if err != nil {
		return nil, ioError("read unsigned delegation", err)
	}
	delegation, err := config.ParseUnsignedDelegation(raw)
	if err != nil {
		return nil, invalidError("validate unsigned delegation", err)
	}
	pair, err := loadPrivate(*keyPath, *passFile, stderr)
	if err != nil {
		return nil, verificationError("decrypt organizer root key", err)
	}
	delegation, err = config.SignDelegation(delegation, pair.Private)
	if err != nil {
		return nil, verificationError("sign config delegation", err)
	}
	if err := config.VerifyDelegationRootSignature(delegation, pair.Public); err != nil {
		return nil, verificationError("self-verify config delegation", err)
	}
	digest, err := envelope.DocumentDigest(delegation)
	if err != nil {
		return nil, err
	}
	encoded, err := canonical.Marshal(delegation)
	if err != nil {
		return nil, err
	}
	if err := writeExclusive(*out, append(encoded, '\n'), 0o644); err != nil {
		return nil, ioError("write signed config delegation", err)
	}
	return struct {
		Path      string `json:"path"`
		Digest    string `json:"digest"`
		RootKeyID string `json:"root_key_id"`
	}{*out, digest, pair.Public.KeyID}, nil
}

func configDelegationVerify(args []string) (any, error) {
	flags := newFlagSet("config delegation-verify")
	delegationPath := flags.String("delegation", "", "signed delegation JSON")
	var rootKeyPaths stringList
	flags.Var(&rootKeyPaths, "root-key", "explicit organizer root public key (repeatable)")
	expectEventID := flags.String("expect-event-id", "", "expected event ID")
	expectRepositoryID := flags.String("expect-repository-id", "", "trusted numeric repository ID")
	sourceTimeText := flags.String("source-time", "", "trusted verification time")
	out := flags.String("out", "", "normalized delegation output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *delegationPath == "" || len(rootKeyPaths) == 0 || *expectEventID == "" || *expectRepositoryID == "" || *sourceTimeText == "" || *out == "" {
		return nil, usageError("usage: eventctl config delegation-verify --delegation PATH --root-key PATH [--root-key PATH ...] --expect-event-id ID --expect-repository-id ID --source-time RFC3339 --out PATH")
	}
	sourceTime, err := parseTrustedSourceTime(*sourceTimeText)
	if err != nil {
		return nil, invalidError("validate delegation verification time", err)
	}
	delegation, err := loadDelegation(*delegationPath)
	if err != nil {
		return nil, invalidError("load config delegation", err)
	}
	roots, err := loadPublicKeys(rootKeyPaths)
	if err != nil {
		return nil, invalidError("load organizer root keys", err)
	}
	verification, err := config.VerifyDelegation(delegation, roots, *expectEventID, *expectRepositoryID, sourceTime)
	if err != nil {
		return nil, verificationError("verify config delegation", err)
	}
	normalized := normalizedDelegation{"valid", config.DelegationKind, verification.Digest, verification.Authority, verification.RootKeyIDs, verification.Delegation}
	if err := writeCanonical(*out, normalized, 0o644); err != nil {
		return nil, ioError("write verified config delegation", err)
	}
	return struct {
		Path      string `json:"path"`
		Digest    string `json:"digest"`
		Threshold int    `json:"threshold"`
		KeyCount  int    `json:"key_count"`
	}{*out, verification.Digest, verification.Authority.Threshold, len(verification.Authority.Keys)}, nil
}

func loadDelegation(path string) (config.Delegation, error) {
	raw, err := readBounded(path, config.MaxBytes)
	if err != nil {
		return config.Delegation{}, err
	}
	return config.ParseDelegation(raw)
}

func loadPublicKeys(paths []string) ([]identity.Public, error) {
	keys := make([]identity.Public, 0, len(paths))
	for _, path := range paths {
		raw, err := readBounded(path, 64*1024)
		if err != nil {
			return nil, err
		}
		key, err := identity.ParsePublic(raw)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}
