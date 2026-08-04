package main

import (
	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/envelope"
)

func runReplay(args []string) (any, error) {
	if len(args) == 0 || args[0] != "classify" {
		return nil, usageError("usage: eventctl replay classify --incoming PATH [--existing PATH] --out PATH")
	}
	flags := newFlagSet("replay classify")
	incomingPath := flags.String("incoming", "", "incoming fingerprint JSON")
	existingPath := flags.String("existing", "", "stored fingerprint JSON")
	out := flags.String("out", "", "classification JSON output")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *incomingPath == "" || *out == "" {
		return nil, usageError("usage: eventctl replay classify --incoming PATH [--existing PATH] --out PATH")
	}
	incoming, err := loadFingerprint(*incomingPath)
	if err != nil {
		return nil, invalidError("load incoming fingerprint", err)
	}
	var existing *envelope.Fingerprint
	if *existingPath != "" {
		value, loadErr := loadFingerprint(*existingPath)
		if loadErr != nil {
			return nil, invalidError("load existing fingerprint", loadErr)
		}
		existing = &value
	}
	disposition, err := envelope.ClassifyReplay(existing, incoming)
	if err != nil {
		return nil, invalidError("classify replay", err)
	}
	result := struct {
		Status      string                     `json:"status"`
		Disposition envelope.ReplayDisposition `json:"disposition"`
		Fingerprint envelope.Fingerprint       `json:"fingerprint"`
	}{"classified", disposition, incoming}
	if err := writeCanonical(*out, result, 0o644); err != nil {
		return nil, ioError("write replay classification", err)
	}
	return result, nil
}
func loadFingerprint(path string) (envelope.Fingerprint, error) {
	raw, err := readBounded(path, 64*1024)
	if err != nil {
		return envelope.Fingerprint{}, err
	}
	var value envelope.Fingerprint
	if err := canonical.StrictUnmarshal(raw, &value); err != nil {
		return envelope.Fingerprint{}, err
	}
	if err := value.Validate(); err != nil {
		return envelope.Fingerprint{}, err
	}
	return value, nil
}
