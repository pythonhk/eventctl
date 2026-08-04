package main

import (
	"fmt"
	"io"
	"time"

	"github.com/pythonhk/eventctl/internal/canonical"
	"github.com/pythonhk/eventctl/internal/config"
	"github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/receipt"
	"github.com/pythonhk/eventctl/internal/statepointer"
)

type normalizedReceipt struct {
	Status         string          `json:"status"`
	Kind           string          `json:"kind"`
	DocumentDigest string          `json:"document_digest"`
	Document       receipt.Receipt `json:"document"`
}

type receiptSummary struct {
	Path           string `json:"path"`
	Kind           string `json:"kind"`
	ReceiptID      string `json:"receipt_id"`
	OperationID    string `json:"operation_id"`
	DocumentDigest string `json:"document_digest"`
	StateSequence  uint64 `json:"state_sequence"`
}

func runReceipt(args []string, stderr io.Writer) (any, error) {
	if len(args) == 0 {
		return nil, usageError("usage: eventctl receipt sign|verify")
	}
	switch args[0] {
	case "sign":
		return receiptSign(args[1:], stderr)
	case "verify":
		return receiptVerify(args[1:])
	default:
		return nil, usageError("usage: eventctl receipt sign|verify")
	}
}

func receiptVerify(args []string) (any, error) {
	flags := newFlagSet("receipt verify")
	configPath := flags.String("config", "", "signed event config")
	authorityPath := flags.String("authority", "", "protected genesis authority")
	statePath := flags.String("state-meta", "", "protected current state metadata")
	receiptPath := flags.String("receipt", "", "signed committed-operation receipt")
	out := flags.String("out", "", "normalized verified receipt output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authorityPath == "" || *statePath == "" || *receiptPath == "" || *out == "" {
		return nil, usageError("usage: eventctl receipt verify --config PATH --authority PATH --state-meta PATH --receipt PATH --out PATH")
	}
	raw, err := readBounded(*receiptPath, receipt.MaxSignedBytesWithLF)
	if err != nil {
		return nil, ioError("read receipt", err)
	}
	parsed, err := receipt.Parse(raw)
	if err != nil {
		return nil, invalidError("validate receipt", err)
	}
	sourceCreatedAt, _ := envelope.ParseTimestamp(parsed.SourceCreatedAt)
	event, digest, meta, err := loadArchivedTrustedContext(*configPath, *authorityPath, *statePath, sourceCreatedAt)
	if err != nil {
		return nil, verificationError("verify historical event trust context", err)
	}
	verified, err := receipt.Verify(raw, receipt.Expected{
		EventID: event.EventID, EventEpoch: event.EventEpoch,
		BaseRepositoryID: event.BaseRepository.ID, ConfigDigest: digest,
		SigningKey: event.Receipts.SigningKey, CurrentState: currentPointer(meta),
		Now: time.Now().UTC(),
	})
	if err != nil {
		return nil, verificationError("verify committed operation receipt", err)
	}
	normalized := normalizedReceipt{"verified", receipt.Kind, verified.DocumentDigest, verified.Document}
	if err := writeCanonical(*out, normalized, 0o644); err != nil {
		return nil, ioError("write verified receipt", err)
	}
	return receiptSummary{*out, receipt.Kind, verified.Document.ReceiptID, verified.Document.OperationID, verified.DocumentDigest, verified.Document.StateAfter.Sequence}, nil
}

func receiptSign(args []string, stderr io.Writer) (any, error) {
	flags := newFlagSet("receipt sign")
	configPath := flags.String("config", "", "signed event config")
	authorityPath := flags.String("authority", "", "protected genesis authority")
	statePath := flags.String("state-meta", "", "protected current state metadata")
	claimPath := flags.String("claim", "", "strict committed receipt-pending claim")
	keyPath := flags.String("key", "", "encrypted dedicated receipt signing key")
	passphraseFile := flags.String("passphrase-file", "", "passphrase file or -")
	out := flags.String("out", "", "raw signed receipt output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *configPath == "" || *authorityPath == "" || *statePath == "" || *claimPath == "" || *keyPath == "" || *out == "" {
		return nil, usageError("usage: eventctl receipt sign --config PATH --authority PATH --state-meta PATH --claim PATH --key PATH --out PATH [--passphrase-file PATH|-]")
	}
	claimRaw, err := readBounded(*claimPath, envelope.MaxDocumentBytes)
	if err != nil {
		return nil, ioError("read committed receipt claim", err)
	}
	claim, err := receipt.ParseCommittedClaim(claimRaw)
	if err != nil {
		return nil, invalidError("validate committed receipt claim", err)
	}
	sourceCreatedAt, _ := envelope.ParseTimestamp(claim.SourceCreatedAt)
	event, digest, meta, err := loadArchivedTrustedContext(*configPath, *authorityPath, *statePath, sourceCreatedAt)
	if err != nil {
		return nil, verificationError("verify archived committed config", err)
	}
	pair, err := loadPrivate(*keyPath, *passphraseFile, stderr)
	if err != nil {
		return nil, verificationError("decrypt receipt signing key", err)
	}
	document, err := receipt.SignCommitted(claim, receipt.SignExpected{
		EventID: event.EventID, EventEpoch: event.EventEpoch,
		BaseRepositoryID: event.BaseRepository.ID, ConfigDigest: digest,
		SigningKey: event.Receipts.SigningKey, CurrentState: currentPointer(meta),
	}, pair.Private)
	if err != nil {
		return nil, verificationError("sign committed operation receipt", err)
	}
	raw, err := canonical.Marshal(document)
	if err != nil {
		return nil, err
	}
	if len(raw) > receipt.MaxSignedBytes {
		return nil, verificationError("enforce signed receipt size", fmt.Errorf("signed receipt is %d bytes, limit is %d", len(raw), receipt.MaxSignedBytes))
	}
	if _, err := receipt.Verify(raw, receipt.Expected{
		EventID: event.EventID, EventEpoch: event.EventEpoch,
		BaseRepositoryID: event.BaseRepository.ID, ConfigDigest: digest,
		SigningKey: event.Receipts.SigningKey, CurrentState: currentPointer(meta),
		Now: time.Now().UTC(),
	}); err != nil {
		return nil, verificationError("self-verify signed receipt", err)
	}
	if err := writeExclusive(*out, append(raw, '\n'), 0o644); err != nil {
		return nil, ioError("write signed receipt", err)
	}
	documentDigest, err := envelope.DocumentDigest(document)
	if err != nil {
		return nil, err
	}
	return receiptSummary{*out, receipt.Kind, document.ReceiptID, document.OperationID, documentDigest, document.StateAfter.Sequence}, nil
}

func currentPointer(meta config.StateMeta) statepointer.Pointer {
	return statepointer.Pointer{Sequence: meta.Sequence, JournalEventDigest: meta.JournalEventDigest}
}
