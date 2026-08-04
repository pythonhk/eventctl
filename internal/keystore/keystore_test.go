package keystore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

var testPassphrase = []byte("correct horse battery staple")

func TestEncryptDecryptRoundTripAndMode(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "identity.age")
	plaintext := bytes.Repeat([]byte("private-key-document\x00\xff"), 4096)

	if err := EncryptFile(context.Background(), path, plaintext, testPassphrase, Limits{}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("encrypted output mode = %v, want regular file", info.Mode())
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("encrypted output permissions = %04o, want 0600", info.Mode().Perm())
	}

	got, err := DecryptFile(context.Background(), path, testPassphrase, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("DecryptFile() = %q, want %q", got, plaintext)
	}
	assertNoTemporaryFiles(t, root)
}

func TestDecryptRejectsTamperingTruncationAndWrongPassphrase(t *testing.T) {
	root := t.TempDir()
	validPath := filepath.Join(root, "valid.age")
	if err := EncryptFile(
		context.Background(), validPath, []byte("private key document"), testPassphrase, Limits{},
	); err != nil {
		t.Fatal(err)
	}
	valid, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		ciphertext []byte
		passphrase []byte
	}{
		{
			name:       "payload tamper",
			ciphertext: mutateLastByte(valid),
			passphrase: testPassphrase,
		},
		{
			name:       "truncation",
			ciphertext: append([]byte(nil), valid[:len(valid)-1]...),
			passphrase: testPassphrase,
		},
		{
			name:       "wrong passphrase",
			ciphertext: valid,
			passphrase: []byte("this is not the passphrase"),
		},
		{
			name:       "trailing ciphertext",
			ciphertext: append(append([]byte(nil), valid...), 0),
			passphrase: testPassphrase,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(root, strings.ReplaceAll(test.name, " ", "-")+".age")
			if err := os.WriteFile(path, test.ciphertext, 0o600); err != nil {
				t.Fatal(err)
			}
			plaintext, err := DecryptFile(context.Background(), path, test.passphrase, Limits{})
			if !errors.Is(err, ErrAuthentication) {
				t.Fatalf("DecryptFile() error = %v, want ErrAuthentication", err)
			}
			if plaintext != nil {
				t.Fatalf("DecryptFile() exposed plaintext after failure: %q", plaintext)
			}
			if strings.Contains(err.Error(), string(test.passphrase)) {
				t.Fatal("DecryptFile() error exposed the supplied passphrase")
			}
		})
	}
}

func TestEncryptIsExclusiveAndFailureIsAtomic(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "existing.age")
	original := []byte("preserve this file")
	if err := os.WriteFile(existing, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(
		context.Background(), existing, []byte("replacement"), testPassphrase, Limits{},
	); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("EncryptFile() error = %v, want ErrDestinationExists", err)
	}
	got, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("existing destination changed to %q, want %q", got, original)
	}

	canceledPath := filepath.Join(root, "canceled.age")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := EncryptFile(canceled, canceledPath, []byte("secret"), testPassphrase, Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("EncryptFile() error = %v, want context.Canceled", err)
	}
	if _, err := os.Lstat(canceledPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed encryption published a destination: %v", err)
	}
	assertNoTemporaryFiles(t, root)
}

func TestLimitsAreEnforced(t *testing.T) {
	root := t.TempDir()
	tooSmall := Limits{MaxPlaintextBytes: 3, MaxCiphertextBytes: 1024 * 1024}
	if err := EncryptFile(
		context.Background(), filepath.Join(root, "oversize.age"), []byte("four"), testPassphrase, tooSmall,
	); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("EncryptFile() error = %v, want ErrLimitExceeded", err)
	}
	lateFailurePath := filepath.Join(root, "ciphertext-too-large.age")
	if err := EncryptFile(
		context.Background(), lateFailurePath, []byte("secret"), testPassphrase,
		Limits{MaxPlaintextBytes: 1024, MaxCiphertextBytes: 1},
	); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("EncryptFile() late error = %v, want ErrLimitExceeded", err)
	}
	if _, err := os.Lstat(lateFailurePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("late encryption failure published a destination: %v", err)
	}

	validPath := filepath.Join(root, "valid.age")
	if err := EncryptFile(context.Background(), validPath, []byte("secret"), testPassphrase, Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptFile(
		context.Background(), validPath, testPassphrase,
		Limits{MaxPlaintextBytes: 1024, MaxCiphertextBytes: 1},
	); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("DecryptFile() error = %v, want ErrLimitExceeded", err)
	}
	plaintext, err := DecryptFile(
		context.Background(), validPath, testPassphrase,
		Limits{MaxPlaintextBytes: 3, MaxCiphertextBytes: 1024 * 1024},
	)
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("DecryptFile() plaintext-limit error = %v, want ErrLimitExceeded", err)
	}
	if plaintext != nil {
		t.Fatalf("DecryptFile() exposed over-limit plaintext: %q", plaintext)
	}
	assertNoTemporaryFiles(t, root)
}

func TestExclusivePublicationRaceHasOneCompleteWinner(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first.tmp")
	second := filepath.Join(root, "second.tmp")
	destination := filepath.Join(root, "identity.age")
	firstContents := bytes.Repeat([]byte("a"), 1024)
	secondContents := bytes.Repeat([]byte("b"), 1024)
	if err := os.WriteFile(first, firstContents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, secondContents, 0o600); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, source := range []string{first, second} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results <- publishExclusive(source, destination)
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	succeeded := 0
	existed := 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrDestinationExists):
			existed++
		default:
			t.Fatalf("publishExclusive() unexpected error: %v", err)
		}
	}
	if succeeded != 1 || existed != 1 {
		t.Fatalf("publish outcomes = %d success, %d exists; want one each", succeeded, existed)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, firstContents) && !bytes.Equal(got, secondContents) {
		t.Fatal("exclusive publication produced partial or mixed contents")
	}
}

func mutateLastByte(input []byte) []byte {
	mutated := append([]byte(nil), input...)
	mutated[len(mutated)-1] ^= 0x80
	return mutated
}

func assertNoTemporaryFiles(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".eventctl-") {
			t.Errorf("temporary file was not removed: %s", entry.Name())
		}
	}
}
