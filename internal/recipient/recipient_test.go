package recipient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/pythonhk/eventctl/internal/keystore"
)

func TestGenerateLoadAndDescribeRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "organizer-identity.age")
	passphrase := []byte("correct horse battery staple")
	public, err := GenerateIdentityFile(context.Background(), path, passphrase, keystore.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(public.Recipient, "age1pq1") || len(public.Recipient) != 1959 {
		t.Fatalf("generated recipient has unexpected profile or length: %d", len(public.Recipient))
	}
	if len(public.Fingerprint) != 64 {
		t.Fatalf("generated fingerprint length = %d, want 64", len(public.Fingerprint))
	}
	identity, err := LoadIdentity(context.Background(), path, passphrase, keystore.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	loadedPublic, err := Describe(identity)
	if err != nil {
		t.Fatal(err)
	}
	if loadedPublic != public {
		t.Fatalf("loaded public data = %#v, want %#v", loadedPublic, public)
	}
}

func TestLoadRejectsWrongPassphraseAndLegacyIdentity(t *testing.T) {
	root := t.TempDir()
	passphrase := []byte("correct horse battery staple")
	path := filepath.Join(root, "hybrid.age")
	if _, err := GenerateIdentityFile(context.Background(), path, passphrase, keystore.Limits{}); err != nil {
		t.Fatal(err)
	}
	if identity, err := LoadIdentity(context.Background(), path, []byte("wrong passphrase"), keystore.Limits{}); !errors.Is(err, keystore.ErrAuthentication) || identity != nil {
		t.Fatalf("LoadIdentity() = %#v, %v; want nil ErrAuthentication", identity, err)
	}

	legacy, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	legacyDocument := []byte(identityDocumentHeader + legacy.String() + "\n")
	legacyPath := filepath.Join(root, "legacy.age")
	if err := keystore.EncryptFile(context.Background(), legacyPath, legacyDocument, passphrase, keystore.Limits{}); err != nil {
		t.Fatal(err)
	}
	if identity, err := LoadIdentity(context.Background(), legacyPath, passphrase, keystore.Limits{}); !errors.Is(err, ErrInvalidIdentityDocument) || identity != nil {
		t.Fatalf("LoadIdentity(legacy) = %#v, %v; want nil ErrInvalidIdentityDocument", identity, err)
	}
}

func TestGenerateDoesNotOverwriteExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.age")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateIdentityFile(
		context.Background(), path, []byte("correct horse battery staple"), keystore.Limits{},
	); !errors.Is(err, keystore.ErrDestinationExists) {
		t.Fatalf("GenerateIdentityFile() error = %v, want ErrDestinationExists", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "preserve" {
		t.Fatalf("existing file changed to %q", contents)
	}
}
