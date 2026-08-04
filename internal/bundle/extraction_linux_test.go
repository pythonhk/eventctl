//go:build linux

package bundle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestDecryptLateFailuresLeaveNoDestinationOrStagingResidue(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	tests := []struct {
		name   string
		mutate func(*forgedBundle)
	}{
		{
			name: "second file digest",
			mutate: func(forged *forgedBundle) {
				forged.manifest.Files = []File{
					{Path: "a.txt", SizeBytes: 1, SHA256: digestHex([]byte("a"))},
					{Path: "b.txt", SizeBytes: 1, SHA256: strings.Repeat("0", 64)},
				}
				forged.fileContents = []byte("ab")
			},
		},
		{
			name: "final age authentication",
			mutate: func(forged *forgedBundle) {
				forged.truncateCiphertext = true
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			forged := validForgedBundle(fixture)
			test.mutate(&forged)
			bundlePath := writeForgedBundle(t, fixture, forged)
			parent := filepath.Join(t.TempDir(), "extract-parent")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(parent, "submission")
			_, err := DecryptToDirectory(
				context.Background(), bundlePath, destination,
				[]*age.HybridIdentity{fixture.identity}, fixture.publicKey, Limits{}, []string{".txt"},
			)
			if err == nil {
				t.Fatal("DecryptToDirectory() unexpectedly succeeded")
			}
			if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed extraction exposed destination: %v", statErr)
			}
			entries, readErr := os.ReadDir(parent)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("failed extraction left staging residue: %#v", entries)
			}
		})
	}
}

func TestDecryptRejectsAuthenticatedCustomClientExtensionsBeforePublication(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	forged := validForgedBundle(fixture)
	forged.manifest.Files = []File{
		{Path: "run.sh", SizeBytes: 1, SHA256: digestHex([]byte("a"))},
		{Path: "tool.exe", SizeBytes: 1, SHA256: digestHex([]byte("b"))},
	}
	forged.fileContents = []byte("ab")
	bundlePath := writeForgedBundle(t, fixture, forged)
	parent := filepath.Join(t.TempDir(), "extract-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(parent, "submission")
	_, err := DecryptToDirectory(
		context.Background(), bundlePath, destination,
		[]*age.HybridIdentity{fixture.identity}, fixture.publicKey, Limits{}, []string{".csv"},
	)
	if !errors.Is(err, ErrDisallowedExtension) {
		t.Fatalf("DecryptToDirectory() error = %v, want ErrDisallowedExtension", err)
	}
	if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("forbidden custom-client manifest exposed destination: %v", statErr)
	}
	entries, readErr := os.ReadDir(parent)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("forbidden custom-client manifest left staging residue: %#v", entries)
	}
}

func TestRenameNoReplacePreservesConcurrentDestination(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	destination := filepath.Join(root, "destination")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(staging, "new"), []byte("new"), 0o600)
	mustWriteFile(t, filepath.Join(destination, "winner"), []byte("winner"), 0o600)
	if err := renameNoReplace(staging, destination); err == nil {
		t.Fatal("renameNoReplace() overwrote concurrent destination")
	}
	assertFileContents(t, filepath.Join(destination, "winner"), []byte("winner"))
	assertFileContents(t, filepath.Join(staging, "new"), []byte("new"))
}
