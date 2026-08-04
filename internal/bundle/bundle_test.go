package bundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/pythonhk/eventctl/internal/identity"
)

func TestPackInspectVerifyAndDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	root := t.TempDir()
	source := filepath.Join(root, "source")
	mustMkdirAll(t, filepath.Join(source, "nested"))
	mustWriteFile(t, filepath.Join(source, "z.txt"), []byte("last\n"), 0o644)
	mustWriteFile(t, filepath.Join(source, "nested", "a.bin"), []byte{0, 1, 2, 3}, 0o600)
	output := filepath.Join(root, "submission.evt")

	packed, err := PackDirectory(context.Background(), PackOptions{
		SourceDir:  source,
		OutputPath: output,
		Binding:    fixture.binding(),
		Recipients: []*age.HybridRecipient{fixture.recipient},
		SigningKey: fixture.privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if packed.BundleSHA256 == "" || packed.BundleSize == 0 {
		t.Fatalf("PackDirectory() returned incomplete bundle metadata: %#v", packed)
	}
	if got := packed.Manifest.Files; len(got) != 2 || got[0].Path != "nested/a.bin" || got[1].Path != "z.txt" {
		t.Fatalf("manifest files are not sorted: %#v", got)
	}
	if runtime.GOOS != "windows" {
		assertFileMode(t, output, 0o600)
	}

	inspection, err := Inspect(context.Background(), output, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if inspection.BundleSHA256 != packed.BundleSHA256 || inspection.BundleSize != packed.BundleSize {
		t.Fatalf("Inspect() = %#v; packed digest/size = %s/%d", inspection, packed.BundleSHA256, packed.BundleSize)
	}
	if got := bindingFromEnvelope(inspection.Envelope); got != fixture.binding() {
		t.Fatalf("Inspect() binding = %#v", got)
	}
	if inspection.EnvelopeSHA256 != packed.EnvelopeSHA256 {
		t.Fatalf("Inspect() envelope digest = %s, want %s", inspection.EnvelopeSHA256, packed.EnvelopeSHA256)
	}

	verified, err := Verify(
		context.Background(),
		output,
		[]*age.HybridIdentity{fixture.identity},
		fixture.publicKey,
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verified, packed.Verified) {
		t.Fatalf("Verify() = %#v, want %#v", verified, packed.Verified)
	}
	if !extractionSupported {
		return
	}

	destination := filepath.Join(root, "decrypted")
	decrypted, err := DecryptToDirectory(
		context.Background(),
		output,
		destination,
		[]*age.HybridIdentity{fixture.identity},
		fixture.publicKey,
		Limits{},
		[]string{".bin", ".txt"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decrypted, packed.Verified) {
		t.Fatalf("DecryptToDirectory() = %#v, want %#v", decrypted, packed.Verified)
	}
	assertFileContents(t, filepath.Join(destination, "nested", "a.bin"), []byte{0, 1, 2, 3})
	assertFileContents(t, filepath.Join(destination, "z.txt"), []byte("last\n"))
	assertFileMode(t, filepath.Join(destination, "nested", "a.bin"), 0o600)
	assertFileMode(t, filepath.Join(destination, "z.txt"), 0o600)
}

func TestPackRejectsUnsafeSourcesLimitsAndExistingOutput(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	baseOptions := func(root, source, output string) PackOptions {
		return PackOptions{
			SourceDir:  source,
			OutputPath: output,
			Binding:    fixture.binding(),
			Recipients: []*age.HybridRecipient{fixture.recipient},
			SigningKey: fixture.privateKey,
		}
	}
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "source")
		mustMkdirAll(t, source)
		mustWriteFile(t, filepath.Join(root, "target"), []byte("secret"), 0o600)
		if err := os.Symlink(filepath.Join(root, "target"), filepath.Join(source, "link")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		_, err := PackDirectory(context.Background(), baseOptions(root, source, filepath.Join(root, "out.evt")))
		if !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("PackDirectory() error = %v, want ErrUnsafePath", err)
		}
	})
	t.Run("output inside source", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "source")
		mustMkdirAll(t, source)
		mustWriteFile(t, filepath.Join(source, "data"), []byte("x"), 0o600)
		_, err := PackDirectory(context.Background(), baseOptions(root, source, filepath.Join(source, "out.evt")))
		if !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("PackDirectory() error = %v, want ErrUnsafePath", err)
		}
	})
	t.Run("output parent symlink aliases source", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "source")
		mustMkdirAll(t, source)
		mustWriteFile(t, filepath.Join(source, "data"), []byte("x"), 0o600)
		alias := filepath.Join(root, "source-alias")
		if err := os.Symlink(source, alias); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		_, err := PackDirectory(context.Background(), baseOptions(root, source, filepath.Join(alias, "out.evt")))
		if !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("PackDirectory() error = %v, want ErrUnsafePath", err)
		}
	})
	t.Run("existing output", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "source")
		mustMkdirAll(t, source)
		mustWriteFile(t, filepath.Join(source, "data"), []byte("x"), 0o600)
		output := filepath.Join(root, "out.evt")
		mustWriteFile(t, output, []byte("preserve"), 0o600)
		_, err := PackDirectory(context.Background(), baseOptions(root, source, output))
		if !errors.Is(err, ErrDestinationExists) {
			t.Fatalf("PackDirectory() error = %v, want ErrDestinationExists", err)
		}
		assertFileContents(t, output, []byte("preserve"))
	})
	t.Run("oversize", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "source")
		mustMkdirAll(t, source)
		mustWriteFile(t, filepath.Join(source, "data"), []byte("12345"), 0o600)
		limits := DefaultLimits()
		limits.MaxFileBytes = 4
		options := baseOptions(root, source, filepath.Join(root, "out.evt"))
		options.Limits = limits
		_, err := PackDirectory(context.Background(), options)
		if !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("PackDirectory() error = %v, want ErrLimitExceeded", err)
		}
	})
	t.Run("too many files", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "source")
		mustMkdirAll(t, source)
		mustWriteFile(t, filepath.Join(source, "a"), []byte("a"), 0o600)
		mustWriteFile(t, filepath.Join(source, "b"), []byte("b"), 0o600)
		limits := DefaultLimits()
		limits.MaxFiles = 1
		options := baseOptions(root, source, filepath.Join(root, "out.evt"))
		options.Limits = limits
		_, err := PackDirectory(context.Background(), options)
		if !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("PackDirectory() error = %v, want ErrLimitExceeded", err)
		}
	})
}

func TestInspectAndVerifyRejectTamperingTruncationAndWrongKeys(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	bundlePath := makeValidBundle(t, fixture)
	original := mustReadFile(t, bundlePath)

	t.Run("ciphertext tamper", func(t *testing.T) {
		mutated := append([]byte(nil), original...)
		mutated[len(mutated)-1] ^= 0x80
		path := filepath.Join(t.TempDir(), "tampered.evt")
		mustWriteFile(t, path, mutated, 0o600)
		_, err := Inspect(context.Background(), path, Limits{})
		if !errors.Is(err, ErrCiphertextDigest) {
			t.Fatalf("Inspect() error = %v, want ErrCiphertextDigest", err)
		}
	})
	t.Run("truncation", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "truncated.evt")
		mustWriteFile(t, path, original[:len(original)-1], 0o600)
		if _, err := Inspect(context.Background(), path, Limits{}); err == nil {
			t.Fatal("Inspect() unexpectedly accepted a truncated bundle")
		}
	})
	t.Run("symlink input", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "linked.evt")
		if err := os.Symlink(bundlePath, path); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := Inspect(context.Background(), path, Limits{}); !errors.Is(err, ErrInvalidFormat) {
			t.Fatalf("Inspect() error = %v, want ErrInvalidFormat", err)
		}
	})
	t.Run("wrong recipient", func(t *testing.T) {
		wrongIdentity, err := age.GenerateHybridIdentity()
		if err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(t.TempDir(), "must-not-exist")
		_, err = Verify(
			context.Background(), bundlePath,
			[]*age.HybridIdentity{wrongIdentity}, fixture.publicKey, Limits{},
		)
		if !errors.Is(err, ErrNoRecipient) {
			t.Fatalf("Verify() error = %v, want ErrNoRecipient", err)
		}
		if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed decryption exposed destination: %v", statErr)
		}
	})
	t.Run("wrong signing key", func(t *testing.T) {
		wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Verify(
			context.Background(), bundlePath,
			[]*age.HybridIdentity{fixture.identity}, wrongPublic, Limits{},
		)
		if !errors.Is(err, ErrSignature) {
			t.Fatalf("Verify() error = %v, want ErrSignature", err)
		}
	})
	t.Run("outer signature", func(t *testing.T) {
		mutated := append([]byte(nil), original...)
		envelopeLength := binary.BigEndian.Uint32(mutated[outerMagicSize : outerMagicSize+4])
		signatureOffset := outerMagicSize + 4 + int(envelopeLength)
		mutated[signatureOffset] ^= 1
		path := filepath.Join(t.TempDir(), "bad-signature.evt")
		mustWriteFile(t, path, mutated, 0o600)
		_, err := Verify(
			context.Background(), path,
			[]*age.HybridIdentity{fixture.identity}, fixture.publicKey, Limits{},
		)
		if !errors.Is(err, ErrSignature) {
			t.Fatalf("Verify() error = %v, want ErrSignature", err)
		}
	})
}

func TestAuthenticatePublicVerifiesOuterSignatureBeforeCiphertext(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	bundlePath := makeValidBundle(t, fixture)
	pair, err := identity.FromSeed(fixture.privateKey.Seed())
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := AuthenticatePublic(context.Background(), bundlePath, pair.Public, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	inspected, err := Inspect(context.Background(), bundlePath, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(authenticated, inspected) {
		t.Fatalf("AuthenticatePublic() = %#v, want %#v", authenticated, inspected)
	}

	mutated := mustReadFile(t, bundlePath)
	envelopeLength := binary.BigEndian.Uint32(mutated[outerMagicSize : outerMagicSize+4])
	signatureOffset := outerMagicSize + 4 + int(envelopeLength)
	mutated[signatureOffset] ^= 1
	mutated[len(mutated)-1] ^= 1
	badPath := filepath.Join(t.TempDir(), "bad-signature-and-ciphertext.evt")
	mustWriteFile(t, badPath, mutated, 0o600)
	if _, err := AuthenticatePublic(context.Background(), badPath, pair.Public, Limits{}); !errors.Is(err, ErrSignature) {
		t.Fatalf("AuthenticatePublic() error = %v, want ErrSignature before ciphertext digest", err)
	}
}

func TestVerifyAuthenticatesCiphertextEOFAndInnerLayers(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	tests := []struct {
		name   string
		mutate func(*forgedBundle)
		want   error
	}{
		{
			name: "authenticated EOF",
			mutate: func(bundle *forgedBundle) {
				bundle.truncateCiphertext = true
			},
			want: ErrInvalidFormat,
		},
		{
			name: "inner signature",
			mutate: func(bundle *forgedBundle) {
				bundle.corruptInnerSignature = true
			},
			want: ErrSignature,
		},
		{
			name: "inner outer binding",
			mutate: func(bundle *forgedBundle) {
				changed := bindingFromManifest(bundle.manifest)
				changed.TeamID = "22222222-2222-4222-8222-222222222222"
				bundle.outerBinding = &changed
			},
			want: ErrManifestMismatch,
		},
		{
			name: "file digest",
			mutate: func(bundle *forgedBundle) {
				bundle.manifest.Files[0].SHA256 = strings.Repeat("0", 64)
			},
			want: ErrFileDigest,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			forged := validForgedBundle(fixture)
			test.mutate(&forged)
			path := writeForgedBundle(t, fixture, forged)
			_, err := Verify(
				context.Background(), path,
				[]*age.HybridIdentity{fixture.identity}, fixture.publicKey, Limits{},
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestVerifyRequiresExactInnerOuterBindingEquality(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	tests := []struct {
		name   string
		mutate func(*Binding)
	}{
		{name: "event epoch", mutate: func(binding *Binding) { binding.EventEpoch = "2" }},
		{name: "key epoch", mutate: func(binding *Binding) { binding.KeyEpoch = "2" }},
		{name: "recipient epoch", mutate: func(binding *Binding) { binding.RecipientEpoch = "4" }},
		{name: "team proposal digest", mutate: func(binding *Binding) { binding.TeamProposalDigest = strings.Repeat("c", 64) }},
		{name: "config digest", mutate: func(binding *Binding) { binding.ConfigDigest = strings.Repeat("d", 64) }},
		{name: "actor ID", mutate: func(binding *Binding) { binding.ActorID = "9007199254740994" }},
		{name: "base repository ID", mutate: func(binding *Binding) { binding.BaseRepositoryID = "12345678901234567891" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			forged := validForgedBundle(fixture)
			outer := bindingFromManifest(forged.manifest)
			test.mutate(&outer)
			forged.outerBinding = &outer
			path := writeForgedBundle(t, fixture, forged)
			_, err := Verify(
				context.Background(), path,
				[]*age.HybridIdentity{fixture.identity}, fixture.publicKey, Limits{},
			)
			if !errors.Is(err, ErrManifestMismatch) {
				t.Fatalf("Verify() error = %v, want ErrManifestMismatch", err)
			}
		})
	}
}

func TestVerifyRejectsMaliciousArchivePaths(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	paths := []string{
		"/absolute.txt",
		".hidden",
		"../traversal.txt",
		"dir/../../traversal.txt",
		"back\\slash.txt",
		"nul\x00byte.txt",
		"C:/windows.txt",
		"dir//duplicate-separator.txt",
		"NUL.txt",
		"COM1.log",
		"trailing.",
		"trailing ",
		"question?.txt",
		"café.txt",
	}
	for _, maliciousPath := range paths {
		maliciousPath := maliciousPath
		t.Run(hex.EncodeToString([]byte(maliciousPath)), func(t *testing.T) {
			t.Parallel()
			forged := validForgedBundle(fixture)
			forged.manifest.Files[0].Path = maliciousPath
			path := writeForgedBundle(t, fixture, forged)
			destination := filepath.Join(t.TempDir(), "must-not-exist")
			_, err := Verify(
				context.Background(), path,
				[]*age.HybridIdentity{fixture.identity}, fixture.publicKey, Limits{},
			)
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("Verify() error = %v, want ErrUnsafePath", err)
			}
			if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("malicious extraction exposed destination: %v", statErr)
			}
		})
	}
}

func TestVerifyRejectsDuplicateCaseAndFileDirectoryCollisions(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	tests := []struct {
		name  string
		paths []string
	}{
		{name: "duplicate", paths: []string{"a.txt", "a.txt"}},
		{name: "case collision", paths: []string{"A.txt", "a.txt"}},
		{name: "file directory collision", paths: []string{"a", "a/b.txt"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			forged := validForgedBundle(fixture)
			forged.manifest.Files = nil
			for _, filePath := range test.paths {
				forged.manifest.Files = append(forged.manifest.Files, File{
					Path: filePath, SizeBytes: 1, SHA256: digestHex([]byte("x")),
				})
			}
			forged.fileContents = bytes.Repeat([]byte("x"), len(test.paths))
			path := writeForgedBundle(t, fixture, forged)
			_, err := Verify(
				context.Background(), path,
				[]*age.HybridIdentity{fixture.identity}, fixture.publicKey, Limits{},
			)
			if !errors.Is(err, ErrUnsafePath) && !errors.Is(err, ErrInvalidFormat) {
				t.Fatalf("Verify() error = %v, want path rejection", err)
			}
		})
	}
}

func TestHybridRecipientFingerprintGoldenDomain(t *testing.T) {
	t.Parallel()

	const encoded = "age1pq1test"
	const expected = "2651fefe8cd806e925f2ac51a665f0712d782def1693ff694219c6b44a8112c1"
	if got := ageRecipientKeyID(encoded); got != expected {
		t.Fatalf("ageRecipientKeyID(%q) = %s, want %s", encoded, got, expected)
	}
}

func TestPackAndVerifyWithTwoHybridRecipients(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	second, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	mustMkdirAll(t, source)
	mustWriteFile(t, filepath.Join(source, "data.txt"), []byte("two recipients\n"), 0o600)
	path := filepath.Join(root, "submission.evt")
	packed, err := PackDirectory(context.Background(), PackOptions{
		SourceDir: source, OutputPath: path, Binding: fixture.binding(),
		Recipients: []*age.HybridRecipient{second.Recipient(), fixture.recipient},
		SigningKey: fixture.privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{
		ageRecipientKeyID(second.Recipient().String()),
		ageRecipientKeyID(fixture.recipient.String()),
	}
	if wantIDs[0] > wantIDs[1] {
		wantIDs[0], wantIDs[1] = wantIDs[1], wantIDs[0]
	}
	if !reflect.DeepEqual(packed.Envelope.RecipientKeyIDs, wantIDs) {
		t.Fatalf("recipient IDs = %#v, want %#v", packed.Envelope.RecipientKeyIDs, wantIDs)
	}
	verified, err := Verify(
		context.Background(), path,
		[]*age.HybridIdentity{second, fixture.identity}, fixture.publicKey, Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verified, packed.Verified) {
		t.Fatalf("Verify() = %#v, want %#v", verified, packed.Verified)
	}

	extra, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	setTests := []struct {
		name       string
		identities []*age.HybridIdentity
	}{
		{name: "missing", identities: []*age.HybridIdentity{fixture.identity}},
		{name: "duplicate", identities: []*age.HybridIdentity{fixture.identity, fixture.identity}},
		{name: "extra", identities: []*age.HybridIdentity{fixture.identity, second, extra}},
	}
	for _, test := range setTests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Verify(context.Background(), path, test.identities, fixture.publicKey, Limits{})
			if !errors.Is(err, ErrRecipientSet) {
				t.Fatalf("Verify() error = %v, want ErrRecipientSet", err)
			}
		})
	}
}

func TestVerifyRejectsPartialRecipientStanzaReplacement(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	declaredSecond, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	undeclared, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	declaredIDs := []string{
		ageRecipientKeyID(fixture.recipient.String()),
		ageRecipientKeyID(declaredSecond.Recipient().String()),
	}
	if declaredIDs[0] > declaredIDs[1] {
		declaredIDs[0], declaredIDs[1] = declaredIDs[1], declaredIDs[0]
	}
	forged := validForgedBundle(fixture)
	forged.encryptionRecipients = []*age.HybridRecipient{fixture.recipient, undeclared.Recipient()}
	forged.declaredRecipientIDs = declaredIDs
	path := writeForgedBundle(t, fixture, forged)
	_, err = Verify(
		context.Background(), path,
		[]*age.HybridIdentity{fixture.identity, declaredSecond}, fixture.publicKey, Limits{},
	)
	if !errors.Is(err, ErrRecipientSet) {
		t.Fatalf("Verify() error = %v, want ErrRecipientSet", err)
	}
}

func TestVerifyRequiresExactHybridStanzaSet(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	declaredSecond, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	undeclared, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	declaredIDs := []string{
		ageRecipientKeyID(fixture.recipient.String()),
		ageRecipientKeyID(declaredSecond.Recipient().String()),
	}
	if declaredIDs[0] > declaredIDs[1] {
		declaredIDs[0], declaredIDs[1] = declaredIDs[1], declaredIDs[0]
	}
	tests := []struct {
		name       string
		recipients []*age.HybridRecipient
		wantError  bool
	}{
		{
			name:       "swapped order",
			recipients: []*age.HybridRecipient{declaredSecond.Recipient(), fixture.recipient},
		},
		{
			name:       "extra undeclared stanza",
			recipients: []*age.HybridRecipient{fixture.recipient, declaredSecond.Recipient(), undeclared.Recipient()},
			wantError:  true,
		},
		{
			name:       "duplicate replaces declared stanza",
			recipients: []*age.HybridRecipient{fixture.recipient, fixture.recipient},
			wantError:  true,
		},
		{
			name:       "missing declared stanza",
			recipients: []*age.HybridRecipient{fixture.recipient},
			wantError:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			forged := validForgedBundle(fixture)
			forged.encryptionRecipients = test.recipients
			forged.declaredRecipientIDs = append([]string(nil), declaredIDs...)
			path := writeForgedBundle(t, fixture, forged)
			_, err := Verify(
				context.Background(), path,
				[]*age.HybridIdentity{fixture.identity, declaredSecond}, fixture.publicKey, Limits{},
			)
			if test.wantError && err == nil {
				t.Fatal("Verify() unexpectedly accepted a non-exact stanza set")
			}
			if !test.wantError && err != nil {
				t.Fatalf("Verify() error = %v, want success", err)
			}
		})
	}
}

func TestVerifyRejectsDeclaredRecipientDifferentFromCiphertextRecipient(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	actualIdentity, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	forged := validForgedBundle(fixture)
	forged.encryptionRecipients = []*age.HybridRecipient{actualIdentity.Recipient()}
	forged.declaredRecipientIDs = []string{ageRecipientKeyID(fixture.recipient.String())}
	path := writeForgedBundle(t, fixture, forged)
	for name, identities := range map[string][]*age.HybridIdentity{
		"declared identity": {fixture.identity},
		"actual identity":   {actualIdentity},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(context.Background(), path, identities, fixture.publicKey, Limits{})
			if !errors.Is(err, ErrNoRecipient) {
				t.Fatalf("Verify() error = %v, want ErrNoRecipient", err)
			}
		})
	}
}

func TestSignatureDomainGoldenVectors(t *testing.T) {
	t.Parallel()

	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	payload := []byte(`{"kind":"golden"}`)
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{
			name: "manifest", domain: manifestSignatureDomain,
			expected: "989b144feeea7a9e5efba5c61f6383df56eb7e11e78d2c1298e1f1e72eeb04309c6aff3e0b5f5b418c98d7eb66d63919cabc664c524898c6414b70843d220805",
		},
		{
			name: "envelope", domain: envelopeSignatureDomain,
			expected: "01018a86a569075f80da8b5f462732b42b61ce885f8ff5bafd3c89de86b9f4a2f80803e172b1b9e5f351a33015550523a53338d6831a0e59e040dfb435717802",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signature := ed25519.Sign(privateKey, signingMessage(test.domain, payload))
			if got := hex.EncodeToString(signature); got != test.expected {
				t.Fatalf("signature = %s, want %s", got, test.expected)
			}
		})
	}
}

func TestPackRejectsInconsistentEd25519PrivateKey(t *testing.T) {
	t.Parallel()

	fixture := newCryptoFixture(t)
	invalid := append(ed25519.PrivateKey(nil), fixture.privateKey...)
	invalid[len(invalid)-1] ^= 1
	root := t.TempDir()
	source := filepath.Join(root, "source")
	mustMkdirAll(t, source)
	mustWriteFile(t, filepath.Join(source, "data.txt"), []byte("x"), 0o600)
	_, err := PackDirectory(context.Background(), PackOptions{
		SourceDir: source, OutputPath: filepath.Join(root, "out.evt"), Binding: fixture.binding(),
		Recipients: []*age.HybridRecipient{fixture.recipient}, SigningKey: invalid,
	})
	if err == nil || !strings.Contains(err.Error(), "inconsistent public-key suffix") {
		t.Fatalf("PackDirectory() error = %v, want inconsistent public-key suffix", err)
	}
}

func TestPublishBundleDoesNotOverwriteDestinationCreatedAfterPreflight(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	work := filepath.Join(root, "work")
	mustMkdirAll(t, work)
	ciphertextPath := filepath.Join(work, "ciphertext")
	ciphertext, err := os.OpenFile(ciphertextPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer ciphertext.Close()
	if _, err := ciphertext.Write([]byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "submission.evt")
	mustWriteFile(t, output, []byte("concurrent winner"), 0o600)
	_, _, err = publishBundle(
		context.Background(), output, []byte(`{}`), make([]byte, ed25519.SignatureSize),
		ciphertext, work, 1024,
	)
	if !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("publishBundle() error = %v, want ErrDestinationExists", err)
	}
	assertFileContents(t, output, []byte("concurrent winner"))
}

type cryptoFixture struct {
	identity   *age.HybridIdentity
	recipient  *age.HybridRecipient
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func newCryptoFixture(t *testing.T) cryptoFixture {
	t.Helper()
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return cryptoFixture{
		identity: identity, recipient: identity.Recipient(),
		privateKey: privateKey, publicKey: publicKey,
	}
}

func (fixture cryptoFixture) binding() Binding {
	return Binding{
		EventID:            "pyhk-2026",
		EventEpoch:         "1",
		BaseRepositoryID:   "12345678901234567890",
		ActorID:            "9007199254740993",
		KeyID:              identity.KeyID(fixture.publicKey),
		KeyEpoch:           "1",
		TeamID:             "11111111-1111-4111-8111-111111111111",
		TeamProposalDigest: strings.Repeat("b", 64),
		AttemptID:          "018f0f92-9f14-4ed0-aeca-123456789abc",
		RequestID:          "018f0f92-9f14-4ed0-aeca-abcdef123456",
		ConfigDigest:       strings.Repeat("a", 64),
		RecipientEpoch:     "3",
		IssuedAt:           "2030-06-01T02:00:00Z",
		ExpiresAt:          "2030-06-01T02:15:00Z",
	}
}

func makeValidBundle(t *testing.T, fixture cryptoFixture) string {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	mustMkdirAll(t, source)
	mustWriteFile(t, filepath.Join(source, "data.txt"), []byte("submission\n"), 0o600)
	output := filepath.Join(root, "submission.evt")
	_, err := PackDirectory(context.Background(), PackOptions{
		SourceDir: source, OutputPath: output, Binding: fixture.binding(),
		Recipients: []*age.HybridRecipient{fixture.recipient}, SigningKey: fixture.privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return output
}

type forgedBundle struct {
	manifest              Manifest
	fileContents          []byte
	outerBinding          *Binding
	corruptInnerSignature bool
	truncateCiphertext    bool
	encryptionRecipients  []*age.HybridRecipient
	declaredRecipientIDs  []string
}

func validForgedBundle(fixture cryptoFixture) forgedBundle {
	contents := []byte("x")
	return forgedBundle{
		manifest: manifestFromBinding(fixture.binding(), []File{{
			Path: "safe.txt", SizeBytes: uint64(len(contents)), SHA256: digestHex(contents),
		}}),
		fileContents: contents,
	}
}

func writeForgedBundle(t *testing.T, fixture cryptoFixture, forged forgedBundle) string {
	t.Helper()
	manifestBytes, err := marshalCanonical(forged.manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestSignature := ed25519.Sign(
		fixture.privateKey,
		signingMessage(manifestSignatureDomain, manifestBytes),
	)
	if forged.corruptInnerSignature {
		manifestSignature[0] ^= 1
	}
	var ciphertext bytes.Buffer
	recipients := forged.encryptionRecipients
	if len(recipients) == 0 {
		recipients = []*age.HybridRecipient{fixture.recipient}
	}
	ageRecipients := make([]age.Recipient, len(recipients))
	for index := range recipients {
		ageRecipients[index] = recipients[index]
	}
	encrypted, err := age.Encrypt(&ciphertext, ageRecipients...)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, encrypted, innerMagic[:])
	mustBinaryWrite(t, encrypted, uint32(len(manifestBytes)))
	mustWrite(t, encrypted, manifestBytes)
	mustWrite(t, encrypted, manifestSignature)
	mustWrite(t, encrypted, forged.fileContents)
	if err := encrypted.Close(); err != nil {
		t.Fatal(err)
	}
	ciphertextBytes := ciphertext.Bytes()
	if forged.truncateCiphertext {
		ciphertextBytes = ciphertextBytes[:len(ciphertextBytes)-1]
	}
	binding := bindingFromManifest(forged.manifest)
	if forged.outerBinding != nil {
		binding = *forged.outerBinding
	}
	plaintextSize, err := plaintextSizeForManifest(manifestBytes, forged.manifest.Files)
	if err != nil {
		t.Fatal(err)
	}
	envelope := envelopeFromBinding(binding)
	envelope.Encryption = EncryptionAlgorithm
	envelope.SignatureAlgorithm = identity.Algorithm
	envelope.RecipientKeyIDs = forged.declaredRecipientIDs
	if len(envelope.RecipientKeyIDs) == 0 {
		envelope.RecipientKeyIDs = []string{ageRecipientKeyID(fixture.recipient.String())}
	}
	envelope.InnerManifestSHA256 = digestHex(manifestBytes)
	envelope.FileCount = uint32(len(forged.manifest.Files))
	envelope.PlaintextSize = plaintextSize
	envelope.CiphertextSize = uint64(len(ciphertextBytes))
	envelope.CiphertextSHA256 = digestHex(ciphertextBytes)
	envelopeBytes, err := marshalCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelopeSignature := ed25519.Sign(
		fixture.privateKey,
		signingMessage(envelopeSignatureDomain, envelopeBytes),
	)
	var bundle bytes.Buffer
	mustWrite(t, &bundle, outerMagic[:])
	mustBinaryWrite(t, &bundle, uint32(len(envelopeBytes)))
	mustWrite(t, &bundle, envelopeBytes)
	mustWrite(t, &bundle, envelopeSignature)
	mustWrite(t, &bundle, ciphertextBytes)
	path := filepath.Join(t.TempDir(), "forged.evt")
	mustWriteFile(t, path, bundle.Bytes(), 0o600)
	return path
}

func mustWrite(t *testing.T, writer io.Writer, value []byte) {
	t.Helper()
	if _, err := writer.Write(value); err != nil {
		t.Fatal(err)
	}
}

func mustBinaryWrite(t *testing.T, writer io.Writer, value any) {
	t.Helper()
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		t.Fatal(err)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func assertFileContents(t *testing.T, path string, want []byte) {
	t.Helper()
	got := mustReadFile(t, path)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s contents = %q, want %q", path, got, want)
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", path, got, want)
	}
}

func TestDigestHexUsesSHA256(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("eventctl"))
	if got, want := digestHex([]byte("eventctl")), hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("digestHex() = %s, want %s", got, want)
	}
}

func TestV1HardSizeLimits(t *testing.T) {
	t.Parallel()

	limits := DefaultLimits()
	if limits.MaxCiphertextBytes != 47_000_000 || limits.MaxPlaintextBytes != 42_000_000 ||
		limits.MaxFileBytes != 42_000_000 || limits.MaxTotalFileBytes != 42_000_000 ||
		MaxBundleBytesV1 != 48_000_000 {
		t.Fatalf("unexpected v1 hard limits: %#v; bundle=%d", limits, MaxBundleBytesV1)
	}
	tooLarge := limits
	tooLarge.MaxPlaintextBytes++
	if _, err := normalizeLimits(tooLarge); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("normalizeLimits() error = %v, want ErrLimitExceeded", err)
	}

	path := filepath.Join(t.TempDir(), "oversized.evt")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(MaxBundleBytesV1 + 1)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(context.Background(), path, Limits{}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Inspect() error = %v, want ErrLimitExceeded", err)
	}
}
