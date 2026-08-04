package bundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
)

// FuzzBundleParsing exercises both unauthenticated public inspection and the
// full authenticated/decrypted parser. Inputs and all parser allocations are
// held under deliberately small caps so corpus growth cannot become a resource
// exhaustion vector in CI.
func FuzzBundleParsing(f *testing.F) {
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		f.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	fixture := cryptoFixture{
		identity: identity, recipient: identity.Recipient(),
		privateKey: privateKey, publicKey: publicKey,
	}
	root := f.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "seed.txt"), []byte("seed\n"), 0o600); err != nil {
		f.Fatal(err)
	}
	validPath := filepath.Join(root, "seed.evt")
	if _, err := PackDirectory(context.Background(), PackOptions{
		SourceDir: source, OutputPath: validPath, Binding: fixture.binding(),
		Recipients: []*age.HybridRecipient{identity.Recipient()}, SigningKey: privateKey,
		Limits: fuzzLimits(),
	}); err != nil {
		f.Fatal(err)
	}
	valid, err := os.ReadFile(validPath)
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte{})
	f.Add(append([]byte(nil), outerMagic[:]...))
	oversizedLength := append([]byte(nil), outerMagic[:]...)
	oversizedLength = binary.BigEndian.AppendUint32(oversizedLength, fuzzLimits().MaxEnvelopeBytes+1)
	f.Add(oversizedLength)
	f.Add(valid)
	for _, length := range []int{1, outerMagicSize, outerMagicSize + 4, len(valid) - 1} {
		f.Add(append([]byte(nil), valid[:length]...))
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 128*1024 {
			t.Skip()
		}
		path := filepath.Join(t.TempDir(), "input.evt")
		if err := os.WriteFile(path, input, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = Inspect(context.Background(), path, fuzzLimits())
		_, _ = Verify(
			context.Background(), path, []*age.HybridIdentity{identity}, publicKey, fuzzLimits(),
		)
	})
}

// FuzzInnerContainer targets the decrypted framing, canonical manifest parser,
// detached inner signature, path trie, and bounded file consumers directly.
// This complements FuzzBundleParsing, whose arbitrary mutations are usually
// rejected earlier by the outer signature or age authentication.
func FuzzInnerContainer(f *testing.F) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	fixture := cryptoFixture{privateKey: privateKey, publicKey: publicKey}
	contents := []byte("seed\n")
	manifest := manifestFromBinding(fixture.binding(), []File{{
		Path: "seed.txt", SizeBytes: uint64(len(contents)), SHA256: digestHex(contents),
	}})
	manifestBytes, err := marshalCanonical(manifest)
	if err != nil {
		f.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, signingMessage(manifestSignatureDomain, manifestBytes))
	var valid bytes.Buffer
	valid.Write(innerMagic[:])
	if err := binary.Write(&valid, binary.BigEndian, uint32(len(manifestBytes))); err != nil {
		f.Fatal(err)
	}
	valid.Write(manifestBytes)
	valid.Write(signature)
	valid.Write(contents)
	validBytes := valid.Bytes()

	envelope := envelopeFromBinding(fixture.binding())
	envelope.InnerManifestSHA256 = digestHex(manifestBytes)
	envelope.FileCount = uint32(len(manifest.Files))
	envelope.PlaintextSize, err = plaintextSizeForManifest(manifestBytes, manifest.Files)
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte{})
	f.Add(append([]byte(nil), innerMagic[:]...))
	oversizedLength := append([]byte(nil), innerMagic[:]...)
	oversizedLength = binary.BigEndian.AppendUint32(oversizedLength, fuzzLimits().MaxManifestBytes+1)
	f.Add(oversizedLength)
	f.Add(append([]byte(nil), validBytes...))
	for _, length := range []int{1, innerMagicSize, innerMagicSize + 4, len(validBytes) - 1} {
		f.Add(append([]byte(nil), validBytes[:length]...))
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 128*1024 {
			t.Skip()
		}
		_, _ = readAndVerifyInner(
			context.Background(), bytes.NewReader(input), envelope, publicKey, fuzzLimits(), "", nil,
		)
	})
}

func fuzzLimits() Limits {
	return Limits{
		MaxCiphertextBytes: 64 * 1024,
		MaxEnvelopeBytes:   8 * 1024,
		MaxFileBytes:       32 * 1024,
		MaxFiles:           64,
		MaxManifestBytes:   32 * 1024,
		MaxPlaintextBytes:  48 * 1024,
		MaxRecipients:      4,
		MaxTotalFileBytes:  48 * 1024,
		MaxValidity:        24 * time.Hour,
	}
}
