package bundle

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/pythonhk/eventctl/internal/identity"
)

const (
	maxAgeHeaderBytes = 64 * 1024
	// A valid ML-KEM-768+X25519 stanza carries a roughly 1.5 KiB encoded
	// encapsulation. Keep the per-line bound comfortably above that while the
	// independent total header cap remains 64 KiB.
	maxAgeHeaderLineBytes = 4096
)

type parsedBundle struct {
	file              *os.File
	envelope          Envelope
	envelopeBytes     []byte
	envelopeSignature []byte
	ciphertextOffset  int64
	bundleSize        uint64
}

// Inspect validates the public envelope, all size bounds, exact container EOF,
// and the ciphertext digest. It cannot authenticate the signer without the
// registered Ed25519 public key; use Verify for that.
func Inspect(ctx context.Context, bundlePath string, limits Limits) (Inspection, error) {
	parsed, normalizedLimits, err := openBundle(bundlePath, limits)
	if err != nil {
		return Inspection{}, err
	}
	defer parsed.file.Close()
	return inspectDigests(ctx, parsed, normalizedLimits)
}

// Verify authenticates both signed layers, requires the exact signed set of
// HybridIdentity values, proves each identity independently unwraps the
// authenticated header, decrypts the complete age stream, verifies every file
// digest, and consumes the authenticated stream through EOF without writing
// plaintext to disk.
func Verify(
	ctx context.Context,
	bundlePath string,
	identities []*age.HybridIdentity,
	signingKey ed25519.PublicKey,
	limits Limits,
) (Verified, error) {
	return processBundle(ctx, bundlePath, identities, signingKey, limits, "", nil)
}

// DecryptToDirectory performs all Verify checks in a private staging directory
// and atomically renames it to destination only after authenticated EOF. Every
// extracted regular file has mode 0600. Destination must not already exist.
func DecryptToDirectory(
	ctx context.Context,
	bundlePath string,
	destination string,
	identities []*age.HybridIdentity,
	signingKey ed25519.PublicKey,
	limits Limits,
	allowedExtensions []string,
) (Verified, error) {
	if !extractionSupported {
		return Verified{}, ErrExtractionUnsupported
	}
	if destination == "" {
		return Verified{}, fmt.Errorf("destination directory is required")
	}
	if _, err := os.Lstat(destination); err == nil {
		return Verified{}, fmt.Errorf("%w: %s", ErrDestinationExists, destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Verified{}, fmt.Errorf("inspect destination: %w", err)
	}
	parent := filepath.Dir(destination)
	base := filepath.Base(filepath.Clean(destination))
	if base == "." || base == string(filepath.Separator) {
		return Verified{}, fmt.Errorf("%w: unsafe destination", ErrUnsafePath)
	}
	staging, err := os.MkdirTemp(parent, "."+base+".eventctl-*")
	if err != nil {
		return Verified{}, fmt.Errorf("create decryption staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0o700); err != nil {
		return Verified{}, fmt.Errorf("secure decryption staging directory: %w", err)
	}
	if len(allowedExtensions) == 0 {
		return Verified{}, fmt.Errorf("%w: extraction policy has no allowed extensions", ErrDisallowedExtension)
	}
	verified, err := processBundle(ctx, bundlePath, identities, signingKey, limits, staging, allowedExtensions)
	if err != nil {
		return Verified{}, err
	}
	if _, err := os.Lstat(destination); err == nil {
		return Verified{}, fmt.Errorf("%w: %s", ErrDestinationExists, destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Verified{}, fmt.Errorf("reinspect destination: %w", err)
	}
	if err := renameNoReplace(staging, destination); err != nil {
		if _, statErr := os.Lstat(destination); statErr == nil {
			return Verified{}, fmt.Errorf("%w: %s", ErrDestinationExists, destination)
		}
		return Verified{}, fmt.Errorf("publish decrypted directory atomically: %w", err)
	}
	return verified, nil
}

func processBundle(
	ctx context.Context,
	bundlePath string,
	identities []*age.HybridIdentity,
	signingKey ed25519.PublicKey,
	requestedLimits Limits,
	destinationRoot string,
	allowedExtensions []string,
) (Verified, error) {
	limits, err := normalizeLimits(requestedLimits)
	if err != nil {
		return Verified{}, err
	}
	if err := validateVerificationKey(signingKey); err != nil {
		return Verified{}, err
	}
	if len(identities) == 0 {
		return Verified{}, fmt.Errorf("%w: at least one hybrid ML-KEM-768+X25519 identity is required", ErrNoRecipient)
	}
	parsed, _, err := openBundle(bundlePath, limits)
	if err != nil {
		return Verified{}, err
	}
	defer parsed.file.Close()
	if identity.KeyID(signingKey) != parsed.envelope.KeyID {
		return Verified{}, fmt.Errorf("%w: signer key ID does not match registered key", ErrSignature)
	}
	if !ed25519.Verify(signingKey, signingMessage(envelopeSignatureDomain, parsed.envelopeBytes), parsed.envelopeSignature) {
		return Verified{}, fmt.Errorf("%w: outer envelope", ErrSignature)
	}
	ageIdentities, err := matchingIdentities(identities, parsed.envelope.RecipientKeyIDs)
	if err != nil {
		return Verified{}, err
	}
	if _, err := parsed.file.Seek(parsed.ciphertextOffset, io.SeekStart); err != nil {
		return Verified{}, fmt.Errorf("seek ciphertext: %w", err)
	}
	if err := validateAgeHeader(
		io.NewSectionReader(parsed.file, parsed.ciphertextOffset, int64(parsed.envelope.CiphertextSize)),
		len(parsed.envelope.RecipientKeyIDs),
	); err != nil {
		return Verified{}, err
	}
	if err := verifyEveryRecipientHeader(ctx, parsed, ageIdentities); err != nil {
		return Verified{}, err
	}
	// Hash the exact ciphertext bytes as age decrypts them. This keeps the
	// authenticated plaintext, signed ciphertext digest, and returned complete
	// bundle digest bound to one descriptor and one streaming pass.
	bundleHash, err := hashBundlePrefix(ctx, parsed)
	if err != nil {
		return Verified{}, err
	}
	ciphertextHash := sha256.New()
	hashedCiphertext := io.TeeReader(
		&contextReader{ctx: ctx, reader: parsed.file},
		io.MultiWriter(bundleHash, ciphertextHash),
	)
	limitedCiphertext := &io.LimitedReader{R: hashedCiphertext, N: int64(parsed.envelope.CiphertextSize)}
	plaintext, err := age.Decrypt(limitedCiphertext, ageIdentities...)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return Verified{}, fmt.Errorf("%w: %v", ErrNoRecipient, err)
		}
		return Verified{}, fmt.Errorf("%w: initialize age decryption: %v", ErrInvalidFormat, err)
	}
	countedPlaintext := &countingReader{reader: plaintext}
	manifest, err := readAndVerifyInner(ctx, countedPlaintext, parsed.envelope, signingKey, limits, destinationRoot, allowedExtensions)
	if err != nil {
		return Verified{}, err
	}
	var trailing [1]byte
	count, eofErr := countedPlaintext.Read(trailing[:])
	if count != 0 || !errors.Is(eofErr, io.EOF) {
		if eofErr == nil {
			eofErr = errors.New("trailing plaintext")
		}
		return Verified{}, fmt.Errorf("%w: encrypted stream did not end authentically: %v", ErrInvalidFormat, eofErr)
	}
	if countedPlaintext.count != parsed.envelope.PlaintextSize {
		return Verified{}, fmt.Errorf("%w: plaintext size differs from signed envelope", ErrManifestMismatch)
	}
	if limitedCiphertext.N != 0 {
		return Verified{}, fmt.Errorf("%w: age reader did not consume ciphertext EOF", ErrInvalidFormat)
	}
	inspection, err := finishInspection(parsed, bundleHash, ciphertextHash)
	if err != nil {
		return Verified{}, err
	}
	return Verified{
		Envelope:       parsed.envelope,
		Manifest:       manifest,
		EnvelopeSHA256: inspection.EnvelopeSHA256,
		BundleSize:     inspection.BundleSize,
		BundleSHA256:   inspection.BundleSHA256,
	}, nil
}

func matchingIdentities(identities []*age.HybridIdentity, signedRecipientKeyIDs []string) ([]age.Identity, error) {
	signed := make(map[string]struct{}, len(signedRecipientKeyIDs))
	for _, keyID := range signedRecipientKeyIDs {
		signed[keyID] = struct{}{}
	}
	if len(identities) != len(signedRecipientKeyIDs) {
		return nil, fmt.Errorf("%w: %w: supplied %d identities for %d signed recipients", ErrNoRecipient, ErrRecipientSet, len(identities), len(signedRecipientKeyIDs))
	}
	byID := make(map[string]*age.HybridIdentity, len(identities))
	for index, identity := range identities {
		if identity == nil {
			return nil, fmt.Errorf("%w: %w: identity %d is nil", ErrNoRecipient, ErrRecipientSet, index)
		}
		keyID := ageRecipientKeyID(identity.Recipient().String())
		if _, declared := signed[keyID]; !declared {
			return nil, fmt.Errorf("%w: %w: supplied identity %s is not signed", ErrNoRecipient, ErrRecipientSet, keyID)
		}
		if _, duplicate := byID[keyID]; duplicate {
			return nil, fmt.Errorf("%w: %w: supplied identity %s is duplicated", ErrNoRecipient, ErrRecipientSet, keyID)
		}
		byID[keyID] = identity
	}
	matched := make([]age.Identity, len(signedRecipientKeyIDs))
	for index, keyID := range signedRecipientKeyIDs {
		identity := byID[keyID]
		if identity == nil {
			return nil, fmt.Errorf("%w: %w: signed recipient %s has no supplied identity", ErrNoRecipient, ErrRecipientSet, keyID)
		}
		matched[index] = identity
	}
	return matched, nil
}

// verifyEveryRecipientHeader proves that each signed recipient identity can
// independently unwrap a stanza from the authenticated age header. Combined
// with the exact stanza count and exact supplied/signed identity-set check,
// this detects anonymous-stanza replacement such as signed [B,C] encrypted to
// [B,A]. It intentionally does not stream plaintext once per identity.
func verifyEveryRecipientHeader(ctx context.Context, parsed *parsedBundle, identities []age.Identity) error {
	for index, identity := range identities {
		section := io.NewSectionReader(parsed.file, parsed.ciphertextOffset, int64(parsed.envelope.CiphertextSize))
		if _, err := age.Decrypt(&contextReader{ctx: ctx, reader: section}, identity); err != nil {
			var noMatch *age.NoIdentityMatchError
			if errors.As(err, &noMatch) {
				return fmt.Errorf("%w: %w: signed identity %d cannot unwrap the ciphertext header", ErrNoRecipient, ErrRecipientSet, index)
			}
			return fmt.Errorf("%w: verify recipient %d header: %v", ErrInvalidFormat, index, err)
		}
	}
	return nil
}

func openBundle(bundlePath string, requestedLimits Limits) (*parsedBundle, Limits, error) {
	limits, err := normalizeLimits(requestedLimits)
	if err != nil {
		return nil, Limits{}, err
	}
	pathInfo, err := os.Lstat(bundlePath)
	if err != nil {
		return nil, Limits{}, fmt.Errorf("inspect bundle path: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, Limits{}, fmt.Errorf("%w: bundle path must be a regular file, not a symlink", ErrInvalidFormat)
	}
	file, err := os.Open(bundlePath)
	if err != nil {
		return nil, Limits{}, fmt.Errorf("open bundle: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, Limits{}, fmt.Errorf("inspect bundle: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || !os.SameFile(pathInfo, info) {
		return nil, Limits{}, fmt.Errorf("%w: bundle is not a regular file", ErrInvalidFormat)
	}
	if uint64(info.Size()) > MaxBundleBytesV1 {
		return nil, Limits{}, fmt.Errorf("%w: bundle exceeds maximum size", ErrLimitExceeded)
	}

	var magic [outerMagicSize]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		return nil, Limits{}, fmt.Errorf("%w: read bundle magic: %v", ErrInvalidFormat, err)
	}
	if magic != outerMagic {
		return nil, Limits{}, fmt.Errorf("%w: unsupported bundle magic", ErrInvalidFormat)
	}
	var envelopeLength uint32
	if err := binary.Read(file, binary.BigEndian, &envelopeLength); err != nil {
		return nil, Limits{}, fmt.Errorf("%w: read envelope length: %v", ErrInvalidFormat, err)
	}
	if envelopeLength == 0 || envelopeLength > limits.MaxEnvelopeBytes {
		return nil, Limits{}, fmt.Errorf("%w: envelope length exceeds limit", ErrLimitExceeded)
	}
	envelopeBytes := make([]byte, envelopeLength)
	if _, err := io.ReadFull(file, envelopeBytes); err != nil {
		return nil, Limits{}, fmt.Errorf("%w: read envelope: %v", ErrInvalidFormat, err)
	}
	var envelope Envelope
	if err := unmarshalCanonical(envelopeBytes, &envelope); err != nil {
		return nil, Limits{}, err
	}
	if err := validateEnvelope(envelope, limits); err != nil {
		return nil, Limits{}, err
	}
	envelopeSignature := make([]byte, ed25519.SignatureSize)
	if _, err := io.ReadFull(file, envelopeSignature); err != nil {
		return nil, Limits{}, fmt.Errorf("%w: read envelope signature: %v", ErrInvalidFormat, err)
	}
	ciphertextOffset, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, Limits{}, fmt.Errorf("locate ciphertext: %w", err)
	}
	expectedSize, err := checkedAdd(uint64(ciphertextOffset), envelope.CiphertextSize)
	if err != nil {
		return nil, Limits{}, err
	}
	if expectedSize != uint64(info.Size()) {
		return nil, Limits{}, fmt.Errorf("%w: bundle is truncated or has trailing bytes", ErrInvalidFormat)
	}
	failed = false
	return &parsedBundle{
		file:              file,
		envelope:          envelope,
		envelopeBytes:     envelopeBytes,
		envelopeSignature: envelopeSignature,
		ciphertextOffset:  ciphertextOffset,
		bundleSize:        uint64(info.Size()),
	}, limits, nil
}

// inspectDigests performs one bounded pass over the file, hashing the full
// bundle and its ciphertext section simultaneously. Inspect calls it without
// authenticating the outer signature; AuthenticatePublic calls it only after
// authenticating that signature. Verify instead hashes the same bytes while
// decrypting them.
func inspectDigests(ctx context.Context, parsed *parsedBundle, _ Limits) (Inspection, error) {
	bundleHash, err := hashBundlePrefix(ctx, parsed)
	if err != nil {
		return Inspection{}, err
	}
	ciphertextHash := sha256.New()
	ciphertext := &io.LimitedReader{R: &contextReader{ctx: ctx, reader: parsed.file}, N: int64(parsed.envelope.CiphertextSize)}
	written, err := io.Copy(io.MultiWriter(bundleHash, ciphertextHash), ciphertext)
	if err != nil {
		return Inspection{}, fmt.Errorf("hash ciphertext: %w", err)
	}
	if ciphertext.N != 0 || uint64(written) != parsed.envelope.CiphertextSize {
		return Inspection{}, ErrCiphertextDigest
	}
	return finishInspection(parsed, bundleHash, ciphertextHash)
}

func hashBundlePrefix(ctx context.Context, parsed *parsedBundle) (hash.Hash, error) {
	if _, err := parsed.file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek bundle: %w", err)
	}
	bundleHash := sha256.New()
	prefixHash := sha256.New()
	prefix := &io.LimitedReader{R: &contextReader{ctx: ctx, reader: parsed.file}, N: parsed.ciphertextOffset}
	if _, err := io.Copy(io.MultiWriter(bundleHash, prefixHash), prefix); err != nil {
		return nil, fmt.Errorf("hash bundle prefix: %w", err)
	}
	if prefix.N != 0 {
		return nil, fmt.Errorf("%w: bundle prefix is truncated", ErrInvalidFormat)
	}
	expectedPrefixHash := sha256.New()
	expectedPrefixHash.Write(outerMagic[:])
	var envelopeLength [4]byte
	binary.BigEndian.PutUint32(envelopeLength[:], uint32(len(parsed.envelopeBytes)))
	expectedPrefixHash.Write(envelopeLength[:])
	expectedPrefixHash.Write(parsed.envelopeBytes)
	expectedPrefixHash.Write(parsed.envelopeSignature)
	if !bytes.Equal(prefixHash.Sum(nil), expectedPrefixHash.Sum(nil)) {
		return nil, fmt.Errorf("%w: bundle prefix changed while inspecting", ErrInvalidFormat)
	}
	return bundleHash, nil
}

func finishInspection(parsed *parsedBundle, bundleHash, ciphertextHash hash.Hash) (Inspection, error) {
	if hex.EncodeToString(ciphertextHash.Sum(nil)) != parsed.envelope.CiphertextSHA256 {
		return Inspection{}, ErrCiphertextDigest
	}
	if parsed.bundleSize > MaxBundleBytesV1 {
		return Inspection{}, fmt.Errorf("%w: bundle exceeds maximum size", ErrLimitExceeded)
	}
	finalInfo, statErr := parsed.file.Stat()
	if statErr != nil {
		return Inspection{}, fmt.Errorf("reinspect bundle: %w", statErr)
	}
	currentOffset, seekErr := parsed.file.Seek(0, io.SeekCurrent)
	if seekErr != nil || currentOffset < 0 || uint64(currentOffset) != parsed.bundleSize ||
		finalInfo.Size() < 0 || uint64(finalInfo.Size()) != parsed.bundleSize {
		return Inspection{}, fmt.Errorf("%w: bundle changed while inspecting", ErrInvalidFormat)
	}
	return Inspection{
		Envelope:       parsed.envelope,
		EnvelopeSHA256: digestHex(parsed.envelopeBytes),
		BundleSize:     parsed.bundleSize,
		BundleSHA256:   hex.EncodeToString(bundleHash.Sum(nil)),
	}, nil
}

func readAndVerifyInner(
	ctx context.Context,
	plaintext io.Reader,
	envelope Envelope,
	signingKey ed25519.PublicKey,
	limits Limits,
	destinationRoot string,
	allowedExtensions []string,
) (Manifest, error) {
	var magic [innerMagicSize]byte
	if _, err := io.ReadFull(plaintext, magic[:]); err != nil {
		return Manifest{}, fmt.Errorf("%w: read encrypted inner magic: %v", ErrInvalidFormat, err)
	}
	if magic != innerMagic {
		return Manifest{}, fmt.Errorf("%w: unsupported encrypted inner magic", ErrInvalidFormat)
	}
	var manifestLength uint32
	if err := binary.Read(plaintext, binary.BigEndian, &manifestLength); err != nil {
		return Manifest{}, fmt.Errorf("%w: read manifest length: %v", ErrInvalidFormat, err)
	}
	if manifestLength == 0 || manifestLength > limits.MaxManifestBytes {
		return Manifest{}, fmt.Errorf("%w: manifest length exceeds limit", ErrLimitExceeded)
	}
	manifestBytes := make([]byte, manifestLength)
	if _, err := io.ReadFull(plaintext, manifestBytes); err != nil {
		return Manifest{}, fmt.Errorf("%w: read manifest: %v", ErrInvalidFormat, err)
	}
	var manifest Manifest
	if err := unmarshalCanonical(manifestBytes, &manifest); err != nil {
		return Manifest{}, err
	}
	if err := validateManifest(manifest, limits); err != nil {
		return Manifest{}, err
	}
	manifestSignature := make([]byte, ed25519.SignatureSize)
	if _, err := io.ReadFull(plaintext, manifestSignature); err != nil {
		return Manifest{}, fmt.Errorf("%w: read manifest signature: %v", ErrInvalidFormat, err)
	}
	if !ed25519.Verify(signingKey, signingMessage(manifestSignatureDomain, manifestBytes), manifestSignature) {
		return Manifest{}, fmt.Errorf("%w: inner manifest", ErrSignature)
	}
	if bindingFromManifest(manifest) != bindingFromEnvelope(envelope) ||
		digestHex(manifestBytes) != envelope.InnerManifestSHA256 ||
		uint32(len(manifest.Files)) != envelope.FileCount {
		return Manifest{}, ErrManifestMismatch
	}
	expectedPlaintextSize, err := plaintextSizeForManifest(manifestBytes, manifest.Files)
	if err != nil {
		return Manifest{}, err
	}
	if expectedPlaintextSize != envelope.PlaintextSize {
		return Manifest{}, fmt.Errorf("%w: declared plaintext size is inconsistent", ErrManifestMismatch)
	}
	if destinationRoot != "" {
		if err := validateManifestExtensions(manifest, allowedExtensions); err != nil {
			return Manifest{}, err
		}
	}
	for _, file := range manifest.Files {
		if err := consumeFile(ctx, plaintext, file, destinationRoot); err != nil {
			return Manifest{}, err
		}
	}
	return manifest, nil
}

func validateManifestExtensions(manifest Manifest, allowedExtensions []string) error {
	allowed := make(map[string]struct{}, len(allowedExtensions))
	for _, extension := range allowedExtensions {
		allowed[extension] = struct{}{}
	}
	for _, file := range manifest.Files {
		extension := path.Ext(file.Path)
		if _, ok := allowed[extension]; !ok {
			return fmt.Errorf("%w: %q has extension %q", ErrDisallowedExtension, file.Path, extension)
		}
	}
	return nil
}

// validateAgeHeader places a small independent bound around age's streaming
// header parser. filippo.io/age correctly authenticates its header but accepts
// an arbitrary number and size of stanzas; a public bundle must not be able to
// allocate up to the full ciphertext limit before recipient selection.
func validateAgeHeader(reader io.Reader, expectedRecipients int) error {
	if expectedRecipients < 1 {
		return fmt.Errorf("%w: no signed recipient IDs", ErrInvalidFormat)
	}
	limited := &io.LimitedReader{R: reader, N: maxAgeHeaderBytes + 1}
	buffered := bufio.NewReaderSize(limited, maxAgeHeaderLineBytes)
	readLine := func() ([]byte, error) {
		line, err := buffered.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("%w: age header line exceeds %d bytes", ErrLimitExceeded, maxAgeHeaderLineBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: read age header: %v", ErrInvalidFormat, err)
		}
		return line, nil
	}
	intro, err := readLine()
	if err != nil {
		return err
	}
	if string(intro) != "age-encryption.org/v1\n" {
		return fmt.Errorf("%w: unsupported age header", ErrInvalidFormat)
	}
	recipientCount := 0
	for {
		line, err := readLine()
		if err != nil {
			return err
		}
		switch {
		case bytes.HasPrefix(line, []byte("-> ")):
			if !bytes.HasPrefix(line, []byte("-> mlkem768x25519 ")) {
				return fmt.Errorf("%w: bundle contains a non-hybrid age stanza", ErrInvalidFormat)
			}
			recipientCount++
			if recipientCount > expectedRecipients {
				return fmt.Errorf("%w: age stanza count exceeds signed recipient count", ErrLimitExceeded)
			}
		case bytes.HasPrefix(line, []byte("--- ")):
			if recipientCount != expectedRecipients {
				return fmt.Errorf("%w: age stanza count differs from signed recipient count", ErrInvalidFormat)
			}
			return nil
		default:
			if recipientCount == 0 {
				return fmt.Errorf("%w: malformed age header", ErrInvalidFormat)
			}
		}
	}
}

func plaintextSizeForManifest(manifestBytes []byte, files []File) (uint64, error) {
	values := []uint64{innerMagicSize, 4, uint64(len(manifestBytes)), ed25519.SignatureSize}
	for _, file := range files {
		values = append(values, file.SizeBytes)
	}
	return checkedAdd(values...)
}

func consumeFile(ctx context.Context, plaintext io.Reader, entry File, destinationRoot string) error {
	var destination *os.File
	writer := io.Writer(io.Discard)
	if destinationRoot != "" {
		filePath := filepath.Join(destinationRoot, filepath.FromSlash(entry.Path))
		relative, err := filepath.Rel(destinationRoot, filePath)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return fmt.Errorf("%w: extracted path escaped staging directory", ErrUnsafePath)
		}
		if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
			return fmt.Errorf("create directory for %q: %w", entry.Path, err)
		}
		destination, err = os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("create decrypted file %q: %w", entry.Path, err)
		}
		writer = destination
	}
	hash := sha256.New()
	limited := &io.LimitedReader{R: &contextReader{ctx: ctx, reader: plaintext}, N: int64(entry.SizeBytes)}
	written, copyErr := io.Copy(io.MultiWriter(writer, hash), limited)
	if destination != nil {
		if copyErr == nil {
			copyErr = destination.Sync()
		}
		closeErr := destination.Close()
		if copyErr == nil {
			copyErr = closeErr
		}
	}
	if copyErr != nil {
		return fmt.Errorf("read encrypted file %q: %w", entry.Path, copyErr)
	}
	if limited.N != 0 || uint64(written) != entry.SizeBytes {
		return fmt.Errorf("%w: file %q is truncated", ErrInvalidFormat, entry.Path)
	}
	if hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
		return fmt.Errorf("%w: %s", ErrFileDigest, entry.Path)
	}
	return nil
}

type countingReader struct {
	reader io.Reader
	count  uint64
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	reader.count += uint64(count)
	return count, err
}
