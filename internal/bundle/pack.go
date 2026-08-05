package bundle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"github.com/pythonhk/eventctl/internal/identity"
)

// PackOptions configures PackDirectory. OutputPath must be outside SourceDir
// and must not already exist.
type PackOptions struct {
	SourceDir  string
	OutputPath string
	Binding    Binding
	Recipients []*age.HybridRecipient
	SigningKey ed25519.PrivateKey
	Limits     Limits
}

type sourceFile struct {
	manifest File
}

type recipientAndID struct {
	recipient *age.HybridRecipient
	keyID     string
}

// PackDirectory signs a canonical file manifest, encrypts it and the regular
// file contents to age hybrid ML-KEM-768+X25519 recipients, signs the
// ciphertext envelope, and
// atomically publishes a mode-0600 bundle on Unix without overwriting an
// existing path. On Windows, age encryption is the confidentiality boundary;
// os.Chmod does not configure a private DACL.
func PackDirectory(ctx context.Context, options PackOptions) (Packed, error) {
	limits, err := normalizeLimits(options.Limits)
	if err != nil {
		return Packed{}, err
	}
	if err := validateSigningKey(options.SigningKey); err != nil {
		return Packed{}, err
	}
	publicKey := options.SigningKey.Public().(ed25519.PublicKey)
	signerKeyID := identity.KeyID(publicKey)
	if options.Binding.KeyID == "" {
		options.Binding.KeyID = signerKeyID
	}
	if options.Binding.KeyID != signerKeyID {
		return Packed{}, fmt.Errorf("signing key ID does not match binding key_id")
	}
	if err := validateBinding(options.Binding, limits.MaxValidity); err != nil {
		return Packed{}, err
	}
	if options.SourceDir == "" || options.OutputPath == "" {
		return Packed{}, fmt.Errorf("source directory and output path are required")
	}
	if err := ensureOutputOutsideSource(options.SourceDir, options.OutputPath); err != nil {
		return Packed{}, err
	}
	sourceInfo, err := os.Lstat(options.SourceDir)
	if err != nil {
		return Packed{}, fmt.Errorf("inspect source directory: %w", err)
	}
	if sourceInfo.Mode()&os.ModeSymlink != 0 || !sourceInfo.IsDir() {
		return Packed{}, fmt.Errorf("%w: source must be a real directory", ErrUnsafePath)
	}
	sourceRoot, err := os.OpenRoot(options.SourceDir)
	if err != nil {
		return Packed{}, fmt.Errorf("open confined source root: %w", err)
	}
	defer sourceRoot.Close()
	openedSourceInfo, err := sourceRoot.Stat(".")
	if err != nil || !openedSourceInfo.IsDir() || !os.SameFile(sourceInfo, openedSourceInfo) {
		return Packed{}, fmt.Errorf("%w: source directory changed while opening", ErrSourceChanged)
	}
	if _, err := os.Lstat(options.OutputPath); err == nil {
		return Packed{}, fmt.Errorf("%w: %s", ErrDestinationExists, options.OutputPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Packed{}, fmt.Errorf("inspect output path: %w", err)
	}

	recipients, err := normalizeRecipients(options.Recipients, limits)
	if err != nil {
		return Packed{}, err
	}
	files, totalBytes, err := collectSourceFiles(ctx, sourceRoot, limits)
	if err != nil {
		return Packed{}, err
	}
	manifest := manifestFromBinding(options.Binding, make([]File, len(files)))
	for index := range files {
		manifest.Files[index] = files[index].manifest
	}
	if err := validateManifest(manifest, limits); err != nil {
		return Packed{}, err
	}
	manifestBytes, err := marshalCanonical(manifest)
	if err != nil {
		return Packed{}, err
	}
	if uint64(len(manifestBytes)) > uint64(limits.MaxManifestBytes) {
		return Packed{}, fmt.Errorf("%w: manifest exceeds %d bytes", ErrLimitExceeded, limits.MaxManifestBytes)
	}
	manifestSignature := ed25519.Sign(options.SigningKey, signingMessage(manifestSignatureDomain, manifestBytes))
	plaintextSize, err := checkedAdd(
		innerMagicSize,
		4,
		uint64(len(manifestBytes)),
		ed25519.SignatureSize,
		totalBytes,
	)
	if err != nil {
		return Packed{}, err
	}
	if plaintextSize > limits.MaxPlaintextBytes {
		return Packed{}, fmt.Errorf("%w: plaintext exceeds %d bytes", ErrLimitExceeded, limits.MaxPlaintextBytes)
	}

	outputDirectory := filepath.Dir(options.OutputPath)
	workDirectory, err := os.MkdirTemp(outputDirectory, ".eventctl-work-*")
	if err != nil {
		return Packed{}, fmt.Errorf("create private bundle work directory: %w", err)
	}
	defer os.RemoveAll(workDirectory)
	if err := os.Chmod(workDirectory, 0o700); err != nil {
		return Packed{}, fmt.Errorf("secure private bundle work directory: %w", err)
	}
	ciphertextPath := filepath.Join(workDirectory, "ciphertext.tmp")
	ciphertextFile, err := os.OpenFile(ciphertextPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return Packed{}, fmt.Errorf("create ciphertext temporary file: %w", err)
	}
	defer ciphertextFile.Close()

	ageRecipients := make([]age.Recipient, len(recipients))
	for index := range recipients {
		ageRecipients[index] = recipients[index].recipient
	}
	encryptedWriter, err := age.Encrypt(ciphertextFile, ageRecipients...)
	if err != nil {
		return Packed{}, fmt.Errorf("initialize age encryption: %w", err)
	}
	writeErr := writeInnerPayload(ctx, encryptedWriter, sourceRoot, files, manifestBytes, manifestSignature)
	closeEncryptionErr := encryptedWriter.Close()
	if writeErr != nil {
		return Packed{}, writeErr
	}
	if closeEncryptionErr != nil {
		return Packed{}, fmt.Errorf("finalize age encryption: %w", closeEncryptionErr)
	}
	if err := ciphertextFile.Sync(); err != nil {
		return Packed{}, fmt.Errorf("sync ciphertext: %w", err)
	}

	ciphertextSize, ciphertextDigest, err := digestOpenRegularFile(ciphertextFile, limits.MaxCiphertextBytes)
	if err != nil {
		return Packed{}, fmt.Errorf("inspect ciphertext: %w", err)
	}
	recipientKeyIDs := make([]string, len(recipients))
	for index := range recipients {
		recipientKeyIDs[index] = recipients[index].keyID
	}
	envelope := envelopeFromBinding(options.Binding)
	envelope.RecipientKeyIDs = recipientKeyIDs
	envelope.InnerManifestSHA256 = digestHex(manifestBytes)
	envelope.FileCount = uint32(len(files))
	envelope.PlaintextSize = plaintextSize
	envelope.CiphertextSize = ciphertextSize
	envelope.CiphertextSHA256 = ciphertextDigest
	envelope.Encryption = EncryptionAlgorithm
	envelope.SignatureAlgorithm = identity.Algorithm
	if err := validateEnvelope(envelope, limits); err != nil {
		return Packed{}, err
	}
	envelopeBytes, err := marshalCanonical(envelope)
	if err != nil {
		return Packed{}, err
	}
	if uint64(len(envelopeBytes)) > uint64(limits.MaxEnvelopeBytes) {
		return Packed{}, fmt.Errorf("%w: envelope exceeds %d bytes", ErrLimitExceeded, limits.MaxEnvelopeBytes)
	}
	envelopeSignature := ed25519.Sign(options.SigningKey, signingMessage(envelopeSignatureDomain, envelopeBytes))
	bundleSize, bundleDigest, err := publishBundle(
		ctx,
		options.OutputPath,
		envelopeBytes,
		envelopeSignature,
		ciphertextFile,
		workDirectory,
		MaxBundleBytesV1,
	)
	if err != nil {
		return Packed{}, err
	}
	return Packed{
		Verified: Verified{
			Envelope:       envelope,
			Manifest:       manifest,
			EnvelopeSHA256: digestHex(envelopeBytes),
			BundleSize:     bundleSize,
			BundleSHA256:   bundleDigest,
		},
	}, nil
}

func normalizeRecipients(input []*age.HybridRecipient, limits Limits) ([]recipientAndID, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("%w: at least one hybrid ML-KEM-768+X25519 recipient is required", ErrNoRecipient)
	}
	if uint64(len(input)) > uint64(limits.MaxRecipients) {
		return nil, fmt.Errorf("%w: recipient count exceeds %d", ErrLimitExceeded, limits.MaxRecipients)
	}
	recipients := make([]recipientAndID, len(input))
	for index, recipient := range input {
		if recipient == nil {
			return nil, fmt.Errorf("recipient %d is nil", index)
		}
		encoded := recipient.String()
		if !strings.HasPrefix(encoded, "age1pq1") {
			return nil, fmt.Errorf("recipient %d is not an age hybrid ML-KEM-768+X25519 recipient", index)
		}
		recipients[index] = recipientAndID{recipient: recipient, keyID: ageRecipientKeyID(encoded)}
	}
	sort.Slice(recipients, func(left, right int) bool {
		return recipients[left].keyID < recipients[right].keyID
	})
	for index := 1; index < len(recipients); index++ {
		if recipients[index-1].keyID == recipients[index].keyID {
			return nil, fmt.Errorf("duplicate recipient %s", recipients[index].keyID)
		}
	}
	return recipients, nil
}

func ensureOutputOutsideSource(sourceDirectory, outputPath string) error {
	sourceAbsolute, err := filepath.Abs(sourceDirectory)
	if err != nil {
		return fmt.Errorf("resolve source directory: %w", err)
	}
	outputAbsolute, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	resolvedSource, err := filepath.EvalSymlinks(sourceAbsolute)
	if err != nil {
		return fmt.Errorf("resolve source directory symlinks: %w", err)
	}
	resolvedOutputParent, err := filepath.EvalSymlinks(filepath.Dir(outputAbsolute))
	if err != nil {
		return fmt.Errorf("resolve output directory symlinks: %w", err)
	}
	resolvedOutput := filepath.Join(resolvedOutputParent, filepath.Base(outputAbsolute))
	relative, err := filepath.Rel(resolvedSource, resolvedOutput)
	if err != nil {
		return fmt.Errorf("compare source and output paths: %w", err)
	}
	if relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: output must be outside the source directory", ErrUnsafePath)
	}
	return nil
}

func collectSourceFiles(ctx context.Context, sourceRoot *os.Root, limits Limits) ([]sourceFile, uint64, error) {
	files := make([]sourceFile, 0, 256)
	paths := newPortablePathSet()
	directories := []string{"."}
	var directoryCount uint64 = 1
	var total uint64
	for len(directories) != 0 {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		directoryPath := directories[len(directories)-1]
		directories = directories[:len(directories)-1]
		directory, err := sourceRoot.Open(filepath.FromSlash(directoryPath))
		if err != nil {
			return nil, 0, fmt.Errorf("open source directory %q: %w", directoryPath, err)
		}
		info, err := directory.Stat()
		if err != nil || !info.IsDir() {
			directory.Close()
			return nil, 0, fmt.Errorf("%w: source directory changed at %q", ErrSourceChanged, directoryPath)
		}
		for {
			entries, readErr := directory.ReadDir(128)
			for _, entry := range entries {
				if err := ctx.Err(); err != nil {
					directory.Close()
					return nil, 0, err
				}
				filePath := pathJoin(directoryPath, entry.Name())
				rootPath := filepath.FromSlash(filePath)
				entryInfo, err := sourceRoot.Lstat(rootPath)
				if err != nil {
					directory.Close()
					return nil, 0, fmt.Errorf("inspect source entry %q: %w", filePath, err)
				}
				if entryInfo.Mode()&os.ModeSymlink != 0 {
					directory.Close()
					return nil, 0, fmt.Errorf("%w: source contains symlink %q", ErrUnsafePath, filePath)
				}
				if entryInfo.IsDir() {
					directoryCount++
					if directoryCount > uint64(limits.MaxFiles)+1 {
						directory.Close()
						return nil, 0, fmt.Errorf("%w: source contains too many directories", ErrLimitExceeded)
					}
					directories = append(directories, filePath)
					continue
				}
				if !entryInfo.Mode().IsRegular() {
					directory.Close()
					return nil, 0, fmt.Errorf("%w: source contains non-regular file %q", ErrUnsafePath, filePath)
				}
				if uint64(len(files)) >= uint64(limits.MaxFiles) {
					directory.Close()
					return nil, 0, fmt.Errorf("%w: source contains more than %d files", ErrLimitExceeded, limits.MaxFiles)
				}
				if entryInfo.Size() < 0 || uint64(entryInfo.Size()) > limits.MaxFileBytes {
					directory.Close()
					return nil, 0, fmt.Errorf("%w: %q exceeds maximum file size", ErrLimitExceeded, filePath)
				}
				archivePath := filepath.ToSlash(filePath)
				if err := validateArchivePath(archivePath); err != nil {
					directory.Close()
					return nil, 0, err
				}
				if err := paths.add(archivePath); err != nil {
					directory.Close()
					return nil, 0, err
				}
				total, err = checkedAdd(total, uint64(entryInfo.Size()))
				if err != nil || total > limits.MaxTotalFileBytes {
					directory.Close()
					return nil, 0, fmt.Errorf("%w: source exceeds maximum total size", ErrLimitExceeded)
				}
				files = append(files, sourceFile{manifest: File{Path: archivePath, SizeBytes: uint64(entryInfo.Size())}})
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				directory.Close()
				return nil, 0, fmt.Errorf("read source directory %q: %w", directoryPath, readErr)
			}
		}
		if err := directory.Close(); err != nil {
			return nil, 0, fmt.Errorf("close source directory %q: %w", directoryPath, err)
		}
	}
	if len(files) == 0 {
		return nil, 0, fmt.Errorf("source directory contains no regular files")
	}
	sort.Slice(files, func(left, right int) bool {
		return files[left].manifest.Path < files[right].manifest.Path
	})
	for index := range files {
		rootPath := filepath.FromSlash(files[index].manifest.Path)
		expectedInfo, err := sourceRoot.Lstat(rootPath)
		if err != nil || !expectedInfo.Mode().IsRegular() || expectedInfo.Size() < 0 || uint64(expectedInfo.Size()) != files[index].manifest.SizeBytes {
			return nil, 0, fmt.Errorf("%w: %q", ErrSourceChanged, files[index].manifest.Path)
		}
		digest, err := hashSourceFile(ctx, sourceRoot, rootPath, expectedInfo)
		if err != nil {
			return nil, 0, err
		}
		files[index].manifest.SHA256 = digest
	}
	return files, total, nil
}

func pathJoin(parent, name string) string {
	if parent == "." {
		return name
	}
	return parent + "/" + name
}

func hashSourceFile(ctx context.Context, sourceRoot *os.Root, filePath string, expectedInfo os.FileInfo) (string, error) {
	file, err := sourceRoot.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open source file %q: %w", filePath, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect source file %q: %w", filePath, err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(expectedInfo, info) || info.Size() != expectedInfo.Size() {
		return "", fmt.Errorf("%w: %q", ErrSourceChanged, filePath)
	}
	hash := sha256.New()
	read := &contextReader{ctx: ctx, reader: file}
	written, err := io.Copy(hash, io.LimitReader(read, expectedInfo.Size()+1))
	if err != nil {
		return "", fmt.Errorf("hash source file %q: %w", filePath, err)
	}
	if written != expectedInfo.Size() {
		return "", fmt.Errorf("%w: %q", ErrSourceChanged, filePath)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeInnerPayload(
	ctx context.Context,
	destination io.Writer,
	sourceRoot *os.Root,
	files []sourceFile,
	manifestBytes []byte,
	manifestSignature []byte,
) error {
	if _, err := destination.Write(innerMagic[:]); err != nil {
		return fmt.Errorf("write encrypted inner magic: %w", err)
	}
	if err := binary.Write(destination, binary.BigEndian, uint32(len(manifestBytes))); err != nil {
		return fmt.Errorf("write encrypted manifest length: %w", err)
	}
	if _, err := destination.Write(manifestBytes); err != nil {
		return fmt.Errorf("write encrypted manifest: %w", err)
	}
	if _, err := destination.Write(manifestSignature); err != nil {
		return fmt.Errorf("write encrypted manifest signature: %w", err)
	}
	for _, source := range files {
		if err := copySourceFile(ctx, destination, sourceRoot, source); err != nil {
			return err
		}
	}
	return nil
}

func copySourceFile(ctx context.Context, destination io.Writer, sourceRoot *os.Root, source sourceFile) error {
	expectedPath := filepath.FromSlash(source.manifest.Path)
	fileInfo, err := sourceRoot.Lstat(expectedPath)
	if err != nil {
		return fmt.Errorf("inspect source file %q: %w", source.manifest.Path, err)
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() || uint64(fileInfo.Size()) != source.manifest.SizeBytes {
		return fmt.Errorf("%w: %q", ErrSourceChanged, source.manifest.Path)
	}
	file, err := sourceRoot.Open(expectedPath)
	if err != nil {
		return fmt.Errorf("open source file %q: %w", source.manifest.Path, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(fileInfo, openedInfo) {
		return fmt.Errorf("%w: %q", ErrSourceChanged, source.manifest.Path)
	}
	hash := sha256.New()
	limited := &io.LimitedReader{R: &contextReader{ctx: ctx, reader: file}, N: int64(source.manifest.SizeBytes) + 1}
	written, err := io.Copy(io.MultiWriter(destination, hash), limited)
	if err != nil {
		return fmt.Errorf("encrypt source file %q: %w", source.manifest.Path, err)
	}
	if uint64(written) != source.manifest.SizeBytes || hex.EncodeToString(hash.Sum(nil)) != source.manifest.SHA256 {
		return fmt.Errorf("%w: %q", ErrSourceChanged, source.manifest.Path)
	}
	return nil
}

func digestOpenRegularFile(file *os.File, maximum uint64) (uint64, string, error) {
	if maximum >= math.MaxInt64 {
		return 0, "", fmt.Errorf("%w: hash limit does not fit a signed 64-bit reader", ErrLimitExceeded)
	}
	info, err := file.Stat()
	if err != nil {
		return 0, "", err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) > maximum {
		return 0, "", fmt.Errorf("%w: invalid file size", ErrLimitExceeded)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, "", err
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return 0, "", err
	}
	finalInfo, err := file.Stat()
	if err != nil {
		return 0, "", err
	}
	if uint64(written) > maximum || written != info.Size() || finalInfo.Size() != info.Size() {
		return 0, "", fmt.Errorf("%w: file changed or grew while hashing", ErrLimitExceeded)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, "", err
	}
	return uint64(written), hex.EncodeToString(hash.Sum(nil)), nil
}

func publishBundle(
	ctx context.Context,
	outputPath string,
	envelopeBytes, envelopeSignature []byte,
	ciphertext *os.File,
	workDirectory string,
	maximumBundleSize uint64,
) (uint64, string, error) {
	temporaryPath := filepath.Join(workDirectory, "bundle.tmp")
	temporary, err := os.OpenFile(temporaryPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return 0, "", fmt.Errorf("create bundle temporary file: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			temporary.Close()
		}
	}()
	if _, err := temporary.Write(outerMagic[:]); err != nil {
		temporary.Close()
		return 0, "", fmt.Errorf("write bundle magic: %w", err)
	}
	if err := binary.Write(temporary, binary.BigEndian, uint32(len(envelopeBytes))); err != nil {
		temporary.Close()
		return 0, "", fmt.Errorf("write envelope length: %w", err)
	}
	if _, err := temporary.Write(envelopeBytes); err != nil {
		temporary.Close()
		return 0, "", fmt.Errorf("write envelope: %w", err)
	}
	if _, err := temporary.Write(envelopeSignature); err != nil {
		temporary.Close()
		return 0, "", fmt.Errorf("write envelope signature: %w", err)
	}
	if _, err := ciphertext.Seek(0, io.SeekStart); err != nil {
		return 0, "", fmt.Errorf("seek ciphertext: %w", err)
	}
	_, copyErr := io.Copy(temporary, &contextReader{ctx: ctx, reader: ciphertext})
	if copyErr != nil {
		return 0, "", fmt.Errorf("write ciphertext: %w", copyErr)
	}
	if err := temporary.Sync(); err != nil {
		return 0, "", fmt.Errorf("sync bundle: %w", err)
	}
	bundleSize, bundleDigest, err := digestOpenRegularFile(temporary, maximumBundleSize)
	if err != nil {
		return 0, "", fmt.Errorf("hash completed bundle: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return 0, "", fmt.Errorf("close bundle: %w", err)
	}
	closed = true
	// The source lives in a private mode-0700 directory under the output
	// directory. A hard link atomically publishes the exact inode and refuses
	// replacement on Unix and Windows alike.
	if err := os.Link(temporaryPath, outputPath); err != nil {
		if _, statErr := os.Lstat(outputPath); statErr == nil {
			return 0, "", fmt.Errorf("%w: %s", ErrDestinationExists, outputPath)
		}
		return 0, "", fmt.Errorf("publish bundle atomically: %w", err)
	}
	// Publication is complete after Link succeeds. Cleanup failure must not turn
	// success into a retry that collides with the already-published output.
	_ = os.Remove(temporaryPath)
	return bundleSize, bundleDigest, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
