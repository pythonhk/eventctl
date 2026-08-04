// Package keystore encrypts private-key documents for storage on disk.
//
// Passphrases are supplied by callers as byte slices. This package never reads
// them from process arguments or the environment and never includes them in an
// error. Callers remain responsible for obtaining passphrases from a terminal
// or inherited file descriptor and clearing their own buffers when practical.
// The age API accepts passphrases as strings, so an immutable internal copy can
// remain until garbage collection. On Windows, age encryption is the
// confidentiality boundary because os.Chmod does not configure Windows ACLs.
package keystore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	"filippo.io/age"
)

const scryptWorkFactor = 18

var (
	ErrAuthentication    = errors.New("keystore authentication failed")
	ErrDestinationExists = errors.New("keystore destination already exists")
	ErrInvalidFormat     = errors.New("invalid keystore ciphertext")
	ErrLimitExceeded     = errors.New("keystore size limit exceeded")
)

// Limits bounds private-key plaintext and attacker-controlled ciphertext.
// The zero value selects DefaultLimits. If either field is set, both must be
// positive.
type Limits struct {
	MaxPlaintextBytes  uint64
	MaxCiphertextBytes uint64
}

// DefaultLimits returns conservative bounds for private-key documents. The
// ciphertext allowance covers age framing and chunk authentication overhead.
func DefaultLimits() Limits {
	return Limits{
		MaxPlaintextBytes:  1024 * 1024,
		MaxCiphertextBytes: 2 * 1024 * 1024,
	}
}

// EncryptFile encrypts plaintext with an age scrypt recipient and atomically
// publishes a mode-0600 file at outputPath. outputPath must not already exist.
// The age writer is always closed after a successful initialization so its
// authenticated final chunk is emitted before publication.
func EncryptFile(
	ctx context.Context,
	outputPath string,
	plaintext []byte,
	passphrase []byte,
	requestedLimits Limits,
) error {
	limits, err := normalizeLimits(requestedLimits)
	if err != nil {
		return err
	}
	if err := validatePassphrase(passphrase); err != nil {
		return err
	}
	if uint64(len(plaintext)) > limits.MaxPlaintextBytes {
		return fmt.Errorf("%w: plaintext exceeds %d bytes", ErrLimitExceeded, limits.MaxPlaintextBytes)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateDestination(outputPath); err != nil {
		return err
	}
	if _, err := os.Lstat(outputPath); err == nil {
		return fmt.Errorf("%w: %s", ErrDestinationExists, outputPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect keystore destination: %w", err)
	}

	parent := filepath.Dir(outputPath)
	base := filepath.Base(filepath.Clean(outputPath))
	workDirectory, err := os.MkdirTemp(parent, "."+base+".eventctl-work-*")
	if err != nil {
		return fmt.Errorf("create private keystore work directory: %w", err)
	}
	defer os.RemoveAll(workDirectory)
	if err := os.Chmod(workDirectory, 0o700); err != nil {
		return fmt.Errorf("secure private keystore work directory: %w", err)
	}
	temporaryPath := filepath.Join(workDirectory, "identity.age")
	temporary, err := os.OpenFile(temporaryPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create keystore temporary file: %w", err)
	}

	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		temporary.Close()
		return fmt.Errorf("initialize keystore recipient: %w", err)
	}
	recipient.SetWorkFactor(scryptWorkFactor)
	encrypted, err := age.Encrypt(temporary, recipient)
	if err != nil {
		temporary.Close()
		return fmt.Errorf("initialize keystore encryption: %w", err)
	}
	_, writeErr := io.Copy(encrypted, &contextReader{ctx: ctx, reader: bytes.NewReader(plaintext)})
	closeEncryptionErr := encrypted.Close()
	if writeErr != nil {
		temporary.Close()
		return fmt.Errorf("encrypt keystore document: %w", writeErr)
	}
	if closeEncryptionErr != nil {
		temporary.Close()
		return fmt.Errorf("finalize keystore encryption: %w", closeEncryptionErr)
	}
	if err := ctx.Err(); err != nil {
		temporary.Close()
		return err
	}
	info, err := temporary.Stat()
	if err != nil {
		temporary.Close()
		return fmt.Errorf("inspect encrypted keystore: %w", err)
	}
	if info.Size() < 0 || uint64(info.Size()) > limits.MaxCiphertextBytes {
		temporary.Close()
		return fmt.Errorf("%w: ciphertext exceeds %d bytes", ErrLimitExceeded, limits.MaxCiphertextBytes)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync encrypted keystore: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close encrypted keystore: %w", err)
	}

	// A hard link within the destination directory is an atomic, no-replace
	// publication primitive. Unlike os.Rename on Unix, it cannot overwrite a
	// path created after the initial existence check.
	if err := publishExclusive(temporaryPath, outputPath); err != nil {
		return err
	}
	return nil
}

// DecryptFile decrypts and authenticates the complete age stream at inputPath.
// It returns plaintext only after observing authenticated EOF, including the
// absence of trailing ciphertext.
func DecryptFile(
	ctx context.Context,
	inputPath string,
	passphrase []byte,
	requestedLimits Limits,
) ([]byte, error) {
	limits, err := normalizeLimits(requestedLimits)
	if err != nil {
		return nil, err
	}
	if err := validatePassphrase(passphrase); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ciphertext, err := os.Open(inputPath)
	if err != nil {
		return nil, fmt.Errorf("open encrypted keystore: %w", err)
	}
	defer ciphertext.Close()
	info, err := ciphertext.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect encrypted keystore: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return nil, fmt.Errorf("%w: ciphertext is not a regular file", ErrInvalidFormat)
	}
	if uint64(info.Size()) > limits.MaxCiphertextBytes {
		return nil, fmt.Errorf("%w: ciphertext exceeds %d bytes", ErrLimitExceeded, limits.MaxCiphertextBytes)
	}

	identity, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, fmt.Errorf("initialize keystore identity: %w", err)
	}
	identity.SetMaxWorkFactor(scryptWorkFactor)
	boundedCiphertext := &io.LimitedReader{R: &contextReader{ctx: ctx, reader: ciphertext}, N: info.Size()}
	decrypted, err := age.Decrypt(boundedCiphertext, identity)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, ErrAuthentication
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidFormat, err)
	}

	boundedPlaintext := &io.LimitedReader{R: decrypted, N: int64(limits.MaxPlaintextBytes) + 1}
	plaintext, err := io.ReadAll(boundedPlaintext)
	if err != nil {
		clear(plaintext)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	if uint64(len(plaintext)) > limits.MaxPlaintextBytes {
		clear(plaintext)
		return nil, fmt.Errorf("%w: plaintext exceeds %d bytes", ErrLimitExceeded, limits.MaxPlaintextBytes)
	}
	if boundedCiphertext.N != 0 {
		clear(plaintext)
		return nil, fmt.Errorf("%w: ciphertext did not reach authenticated EOF", ErrInvalidFormat)
	}
	return plaintext, nil
}

func publishExclusive(sourcePath, destinationPath string) error {
	if err := os.Link(sourcePath, destinationPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrDestinationExists, destinationPath)
		}
		return fmt.Errorf("publish encrypted keystore atomically: %w", err)
	}
	return nil
}

func normalizeLimits(limits Limits) (Limits, error) {
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	if limits.MaxPlaintextBytes == 0 || limits.MaxCiphertextBytes == 0 {
		return Limits{}, fmt.Errorf("%w: both limits must be positive", ErrLimitExceeded)
	}
	if limits.MaxPlaintextBytes >= math.MaxInt64 || limits.MaxCiphertextBytes >= math.MaxInt64 {
		return Limits{}, fmt.Errorf("%w: limits must fit signed 64-bit readers", ErrLimitExceeded)
	}
	return limits, nil
}

func validatePassphrase(passphrase []byte) error {
	if len(passphrase) == 0 {
		return errors.New("keystore passphrase must not be empty")
	}
	return nil
}

func validateDestination(path string) error {
	if path == "" {
		return errors.New("keystore destination is required")
	}
	base := filepath.Base(filepath.Clean(path))
	if base == "." || base == string(filepath.Separator) {
		return errors.New("keystore destination must name a file")
	}
	return nil
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
