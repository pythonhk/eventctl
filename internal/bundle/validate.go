package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/pythonhk/eventctl/internal/canonical"
	protocolenvelope "github.com/pythonhk/eventctl/internal/envelope"
	"github.com/pythonhk/eventctl/internal/identity"
)

const maxArchivePathBytes = 255

func marshalCanonical(value any) ([]byte, error) {
	encoded, err := canonical.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode canonical JSON: %w", err)
	}
	return encoded, nil
}

func unmarshalCanonical(data []byte, value any) error {
	canonicalData, err := canonical.Canonicalize(data)
	if err != nil {
		return fmt.Errorf("%w: decode canonical JSON: %v", ErrInvalidFormat, err)
	}
	if !bytes.Equal(data, canonicalData) {
		return fmt.Errorf("%w: JSON is not in canonical eventctl encoding", ErrInvalidFormat)
	}
	if err := canonical.StrictUnmarshal(data, value); err != nil {
		return fmt.Errorf("%w: decode canonical JSON: %v", ErrInvalidFormat, err)
	}
	return nil
}

func validateBinding(binding Binding) error {
	if !protocolenvelope.IsEventID(binding.EventID) {
		return fmt.Errorf("%w: event_id is invalid", ErrInvalidFormat)
	}
	if err := identity.ValidateDecimal(binding.EventEpoch, "event_epoch"); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidFormat, err)
	}
	if !protocolenvelope.IsUUID(binding.RequestID) || !protocolenvelope.IsUUID(binding.AttemptID) {
		return fmt.Errorf("%w: request_id and attempt_id must be lower-case UUIDv4 values", ErrInvalidFormat)
	}
	if !isCanonicalDecimalID(binding.BaseRepositoryID) {
		return fmt.Errorf("%w: base_repository_id must be a positive canonical decimal string of at most 20 digits", ErrInvalidFormat)
	}
	if !isCanonicalDecimalID(binding.ActorID) {
		return fmt.Errorf("%w: actor_id must be a positive canonical decimal string of at most 20 digits", ErrInvalidFormat)
	}
	if !identity.IsDigest(binding.KeyID) || !identity.IsDigest(binding.ConfigDigest) {
		return fmt.Errorf("%w: key_id and config_digest must be lowercase SHA-256 digests", ErrInvalidFormat)
	}
	if err := identity.ValidateDecimal(binding.KeyEpoch, "key_epoch"); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidFormat, err)
	}
	if !protocolenvelope.IsUUID(binding.TeamID) {
		return fmt.Errorf("%w: team_id must be a lower-case UUIDv4", ErrInvalidFormat)
	}
	if !identity.IsDigest(binding.TeamProposalDigest) {
		return fmt.Errorf("%w: team_proposal_digest must be a lowercase SHA-256 digest", ErrInvalidFormat)
	}
	if err := identity.ValidateDecimal(binding.RecipientEpoch, "recipient_epoch"); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidFormat, err)
	}
	if err := protocolenvelope.ValidateWindow(binding.IssuedAt, binding.ExpiresAt, time.Time{}); err != nil {
		return fmt.Errorf("%w: invalid validity window: %v", ErrInvalidFormat, err)
	}
	return nil
}

func isCanonicalDecimalID(value string) bool {
	if len(value) == 0 || len(value) > 20 || value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validateManifest(manifest Manifest, limits Limits) error {
	if manifest.Kind != ManifestKind || manifest.Protocol != Protocol || manifest.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: unsupported manifest discriminator", ErrInvalidFormat)
	}
	if err := validateBinding(bindingFromManifest(manifest)); err != nil {
		return err
	}
	if len(manifest.Files) == 0 {
		return fmt.Errorf("%w: manifest has no files", ErrInvalidFormat)
	}
	if uint64(len(manifest.Files)) > uint64(limits.MaxFiles) {
		return fmt.Errorf("%w: manifest file count exceeds %d", ErrLimitExceeded, limits.MaxFiles)
	}
	var total uint64
	paths := newPortablePathSet()
	for index, file := range manifest.Files {
		if err := validateArchivePath(file.Path); err != nil {
			return fmt.Errorf("file %d: %w", index, err)
		}
		if file.SizeBytes > limits.MaxFileBytes {
			return fmt.Errorf("%w: %q exceeds maximum file size", ErrLimitExceeded, file.Path)
		}
		if !isLowerHex(file.SHA256, sha256.Size*2) {
			return fmt.Errorf("%w: %q has an invalid SHA-256 digest", ErrInvalidFormat, file.Path)
		}
		var err error
		total, err = checkedAdd(total, file.SizeBytes)
		if err != nil || total > limits.MaxTotalFileBytes {
			return fmt.Errorf("%w: total file size exceeds %d", ErrLimitExceeded, limits.MaxTotalFileBytes)
		}
		if index > 0 {
			previous := manifest.Files[index-1].Path
			if previous >= file.Path {
				return fmt.Errorf("%w: file paths are duplicated or not strictly sorted", ErrInvalidFormat)
			}
		}
		if err := paths.add(file.Path); err != nil {
			return err
		}
	}
	return nil
}

func validateEnvelope(envelope Envelope, limits Limits) error {
	if envelope.Kind != EnvelopeKind || envelope.Protocol != Protocol || envelope.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: unsupported envelope discriminator", ErrInvalidFormat)
	}
	if err := validateBinding(bindingFromEnvelope(envelope)); err != nil {
		return err
	}
	if envelope.Encryption != EncryptionAlgorithm || envelope.SignatureAlgorithm != identity.Algorithm {
		return fmt.Errorf("%w: unsupported cryptographic algorithms", ErrInvalidFormat)
	}
	if !isLowerHex(envelope.InnerManifestSHA256, sha256.Size*2) ||
		!isLowerHex(envelope.CiphertextSHA256, sha256.Size*2) {
		return fmt.Errorf("%w: envelope contains an invalid digest", ErrInvalidFormat)
	}
	if len(envelope.RecipientKeyIDs) == 0 || uint64(len(envelope.RecipientKeyIDs)) > uint64(limits.MaxRecipients) {
		return fmt.Errorf("%w: invalid recipient count", ErrLimitExceeded)
	}
	for index, keyID := range envelope.RecipientKeyIDs {
		if !isLowerHex(keyID, sha256.Size*2) {
			return fmt.Errorf("%w: invalid recipient key ID", ErrInvalidFormat)
		}
		if index > 0 && envelope.RecipientKeyIDs[index-1] >= keyID {
			return fmt.Errorf("%w: recipient key IDs are duplicated or not sorted", ErrInvalidFormat)
		}
	}
	if envelope.FileCount == 0 || envelope.FileCount > limits.MaxFiles {
		return fmt.Errorf("%w: invalid file count", ErrLimitExceeded)
	}
	if envelope.PlaintextSize == 0 || envelope.PlaintextSize > limits.MaxPlaintextBytes {
		return fmt.Errorf("%w: invalid plaintext size", ErrLimitExceeded)
	}
	if envelope.CiphertextSize == 0 || envelope.CiphertextSize > limits.MaxCiphertextBytes {
		return fmt.Errorf("%w: invalid ciphertext size", ErrLimitExceeded)
	}
	return nil
}

type portablePathNode struct {
	children map[string]*portablePathNode
	filePath string
}

type portablePathSet struct {
	root portablePathNode
}

func newPortablePathSet() *portablePathSet {
	return &portablePathSet{root: portablePathNode{children: make(map[string]*portablePathNode)}}
}

// add rejects exact, ASCII-case-folded, and file/directory prefix collisions
// in O(number of path segments). validateArchivePath has already restricted
// paths to ASCII, so strings.ToLower is the complete portable case fold.
func (paths *portablePathSet) add(filePath string) error {
	node := &paths.root
	for _, segment := range strings.Split(filePath, "/") {
		if node.filePath != "" {
			return fmt.Errorf("%w: file and directory paths collide at %q and %q", ErrUnsafePath, node.filePath, filePath)
		}
		folded := strings.ToLower(segment)
		next := node.children[folded]
		if next == nil {
			next = &portablePathNode{children: make(map[string]*portablePathNode)}
			node.children[folded] = next
		}
		node = next
	}
	if node.filePath != "" {
		return fmt.Errorf("%w: case-colliding paths %q and %q", ErrUnsafePath, node.filePath, filePath)
	}
	if len(node.children) != 0 {
		return fmt.Errorf("%w: file and directory paths collide at %q", ErrUnsafePath, filePath)
	}
	node.filePath = filePath
	return nil
}

func validateArchivePath(value string) error {
	if value == "" || len(value) > maxArchivePathBytes || !utf8.ValidString(value) {
		return fmt.Errorf("%w: path is empty, too long, or invalid UTF-8", ErrUnsafePath)
	}
	if strings.ContainsRune(value, 0) || strings.Contains(value, "\\") || strings.Contains(value, ":") ||
		strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || path.IsAbs(value) || path.Clean(value) != value {
		return fmt.Errorf("%w: %q is absolute, traversing, or non-canonical", ErrUnsafePath, value)
	}
	segments := strings.Split(value, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." ||
			strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") || isWindowsDeviceName(segment) {
			return fmt.Errorf("%w: path segment %q is not portable", ErrUnsafePath, segment)
		}
		for index, r := range segment {
			isAlphaNumeric := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
			if !isAlphaNumeric && r != '.' && r != '_' && r != '-' || index == 0 && !isAlphaNumeric {
				return fmt.Errorf("%w: path contains a non-portable character", ErrUnsafePath)
			}
		}
	}
	return nil
}

func isWindowsDeviceName(segment string) bool {
	base := segment
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	base = strings.ToUpper(base)
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
		base == "CONIN$" || base == "CONOUT$" {
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) {
		return base[3] >= '1' && base[3] <= '9'
	}
	return false
}

func isLowerHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func digestHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func ageRecipientKeyID(encodedRecipient string) string {
	return digestHex([]byte(HybridRecipientFingerprintDomain + encodedRecipient))
}

// HybridRecipientFingerprint returns the v1 organizer-recipient fingerprint.
// Only the native age HybridRecipient profile is accepted by its static type;
// callers cannot pass legacy X25519, SSH, plugin, or scrypt recipients.
func HybridRecipientFingerprint(recipient *age.HybridRecipient) (string, error) {
	if recipient == nil {
		return "", fmt.Errorf("hybrid recipient is nil")
	}
	encoded := recipient.String()
	parsed, err := age.ParseHybridRecipient(encoded)
	if err != nil || parsed.String() != encoded || !strings.HasPrefix(encoded, "age1pq1") {
		return "", fmt.Errorf("hybrid recipient is not in canonical age encoding")
	}
	return ageRecipientKeyID(encoded), nil
}
