package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/samber/lo"
)

const (
	Protocol = "eventctl/v1"
	MaxBytes = 64 << 20
)

type Binding struct {
	EventID            string `json:"event_id"`
	EventEpoch         int    `json:"event_epoch"`
	RequestID          string `json:"request_id"`
	AttemptID          string `json:"attempt_id"`
	ActorID            string `json:"actor_id"`
	KeyEpoch           int    `json:"key_epoch"`
	TeamID             string `json:"team_id"`
	TeamProposalDigest string `json:"team_proposal_digest"`
	BaseRepositoryID   int64  `json:"base_repository_id"`
	ConfigDigest       string `json:"config_digest"`
	IssuedAt           string `json:"issued_at"`
	ExpiresAt          string `json:"expires_at"`
}

func (b Binding) Validate() error {
	if b.EventID == "" || b.RequestID == "" || b.AttemptID == "" || b.ActorID == "" || b.TeamID == "" || b.TeamProposalDigest == "" || b.ConfigDigest == "" {
		return errors.New("binding contains an empty identifier or digest")
	}
	if b.EventEpoch < 1 || b.KeyEpoch < 1 || b.BaseRepositoryID < 1 {
		return errors.New("binding epochs and repository ID must be positive")
	}
	issued, err := time.Parse(time.RFC3339Nano, b.IssuedAt)
	if err != nil {
		return fmt.Errorf("invalid issued_at: %w", err)
	}
	expires, err := time.Parse(time.RFC3339Nano, b.ExpiresAt)
	if err != nil {
		return fmt.Errorf("invalid expires_at: %w", err)
	}
	if !expires.After(issued) {
		return errors.New("expires_at must be after issued_at")
	}
	return nil
}

func BindingsEqual(left, right Binding) bool {
	return left == right
}

func ReadBinding(path string) (Binding, error) {
	var binding Binding
	if err := readJSON(path, &binding); err != nil {
		return binding, fmt.Errorf("read binding: %w", err)
	}
	if err := binding.Validate(); err != nil {
		return binding, err
	}
	return binding, nil
}

type SigningPublic struct {
	Kind      string `json:"kind"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type signingPrivate struct {
	Kind       string `json:"kind"`
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"key_id"`
	PrivateKey string `json:"private_key"`
}

type RecipientPublic struct {
	Kind      string        `json:"kind"`
	Algorithm string        `json:"algorithm"`
	KeyID     string        `json:"key_id"`
	PublicKey string        `json:"public_key"`
	Recipient age.Recipient `json:"-"`
}

type recipientPrivate struct {
	Kind      string `json:"kind"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Identity  string `json:"identity"`
}

type KeyGenerationResult struct {
	SigningPrivate   string `json:"signing_private_key"`
	SigningPublic    string `json:"signing_public_key"`
	RecipientPrivate string `json:"recipient_private_key"`
	RecipientPublic  string `json:"recipient_public_key"`
	SigningKeyID     string `json:"signing_key_id"`
	RecipientKeyID   string `json:"recipient_key_id"`
}

type SigningKey struct {
	Public  SigningPublic
	Private ed25519.PrivateKey
}

type RecipientKey struct {
	Public   RecipientPublic
	Identity *age.HybridIdentity
}

func GenerateKeyDirectory(directory, passphrase string) (KeyGenerationResult, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return KeyGenerationResult{}, fmt.Errorf("create key directory: %w", err)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	signingID := fingerprint(public)
	signingPublic := SigningPublic{"signing-public", "ed25519", signingID, base64.StdEncoding.EncodeToString(public)}
	signingPrivate := signingPrivate{"signing-private", "ed25519", signingID, base64.StdEncoding.EncodeToString(private)}
	identity, _ := age.GenerateHybridIdentity()
	recipientID := fingerprint([]byte(identity.Recipient().String()))
	recipientPublic := RecipientPublic{Kind: "recipient-public", Algorithm: "age-hybrid-mlkem768-x25519", KeyID: recipientID, PublicKey: identity.Recipient().String(), Recipient: identity.Recipient()}
	recipientPrivate := recipientPrivate{"recipient-private", "age-hybrid-mlkem768-x25519", recipientID, identity.String()}
	signingCiphertext := encryptWithPass(mustJSON(signingPrivate), passphrase)
	recipientCiphertext := encryptWithPass(mustJSON(recipientPrivate), passphrase)
	signingPrivatePath := filepath.Join(directory, "signing.private.age")
	signingPublicPath := filepath.Join(directory, "signing.public.json")
	recipientPrivatePath := filepath.Join(directory, "recipient.private.age")
	recipientPublicPath := filepath.Join(directory, "recipient.public.json")
	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{signingPrivatePath, signingCiphertext, 0o600},
		{signingPublicPath, mustJSON(signingPublic), 0o644},
		{recipientPrivatePath, recipientCiphertext, 0o600},
		{recipientPublicPath, mustJSON(recipientPublic), 0o644},
	} {
		if err := writeExclusive(file.path, file.data, file.mode); err != nil {
			return KeyGenerationResult{}, fmt.Errorf("write key file %s: %w", file.path, err)
		}
	}
	return KeyGenerationResult{signingPrivatePath, signingPublicPath, recipientPrivatePath, recipientPublicPath, signingID, recipientID}, nil
}

func LoadSigningPrivate(path, passphrase string) (SigningKey, error) {
	data, err := readFile(path)
	if err != nil {
		return SigningKey{}, fmt.Errorf("read signing key: %w", err)
	}
	plain, err := decryptWithPass(data, passphrase)
	if err != nil {
		return SigningKey{}, fmt.Errorf("decrypt signing key: %w", err)
	}
	var document signingPrivate
	if err := json.Unmarshal(plain, &document); err != nil {
		return SigningKey{}, fmt.Errorf("decode signing key: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(document.PrivateKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return SigningKey{}, errors.New("invalid signing private key")
	}
	private := ed25519.PrivateKey(key)
	public := private.Public().(ed25519.PublicKey)
	if document.Kind != "signing-private" || document.Algorithm != "ed25519" || document.KeyID != fingerprint(public) {
		return SigningKey{}, errors.New("signing key metadata does not match")
	}
	return SigningKey{Public: SigningPublic{"signing-public", "ed25519", document.KeyID, base64.StdEncoding.EncodeToString(public)}, Private: private}, nil
}

func LoadSigningPublic(path string) (SigningPublic, error) {
	var document SigningPublic
	if err := readJSON(path, &document); err != nil {
		return document, fmt.Errorf("read signing public key: %w", err)
	}
	key, err := decodeSigningPublic(document)
	if err != nil {
		return document, err
	}
	if document.KeyID != fingerprint(key) {
		return document, errors.New("signing public key fingerprint mismatch")
	}
	return document, nil
}

func LoadRecipientPublic(path string) (RecipientPublic, error) {
	var document RecipientPublic
	if err := readJSON(path, &document); err != nil {
		return document, fmt.Errorf("read recipient public key: %w", err)
	}
	if document.Kind != "recipient-public" || document.Algorithm != "age-hybrid-mlkem768-x25519" {
		return document, errors.New("invalid recipient public key metadata")
	}
	recipient, err := age.ParseHybridRecipient(document.PublicKey)
	if err != nil {
		return document, fmt.Errorf("parse recipient public key: %w", err)
	}
	if document.KeyID != fingerprint([]byte(recipient.String())) {
		return document, errors.New("recipient public key fingerprint mismatch")
	}
	document.Recipient = recipient
	return document, nil
}

func LoadRecipientPrivate(path, passphrase string) (RecipientKey, error) {
	data, err := readFile(path)
	if err != nil {
		return RecipientKey{}, fmt.Errorf("read recipient key: %w", err)
	}
	plain, err := decryptWithPass(data, passphrase)
	if err != nil {
		return RecipientKey{}, fmt.Errorf("decrypt recipient key: %w", err)
	}
	var document recipientPrivate
	if err := json.Unmarshal(plain, &document); err != nil {
		return RecipientKey{}, fmt.Errorf("decode recipient key: %w", err)
	}
	if document.Kind != "recipient-private" || document.Algorithm != "age-hybrid-mlkem768-x25519" {
		return RecipientKey{}, errors.New("invalid recipient private key metadata")
	}
	identity, err := age.ParseHybridIdentity(document.Identity)
	if err != nil {
		return RecipientKey{}, fmt.Errorf("parse recipient private key: %w", err)
	}
	public := identity.Recipient().String()
	if document.KeyID != fingerprint([]byte(public)) {
		return RecipientKey{}, errors.New("recipient private key fingerprint mismatch")
	}
	return RecipientKey{Public: RecipientPublic{Kind: "recipient-public", Algorithm: document.Algorithm, KeyID: document.KeyID, PublicKey: public, Recipient: identity.Recipient()}, Identity: identity}, nil
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

func Sign(domain string, value any, key SigningKey) Signature {
	message := signedMessage(domain, value)
	return Signature{"ed25519", key.Public.KeyID, base64.StdEncoding.EncodeToString(ed25519.Sign(key.Private, message))}
}

func Verify(domain string, value any, signature Signature, public SigningPublic) error {
	key, err := decodeSigningPublic(public)
	if err != nil {
		return err
	}
	if signature.Algorithm != "ed25519" || signature.KeyID != public.KeyID {
		return errors.New("signature metadata does not match signer")
	}
	signed, err := base64.StdEncoding.DecodeString(signature.Value)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	message := signedMessage(domain, value)
	if !ed25519.Verify(key, message, signed) {
		return errors.New("signature verification failed")
	}
	return nil
}

type IdentityRegistration struct {
	Kind      string        `json:"kind"`
	Binding   Binding       `json:"binding"`
	ActorID   string        `json:"actor_id"`
	Signer    SigningPublic `json:"signer"`
	Signature Signature     `json:"signature"`
}

func RegisterIdentity(binding Binding, actorID string, key SigningKey) (IdentityRegistration, error) {
	unsigned := struct {
		Kind    string        `json:"kind"`
		Binding Binding       `json:"binding"`
		ActorID string        `json:"actor_id"`
		Signer  SigningPublic `json:"signer"`
	}{"identity-registration", binding, actorID, key.Public}
	signature := Sign("identity.register", unsigned, key)
	return IdentityRegistration{unsigned.Kind, binding, actorID, key.Public, signature}, nil
}

func VerifyIdentity(document IdentityRegistration, expected Binding, public SigningPublic) error {
	if document.Kind != "identity-registration" || !BindingsEqual(document.Binding, expected) {
		return errors.New("identity registration binding mismatch")
	}
	if document.Signer.KeyID != public.KeyID {
		return errors.New("identity signer mismatch")
	}
	unsigned := struct {
		Kind    string        `json:"kind"`
		Binding Binding       `json:"binding"`
		ActorID string        `json:"actor_id"`
		Signer  SigningPublic `json:"signer"`
	}{document.Kind, document.Binding, document.ActorID, document.Signer}
	return Verify("identity.register", unsigned, document.Signature, public)
}

type TeamProposal struct {
	Kind      string        `json:"kind"`
	Binding   Binding       `json:"binding"`
	TeamID    string        `json:"team_id"`
	Members   []string      `json:"members"`
	Signer    SigningPublic `json:"signer"`
	Signature Signature     `json:"signature"`
}

type TeamConsent struct {
	Kind         string        `json:"kind"`
	TeamID       string        `json:"team_id"`
	ActorID      string        `json:"actor_id"`
	ProposalHash string        `json:"proposal_hash"`
	Signer       SigningPublic `json:"signer"`
	Signature    Signature     `json:"signature"`
}

type TeamVerification struct {
	TeamID       string `json:"team_id"`
	MemberCount  int    `json:"member_count"`
	ConsentCount int    `json:"consent_count"`
	Verified     bool   `json:"verified"`
}

func RegisterTeam(binding Binding, teamID string, members []string, key SigningKey) (TeamProposal, error) {
	if teamID == "" || teamID != binding.TeamID {
		return TeamProposal{}, errors.New("team ID does not match binding")
	}
	members = NormalizeMembers(members)
	if len(members) == 0 {
		return TeamProposal{}, errors.New("at least one team member is required")
	}
	unsigned := struct {
		Kind    string        `json:"kind"`
		Binding Binding       `json:"binding"`
		TeamID  string        `json:"team_id"`
		Members []string      `json:"members"`
		Signer  SigningPublic `json:"signer"`
	}{"team-proposal", binding, teamID, members, key.Public}
	signature := Sign("team.register", unsigned, key)
	return TeamProposal{unsigned.Kind, binding, teamID, members, key.Public, signature}, nil
}

func RegisterConsent(proposal TeamProposal, actorID string, key SigningKey) (TeamConsent, error) {
	if !lo.Contains(proposal.Members, actorID) {
		return TeamConsent{}, errors.New("actor is not a proposed team member")
	}
	hash := DigestJSON(proposal)
	unsigned := struct {
		Kind         string        `json:"kind"`
		TeamID       string        `json:"team_id"`
		ActorID      string        `json:"actor_id"`
		ProposalHash string        `json:"proposal_hash"`
		Signer       SigningPublic `json:"signer"`
	}{"team-consent", proposal.TeamID, actorID, hash, key.Public}
	signature := Sign("team.consent", unsigned, key)
	return TeamConsent{unsigned.Kind, unsigned.TeamID, actorID, hash, key.Public, signature}, nil
}

func VerifyTeam(proposal TeamProposal, consents []TeamConsent) (TeamVerification, error) {
	if proposal.Kind != "team-proposal" || len(proposal.Members) == 0 {
		return TeamVerification{}, errors.New("invalid team proposal")
	}
	unsigned := struct {
		Kind    string        `json:"kind"`
		Binding Binding       `json:"binding"`
		TeamID  string        `json:"team_id"`
		Members []string      `json:"members"`
		Signer  SigningPublic `json:"signer"`
	}{proposal.Kind, proposal.Binding, proposal.TeamID, proposal.Members, proposal.Signer}
	if err := Verify("team.register", unsigned, proposal.Signature, proposal.Signer); err != nil {
		return TeamVerification{}, err
	}
	hash := DigestJSON(proposal)
	seen := make(map[string]bool, len(consents))
	for _, consent := range consents {
		if consent.Kind != "team-consent" || consent.TeamID != proposal.TeamID || consent.ProposalHash != hash || seen[consent.ActorID] {
			return TeamVerification{}, errors.New("invalid or duplicate team consent")
		}
		if !lo.Contains(proposal.Members, consent.ActorID) {
			return TeamVerification{}, errors.New("team consent is not from a proposed member")
		}
		unsignedConsent := struct {
			Kind         string        `json:"kind"`
			TeamID       string        `json:"team_id"`
			ActorID      string        `json:"actor_id"`
			ProposalHash string        `json:"proposal_hash"`
			Signer       SigningPublic `json:"signer"`
		}{consent.Kind, consent.TeamID, consent.ActorID, consent.ProposalHash, consent.Signer}
		if err := Verify("team.consent", unsignedConsent, consent.Signature, consent.Signer); err != nil {
			return TeamVerification{}, err
		}
		seen[consent.ActorID] = true
	}
	if len(seen) != len(proposal.Members) {
		return TeamVerification{}, errors.New("team is missing member consent")
	}
	return TeamVerification{proposal.TeamID, len(proposal.Members), len(consents), true}, nil
}

type Submission struct {
	Kind           string        `json:"kind"`
	Binding        Binding       `json:"binding"`
	PayloadSHA256  string        `json:"payload_sha256"`
	PayloadSize    int64         `json:"payload_size"`
	MetadataSHA256 string        `json:"metadata_sha256,omitempty"`
	MetadataSize   int64         `json:"metadata_size,omitempty"`
	Signer         SigningPublic `json:"signer"`
	Signature      Signature     `json:"signature"`
}

func PrepareSubmission(binding Binding, payload, metadata []byte, key SigningKey) (Submission, error) {
	payloadDigest := digest(payload)
	metadataDigest := ""
	if len(metadata) > 0 {
		metadataDigest = digest(metadata)
	}
	unsigned := struct {
		Kind           string        `json:"kind"`
		Binding        Binding       `json:"binding"`
		PayloadSHA256  string        `json:"payload_sha256"`
		PayloadSize    int64         `json:"payload_size"`
		MetadataSHA256 string        `json:"metadata_sha256,omitempty"`
		MetadataSize   int64         `json:"metadata_size,omitempty"`
		Signer         SigningPublic `json:"signer"`
	}{"submission", binding, payloadDigest, int64(len(payload)), metadataDigest, int64(len(metadata)), key.Public}
	signature := Sign("submission.prepare", unsigned, key)
	return Submission{unsigned.Kind, binding, payloadDigest, unsigned.PayloadSize, metadataDigest, unsigned.MetadataSize, key.Public, signature}, nil
}

func NormalizeMembers(members []string) []string {
	clean := lo.Map(members, func(member string, _ int) string { return strings.TrimSpace(member) })
	clean = lo.Filter(clean, func(member string, _ int) bool { return member != "" })
	clean = lo.Uniq(clean)
	sort.Strings(clean)
	return clean
}

func DigestJSON(value any) string {
	return digest(mustJSON(value))
}

func WriteJSON(path string, value any) error {
	return writeExclusive(path, mustJSON(value), 0o644)
}

func ReadJSON(path string, value any) error {
	return readJSON(path, value)
}

func ReadBytes(path string) ([]byte, error) {
	return readFile(path)
}

func WriteExclusive(path string, data []byte, mode os.FileMode) error {
	return writeExclusive(path, data, mode)
}

func fingerprint(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:8])
}

func digest(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

func signedMessage(domain string, value any) []byte {
	return append([]byte("eventctl:"+Protocol+":"+domain+"\x00"), mustJSON(value)...)
}

func decodeSigningPublic(document SigningPublic) (ed25519.PublicKey, error) {
	if document.Kind != "signing-public" || document.Algorithm != "ed25519" {
		return nil, errors.New("invalid signing public key metadata")
	}
	key, err := base64.StdEncoding.DecodeString(document.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid signing public key")
	}
	return ed25519.PublicKey(key), nil
}

func encryptWithPass(data []byte, passphrase string) []byte {
	recipient, _ := age.NewScryptRecipient(passphrase)
	var output bytes.Buffer
	writer, _ := age.Encrypt(&output, recipient)
	_, _ = writer.Write(data)
	_ = writer.Close()
	return output.Bytes()
}

func decryptWithPass(data []byte, passphrase string) ([]byte, error) {
	identity, _ := age.NewScryptIdentity(passphrase)
	reader, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(reader, MaxBytes))
}

func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, _ := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	if len(data) > MaxBytes {
		return nil, errors.New("file exceeds size limit")
	}
	return data, nil
}

func readJSON(path string, value any) error {
	data, err := readFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("JSON document contains trailing data")
	}
	return nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, _ = file.Write(data)
	_ = file.Close()
	return nil
}

func mustJSON(value any) []byte {
	data, _ := json.MarshalIndent(value, "", "  ")
	return append(data, '\n')
}
