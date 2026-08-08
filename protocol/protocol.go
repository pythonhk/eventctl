// Package protocol implements the portable eventctl/v3 artifact format.
//
// It deliberately knows nothing about GitHub, event policy, registries, or
// scoring. Those are trusted-controller concerns. It only owns local keys,
// signed tar artifacts, and encrypted feedback tar artifacts.
package protocol

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/samber/lo"
)

const (
	// Version identifies the artifact protocol, independently from the CLI
	// release version.
	Version = "eventctl/v3"

	// MaxArtifactBytes bounds one input or decoded tar artifact. Event-specific
	// scorers can impose a tighter submission limit.
	MaxArtifactBytes = 64 << 20
)

var (
	eventIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	githubIDPattern = regexp.MustCompile(`^[1-9][0-9]*$`)
	uuidV4Pattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

var epoch = time.Unix(0, 0).UTC()

// KeyPaths are the four files emitted by key-gen.
type KeyPaths struct {
	SignaturePrivate  string `json:"signature_private_key"`
	SignaturePublic   string `json:"signature_public_key"`
	EncryptionPrivate string `json:"encryption_private_key"`
	EncryptionPublic  string `json:"encryption_public_key"`
}

// File describes one file carried by a public request or encrypted wrapper.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest is the signed metadata in every eventctl tar artifact. Signature
// signs the canonical Go JSON encoding of this value with Signature omitted.
type Manifest struct {
	Protocol            string   `json:"protocol"`
	Kind                string   `json:"kind"`
	EventID             string   `json:"event_id,omitempty"`
	GitHubID            string   `json:"github_id,omitempty"`
	TeamID              string   `json:"team_id,omitempty"`
	TeamName            string   `json:"team_name,omitempty"`
	Members             []string `json:"members,omitempty"`
	FormationSHA256     string   `json:"formation_sha256,omitempty"`
	AttemptID           string   `json:"attempt_id,omitempty"`
	Files               []File   `json:"files"`
	SigningPublicKey    string   `json:"signing_public_key"`
	EncryptionPublicKey string   `json:"encryption_public_key,omitempty"`
	Signature           string   `json:"signature,omitempty"`
}

// Artifact is a parsed tar artifact. Files uses tar paths, for example
// files/exploit.whl or payload.age.
type Artifact struct {
	Manifest Manifest
	Files    map[string][]byte
	SHA256   string
}

// EncryptionPublic is an age recipient with its canonical text form.
type EncryptionPublic struct {
	Text      string
	Recipient age.Recipient
}

// Result describes an artifact written by eventctl.
type Result struct {
	Output         string `json:"output"`
	SHA256         string `json:"sha256"`
	TeamID         string `json:"team_id,omitempty"`
	AttemptID      string `json:"attempt_id,omitempty"`
	FileCount      int    `json:"file_count"`
	RecipientCount int    `json:"recipient_count,omitempty"`
}

// GenerateKeyDirectory creates an independent Ed25519 signing key pair and
// a native age hybrid encryption key pair. Existing key files are never
// overwritten.
func GenerateKeyDirectory(directory string) (KeyPaths, error) {
	paths := KeyPaths{
		SignaturePrivate:  filepath.Join(directory, "signature", "key"),
		SignaturePublic:   filepath.Join(directory, "signature", "key.pub"),
		EncryptionPrivate: filepath.Join(directory, "encryption", "key"),
		EncryptionPublic:  filepath.Join(directory, "encryption", "key.pub"),
	}
	for _, keyDirectory := range []string{filepath.Dir(paths.SignaturePrivate), filepath.Dir(paths.EncryptionPrivate)} {
		if err := os.MkdirAll(keyDirectory, 0o700); err != nil {
			return KeyPaths{}, fmt.Errorf("create key directory: %w", err)
		}
	}

	public, private := lo.Must2(ed25519.GenerateKey(rand.Reader))
	privatePEM := signingPrivatePEM(private)
	publicPEM := SigningPublicPEM(public)
	identity := lo.Must(age.GenerateHybridIdentity())

	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{paths.SignaturePrivate, privatePEM, 0o600},
		{paths.SignaturePublic, []byte(publicPEM), 0o644},
		{paths.EncryptionPrivate, []byte(identity.String() + "\n"), 0o600},
		{paths.EncryptionPublic, []byte(identity.Recipient().String() + "\n"), 0o644},
	} {
		if err := writeNew(file.path, file.data, file.mode); err != nil {
			return KeyPaths{}, err
		}
	}
	return paths, nil
}

// LoadSigningPrivate reads an Ed25519 PKCS#8 PEM private key.
func LoadSigningPrivate(file string) (ed25519.PrivateKey, error) {
	data, err := readFile(file)
	if err != nil {
		return nil, fmt.Errorf("read signing private key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid signing private key PEM")
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing private key: %w", err)
	}
	key, ok := value.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing private key is not Ed25519")
	}
	return key, nil
}

// LoadSigningPublic reads an Ed25519 PKIX PEM public key.
func LoadSigningPublic(file string) (ed25519.PublicKey, error) {
	data, err := readFile(file)
	if err != nil {
		return nil, fmt.Errorf("read signing public key: %w", err)
	}
	return ParseSigningPublicPEM(string(data))
}

// ParseSigningPublicPEM parses an Ed25519 PKIX PEM public key.
func ParseSigningPublicPEM(value string) (ed25519.PublicKey, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid signing public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing public key: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("signing public key is not Ed25519")
	}
	return key, nil
}

// SigningPublicPEM returns the canonical PKIX PEM representation of an
// Ed25519 public key.
func SigningPublicPEM(key ed25519.PublicKey) string {
	data := lo.Must(x509.MarshalPKIXPublicKey(key))
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: data}))
}

// LoadEncryptionPrivate reads a native age hybrid private identity.
func LoadEncryptionPrivate(file string) (*age.HybridIdentity, error) {
	data, err := readFile(file)
	if err != nil {
		return nil, fmt.Errorf("read encryption private key: %w", err)
	}
	identity, err := age.ParseHybridIdentity(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("parse encryption private key: %w", err)
	}
	return identity, nil
}

// LoadEncryptionPublic reads a native age hybrid recipient public key.
func LoadEncryptionPublic(file string) (EncryptionPublic, error) {
	data, err := readFile(file)
	if err != nil {
		return EncryptionPublic{}, fmt.Errorf("read encryption public key: %w", err)
	}
	return ParseEncryptionPublic(strings.TrimSpace(string(data)))
}

// ParseEncryptionPublic parses a native age hybrid recipient public key.
func ParseEncryptionPublic(value string) (EncryptionPublic, error) {
	recipient, err := age.ParseHybridRecipient(value)
	if err != nil {
		return EncryptionPublic{}, fmt.Errorf("parse encryption public key: %w", err)
	}
	return EncryptionPublic{Text: recipient.String(), Recipient: recipient}, nil
}

// NewFormation makes an unsigned formation manifest. WriteArtifact signs it.
func NewFormation(eventID, githubID, teamName, signingPublic, encryptionPublic string, members []string) (Manifest, error) {
	teamID := NewUUIDV4()
	normalized, err := normalizeMembers(members)
	if err != nil {
		return Manifest{}, err
	}
	if !contains(normalized, githubID) {
		return Manifest{}, errors.New("formation initiator must be a team member")
	}
	manifest := Manifest{
		Protocol:            Version,
		Kind:                "team-formation",
		EventID:             eventID,
		GitHubID:            githubID,
		TeamID:              teamID,
		TeamName:            teamName,
		Members:             normalized,
		Files:               []File{},
		SigningPublicKey:    signingPublic,
		EncryptionPublicKey: encryptionPublic,
	}
	return manifest, validateManifest(manifest)
}

// NewTeamKey makes an unsigned member key-proof manifest tied to formation.
func NewTeamKey(formation Artifact, githubID, signingPublic, encryptionPublic string) (Manifest, error) {
	if err := VerifyArtifactSelf(formation); err != nil {
		return Manifest{}, fmt.Errorf("verify formation: %w", err)
	}
	if formation.Manifest.Kind != "team-formation" {
		return Manifest{}, errors.New("formation artifact is not a team formation")
	}
	if formation.Manifest.GitHubID == githubID {
		return Manifest{}, errors.New("formation initiator already supplied a key proof")
	}
	if !contains(formation.Manifest.Members, githubID) {
		return Manifest{}, errors.New("key-proof member is not in the formation")
	}
	manifest := Manifest{
		Protocol:            Version,
		Kind:                "team-key",
		EventID:             formation.Manifest.EventID,
		GitHubID:            githubID,
		TeamID:              formation.Manifest.TeamID,
		FormationSHA256:     formation.SHA256,
		Files:               []File{},
		SigningPublicKey:    signingPublic,
		EncryptionPublicKey: encryptionPublic,
	}
	return manifest, validateManifest(manifest)
}

// NewSubmission makes an unsigned submission manifest. WriteArtifact adds file
// digests and signs it.
func NewSubmission(eventID, githubID, teamID, signingPublic string) (Manifest, error) {
	attemptID := NewUUIDV4()
	manifest := Manifest{
		Protocol:         Version,
		Kind:             "submission",
		EventID:          eventID,
		GitHubID:         githubID,
		TeamID:           teamID,
		AttemptID:        attemptID,
		Files:            []File{},
		SigningPublicKey: signingPublic,
	}
	if err := validateSubmissionIdentity(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// WriteArtifact creates a deterministic public request tar containing
// manifest.json and optional files/ entries.
func WriteArtifact(output string, manifest Manifest, inputPaths []string, signingPrivate ed25519.PrivateKey) (Result, error) {
	entries, files := []tarEntry{}, []File{}
	if len(inputPaths) > 0 {
		var err error
		entries, files, err = inputEntries(inputPaths)
		if err != nil {
			return Result{}, err
		}
	}
	manifest.Files = files
	if err := validateManifest(manifest); err != nil {
		return Result{}, err
	}
	manifest = signManifest(manifest, signingPrivate)
	manifestData := lo.Must(json.Marshal(manifest))
	entries = append([]tarEntry{{Name: "manifest.json", Data: manifestData, Mode: 0o644}}, entries...)
	data, err := marshalTar(entries)
	if err != nil {
		return Result{}, err
	}
	if err := writeOutput(output, data, 0o644); err != nil {
		return Result{}, err
	}
	return artifactResult(output, data, manifest, len(files), 0), nil
}

// ReadArtifact parses an eventctl public or feedback tar without granting any
// authority to the manifest's self-declared signing key.
func ReadArtifact(file string) (Artifact, error) {
	data, err := readFile(file)
	if err != nil {
		return Artifact{}, fmt.Errorf("read artifact: %w", err)
	}
	entries, err := readTar(data)
	if err != nil {
		return Artifact{}, fmt.Errorf("read artifact tar: %w", err)
	}
	manifestData, ok := entries["manifest.json"]
	if !ok {
		return Artifact{}, errors.New("artifact is missing manifest.json")
	}
	var manifest Manifest
	if err := decodeJSON(manifestData, &manifest); err != nil {
		return Artifact{}, fmt.Errorf("decode artifact manifest: %w", err)
	}
	if err := validateManifest(manifest); err != nil {
		return Artifact{}, err
	}
	delete(entries, "manifest.json")
	if err := validateEntries(manifest, entries); err != nil {
		return Artifact{}, err
	}
	digest := sha256.Sum256(data)
	return Artifact{Manifest: manifest, Files: entries, SHA256: hex.EncodeToString(digest[:])}, nil
}

// signManifest signs the manifests constructed by this package. Callers use
// the constructor functions above, which own the artifact shape.
func signManifest(manifest Manifest, signingPrivate ed25519.PrivateKey) Manifest {
	manifest.SigningPublicKey = SigningPublicPEM(signingPrivate.Public().(ed25519.PublicKey))
	manifest.Signature = ""
	payload := manifestPayload(manifest)
	manifest.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(signingPrivate, payload))
	return manifest
}

// VerifyArtifactSelf verifies an artifact against the public key included in
// its manifest. Controllers must additionally compare that key to registry
// state before accepting the artifact.
func VerifyArtifactSelf(artifact Artifact) error {
	return VerifyArtifact(artifact, lo.Must(ParseSigningPublicPEM(artifact.Manifest.SigningPublicKey)))
}

// VerifyArtifact verifies a parsed artifact against a trusted Ed25519 public
// key. ReadArtifact validates the declared public key before this step.
func VerifyArtifact(artifact Artifact, trusted ed25519.PublicKey) error {
	declared := lo.Must(ParseSigningPublicPEM(artifact.Manifest.SigningPublicKey))
	if !bytes.Equal(trusted, declared) {
		return errors.New("artifact signing key does not match trusted key")
	}
	signature, err := base64.RawStdEncoding.DecodeString(artifact.Manifest.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("artifact signature is invalid")
	}
	payload := manifestPayload(artifact.Manifest)
	if !ed25519.Verify(trusted, payload, signature) {
		return errors.New("artifact signature does not verify")
	}
	return nil
}

// SealFeedback signs and encrypts input files. The outer feedback.tar is a
// real tar containing manifest.json and payload.age; the encrypted payload is
// a second deterministic tar of files/ entries.
func SealFeedback(inputPaths []string, output string, signingPrivate ed25519.PrivateKey, recipients []age.Recipient) (Result, error) {
	entries, _, err := inputEntries(inputPaths)
	if err != nil {
		return Result{}, err
	}
	payload, err := marshalTar(entries)
	if err != nil {
		return Result{}, err
	}
	var encrypted bytes.Buffer
	writer := lo.Must(age.Encrypt(&encrypted, recipients...))
	_, _ = writer.Write(payload)
	lo.Must0(writer.Close())
	public := SigningPublicPEM(signingPrivate.Public().(ed25519.PublicKey))
	digest := sha256.Sum256(encrypted.Bytes())
	manifest := Manifest{
		Protocol:         Version,
		Kind:             "feedback",
		Files:            []File{{Path: "payload.age", SHA256: hex.EncodeToString(digest[:]), Size: int64(encrypted.Len())}},
		SigningPublicKey: public,
	}
	manifest = signManifest(manifest, signingPrivate)
	manifestData := lo.Must(json.Marshal(manifest))
	data := lo.Must(marshalTar([]tarEntry{{Name: "manifest.json", Data: manifestData, Mode: 0o644}, {Name: "payload.age", Data: encrypted.Bytes(), Mode: 0o600}}))
	if err := writeOutput(output, data, 0o600); err != nil {
		return Result{}, err
	}
	return artifactResult(output, data, manifest, len(entries), len(recipients)), nil
}

// OpenFeedback verifies, decrypts, and safely extracts feedback files into an
// initially empty output directory.
func OpenFeedback(input, outputDirectory string, trustedSigningPublic ed25519.PublicKey, encryptionPrivate *age.HybridIdentity) (Result, error) {
	artifact, err := ReadArtifact(input)
	if err != nil {
		return Result{}, err
	}
	if artifact.Manifest.Kind != "feedback" {
		return Result{}, errors.New("artifact is not encrypted feedback")
	}
	if err := VerifyArtifact(artifact, trustedSigningPublic); err != nil {
		return Result{}, err
	}
	reader, err := age.Decrypt(bytes.NewReader(artifact.Files["payload.age"]), encryptionPrivate)
	if err != nil {
		return Result{}, fmt.Errorf("decrypt feedback: %w", err)
	}
	payload, err := io.ReadAll(io.LimitReader(reader, MaxArtifactBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("read feedback payload: %w", err)
	}
	entries, err := readTar(payload)
	if err != nil {
		return Result{}, fmt.Errorf("read feedback payload tar: %w", err)
	}
	if len(entries) == 0 {
		return Result{}, errors.New("feedback payload is empty")
	}
	if err := os.MkdirAll(outputDirectory, 0o700); err != nil {
		return Result{}, fmt.Errorf("create feedback output directory: %w", err)
	}
	contents := lo.Must(os.ReadDir(outputDirectory))
	if len(contents) != 0 {
		return Result{}, errors.New("feedback output directory must be empty")
	}
	names := make([]string, 0, len(entries))
	for name := range entries {
		if !isInputPath(name) {
			return Result{}, errors.New("feedback payload contains an invalid path")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		target := filepath.Join(outputDirectory, filepath.FromSlash(strings.TrimPrefix(name, "files/")))
		if err := os.WriteFile(target, entries[name], 0o600); err != nil {
			return Result{}, fmt.Errorf("write feedback file %s: %w", name, err)
		}
	}
	return Result{Output: outputDirectory, SHA256: artifact.SHA256, FileCount: len(entries)}, nil
}

// NewUUIDV4 creates the opaque identifier used for teams and attempts.
func NewUUIDV4() string {
	value := make([]byte, 16)
	_ = lo.Must(rand.Read(value))
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

// ValidateEventID validates the repository-slug event identifier accepted by
// the participant CLI.
func ValidateEventID(eventID string) error {
	if !eventIDPattern.MatchString(eventID) {
		return errors.New("event ID must be an owner/repository slug")
	}
	return nil
}

func signingPrivatePEM(key ed25519.PrivateKey) []byte {
	data := lo.Must(x509.MarshalPKCS8PrivateKey(key))
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data})
}

func writeNew(file string, data []byte, mode os.FileMode) error {
	handle, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("write key file %s: %w", file, err)
	}
	_ = lo.Must(handle.Write(data))
	lo.Must0(handle.Close())
	return nil
}

func readFile(file string) ([]byte, error) {
	info, err := os.Stat(file)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("path is not a regular file")
	}
	if info.Size() > MaxArtifactBytes {
		return nil, errors.New("file exceeds size limit")
	}
	return os.ReadFile(file)
}

func normalizeMembers(members []string) ([]string, error) {
	if len(members) == 0 {
		return nil, errors.New("at least one team member is required")
	}
	for _, member := range members {
		if !githubIDPattern.MatchString(member) {
			return nil, errors.New("GitHub IDs must be positive decimal numbers")
		}
	}
	unique := lo.Uniq(members)
	if len(unique) != len(members) {
		return nil, errors.New("team members must not repeat")
	}
	sort.Slice(unique, func(left, right int) bool {
		if len(unique[left]) != len(unique[right]) {
			return len(unique[left]) < len(unique[right])
		}
		return unique[left] < unique[right]
	})
	return unique, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.Protocol != Version {
		return errors.New("artifact protocol is invalid")
	}
	if _, err := ParseSigningPublicPEM(manifest.SigningPublicKey); err != nil {
		return err
	}
	switch manifest.Kind {
	case "team-formation":
		if err := validateFormation(manifest); err != nil {
			return err
		}
	case "team-key":
		if err := validateKey(manifest); err != nil {
			return err
		}
	case "submission":
		if err := validateSubmission(manifest); err != nil {
			return err
		}
	case "feedback":
		if err := validateFeedback(manifest); err != nil {
			return err
		}
	default:
		return errors.New("artifact kind is invalid")
	}
	return nil
}

func validateFormation(manifest Manifest) error {
	if err := validateTeamIdentity(manifest); err != nil {
		return err
	}
	if !validText(manifest.TeamName) || manifest.FormationSHA256 != "" || manifest.AttemptID != "" || len(manifest.Files) != 0 {
		return errors.New("team formation fields are invalid")
	}
	members, err := normalizeMembers(manifest.Members)
	if err != nil || !slices.Equal(members, manifest.Members) || !contains(members, manifest.GitHubID) {
		return errors.New("team formation members are invalid")
	}
	if _, err := ParseEncryptionPublic(manifest.EncryptionPublicKey); err != nil {
		return err
	}
	return nil
}

func validateKey(manifest Manifest) error {
	if err := validateTeamIdentity(manifest); err != nil {
		return err
	}
	if !digestPattern.MatchString(manifest.FormationSHA256) || manifest.TeamName != "" || len(manifest.Members) != 0 || manifest.AttemptID != "" || len(manifest.Files) != 0 {
		return errors.New("team key fields are invalid")
	}
	if _, err := ParseEncryptionPublic(manifest.EncryptionPublicKey); err != nil {
		return err
	}
	return nil
}

func validateSubmissionIdentity(manifest Manifest) error {
	if err := validateTeamIdentity(manifest); err != nil {
		return err
	}
	if !uuidV4Pattern.MatchString(manifest.AttemptID) || manifest.TeamName != "" || len(manifest.Members) != 0 || manifest.FormationSHA256 != "" || manifest.EncryptionPublicKey != "" {
		return errors.New("submission identity fields are invalid")
	}
	return nil
}

func validateSubmission(manifest Manifest) error {
	if err := validateSubmissionIdentity(manifest); err != nil {
		return err
	}
	if len(manifest.Files) == 0 || !validFiles(manifest.Files, isInputPath) {
		return errors.New("submission files are invalid")
	}
	return nil
}

func validateFeedback(manifest Manifest) error {
	if manifest.EventID != "" || manifest.GitHubID != "" || manifest.TeamID != "" || manifest.TeamName != "" || len(manifest.Members) != 0 || manifest.FormationSHA256 != "" || manifest.AttemptID != "" || manifest.EncryptionPublicKey != "" {
		return errors.New("feedback identity fields are invalid")
	}
	if len(manifest.Files) != 1 || !validFiles(manifest.Files, func(value string) bool { return value == "payload.age" }) {
		return errors.New("feedback files are invalid")
	}
	return nil
}

func validateTeamIdentity(manifest Manifest) error {
	if err := ValidateEventID(manifest.EventID); err != nil {
		return err
	}
	if !githubIDPattern.MatchString(manifest.GitHubID) || !uuidV4Pattern.MatchString(manifest.TeamID) {
		return errors.New("artifact team identity is invalid")
	}
	return nil
}

func validFiles(files []File, allowed func(string) bool) bool {
	for index, file := range files {
		if !allowed(file.Path) || !digestPattern.MatchString(file.SHA256) || file.Size < 0 || (index > 0 && files[index-1].Path >= file.Path) {
			return false
		}
	}
	return true
}

func validText(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func manifestPayload(manifest Manifest) []byte {
	manifest.Signature = ""
	data := lo.Must(json.Marshal(manifest))
	return append([]byte(Version+"\x00"+manifest.Kind+"\x00"), data...)
}

type tarEntry struct {
	Name string
	Data []byte
	Mode int64
}

func inputEntries(inputPaths []string) ([]tarEntry, []File, error) {
	if len(inputPaths) == 0 {
		return nil, nil, errors.New("at least one input file is required")
	}
	entries := make([]tarEntry, 0, len(inputPaths))
	seen := make(map[string]bool, len(inputPaths))
	for _, input := range inputPaths {
		data, err := readFile(input)
		if err != nil {
			return nil, nil, fmt.Errorf("read input %s: %w", input, err)
		}
		name := path.Join("files", filepath.Base(input))
		if !isInputPath(name) || seen[name] {
			return nil, nil, errors.New("input file names must be unique simple file names")
		}
		seen[name] = true
		entries = append(entries, tarEntry{Name: name, Data: data, Mode: 0o644})
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name < entries[right].Name })
	files := make([]File, 0, len(entries))
	for _, entry := range entries {
		digest := sha256.Sum256(entry.Data)
		files = append(files, File{Path: entry.Name, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(entry.Data))})
	}
	return entries, files, nil
}

func marshalTar(entries []tarEntry) ([]byte, error) {
	sorted := append([]tarEntry(nil), entries...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left].Name < sorted[right].Name })
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, entry := range sorted {
		if !safeTarName(entry.Name) {
			return nil, errors.New("tar entry path is invalid")
		}
		header := &tar.Header{Name: entry.Name, Mode: entry.Mode, Size: int64(len(entry.Data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR, ModTime: epoch}
		lo.Must0(writer.WriteHeader(header))
		_, _ = writer.Write(entry.Data)
	}
	lo.Must0(writer.Close())
	return buffer.Bytes(), nil
}

func readTar(data []byte) (map[string][]byte, error) {
	reader := tar.NewReader(bytes.NewReader(data))
	entries := map[string][]byte{}
	var total int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg || !safeTarName(header.Name) || header.Size < 0 || header.Size > MaxArtifactBytes-total {
			return nil, errors.New("tar entry is invalid")
		}
		if _, exists := entries[header.Name]; exists {
			return nil, errors.New("tar contains duplicate path")
		}
		entry := make([]byte, header.Size)
		if _, err := io.ReadFull(reader, entry); err != nil {
			return nil, err
		}
		total += header.Size
		entries[header.Name] = entry
	}
}

func validateEntries(manifest Manifest, entries map[string][]byte) error {
	if manifest.Kind == "feedback" {
		if len(entries) != 1 || entries["payload.age"] == nil {
			return errors.New("feedback tar entries are invalid")
		}
		return validateFileContent(manifest.Files[0], entries["payload.age"])
	}
	if len(entries) != len(manifest.Files) {
		return errors.New("artifact tar entries do not match manifest")
	}
	for _, file := range manifest.Files {
		data, exists := entries[file.Path]
		if !exists {
			return errors.New("artifact is missing a manifest file")
		}
		if err := validateFileContent(file, data); err != nil {
			return err
		}
	}
	return nil
}

func validateFileContent(file File, data []byte) error {
	if int64(len(data)) != file.Size {
		return errors.New("artifact file size does not match manifest")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != file.SHA256 {
		return errors.New("artifact file digest does not match manifest")
	}
	return nil
}

func safeTarName(value string) bool {
	return value != "" && !strings.HasPrefix(value, "/") && !strings.Contains(value, "\\") && path.Clean(value) == value && !strings.HasPrefix(value, "../") && value != ".."
}

func isInputPath(value string) bool {
	return strings.HasPrefix(value, "files/") && strings.Count(value, "/") == 1 && path.Base(value) != "." && path.Base(value) != ".."
}

func writeOutput(output string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(output, data, mode); err != nil {
		return fmt.Errorf("write output %s: %w", output, err)
	}
	return nil
}

func artifactResult(output string, data []byte, manifest Manifest, fileCount, recipientCount int) Result {
	digest := sha256.Sum256(data)
	return Result{Output: output, SHA256: hex.EncodeToString(digest[:]), TeamID: manifest.TeamID, AttemptID: manifest.AttemptID, FileCount: fileCount, RecipientCount: recipientCount}
}

func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}
