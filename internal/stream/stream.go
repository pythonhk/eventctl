package stream

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"filippo.io/age"
	"github.com/pythonhk/eventctl/internal/protocol"
	"github.com/samber/lo"
)

var magic = [8]byte{'E', 'V', 'T', 'C', 'T', 'L', 1, 0}

type Header struct {
	Protocol        string                 `json:"protocol"`
	Binding         protocol.StreamBinding `json:"binding"`
	Signer          protocol.SigningPublic `json:"signer"`
	RecipientKeyIDs []string               `json:"recipient_key_ids"`
	PayloadSize     int64                  `json:"payload_size"`
	PayloadSHA256   string                 `json:"payload_sha256"`
	Signature       protocol.Signature     `json:"signature"`
}

type Result struct {
	Size           int64  `json:"size"`
	SHA256         string `json:"sha256"`
	RecipientCount int    `json:"recipient_count"`
}

func SealFile(input, output string, binding protocol.StreamBinding, signingKey protocol.SigningKey, recipients []protocol.RecipientPublic, identities []age.Recipient) (Result, error) {
	payload, err := protocol.ReadBytes(input)
	if err != nil {
		return Result{}, fmt.Errorf("read stream: %w", err)
	}
	digest := sha256.Sum256(payload)
	ids := make([]string, len(recipients))
	for index, recipient := range recipients {
		ids[index] = recipient.KeyID
	}
	sort.Strings(ids)
	unsigned := Header{Protocol: protocol.Protocol, Binding: binding, Signer: signingKey.Public, RecipientKeyIDs: ids, PayloadSize: int64(len(payload)), PayloadSHA256: hex.EncodeToString(digest[:])}
	signature := protocol.Sign("stream.sigcrypt", unsigned, signingKey)
	header := unsigned
	header.Signature = signature
	headerBytes := lo.Must(json.Marshal(header))
	var cipher bytes.Buffer
	writer, encryptErr := age.Encrypt(&cipher, identities...)
	if encryptErr != nil {
		return Result{}, fmt.Errorf("encrypt stream: %w", encryptErr)
	}
	// The authenticated writer targets bytes.Buffer, whose writes cannot fail.
	lo.Must(writer.Write(payload))
	lo.Must0(writer.Close())
	container := make([]byte, 0, len(magic)+4+len(headerBytes)+cipher.Len())
	container = append(container, magic[:]...)
	headerLength := [4]byte{}
	binary.BigEndian.PutUint32(headerLength[:], uint32(len(headerBytes)))
	container = append(container, headerLength[:]...)
	container = append(container, headerBytes...)
	container = append(container, cipher.Bytes()...)
	if err := protocol.WriteExclusive(output, container, 0o600); err != nil {
		return Result{}, fmt.Errorf("write encrypted stream: %w", err)
	}
	return Result{int64(len(payload)), hex.EncodeToString(digest[:]), len(recipients)}, nil
}

func OpenFile(input, output string, expected protocol.StreamBinding, signer protocol.SigningPublic, recipient protocol.RecipientKey) (Result, error) {
	data, err := protocol.ReadBytes(input)
	if err != nil {
		return Result{}, fmt.Errorf("read encrypted stream: %w", err)
	}
	if len(data) < len(magic)+4 || !bytes.Equal(data[:len(magic)], magic[:]) {
		return Result{}, errors.New("invalid eventctl stream header")
	}
	headerSize := binary.BigEndian.Uint32(data[len(magic) : len(magic)+4])
	start := len(magic) + 4
	end := start + int(headerSize)
	if end > len(data) || headerSize > protocol.MaxBytes {
		return Result{}, errors.New("invalid eventctl stream header size")
	}
	var header Header
	if err := json.Unmarshal(data[start:end], &header); err != nil {
		return Result{}, fmt.Errorf("decode stream header: %w", err)
	}
	if header.Protocol != protocol.Protocol || header.Binding != expected {
		return Result{}, errors.New("stream binding mismatch")
	}
	if err := protocol.Verify("stream.sigcrypt", Header{header.Protocol, header.Binding, header.Signer, header.RecipientKeyIDs, header.PayloadSize, header.PayloadSHA256, protocol.Signature{}}, header.Signature, signer); err != nil {
		return Result{}, err
	}
	if header.Signer.KeyID != signer.KeyID {
		return Result{}, errors.New("stream signer mismatch")
	}
	if !contains(header.RecipientKeyIDs, recipient.Public.KeyID) {
		return Result{}, errors.New("recipient is not authorized for stream")
	}
	reader, err := age.Decrypt(bytes.NewReader(data[end:]), recipient.Identity)
	if err != nil {
		return Result{}, fmt.Errorf("decrypt stream: %w", err)
	}
	payload, err := io.ReadAll(io.LimitReader(reader, protocol.MaxBytes+1))
	if err != nil {
		return Result{}, err
	}
	if len(payload) > protocol.MaxBytes || int64(len(payload)) != header.PayloadSize {
		return Result{}, errors.New("stream size does not match signed header")
	}
	digest := sha256.Sum256(payload)
	actual := hex.EncodeToString(digest[:])
	if actual != header.PayloadSHA256 {
		return Result{}, errors.New("stream digest does not match signed header")
	}
	if err := protocol.WriteExclusive(output, payload, 0o600); err != nil {
		return Result{}, fmt.Errorf("write plaintext stream: %w", err)
	}
	return Result{int64(len(payload)), actual, 1}, nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
