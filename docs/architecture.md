# eventctl architecture

`eventctl` is intentionally a local protocol tool. GitHub Actions or an event
repository supplies the files and protected-state policy; `eventctl` supplies
the deterministic binding, signatures, age encryption, and schema checks.

```text
event repository / GitHub Actions
            │ files + binding JSON
            ▼
       Cobra command layer
            │
     ┌──────┴──────┐
     ▼             ▼
  protocol       stream
 identities,    signed header
 teams, docs    + age payload
```

## Protocol boundaries

`internal/protocol` owns the v1 binding, Ed25519 documents, age key files,
identity registration, team proposal/consent, and submission digests. A
binding includes the event ID and epoch, request and attempt IDs, actor, key
epoch, team proposal digest, base repository ID, configuration digest, and an
issued/expiry window. JSON documents use fixed structs, so the bytes signed for
one operation are stable and do not depend on map iteration order.

`internal/stream` owns the bounded binary container used by `sigcrypt` and
`decverify`:

```text
8-byte magic | 4-byte big-endian header length | JSON header | age ciphertext
```

The header signs the binding, signer document, sorted recipient key IDs,
payload size, and payload SHA-256. Decryption requires both a valid signer and
an authorized recipient key ID. Plaintext is written with an exclusive create,
so replaying a successful output path cannot overwrite an earlier result.

## Key custody

`key-gen` writes an encrypted Ed25519 private document and an encrypted age
hybrid ML-KEM768/X25519 identity. Public documents contain short SHA-256
fingerprints used in signed metadata and recipient authorization. Signing and
decryption private keys never share key material; one setup passphrase protects
both files only for operational convenience.

## Workflow boundary

The CLI does not authenticate GitHub requests, open pull requests, push refs,
or update protected state. A reusable event repository should verify GitHub's
actor/repository context and maintain replay state in its own protected branch,
then call `eventctl` for the cryptographic operation. This keeps the starter
repository generic across events and leaves organizer policy outside the
binary.

## Testing boundary

The only test suite is `tests/e2e`. It builds the real command binary with
`go build -cover -coverpkg=./...`, runs every command through a subprocess, and
exercises malformed context, key, team, signature, stream, and output cases.
The coverage task converts the binary's `GOCOVERDIR` output with `go tool
covdata` and fails unless every statement in the reachable implementation is
covered.
