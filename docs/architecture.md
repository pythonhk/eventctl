# Architecture and trust model

## Responsibilities

`eventctl` is an offline cryptographic and serialization tool. It is responsible
for:

- generating and loading participant Ed25519 keys;
- producing and verifying versioned, domain-separated signed envelopes;
- canonicalizing protocol JSON deterministically;
- assembling bounded file manifests;
- signing plaintext submission manifests before encryption;
- encrypting and decrypting submission bundles with the vetted Go `age`
  implementation; and
- rejecting malformed, ambiguous, truncated, oversized, or unsafe inputs.

It is deliberately not responsible for GitHub authentication, repository
mutation, workflow dispatch, quota decisions, team activation, scoring, or event
lifecycle decisions. Those decisions require current server-side state.

## Independent trust inputs

Three checks are required and must not substitute for one another:

1. **CLI release trust** verifies that the executable came from the expected
   `pythonhk/eventctl` release workflow and matches the event's pinned version
   and platform checksum.
2. **Event configuration trust** verifies the event ID, numeric upstream
   repository ID, protocol version, limits, recipient key and epoch, and the
   one v1 configuration digest pinned in protected genesis. Genesis also pins
   the root-verified delegation digest, authority, and validity window.
3. **GitHub actor trust** compares the numeric actor ID in a verified envelope
   with numeric IDs from the GitHub webhook and freshly fetched API metadata.

A valid signature proves possession of a participant key. It does not prove
that GitHub authenticated the expected actor, that an attempt is fresh, or that
quota remains. Durable protected event state supplies those properties.

## Protocol rules

- Protocol versions are independent of CLI semantic versions.
- Envelopes use fixed schemas and reject unknown fields.
- IDs and digests are serialized unambiguously; GitHub database IDs are decimal
  strings to avoid consumer integer-precision differences.
- Signatures are domain separated by protocol and action kind.
- Signing keys and encryption identities are never derived from one another.
- Participant signing material is never accepted through command-line arguments
  or environment variables.
- Encryption is sign-then-encrypt. Important public routing hints are duplicated
  inside the encrypted signed manifest and must match after decryption.
- A parser must consume the authenticated encrypted stream through EOF before
  reporting success.

## Replay model

The CLI creates random request and attempt identifiers, but replay protection is
stateful and enforced by the event controller:

```text
(event_id, request_kind, request_id) -> request_digest and terminal result
```

Actor, repository, epochs, key identity, and configuration remain covered by
the request digest and must be verified against trusted context before this
replay-key lookup.

- The same replay key with the same request digest returns the original result.
- The same replay key with a different request digest is an idempotency
  conflict.
- The same content under a new attempt ID is an intentional new attempt.
- A copied envelope fails when its signed actor, repository, event, action, team
  generation, configuration digest, PR address, or sealed head SHA differs from
  trusted GitHub and event state.

Timestamps and expiry windows limit stale requests but are not replay protection.

## Submission transport

The CLI prepares an encrypted artifact but does not call the result “submitted.”
Submission occurs only when the GitHub controller authenticates the actor,
resolves the upstream PR by base plus fork owner and branch, verifies the exact
numeric fork repository and head SHA, and atomically reserves an attempt in
protected state.

The PR and source branch are the address. The exact head SHA and payload digest
are the tamper seal.

## Private-key handling

Key files are created outside the repository with restrictive permissions and
exclusive writes. Passphrases are read from a terminal or
`--passphrase-file` (`-` means standard input), never from a passphrase-valued
argument or environment variable. Backups remain encrypted. Logs and JSON
output must never contain private keys, passphrases, or decrypted submission
bytes.
