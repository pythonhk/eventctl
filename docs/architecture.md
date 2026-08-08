# eventctl architecture

`eventctl` is a local protocol tool, not an event platform. The repository
controls GitHub transport, review, and state promotion; `eventctl` controls
strict documents, signatures, age encryption, and verification.

```text
participant fork / organizer workflow
                 │ files, trusted actor ID, immutable source time
                 ▼
            Cobra command layer
                 │
        ┌────────┴────────┐
        ▼                 ▼
  protocol v2        stream container
  event + registry   signed header + age payload
```

## Trust model

The repository has two relevant branches:

```text
main     public event binding, workflows, request history
registry protected authoritative event state
```

`event/binding.json` from trusted `main` defines policy and derives an event
reference. A participant-signed document carries that reference. The reviewed
`registry/state.json` from `registry` contains the active identities, teams,
and attempts. Both are command inputs; neither is fetched over the network by
the CLI.

There is deliberately no GitHub App, app private key, organizer PEM, GitHub
token, or GitHub API client in the runtime. GitHub verifies who opened a pull
request; the trusted workflow passes that numeric actor ID and GitHub-created
timestamp to `eventctl`. The organizer promotes the resulting verified record
through a normal reviewed registry PR.

## Protocol documents

All JSON documents are bounded, reject duplicate keys and unknown fields, and
use concrete structures for stable signed bytes. Signatures are Ed25519 over:

```text
eventctl:eventctl/v2:<operation>\0<stable unsigned JSON>
```

The protocol has four main public document types:

- `identity-registration`: binds a GitHub actor ID to an Ed25519 public key,
  age recipient public key, key epoch, event reference, and short request
  window.
- `team-proposal` and `team-consent`: bind the exact sorted member set and
  their registry-pinned key epochs. All members must consent separately.
- `submission`: binds a team, actor, attempt, payload/metadata digests, and
  request window.
- `stream-binding`: binds an encrypted result artifact to the event, team,
  attempt, purpose, and trusted artifact ID.

The protected registry is intentionally one normalized document, rather than
separate identity, membership, and replay indexes. It validates:

- event reference and lifecycle phase;
- sorted active identities and their public keys;
- sorted active teams, with no member active in two teams;
- sorted attempts whose submitter belongs to the recorded team.

`team verify` rejects a team ID or member already active in that registry.
`submission verify` requires `submissions_open`, active membership with the
same key epoch, and an unused attempt within the binding's quotas. The command
does not write state—the reviewed registry PR is the durable state transition.

## Key custody and stream crypto

`key-gen` creates separate participant key material:

```text
Ed25519 private key      signs participant documents
age hybrid private key   decrypts artifacts addressed to that participant
```

Both private files are age-scrypt encrypted with one local passphrase. The
separate primitives are intentional: an Ed25519 key cannot be safely reused
as an age encryption key.

The stream container is:

```text
8-byte magic | 4-byte big-endian header length | JSON header | age ciphertext
```

The signed header covers the public stream binding, signer, sorted recipient
key IDs, payload size, and SHA-256 digest. The payload is age-encrypted to all
recipient public keys. `decverify` verifies the header before accepting a
decrypted payload and creates its output exclusively.

## Testing boundary

The only test suite is `tests/e2e`. It builds the real CLI with
`-cover -coverpkg=./...`, invokes it as a subprocess, and drives state through
event binding, identity, team, submission, stream, malformed-file, replay, and
quota scenarios. Every subprocess inherits `GOCOVERDIR`; `mise run test`
merges the counters and requires 100.0% statement coverage.
