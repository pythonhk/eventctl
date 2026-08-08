# eventctl

`eventctl` is the small, offline CLI behind reusable PythonHK event
repositories. It creates participant keys, signs event-bound registrations,
team requests, and submissions, and encrypts result files for a team.

It has no GitHub App, PEM, GitHub token, network client, Git mutation, or
organizer private key. The event repository supplies the trusted public event
binding and its protected `registry` branch supplies the authoritative state.

## Commands

```text
eventctl version
eventctl doctor [--event BINDING --registry REGISTRY]
eventctl key-gen --out DIR --passphrase-file PATH

eventctl identity register|verify ...
eventctl team propose|consent|verify ...
eventctl submission prepare|verify ...

eventctl sigcrypt ...
eventctl decverify ...
```

Every command writes exactly one JSON response to standard output. A successful
response has `ok: true`; a rejected request has `ok: false` and a non-empty
`error`. The process exits nonzero for the latter.

## The two-branch model

```text
main     public event binding, workflows, and merged participant requests
registry protected authoritative identities, activated teams, and attempts
```

Participants work from forks and open pull requests to `main`. The normal
read-only workflow checks the GitHub actor and request shape. An organizer then
uses `eventctl` with the immutable GitHub creation time and writes the accepted
result through a reviewed PR to `registry`. No participant request changes
state by itself.

`event/binding.json` is public, reviewed policy. It includes the event and
repository IDs, event epoch, validity window, terms digest, request TTLs, and
team/attempt limits. Every signed document embeds its derived event reference,
so it cannot be replayed into a different event, repository, or policy
revision.

The single registry document is also event-bound:

```json
{
  "v": 2,
  "kind": "event-registry",
  "event": { "event_id": "...", "event_epoch": 1, "repository_id": "...", "binding_sha256": "..." },
  "revision": 0,
  "phase": "formation_open",
  "enabled": true,
  "disabled_reason": "",
  "identities": [],
  "teams": [],
  "attempts": []
}
```

The valid phases are `draft`, `registration_open`, `formation_open`,
`submissions_open`, and `closed`. `eventctl` requires `formation_open` for
team work and `submissions_open` for admission. It rejects an enabled registry
with a disabled reason, or a disabled registry without one.

## One participant setup

```bash
eventctl key-gen \
  --out participant-identity \
  --passphrase-file passphrase.txt
```

This creates four files:

```text
signing.private.age       encrypted Ed25519 signing key
signing.public.json       Ed25519 verification document
recipient.private.age     encrypted age hybrid decryption identity
recipient.public.json     age hybrid recipient document
```

The two key types remain separate: Ed25519 signs documents, while age hybrid
ML-KEM768/X25519 decrypts team data. One passphrase protects both local private
files for convenience; the passphrase is only read from a file.

## Registration and team formation

Registration is self-signed, but it becomes active only when its verified
record is reviewed into `registry.identities`. The `--source-time` supplied to
verification must be a trusted immutable time, normally GitHub's pull-request
creation time—not a participant commit timestamp.

```bash
eventctl identity register \
  --event event/binding.json --actor-id 12345 \
  --sig-private-key participant-identity/signing.private.age \
  --recipient-public-key participant-identity/recipient.public.json \
  --passphrase-file passphrase.txt --output registration.json

eventctl identity verify \
  --event event/binding.json --input registration.json \
  --expect-actor-id 12345 --source-time 2026-08-08T12:00:00Z \
  --output identity-record.json
```

An active member proposes a sorted team from the protected registry. Every
listed member, including the proposer, separately signs their consent. The
verifier resolves every signing and recipient key from the active registry;
keys claimed only in the request are never trusted.

```bash
eventctl team propose \
  --event event/binding.json --registry registry/state.json \
  --actor-id 12345 --member 12345 --member 67890 \
  --sig-private-key participant-identity/signing.private.age \
  --passphrase-file passphrase.txt --output proposal.json

eventctl team consent \
  --event event/binding.json --registry registry/state.json \
  --proposal proposal.json --actor-id 67890 \
  --sig-private-key teammate-identity/signing.private.age \
  --passphrase-file teammate-passphrase.txt --output consent.json

eventctl team verify \
  --event event/binding.json --registry registry/state.json \
  --proposal proposal.json --proposal-source-time 2026-08-08T12:00:00Z \
  --consent captain-consent.json --consent consent.json \
  --consent-source-time 12345=2026-08-08T12:01:00Z \
  --consent-source-time 67890=2026-08-08T12:02:00Z \
  --output verified-team.json
```

The organizer records the verifier's team ID, proposal digest, and members as
one `registry.teams` entry. The registry prevents another active team from
reusing that team ID or any member.

## Submission admission

Participants prepare an event-bound, signed request alongside the exact
submission file. `prepare` has no state effect; `verify` is the admission
operation used from the protected registry workflow.

```bash
eventctl submission prepare \
  --event event/binding.json --input exploit-package.zip \
  --metadata metadata.json --team-id TEAM_UUID --attempt-id ATTEMPT_UUID \
  --actor-id 12345 --sig-private-key participant-identity/signing.private.age \
  --passphrase-file passphrase.txt --output submission.json

eventctl submission verify \
  --event event/binding.json --registry registry/state.json \
  --request submission.json --bundle exploit-package.zip --metadata metadata.json \
  --expect-actor-id 12345 --source-time 2026-08-08T12:10:00Z \
  --output verified-submission.json
```

Verification requires an active team, an active member with the same key
epoch, an unused attempt ID, and remaining per-team and total quotas. The
reviewed registry update records the attempt; it is the durable replay guard.

## Encrypted result artifacts

`sigcrypt` signs a bounded byte stream and encrypts it to one or more team
recipient public keys. A GitHub Actions judge can upload the ciphertext as an
artifact. Any intended team member can download it and run `decverify` using
their own recipient private key.

```bash
eventctl sigcrypt \
  --input judge.log --output judge.log.eventctl --context stream-binding.json \
  --sig-private-key organizer/signing.private.age \
  --passphrase-file organizer-passphrase.txt \
  --enc-public-key captain/recipient.public.json \
  --enc-public-key teammate/recipient.public.json

eventctl decverify \
  --input judge.log.eventctl --output judge.log --context stream-binding.json \
  --ver-public-key organizer/signing.public.json \
  --dec-private-key teammate/recipient.private.age \
  --passphrase-file teammate-passphrase.txt
```

The stream header signs the event reference, stream purpose, signer, sorted
recipient key IDs, payload size, and SHA-256 digest. Input files are capped at
64 MiB and outputs are exclusive creates, so an existing file is never
overwritten silently.

## Development

The repository has one test entrypoint:

```bash
mise run test
```

It builds an instrumented `eventctl` binary and drives it as a real subprocess
through the complete registration, team, submission, stream, error, replay,
and quota lifecycle. It then merges `GOCOVERDIR` data and fails unless
statement coverage is exactly 100.0%. There are no unit-test tasks.

`mise run format-code` formats Go sources. CI runs the same `mise run test`
entrypoint rather than a separate test command.

## License

MIT. See [LICENSE](LICENSE).
