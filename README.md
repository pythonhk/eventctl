# eventctl

`eventctl` is a small, offline-first CLI for reusable PythonHK event
repositories. It keeps participant registration, team consent, submission
attestation, and encrypted event byte streams on one stable protocol surface.
The CLI does not hold GitHub credentials or mutate repositories.

## Commands

```text
eventctl version
eventctl doctor
eventctl key-gen --out DIR --passphrase-file PATH
eventctl sigcrypt --input PATH --output PATH --context PATH \
  --sig-private-key PATH --passphrase-file PATH \
  --enc-public-key PATH [--enc-public-key PATH ...]
eventctl decverify --input PATH --output PATH --context PATH \
  --ver-public-key PATH --dec-private-key PATH --passphrase-file PATH
eventctl identity register|verify ...
eventctl team register|consent|verify ...
eventctl submission prepare ...
```

Every command emits one JSON response. Successful responses have `ok: true`;
failures have `ok: false` and a non-empty `error`. Cobra owns the help and
argument contract, while diagnostics remain on standard error.

## One-time participant setup

```bash
eventctl key-gen \
  --out participant-identity \
  --passphrase-file passphrase.txt
```

The setup writes four files:

```text
signing.private.age       encrypted Ed25519 signing key
signing.public.json       Ed25519 verification document
recipient.private.age     encrypted age hybrid decryption identity
recipient.public.json     age hybrid recipient document
```

Signing and decryption keys are separate. The same setup passphrase protects
both encrypted private files, but it is never accepted as a command-line
value. The recipient algorithm is Filippo's age hybrid
ML-KEM768/X25519 construction.

## Event binding and team consent

The JSON passed to `--context` binds an operation to the event, event and key
epochs, request and attempt IDs, actor, team proposal digest, base repository,
configuration digest, and a strict issued/expiry window. The binding is signed
as part of every identity, team, submission, and stream operation.

```bash
eventctl identity register \
  --context binding.json --actor-id 100 \
  --sig-private-key participant-identity/signing.private.age \
  --passphrase-file passphrase.txt --output identity.json

eventctl team register \
  --context binding.json --team-id team-001 \
  --member 200 --member 300 \
  --sig-private-key organizer/signing.private.age \
  --passphrase-file organizer-passphrase.txt --output team.json

eventctl team consent \
  --proposal team.json --actor-id 200 \
  --sig-private-key member-200/signing.private.age \
  --passphrase-file member-200-passphrase.txt --output consent-200.json

eventctl team verify \
  --proposal team.json --consent consent-200.json --consent consent-300.json
```

Team verification succeeds only when every proposed actor has one valid,
unique consent for the exact proposal digest.

## Signed and encrypted byte streams

`sigcrypt` takes one bounded file-like byte stream. It signs a header containing
the binding, signer, sorted recipient set, payload size, and SHA-256 digest,
then encrypts the payload to every declared age recipient. Any authorized team
member can decrypt with their own private recipient identity.

```bash
eventctl sigcrypt \
  --input judge.log --output judge.log.eventctl --context binding.json \
  --sig-private-key organizer/signing.private.age \
  --passphrase-file organizer-passphrase.txt \
  --enc-public-key member-200/recipient.public.json \
  --enc-public-key member-300/recipient.public.json

eventctl decverify \
  --input judge.log.eventctl --output judge.log --context binding.json \
  --ver-public-key organizer/signing.public.json \
  --dec-private-key member-200/recipient.private.age \
  --passphrase-file member-200-passphrase.txt
```

The operation is fail-closed: wrong event context, signer, recipient, key
passphrase, ciphertext, header, digest, size, or output path is rejected. Files
are bounded at 64 MiB and outputs are created exclusively, so an existing
result is never silently overwritten.

## Submission preparation

```bash
eventctl submission prepare \
  --context binding.json --input exploit-package.zip \
  --metadata submission-metadata.json \
  --sig-private-key participant-identity/signing.private.age \
  --passphrase-file passphrase.txt --output submission.json
```

The submission document records payload and optional metadata digests and is
signed with the participant's signing key. Transport, GitHub pull requests,
and protected event state stay outside this CLI.

## Development and coverage

The repository intentionally contains only the command layer, protocol, stream
implementation, build metadata, and one public-interface E2E suite. The E2E
suite builds an instrumented `eventctl` binary, invokes that binary as a real
subprocess, and checks success and failure scenarios through JSON responses.

```bash
mise run format-code
mise run test
mise run coverage-html
```

`mise run test` is the only test entrypoint. It always builds and runs the
instrumented CLI through the black-box E2E suite, converts the emitted
`GOCOVERDIR` counters with `go tool covdata`, prints the function report, and
enforces `total: (statements) 100.0%`. `mise run coverage-html` depends on that
same test task and renders the fresh report as HTML. Generated files under
`coverage/` are ignored.

The requested Go stack is deliberately visible in `go.mod`: Cobra,
`samber/lo`, `caarlos0/env/v11`, `filippo.io/age`, and Testify.

## License

MIT. See [LICENSE](LICENSE).
