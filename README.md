# eventctl

`eventctl` is the offline-first command-line companion for reusable PythonHK
GitHub events. It creates participant signing keys, produces signed registration
and team-consent messages, and packages submissions as authenticated encrypted
bundles that are safe to commit to a public Git repository.

Event repositories consume a prebuilt, pinned `eventctl` release. They must not
compile the CLI during an event workflow or download an unverified `latest`
binary.

## Security properties

- GitHub's numeric account ID is the identity; usernames are display data.
- Every signed action is bound to an event ID, numeric upstream repository ID,
  actor ID, action kind, key epoch, configuration digest, and unique request ID.
- Every team member signs the same immutable team proposal. Partial consent does
  not activate a team.
- A submission attempt is distinct from its content. Replaying the same attempt
  is idempotent, while deliberately submitting the same content with a fresh
  attempt ID is allowed by policy.
- Confidential submissions are signed before encryption. Encryption does not
  replace authentication, actor binding, or durable replay tracking.
- V1 fixes the event and config epochs at `1`. Protected genesis pins the exact
  config digest, delegated signing authority, and delegation validity window;
  a derived event does not adopt an edited config after bootstrap.
- The CLI does not hold GitHub credentials, push commits, open pull requests, or
  mutate event state.

## Command families

The implemented v1 interface is organized around:

```text
eventctl version --json
eventctl help [COMMAND [SUBCOMMAND]]
eventctl envelope classify --request PATH --out PATH
eventctl config validate|digest|sign|verify|delegation-sign|delegation-verify
eventctl doctor
eventctl key generate|show|backup
eventctl recipient generate|show
eventctl identity register|verify
eventctl team propose|consent|verify
eventctl submission pack|inspect|verify|prepare|authenticate-request|verify-request|decrypt-verify
eventctl replay classify
eventctl receipt sign|verify
eventctl scorer validate-request|sign-result|verify
```

Artifact-producing commands require an explicit output path. Machine-readable
output is written to standard output; diagnostics are written to standard
error. Protocol versions are independent of CLI semantic versions, and the CLI
fails closed on unsupported protocol majors.

Runtime verification commands require the signed config, protected genesis,
and protected current-state metadata from the same immutable state ref. Intake
commands additionally require a trusted GitHub source timestamp. Bootstrap
config verification requires the signed organizer-root delegation and every
explicit root public key. Run a command with missing arguments to receive its
exact usage contract as structured JSON.

`submission authenticate-request` verifies the signed request, actor,
registered key, repository, event/config, validity-window, digest, and replay
bindings without reading mutable pull-request metadata or the referenced
bundle. It is a replay-lookup primitive, not submission admission: a request
that is not already present in protected replay state must still pass
`submission verify-request` against fresh PR metadata and the exact bundle.

`eventctl help`, `eventctl --help`, and `eventctl -h` return successful
machine-readable help in the same `pythonhk.eventctl/output/v1` response wrapper
as ordinary commands. Command-family and exact-command help are available as,
for example, `eventctl submission --help`, `eventctl help submission`, and
`eventctl submission pack --help`. To create the passphrase-protected hybrid
identity used for submission encryption, start with:

```bash
eventctl recipient generate \
  --identity-out judge-recipient.age \
  --recipient-out judge-recipient.txt
```

Private signing keys and hybrid recipient identities are passphrase-encrypted.
Passphrases are read from a terminal or `--passphrase-file`; they are never
accepted as command-line values. Submission decryption and extraction are
Linux-only and require every recipient identity named by the accepted archived
configuration.

Request timing is strict: the trusted GitHub source creation time must be
between the signed `issued_at` and `expires_at`, inclusive. Participant systems
should have synchronized clocks; after a `request is not yet valid` error,
correct the clock and generate a fresh request rather than editing timestamps.

`eventctl envelope classify` is a reconciler routing primitive, not a security
verifier. It accepts strict, bounded concrete v1 request JSON either directly
or inside the exact one-key `{ "envelope": ... }` transport wrapper, and writes
only `{status, trust, kind, request_id}` with `trust` fixed to `unverified`.
The original request must still pass its normal signature, actor, repository,
configuration, source-time, and lifecycle checks before any state effect.

## Build from source

Building from source is intended for CLI contributors, not event participants:

```bash
go test ./...
go build -o ./bin/eventctl ./cmd/eventctl
./bin/eventctl version --json
```

Official releases contain platform archives, SHA-256 checksums, SPDX SBOMs, and
build provenance. Event templates pin the expected version and per-platform
checksum in reviewed configuration.

## Trust boundary

`eventctl` handles canonicalization, cryptography, schema checks, and encrypted
bundle parsing. Bash in the event repository handles GitHub transport and calls
the CLI through a narrow adapter. Privileged GitHub workflows must independently
verify every participant envelope and must never execute participant-controlled
content.

See the event template's protocol and security documentation for the complete
state machine, replay rules, and workflow trust boundaries.

## License

MIT. See [LICENSE](LICENSE).
