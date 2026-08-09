# eventctl

`eventctl` is a small offline CLI for GitHub-native PythonHK events. It makes
portable team and submission artifacts, and signs and encrypts participant
feedback. It deliberately has no GitHub client, registry mutation, policy
engine, GitHub App, PAT, shell runtime, or organizer private key.

The repository workflow owns actor authentication, protected state, admission,
and scoring. `eventctl` owns participant keys and the `eventctl/v3` artifact
format.

## Commands

```text
eventctl version
eventctl doctor
eventctl key-gen --out DIR

eventctl team form --event-id ID --team-name NAME --github-id ID --member ID... \
  --sig-priv-key PATH --enc-pub-key PATH --out formation.tar
eventctl team key --formation formation.tar --github-id ID \
  --sig-priv-key PATH --enc-pub-key PATH --out key.tar

eventctl submission prepare --event-id ID --github-id ID --team-id UUID \
  --input PATH... --sig-priv-key PATH --out submission.tar

eventctl sigcrypt --input PATH... --out feedback.tar \
  --sig-priv-key PATH --enc-pub-key PATH...
eventctl decverify --input feedback.tar --out-dir DIR \
  --sig-pub-key PATH --enc-priv-key PATH
```

Every command writes one JSON response to standard output. A rejected command
has `ok: false` and exits nonzero. `doctor` can additionally validate an
optional `EVENTCTL_EVENT_ID=owner/repository` environment value.

## Keys

`key-gen` creates independent key pairs with no passphrase wrapper:

```text
DIR/
├── signature/
│   ├── key       Ed25519 PKCS#8 PEM private key (0600)
│   └── key.pub   Ed25519 PKIX PEM public key
└── encryption/
    ├── key       age hybrid ML-KEM768/X25519 private identity (0600)
    └── key.pub   age hybrid recipient public key
```

The signing key proves who made an artifact. The encryption key decrypts
feedback. They are intentionally distinct.

## Team onboarding

GitHub IDs are numeric account IDs. `team form` generates a UUIDv4 team ID,
prints it in its response, and requires its initiator to appear in the sorted
`--member` set. Team names are free-form visible names.

```text
one person:     formation.tar
two or more:    formation.tar + one key.tar from every other listed member
```

`formation.tar` self-proves the initiator's signing and encryption public
keys. A solo formation is therefore sufficient for a trusted controller to
activate that team. For a multi-member team, each additional person produces a
`key.tar` tied to the formation tar's SHA-256 digest. There is no captain
field, registry mutation, or GitHub integration in the CLI.

## Artifacts

Public request artifacts are plain deterministic tar archives. Each contains a
signed `manifest.json`; submission tars also contain sorted `files/<basename>`
entries. The manifest binds the protocol, event slug, numeric actor ID, team
UUID, generated attempt UUID when applicable, public signing key, and file
digests.

`sigcrypt` creates `feedback.tar`, an outer tar with exactly:

```text
manifest.json
payload.age
```

The manifest is signed with Ed25519. `payload.age` is one age-encrypted inner
tar and can be decrypted by any listed recipient key. Age encryption is
intentionally randomized; the surrounding tar layout and manifest encoding are
canonical. `decverify` verifies the trusted signer before safely extracting to
an initially empty directory.

## Repository contract

The reusable starter uses these branch roles:

```text
main         participant-facing material and workflows
registry     protected trusted team state
leaderboard  derived public scores
```

The trusted controller stores only this team state on `registry`:

```text
teams/<uuid>/
  team.json
  state.json
  <github-id>.sig.pub
  <github-id>.enc.pub
```

`team.json` is immutable: ID, free-form name, and sorted numeric members.
`state.json` holds mutable operational provenance, attempts, status, and score
state. An organizer can set a team status to `disabled`; `eventctl` never makes
that decision.

## Development

The sole test entry point is:

```bash
mise run test
```

It compiles the CLI with coverage instrumentation and drives it only as a
subprocess. The suite creates real keys and artifacts, including malformed tar
fixtures and independently signed encrypted feedback, and requires exactly
100.0% Go statement coverage. There are no unit-test tasks or tracked shell
scripts.

The reusable workflow controller imports the public Go package:

```text
github.com/pythonhk/eventctl/protocol
```

## License

MIT. See [LICENSE](LICENSE).
