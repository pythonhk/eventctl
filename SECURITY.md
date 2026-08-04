# Security policy

`eventctl` handles participant signing keys and encrypted event submissions.
Security reports should therefore avoid public issues until maintainers have
assessed the impact and users have a safe upgrade.

## Supported versions

Only the latest published release receives security fixes. Event repositories
must pin an exact archive digest, but organizers should migrate to a newer
release after reviewing protocol compatibility and release attestations.

| Release | Security updates |
| --- | --- |
| Latest immutable release | Yes |
| Earlier releases and unreleased builds | No |

## Report a vulnerability

Use **Report a vulnerability** on the repository's Security tab to open a
private vulnerability report. Include:

- the affected `eventctl` version and platform;
- the exact command or protocol operation involved;
- whether confidentiality, signature verification, identity binding, replay
  safety, archive extraction, or release integrity is affected;
- minimal reproduction steps or a proof of concept with synthetic data; and
- any known workarounds or evidence of active exploitation.

Do not include real participant private keys, plaintext submissions, recovery
material, GitHub tokens, or event secrets. Maintainers will acknowledge the
report privately, validate it, coordinate remediation, and publish an advisory
when users have a safe release.

## Release integrity

Official binaries exist only as immutable GitHub release assets in
`pythonhk/eventctl`. Each supported archive must:

- appear in `SHA256SUMS`;
- have SLSA provenance signed by
  `pythonhk/eventctl/.github/workflows/release.yml`;
- have an SPDX 2.3 SBOM attestation from the same workflow and source tag;
- report the exact full source commit digest pinned by the consumer lock; and
- belong to a verifiable immutable GitHub release.

See `docs/release.md` for exact verification commands. Treat a missing or
invalid checksum, attestation, immutable-release record, or version/commit
binding as a security failure. Do not fall back to building from an event fork
or downloading another asset. Use GitHub CLI 2.93.0 or newer; older versions
must not perform release or artifact-attestation verification because they are
affected by GHSA-8xvp-7hj6-mcj9.

## Key and data handling

- Generate participant private keys outside event repository checkouts and
  keep them with user-only filesystem permissions.
- Never commit plaintext submissions, private keys, decrypted temporary files,
  access tokens, or organizer decryption identities.
- A successful encryption command does not prove the recipient identity is
  correct. Verify the event configuration digest and recipient information
  through the organizer's trusted channel first.
- Signatures establish the protocol identity and context encoded in the signed
  envelope; they do not make untrusted files safe to execute.
- Decrypt and score participant-controlled data only in the event system's
  isolated scoring boundary, never in a privileged repository-state writer.

The CLI and its release pipeline are one part of the event trust boundary. The
event template's protected state, actor binding, replay handling, shutdown
controls, and isolated scorer remain independently required.
