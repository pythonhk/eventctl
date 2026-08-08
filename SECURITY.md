# Security policy

`eventctl` handles participant signing keys, team attestations, and encrypted
event byte streams. Please report vulnerabilities privately through the
repository's GitHub Security tab.

Include the affected version, command, platform, synthetic reproduction, and
whether confidentiality, signature verification, actor/team binding, replay
safety, or output integrity is affected. Never include real private keys,
plaintext submissions, GitHub tokens, or event secrets.

## Operational boundary

- Keep encrypted private key files outside event repository checkouts when
  possible, with user-only filesystem permissions.
- Do not commit private keys, plaintext event logs, decrypted outputs, or
  passphrase files.
- Verify the event binding and recipient documents through the organizer's
  trusted channel before encrypting.
- Treat decrypted participant data as untrusted input and execute it only in
  the event's isolated scoring boundary.
- The CLI does not authenticate GitHub requests, update protected state, or
  replace repository-level replay and actor checks.

Only the current protocol release is supported. Event repositories should pin
the exact binary version and review protocol compatibility before upgrading.
