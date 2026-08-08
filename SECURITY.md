# Security policy

`eventctl` handles participant signing keys, event-bound attestations,
protected-registry verification, and encrypted event byte streams. Please
report vulnerabilities privately through the repository's GitHub Security tab.

Include the affected version, command, platform, synthetic reproduction, and
whether confidentiality, signature verification, actor/team binding, replay
safety, or output integrity is affected. Never include real private keys,
plaintext submissions, GitHub tokens, or event secrets.

## Operational boundary

- Keep encrypted private key files outside event repository checkouts when
  possible, with user-only filesystem permissions.
- Do not commit private keys, plaintext event logs, decrypted outputs, or
  passphrase files.
- Verify the public event binding through trusted `main`, and consume registry
  state only from its protected branch.
- Treat decrypted participant data as untrusted input and execute it only in
  the event's isolated scoring boundary.
- Treat GitHub actor and immutable request-creation time as repository inputs;
  they are not claims a participant can sign for themselves.
- The CLI does not authenticate GitHub requests, update protected state, or
  replace the organizer's reviewed registry transition. It verifies that the
  supplied state enforces active membership, replay, and quota rules.
- There is no GitHub App, PEM, GitHub token, or network client in normal
  eventctl operation.

Only the current protocol release is supported. Event repositories should pin
the exact binary version and review protocol compatibility before upgrading.
