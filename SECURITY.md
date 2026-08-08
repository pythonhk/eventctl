# Security policy

Report a vulnerability privately through the repository's GitHub Security tab.
Include the affected version, command, platform, synthetic reproduction, and
the impact on artifact integrity, signer verification, recipient
confidentiality, or safe extraction. Never include real private keys, plaintext
submissions, decrypted feedback, tokens, or event secrets.

## Security boundary

- `eventctl` is offline. It does not authenticate GitHub users, call GitHub,
  mutate a registry, enforce organizer policy, or run submitted code.
- GitHub Actions binds a request manifest's numeric `github_id` to the account
  that opened its pull request. The protected controller verifies this before
  accepting an artifact.
- Team membership, names, and registered public keys become immutable when a
  team is activated. Operational status and scoring remain trusted registry
  state.
- Ed25519 signing and age hybrid ML-KEM768/X25519 encryption use independent
  key pairs. Do not reuse, commit, or share either private key.
- Treat every decrypted feedback file and submitted artifact as untrusted data.
  Only an event-specific isolated scorer may execute it.
- `decverify` extracts only flat `files/<name>` entries into an initially empty
  directory. Do not bypass that boundary by manually unpacking untrusted tars.
- A public Actions artifact is not a confidentiality boundary. Upload only
  feedback encrypted to the team's registered encryption public keys, never raw
  scorer logs.

Only the current `eventctl/v3` protocol is supported. Event repositories
should pin the exact released CLI and review protocol changes before upgrading.
