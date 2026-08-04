# Release and verification runbook

`eventctl` releases are prebuilt once and reused by every event repository. An
event must pin an exact version, full source and signer-workflow commit digests,
platform archive, and archive SHA-256 digest; it must never download `latest`
or compile the CLI during an event workflow. For this same-repository workflow,
the source and signer digests must be equal.

## Release contract

The repository-owned tool versions are in
`scripts/release/tool-versions.env`. Release archives follow this stable naming
contract:

```text
eventctl_VERSION_darwin_amd64.tar.gz
eventctl_VERSION_darwin_arm64.tar.gz
eventctl_VERSION_linux_amd64.tar.gz
eventctl_VERSION_linux_arm64.tar.gz
eventctl_VERSION_windows_amd64.zip
eventctl_VERSION_windows_arm64.zip
```

Every archive contains exactly one executable plus the tagged source
`LICENSE`, has a matching `.spdx.json` SPDX 2.3 SBOM, and is listed in
`SHA256SUMS`. The SBOM document name and its archive package name, SHA-256
version, and checksum must identify that exact paired archive. No other archive
entries are allowed. The binary reports the release version, full source
commit digest, and exact UTC source commit date through:

```bash
eventctl version --json
```

`eventctl doctor` must also report the operating system and architecture named
by the archive. Native verification checks both fields so emulation cannot make
a mislabeled archive appear valid.

The build uses `CGO_ENABLED=0`, `-trimpath`, a fixed commit timestamp, no Go
build ID, the pinned Go toolchain, and no restored Go dependency/build cache.
CI builds the archives twice and requires byte-for-byte identical archive
hashes. SBOM generation scans the built archive locally; online package-data
enrichment and Syft's update check are intentionally disabled.
Release tests and builds also use Go's read-only module mode, so they cannot
silently repair dependency metadata after the tag is created.

## One-time repository controls

Configure these controls before the first tag is pushed. They are repository
state and are not supplied by the source tree.

1. Keep `pythonhk/eventctl` public and set the default workflow token to read
   repository contents only.
2. Create a protected environment named `release`. Require at least one
   maintainer reviewer, prevent self-review, and restrict deployment branches
   and tags to protected `v*` tags.
3. Enable **release immutability** in repository settings. This applies only to
   releases published after it is enabled.
4. Add a tag ruleset for `v*` that restricts creation to release maintainers
   and blocks update and deletion. Published immutable releases also lock their
   tag and assets.
5. Protect `main`: require pull requests, CODEOWNERS review for
   `.github/workflows/**`, `.goreleaser.yaml`, `scripts/release/**`, and
   `internal/buildinfo/**`, and require the complete CI check set.
6. Allow only the actions used by the workflows. They are pinned to full
   40-character commit SHAs; the version comments are review hints, not the
   security boundary.
7. Enable private vulnerability reporting so `SECURITY.md`'s reporting path is
   available before the first public release.

Before approving the first `release` environment deployment, an administrator
must read back the immutable-release setting and the tag ruleset from GitHub.
The release job also requires `isImmutable: true` after publication and fails
otherwise, but that postcondition is not a substitute for the pre-release
readback.

## Prepare a release

1. Merge the intended release commit into `main`.
2. Confirm all required CI jobs passed for that exact commit, including the
   reproducible snapshot build and native tests.
3. Review dependency, cryptography, workflow, action-pin, Go toolchain,
   GoReleaser, and Syft changes explicitly.
4. Create an annotated SemVer tag. Prereleases may use a SemVer suffix.
   Build metadata (`+metadata`) is intentionally not accepted in release tags,
   so each tag maps to one unambiguous archive-name version.

```bash
git switch main
git pull --ff-only
git tag -a v1.2.3 -m 'eventctl v1.2.3'
git push origin v1.2.3
```

The tag push starts `.github/workflows/release.yml`. Before approving its
protected environment, compare the workflow commit SHA with the reviewed
`main` commit and confirm no release already exists for the tag.

## What the workflow proves

The workflow performs these gates in order:

1. Verify the annotated SemVer tag resolves to the checked-out commit, is
   reachable from `origin/main`, and has no existing release.
2. Rerun the complete Go, race, vulnerability, fuzz, Bash, workflow, action-pin,
   and release-boundary gates on the exact tagged source. Cross-compile six
   CGO-free binaries, produce paired SPDX 2.3 SBOMs and `SHA256SUMS`, and build
   twice from independent empty Go build caches to prove reproducibility.
3. On fresh native Linux, macOS, and Windows runners for both amd64 and arm64,
   rerun native source tests, download the candidate, and verify the exact
   version, source digest, UTC source date, operating system, and architecture.
4. Enter the protected `release` environment and create an asset-complete draft
   release. Compare GitHub's server-computed SHA-256 digest and size for every
   one of the thirteen draft assets with the local files at initial upload and
   again immediately before publication; also peel the remote tag and require
   it to equal the source digest at that boundary.
5. Create GitHub SLSA provenance for every archive and an SPDX SBOM attestation
   for each corresponding archive.
6. Publish the draft and require `isImmutable: true`, the same release ID, the
   exact thirteen server-computed asset digests and sizes, and the same peeled
   tag target. A mismatch after publication makes the version unusable.
7. Verify GitHub's immutable release attestation. On a second set of fresh
   native runners, verify that record before download, then verify each archive
   and `SHA256SUMS` against the immutable release plus both hosted attestations
   before extracting or executing any binary.
8. Verify the public binary's checksum, archive allowlist, exact version,
   source digest and date, and native operating system and architecture.

The post-publication jobs are evidence about the actual public release, not a
local build artifact. If one fails, do not replace an asset or move the tag.

## Consumer verification

Download only the platform archive and `SHA256SUMS`. The following example is
for macOS arm64; replace the archive name for another target. Verification
requires GitHub CLI 2.93.0 or newer. Versions through 2.92.0 are affected by
[GHSA-8xvp-7hj6-mcj9](https://github.com/cli/cli/security/advisories/GHSA-8xvp-7hj6-mcj9)
and must not be used for release or attestation verification.

```bash
tag=v1.2.3
version=${tag#v}
asset="eventctl_${version}_darwin_arm64.tar.gz"
# Read this full 40- or 64-character value from the reviewed event lock.
source_digest="$EVENTCTL_SOURCE_DIGEST"
signer_digest="$EVENTCTL_SIGNER_DIGEST"
# Read the exact UTC source commit date from the same reviewed lock.
source_date="$EVENTCTL_SOURCE_DATE"
expected_os=darwin
expected_arch=arm64

[[ $source_digest =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]
[[ $signer_digest =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]
[[ $signer_digest == "$source_digest" ]]
[[ $source_date =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]

# Fail before any network access if GitHub CLI is absent, unsupported, or old.
scripts/release/require-gh-version.sh

# Verify the immutable release record before downloading any asset.
gh release verify "$tag" --repo pythonhk/eventctl

gh release download "$tag" \
  --repo pythonhk/eventctl \
  --pattern "$asset" \
  --pattern SHA256SUMS

# Bind both downloaded files to the already-verified immutable release before
# trusting their contents or executing the binary.
gh release verify-asset "$tag" "$asset" --repo pythonhk/eventctl
gh release verify-asset "$tag" SHA256SUMS --repo pythonhk/eventctl

expected=$(awk -v name="$asset" '$2 == name || $2 == "*" name { print $1 }' SHA256SUMS)
actual=$(shasum -a 256 "$asset" | awk '{ print $1 }')
test "$actual" = "$expected"

gh attestation verify "$asset" \
  --repo pythonhk/eventctl \
  --deny-self-hosted-runners \
  --signer-digest "$signer_digest" \
  --signer-workflow pythonhk/eventctl/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag" \
  --source-digest "$source_digest" \
  --predicate-type https://slsa.dev/provenance/v1

gh attestation verify "$asset" \
  --repo pythonhk/eventctl \
  --deny-self-hosted-runners \
  --signer-digest "$signer_digest" \
  --signer-workflow pythonhk/eventctl/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag" \
  --source-digest "$source_digest" \
  --predicate-type https://spdx.dev/Document/v2.3

# Reject duplicate, traversal, link, and extra-entry archive shapes before use.
expected_entries=$(printf '%s\n' LICENSE eventctl | LC_ALL=C sort)
actual_entries=$(tar -tzf "$asset" | LC_ALL=C sort)
test "$actual_entries" = "$expected_entries"
verify_dir=$(mktemp -d)
trap 'rm -rf -- "$verify_dir"' EXIT HUP INT TERM
tar -xzf "$asset" -C "$verify_dir"
test -f "$verify_dir/eventctl" && test ! -L "$verify_dir/eventctl"
test -f "$verify_dir/LICENSE" && test ! -L "$verify_dir/LICENSE"
version_json=$("$verify_dir/eventctl" version --json)
printf '%s' "$version_json" | jq -e \
  --arg version "$version" \
  --arg commit "$source_digest" \
  --arg date "$source_date" \
  '.version == $version and .commit == $commit and .date == $date'

doctor_json=$("$verify_dir/eventctl" doctor)
printf '%s' "$doctor_json" | jq -e \
  --arg operating_system "$expected_os" \
  --arg architecture "$expected_arch" \
  '.output_version == "pythonhk.eventctl/output/v1" and
   .ok == true and .command == "doctor" and .error == null and
   .result.status == "healthy" and
   .result.operating_system == $operating_system and
   .result.architecture == $architecture'

```

The event starter's installer must perform the equivalent checksum and
provenance validation before extracting or executing the CLI, and it must
verify the immutable release record before downloading. A checksum fetched from
the same release protects transfer integrity; the GitHub attestation binds that
digest to this repository and workflow.

## Failed and superseded releases

- Failure before draft creation leaves GitHub release state unchanged.
- A failed draft is unpublished and mutable. Inspect the workflow and draft
  assets, record the reason, then an authorized maintainer may remove only that
  draft before rerunning the same tag.
- Once published, the release and its tag are immutable. Any build, native
  execution, checksum, SBOM, attestation, or readback failure makes the version
  unusable. Fix the cause and publish a new patch version; never reuse or move
  the old tag.
- If a release was accidentally published without immutability, treat it as
  compromised, enable immutability, and publish a new version. Enabling the
  setting is not retroactive.

## Updating release dependencies

Dependabot may propose action or Go module updates, but it does not replace
review. For every action update, resolve the advertised immutable version tag
in the action's official repository, record the full commit SHA in `uses:`, and
retain the human-readable version comment. Then run:

```bash
scripts/release/check-action-pins.sh
scripts/release/load-tool-versions.sh
```

For GoReleaser or Syft updates, update the single version contract, review their
official release notes and checksums, run `goreleaser check`, and require CI to
re-prove deterministic archives. Never use a version range, floating major tag,
or `latest` in the release workflow.

The initial reviewed action set is:

| Action | Version | Pinned commit |
| --- | --- | --- |
| `actions/checkout` | `v7.0.1` | [`3d3c42e5aac5ba805825da76410c181273ba90b1`](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1) |
| `actions/setup-go` | `v7.0.0` | [`b7ad1dad31e06c5925ef5d2fc7ad053ef454303e`](https://github.com/actions/setup-go/commit/b7ad1dad31e06c5925ef5d2fc7ad053ef454303e) |
| `actions/upload-artifact` | `v7.0.1` | [`043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`](https://github.com/actions/upload-artifact/commit/043fb46d1a93c77aae656e7c1c64a875d1fc6a0a) |
| `actions/download-artifact` | `v8.0.1` | [`3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c`](https://github.com/actions/download-artifact/commit/3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c) |
| `actions/attest` | `v4.2.1` | [`508db95dd578ae2727ebd6217d5ba78e4fbda05d`](https://github.com/actions/attest/commit/508db95dd578ae2727ebd6217d5ba78e4fbda05d) |
| `anchore/sbom-action` | `v0.24.0` | [`e22c389904149dbc22b58101806040fa8d37a610`](https://github.com/anchore/sbom-action/commit/e22c389904149dbc22b58101806040fa8d37a610) |
| `goreleaser/goreleaser-action` | `v7.2.3` | [`f06c13b6b1a9625abc9e6e439d9c05a8f2190e94`](https://github.com/goreleaser/goreleaser-action/commit/f06c13b6b1a9625abc9e6e439d9c05a8f2190e94) |

## Release evidence

Retain the tag commit, protected-environment approval, workflow URL, CI and
native job results, release URL, exact asset names, draft digest/size readback,
`SHA256SUMS`, SPDX SBOMs, artifact-attestation verification output,
immutable-release verification, and the version JSON from every native target.
These are the minimum facts needed to reproduce the release decision.
