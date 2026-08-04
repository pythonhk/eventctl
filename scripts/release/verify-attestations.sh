#!/usr/bin/env bash
set -Eeuo pipefail

asset_path=${1:-}
repo=${2:-pythonhk/eventctl}
tag=${3:-}
source_digest=${4:-}
signer_workflow="$repo/.github/workflows/release.yml"
source_ref="refs/tags/$tag"
CDPATH=''
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

[[ -f $asset_path ]] || {
	printf 'asset not found: %s\n' "$asset_path" >&2
	exit 1
}
if [[ $repo != pythonhk/eventctl ]]; then
	printf 'refusing to verify attestations from unexpected repository: %s\n' "$repo" >&2
	exit 1
fi
if [[ ! $source_digest =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
	printf 'invalid source commit digest: %s\n' "$source_digest" >&2
	exit 1
fi
"$script_dir/require-gh-version.sh"

verify_predicate() {
	predicate_type=$1
	attempt=1
	while ((attempt <= 15)); do
		if gh attestation verify "$asset_path" \
			--repo "$repo" \
			--deny-self-hosted-runners \
			--signer-digest "$source_digest" \
			--signer-workflow "$signer_workflow" \
			--source-ref "$source_ref" \
			--source-digest "$source_digest" \
			--predicate-type "$predicate_type"; then
			return 0
		fi
		sleep 3
		attempt=$((attempt + 1))
	done
	return 1
}

verify_predicate https://slsa.dev/provenance/v1
verify_predicate https://spdx.dev/Document/v2.3
printf 'verified provenance and SPDX attestations for %s\n' "$asset_path"
