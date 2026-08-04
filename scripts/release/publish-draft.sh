#!/usr/bin/env bash
set -Eeuo pipefail

tag=${1:-}
dist_dir=${2:-dist}
repo=${3:-${GITHUB_REPOSITORY:-}}
version=${tag#v}
CDPATH=''
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if [[ $repo != pythonhk/eventctl ]]; then
	printf 'refusing to publish to unexpected repository: %s\n' "$repo" >&2
	exit 1
fi
semver_regex='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$'
if [[ ! $tag =~ $semver_regex ]]; then
	printf 'refusing invalid release tag: %s\n' "$tag" >&2
	exit 1
fi
"$script_dir/require-gh-version.sh"
"$script_dir/verify-dist.sh" "$dist_dir" "$version"

if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
	printf 'release already exists and will not be modified: %s\n' "$tag" >&2
	exit 1
fi

assets=("$dist_dir/SHA256SUMS")
for target in \
	darwin_amd64.tar.gz \
	darwin_arm64.tar.gz \
	linux_amd64.tar.gz \
	linux_arm64.tar.gz \
	windows_amd64.zip \
	windows_arm64.zip; do
	archive="$dist_dir/eventctl_${version}_${target}"
	assets+=("$archive" "$archive.spdx.json")
done

for asset in "${assets[@]}"; do
	[[ -f $asset ]] || {
		printf 'missing release asset: %s\n' "$asset" >&2
		exit 1
	}
done

release_flags=(
	--repo "$repo"
	--draft
	--verify-tag
	--generate-notes
	--title "eventctl $tag"
)
is_prerelease=false
if [[ $tag == *-* ]]; then
	release_flags+=(--prerelease --latest=false)
	is_prerelease=true
fi
gh release create "$tag" "${assets[@]}" "${release_flags[@]}"

release_json=$(gh release view "$tag" --repo "$repo" \
	--json databaseId,isDraft,isPrerelease,tagName,assets)
printf '%s' "$release_json" | jq -e --arg tag "$tag" \
	--argjson prerelease "$is_prerelease" \
	'.isDraft == true and .isPrerelease == $prerelease and
   .tagName == $tag and
   (.databaseId | type == "number" and . > 0 and floor == .) and
   (.assets | length) == 13' >/dev/null
release_id=$(printf '%s' "$release_json" | jq -er '.databaseId')

expected_assets=$(mktemp "${TMPDIR:-/tmp}/eventctl-assets-expected.XXXXXX")
actual_assets=$(mktemp "${TMPDIR:-/tmp}/eventctl-assets-actual.XXXXXX")
# Invoked by the trap below.
# shellcheck disable=SC2329
cleanup() {
	# shellcheck disable=SC2317 # Reached indirectly through the EXIT/signal trap.
	rm -f -- "$expected_assets" "$actual_assets"
}
trap cleanup EXIT HUP INT TERM

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

for asset in "${assets[@]}"; do
	asset_name=$(basename -- "$asset")
	asset_digest=$(hash_file "$asset")
	asset_size=$(wc -c <"$asset" | tr -d '[:space:]')
	printf '%s\tsha256:%s\t%s\n' "$asset_name" "$asset_digest" "$asset_size"
done | LC_ALL=C sort >"$expected_assets"

# `gh release create` returning successfully is not the upload-integrity
# boundary. Read the server-computed digest and size for every draft asset,
# including SPDX documents and SHA256SUMS, before the release is published.
attempt=1
while ((attempt <= 10)); do
	if gh api \
		-H 'Accept: application/vnd.github+json' \
		-H 'X-GitHub-Api-Version: 2026-03-10' \
		"repos/$repo/releases/$release_id/assets?per_page=100" \
		--jq '.[] | select(.state == "uploaded") | [.name, .digest, (.size | tostring)] | @tsv' |
		LC_ALL=C sort >"$actual_assets" &&
		cmp -s "$expected_assets" "$actual_assets"; then
		printf 'created and digest-verified asset-complete draft release %s\n' "$tag"
		while IFS= read -r asset_record; do
			printf 'draft asset\t%s\n' "$asset_record"
		done <"$actual_assets"
		exit 0
	fi
	sleep 2
	attempt=$((attempt + 1))
done

printf 'draft release asset digest readback did not match local files\n' >&2
diff -u "$expected_assets" "$actual_assets" >&2 || true
exit 1
