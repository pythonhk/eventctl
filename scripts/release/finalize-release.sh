#!/usr/bin/env bash
set -Eeuo pipefail

tag=${1:-}
repo=${2:-${GITHUB_REPOSITORY:-}}
dist_dir=${3:-dist}
expected_source_digest=${4:-}
CDPATH=''
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if [[ $repo != pythonhk/eventctl ]]; then
	printf 'refusing to finalize unexpected repository: %s\n' "$repo" >&2
	exit 1
fi
semver_regex='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$'
if [[ ! $tag =~ $semver_regex ]]; then
	printf 'refusing invalid release tag: %s\n' "$tag" >&2
	exit 1
fi
if [[ ! $expected_source_digest =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
	printf 'expected source digest must be a full Git commit digest: %s\n' \
		"$expected_source_digest" >&2
	exit 1
fi
"$script_dir/require-gh-version.sh"

version=${tag#v}
"$script_dir/verify-dist.sh" "$dist_dir" "$version"

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

expected_assets=$(mktemp "${TMPDIR:-/tmp}/eventctl-finalize-expected.XXXXXX")
actual_assets=$(mktemp "${TMPDIR:-/tmp}/eventctl-finalize-actual.XXXXXX")
# Invoked by the trap below.
# shellcheck disable=SC2329
cleanup() {
	# shellcheck disable=SC2317 # Reached indirectly through the EXIT/signal trap.
	rm -f -- "$expected_assets" "$actual_assets"
}
trap cleanup EXIT HUP INT TERM

hash_file() {
	local path=$1
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$path" | awk '{print $1}'
	else
		shasum -a 256 "$path" | awk '{print $1}'
	fi
}

for asset in "${assets[@]}"; do
	if [[ ! -f $asset || -L $asset ]]; then
		printf 'release asset is missing or unsafe: %s\n' "$asset" >&2
		exit 1
	fi
	asset_name=$(basename -- "$asset")
	asset_digest=$(hash_file "$asset")
	asset_size=$(wc -c <"$asset" | tr -d '[:space:]')
	printf '%s\tsha256:%s\t%s\n' "$asset_name" "$asset_digest" "$asset_size"
done | LC_ALL=C sort >"$expected_assets"

read_server_assets() {
	local release_id=$1
	local output_file=$2
	gh api \
		-H 'Accept: application/vnd.github+json' \
		-H 'X-GitHub-Api-Version: 2026-03-10' \
		"repos/$repo/releases/$release_id/assets?per_page=100" \
		--jq '.[] | select(.state == "uploaded") | [.name, .digest, (.size | tostring)] | @tsv' |
		LC_ALL=C sort >"$output_file"
}

resolve_remote_tag_commit() {
	local object_record
	local object_type
	local object_digest
	local peel_attempt=1
	object_record=$(gh api \
		-H 'Accept: application/vnd.github+json' \
		-H 'X-GitHub-Api-Version: 2026-03-10' \
		"repos/$repo/git/ref/tags/$tag" \
		--jq '[.object.type, .object.sha] | @tsv')
	IFS=$'\t' read -r object_type object_digest <<<"$object_record"
	while ((peel_attempt <= 8)); do
		if [[ ! $object_digest =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
			printf 'remote tag contains an invalid object digest\n' >&2
			return 1
		fi
		case "$object_type" in
			commit)
				printf '%s\n' "$object_digest"
				return 0
				;;
			tag)
				object_record=$(gh api \
					-H 'Accept: application/vnd.github+json' \
					-H 'X-GitHub-Api-Version: 2026-03-10' \
					"repos/$repo/git/tags/$object_digest" \
					--jq '[.object.type, .object.sha] | @tsv')
				IFS=$'\t' read -r object_type object_digest <<<"$object_record"
				;;
			*)
				printf 'remote release tag resolves to unsupported object type: %s\n' \
					"$object_type" >&2
				return 1
				;;
		esac
		peel_attempt=$((peel_attempt + 1))
	done
	printf 'remote release tag nesting exceeds the supported limit\n' >&2
	return 1
}

assert_remote_tag_commit() {
	local remote_source_digest
	remote_source_digest=$(resolve_remote_tag_commit)
	if [[ $remote_source_digest != "$expected_source_digest" ]]; then
		printf 'remote tag commit %s differs from built source %s\n' \
			"$remote_source_digest" "$expected_source_digest" >&2
		return 1
	fi
}

is_prerelease=false
if [[ $tag == *-* ]]; then
	is_prerelease=true
fi

release_json=$(gh release view "$tag" --repo "$repo" \
	--json databaseId,isDraft,isPrerelease,tagName,assets)
printf '%s' "$release_json" | jq -e --arg tag "$tag" \
	--argjson prerelease "$is_prerelease" \
	'.isDraft == true and .isPrerelease == $prerelease and
   .tagName == $tag and .databaseId > 0 and
   ([.assets[].name] | length) == 13' >/dev/null
release_id=$(printf '%s' "$release_json" | jq -er '.databaseId')

# The prior draft-upload readback is not a publication authorization: drafts
# remain mutable. Re-read every server-computed digest and size, plus the
# peeled remote tag target, immediately before the irreversible publish call.
read_server_assets "$release_id" "$actual_assets"
if ! cmp -s "$expected_assets" "$actual_assets"; then
	printf 'draft release assets changed after their initial upload readback\n' >&2
	diff -u "$expected_assets" "$actual_assets" >&2 || true
	exit 1
fi
assert_remote_tag_commit

edit_flags=(--repo "$repo" --draft=false --verify-tag)
if [[ $is_prerelease == true ]]; then
	edit_flags+=(--prerelease --latest=false)
else
	edit_flags+=(--prerelease=false --latest)
fi
gh release edit "$tag" "${edit_flags[@]}"

attempt=1
release_json=''
while ((attempt <= 15)); do
	if release_json=$(gh release view "$tag" --repo "$repo" \
		--json databaseId,isDraft,isImmutable,isPrerelease,tagName,assets) &&
		printf '%s' "$release_json" | jq -e --arg tag "$tag" \
			--argjson release_id "$release_id" \
			--argjson prerelease "$is_prerelease" \
			'.databaseId == $release_id and
     .isDraft == false and .isImmutable == true and
     .isPrerelease == $prerelease and .tagName == $tag and
     ([.assets[].name] | length) == 13' >/dev/null &&
		assert_remote_tag_commit &&
		read_server_assets "$release_id" "$actual_assets" &&
		cmp -s "$expected_assets" "$actual_assets"; then
		printf 'published immutable digest-complete release %s\n' "$tag"
		exit 0
	fi
	sleep 2
	attempt=$((attempt + 1))
done

printf 'release was published but immutable digest/tag equality was not proven; supersede it with a new version\n' >&2
printf '%s\n' "$release_json" >&2
diff -u "$expected_assets" "$actual_assets" >&2 || true
exit 1
