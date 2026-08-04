#!/usr/bin/env bash
set -Eeuo pipefail

tag=${1:-}
repo=${2:-pythonhk/eventctl}
expected_source_digest=${3:-}
version=${tag#v}
CDPATH=''
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if [[ $repo != pythonhk/eventctl ]]; then
	printf 'refusing to verify an unexpected repository: %s\n' "$repo" >&2
	exit 1
fi
if [[ ! $expected_source_digest =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
	printf 'expected source digest must be a full Git commit digest: %s\n' \
		"$expected_source_digest" >&2
	exit 1
fi
"$script_dir/require-gh-version.sh"

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
			*) return 1 ;;
		esac
		peel_attempt=$((peel_attempt + 1))
	done
	return 1
}

tag_matches_source() {
	local remote_source_digest
	remote_source_digest=$(resolve_remote_tag_commit) || return 1
	[[ $remote_source_digest == "$expected_source_digest" ]]
}

expected_assets_json=$(
	printf '%s\n' \
		SHA256SUMS \
		"eventctl_${version}_darwin_amd64.tar.gz" \
		"eventctl_${version}_darwin_amd64.tar.gz.spdx.json" \
		"eventctl_${version}_darwin_arm64.tar.gz" \
		"eventctl_${version}_darwin_arm64.tar.gz.spdx.json" \
		"eventctl_${version}_linux_amd64.tar.gz" \
		"eventctl_${version}_linux_amd64.tar.gz.spdx.json" \
		"eventctl_${version}_linux_arm64.tar.gz" \
		"eventctl_${version}_linux_arm64.tar.gz.spdx.json" \
		"eventctl_${version}_windows_amd64.zip" \
		"eventctl_${version}_windows_amd64.zip.spdx.json" \
		"eventctl_${version}_windows_arm64.zip" \
		"eventctl_${version}_windows_arm64.zip.spdx.json" |
		jq -R -s 'split("\n") | map(select(length > 0)) | sort'
)

attempt=1
while ((attempt <= 20)); do
	if release_json=$(gh release view "$tag" --repo "$repo" \
		--json isDraft,isImmutable,tagName,assets) &&
		printf '%s' "$release_json" | jq -e --arg tag "$tag" \
			--argjson expected "$expected_assets_json" \
			'.isDraft == false and .isImmutable == true and
     .tagName == $tag and
     ([.assets[].name] | sort) == $expected' >/dev/null &&
		tag_matches_source &&
		gh release verify "$tag" --repo "$repo"; then
		printf 'verified immutable GitHub release record for %s\n' "$tag"
		exit 0
	fi
	sleep 3
	attempt=$((attempt + 1))
done

printf 'could not verify immutable release record for %s\n' "$tag" >&2
exit 1
