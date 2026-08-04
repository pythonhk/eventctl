#!/usr/bin/env bash
set -Eeuo pipefail

tag=${1:-${GITHUB_REF_NAME:-}}
expected_repo=${2:-pythonhk/eventctl}
actual_repo=${GITHUB_REPOSITORY:-$expected_repo}
CDPATH=''
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

semver_regex='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$'
if [[ ! $tag =~ $semver_regex ]]; then
	printf 'release tag must be SemVer with a v prefix: %s\n' "$tag" >&2
	exit 1
fi
if [[ $actual_repo != "$expected_repo" ]]; then
	printf 'refusing to release from %s; expected %s\n' "$actual_repo" "$expected_repo" >&2
	exit 1
fi
if [[ $(git cat-file -t "$tag") != tag ]]; then
	printf 'release tag must be annotated: %s\n' "$tag" >&2
	exit 1
fi

tag_commit=$(git rev-parse --verify "${tag}^{commit}")
head_commit=$(git rev-parse --verify HEAD)
if [[ $tag_commit != "$head_commit" ]]; then
	printf 'checked-out commit %s does not match %s (%s)\n' \
		"$head_commit" "$tag" "$tag_commit" >&2
	exit 1
fi
if ! git merge-base --is-ancestor "$tag_commit" refs/remotes/origin/main; then
	printf 'tag commit is not reachable from origin/main: %s\n' "$tag_commit" >&2
	exit 1
fi
if [[ -n $(git status --porcelain --untracked-files=all) ]]; then
	printf 'tracked or untracked files changed before release build\n' >&2
	git status --short >&2
	exit 1
fi

"$script_dir/require-gh-version.sh"
if gh release view "$tag" --repo "$expected_repo" >/dev/null 2>&1; then
	printf 'release already exists and will not be overwritten: %s\n' "$tag" >&2
	exit 1
fi

printf 'validated release tag %s at %s\n' "$tag" "$tag_commit"
