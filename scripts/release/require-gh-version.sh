#!/usr/bin/env bash
set -Eeuo pipefail

CDPATH=''
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# Trusted repository configuration, resolved independently of the caller.
# shellcheck disable=SC1091
source "$script_dir/tool-versions.env"

if [[ ! $GH_MIN_VERSION =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
	printf 'invalid GitHub CLI security floor: %s\n' "$GH_MIN_VERSION" >&2
	exit 1
fi
required_major=${BASH_REMATCH[1]}
required_minor=${BASH_REMATCH[2]}
required_patch=${BASH_REMATCH[3]}

if ! command -v gh >/dev/null 2>&1; then
	printf 'GitHub CLI >= %s is required\n' "$GH_MIN_VERSION" >&2
	exit 1
fi
if ! version_output=$(gh --version 2>&1); then
	printf 'could not determine the GitHub CLI version\n' >&2
	exit 1
fi
version_line=${version_output%%$'\n'*}
if [[ ! $version_line =~ ^gh[[:space:]]+version[[:space:]]+([0-9]+)\.([0-9]+)\.([0-9]+)([[:space:]]|$) ]]; then
	printf 'unrecognized GitHub CLI version output: %s\n' "$version_line" >&2
	exit 1
fi
actual_major=${BASH_REMATCH[1]}
actual_minor=${BASH_REMATCH[2]}
actual_patch=${BASH_REMATCH[3]}
actual_version=$actual_major.$actual_minor.$actual_patch

if ((actual_major < required_major)) ||
	((actual_major == required_major && actual_minor < required_minor)) ||
	((actual_major == required_major && actual_minor == required_minor && actual_patch < required_patch)); then
	printf 'GitHub CLI %s is unsafe; version %s or newer is required\n' \
		"$actual_version" "$GH_MIN_VERSION" >&2
	exit 1
fi

printf 'GitHub CLI %s satisfies security floor %s\n' \
	"$actual_version" "$GH_MIN_VERSION"
