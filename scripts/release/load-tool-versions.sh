#!/usr/bin/env bash
set -Eeuo pipefail

CDPATH=''
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# This file is trusted repository configuration, never participant input.
# The path is resolved from this script, not the caller's working directory.
# shellcheck disable=SC1091
source "$script_dir/tool-versions.env"

for tool_name in \
	GO_VERSION \
	GORELEASER_VERSION \
	SYFT_VERSION \
	GOVULNCHECK_VERSION \
	ACTIONLINT_VERSION \
	SHFMT_VERSION; do
	tool_value=${!tool_name}
	if [[ ! $tool_value =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		printf 'invalid %s in tool-versions.env: %s\n' "$tool_name" "$tool_value" >&2
		exit 1
	fi
done

if [[ ! $GH_MIN_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	printf 'invalid GH_MIN_VERSION in tool-versions.env: %s\n' "$GH_MIN_VERSION" >&2
	exit 1
fi

if [[ -n ${GITHUB_OUTPUT:-} ]]; then
	{
		printf 'go=%s\n' "$GO_VERSION"
		printf 'goreleaser=%s\n' "$GORELEASER_VERSION"
		printf 'syft=%s\n' "$SYFT_VERSION"
		printf 'govulncheck=%s\n' "$GOVULNCHECK_VERSION"
		printf 'actionlint=%s\n' "$ACTIONLINT_VERSION"
		printf 'shfmt=%s\n' "$SHFMT_VERSION"
		printf 'gh_min=%s\n' "$GH_MIN_VERSION"
	} >>"$GITHUB_OUTPUT"
else
	printf 'Go %s; GoReleaser %s; Syft %s; GitHub CLI >= %s\n' \
		"$GO_VERSION" "$GORELEASER_VERSION" "$SYFT_VERSION" "$GH_MIN_VERSION"
fi
