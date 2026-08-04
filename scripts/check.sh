#!/usr/bin/env bash

set -Eeuo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

# Trusted repository-owned toolchain contract.
# shellcheck disable=SC1091
source "$repository_root/scripts/release/tool-versions.env"

required_commands=(go gofmt govulncheck)
for command_name in "${required_commands[@]}"; do
	if ! command -v "$command_name" >/dev/null 2>&1; then
		echo "required command not found: $command_name" >&2
		exit 127
	fi
done

actual_go_version="$(go env GOVERSION)"
if [[ $actual_go_version != "go$GO_VERSION" ]]; then
	echo "Go $GO_VERSION is required; found ${actual_go_version#go}" >&2
	exit 1
fi
actual_govulncheck_version="$(govulncheck -version | awk '$1 == "Scanner:" { print $2 }')"
if [[ $actual_govulncheck_version != "govulncheck@$GOVULNCHECK_VERSION" ]]; then
	echo "govulncheck $GOVULNCHECK_VERSION is required; found ${actual_govulncheck_version:-unknown}" >&2
	exit 1
fi

unformatted="$(gofmt -l .)"
if [[ -n "$unformatted" ]]; then
	echo "gofmt is required for:" >&2
	echo "$unformatted" >&2
	exit 1
fi

go mod tidy -diff
go mod verify
go vet -mod=readonly ./...
go test -mod=readonly -count=1 ./...
go test -mod=readonly -race -count=1 ./...
GOFLAGS=-mod=readonly govulncheck ./...
