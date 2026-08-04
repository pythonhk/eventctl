#!/usr/bin/env bash
set -Eeuo pipefail

workflow_dir=${1:-.github/workflows}
CDPATH=''
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/../.." && pwd)

if [[ ! -d $workflow_dir ]]; then
	printf 'workflow directory not found: %s\n' "$workflow_dir" >&2
	exit 1
fi

workflow_dir=$(cd -- "$workflow_dir" && pwd)
cd "$repo_dir"
exec go run -mod=readonly "$script_dir/actionpins/main.go" "$workflow_dir"
