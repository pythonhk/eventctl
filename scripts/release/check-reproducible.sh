#!/usr/bin/env bash
set -Eeuo pipefail

# Release builds pin Syft explicitly; its independent update check would add an
# unnecessary network dependency and cannot change this run's installed binary.
export SYFT_CHECK_FOR_APP_UPDATE=false

version=${1:-}
build_mode=${2:-snapshot}
CDPATH=''
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
	printf 'invalid snapshot version: %s\n' "$version" >&2
	exit 1
fi
case "$build_mode" in
	snapshot | release) ;;
	*)
		printf 'invalid reproducibility build mode: %s\n' "$build_mode" >&2
		exit 1
		;;
esac

comparison_dir=$(mktemp -d "${TMPDIR:-/tmp}/eventctl-reproducible.XXXXXX")
cleanup() {
	rm -rf -- "$comparison_dir"
}
trap cleanup EXIT HUP INT TERM

archive_hashes() {
	output_file=$1
	if command -v sha256sum >/dev/null 2>&1; then
		for archive in dist/*.tar.gz dist/*.zip; do
			sha256sum "$archive"
		done | LC_ALL=C sort -k2 >"$output_file"
	else
		for archive in dist/*.tar.gz dist/*.zip; do
			shasum -a 256 "$archive"
		done | LC_ALL=C sort -k2 >"$output_file"
	fi
}

goreleaser_args=(release --clean --skip=publish)
if [[ $build_mode == snapshot ]]; then
	goreleaser_args+=(--snapshot)
fi

# Force both builds through independent empty Go build caches. The module
# source cache may be shared because go.sum and -mod=readonly authenticate it.
first_go_cache="$comparison_dir/go-cache-first"
second_go_cache="$comparison_dir/go-cache-second"
GOCACHE="$first_go_cache" goreleaser "${goreleaser_args[@]}"
"$script_dir/verify-dist.sh" dist "$version"
archive_hashes "$comparison_dir/first"

GOCACHE="$second_go_cache" goreleaser "${goreleaser_args[@]}"
"$script_dir/verify-dist.sh" dist "$version"
archive_hashes "$comparison_dir/second"

if ! diff -u "$comparison_dir/first" "$comparison_dir/second"; then
	printf 'release archives are not reproducible across identical builds\n' >&2
	exit 1
fi

printf 'release archives are byte-for-byte reproducible\n'
