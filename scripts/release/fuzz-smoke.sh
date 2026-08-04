#!/usr/bin/env bash
set -Eeuo pipefail

fuzz_time=${FUZZ_TIME:-5s}
if [[ ! $fuzz_time =~ ^[1-9][0-9]*(ms|s|m)$ ]]; then
	printf 'invalid FUZZ_TIME: %s\n' "$fuzz_time" >&2
	exit 1
fi

target_count=0
while IFS=: read -r test_file target_line; do
	[[ -n $test_file && -n $target_line ]] || continue
	target_name=${target_line#func }
	target_name=${target_name%%(*}
	package_dir=$(dirname -- "$test_file")
	target_count=$((target_count + 1))
	printf 'fuzz smoke: %s (%s)\n' "$target_name" "$package_dir"
	(
		cd "$package_dir"
		go test -mod=readonly . -run '^$' -fuzz "^${target_name}$" -fuzztime "$fuzz_time"
	)
done < <(
	find . -type f -name '*_test.go' -not -path './vendor/*' -exec \
		grep -H -E '^func Fuzz[A-Za-z0-9_]+\(' {} + 2>/dev/null || true
)

if ((target_count == 0)); then
	printf 'no Go fuzz targets found; at least one security-boundary fuzz target is required\n' >&2
	exit 1
fi
