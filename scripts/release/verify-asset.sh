#!/usr/bin/env bash
set -Eeuo pipefail

dist_dir=${1:-}
version=${2:-}
platform=${3:-}
architecture=${4:-}
expected_commit=${5:-}
expected_date=${6:-}
derived_date=''
CDPATH=''
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/../.." && pwd)
source_license="$repo_dir/LICENSE"

license_matches_source() {
	candidate=$1
	if command -v git >/dev/null 2>&1 &&
		git -C "$repo_dir" rev-parse --verify HEAD >/dev/null 2>&1; then
		git -C "$repo_dir" cat-file -e HEAD:LICENSE >/dev/null 2>&1 &&
			git -C "$repo_dir" show HEAD:LICENSE | cmp -s - "$candidate"
		return
	fi
	cmp -s "$source_license" "$candidate"
}

case "$platform/$architecture" in
	darwin/amd64 | darwin/arm64 | linux/amd64 | linux/arm64 | windows/amd64 | windows/arm64) ;;
	*)
		printf 'unsupported verification target: %s/%s\n' "$platform" "$architecture" >&2
		exit 1
		;;
esac
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
	printf 'invalid version: %s\n' "$version" >&2
	exit 1
fi
if [[ -n $expected_commit && ! $expected_commit =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
	printf 'expected commit must be a full 40- or 64-character digest: %s\n' \
		"$expected_commit" >&2
	exit 1
fi
if [[ ! -f $source_license ]]; then
	printf 'source license not found: %s\n' "$source_license" >&2
	exit 1
fi
if [[ -n $expected_commit ]]; then
	if ! derived_date=$(TZ=UTC git -C "$repo_dir" show -s \
		--format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ \
		"$expected_commit"); then
		printf 'could not derive the expected UTC commit date for %s\n' \
			"$expected_commit" >&2
		exit 1
	fi
	if [[ ! $derived_date =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
		printf 'derived commit date is not canonical UTC RFC3339: %s\n' \
			"$derived_date" >&2
		exit 1
	fi
	if [[ -n $expected_date && $expected_date != "$derived_date" ]]; then
		printf 'provided commit date %s differs from independently derived date %s\n' \
			"$expected_date" "$derived_date" >&2
		exit 1
	fi
	expected_date=$derived_date
elif [[ -n $expected_date ]]; then
	printf 'an expected commit date requires an expected commit digest\n' >&2
	exit 1
fi

extension=tar.gz
binary_name=eventctl
if [[ $platform == windows ]]; then
	extension=zip
	binary_name=eventctl.exe
fi
asset_name="eventctl_${version}_${platform}_${architecture}.${extension}"
asset_path="$dist_dir/$asset_name"

[[ -f $asset_path && -f $dist_dir/SHA256SUMS ]] || {
	printf 'missing %s or SHA256SUMS under %s\n' "$asset_name" "$dist_dir" >&2
	exit 1
}

checksum_line=$(awk -v name="$asset_name" '$2 == name || $2 == "*" name { print }' \
	"$dist_dir/SHA256SUMS")
if [[ -z $checksum_line || $checksum_line == *$'\n'* ]]; then
	printf 'expected exactly one checksum for %s\n' "$asset_name" >&2
	exit 1
fi
expected_hash=${checksum_line%%[[:space:]]*}
if command -v sha256sum >/dev/null 2>&1; then
	actual_hash=$(sha256sum "$asset_path" | awk '{print $1}')
else
	actual_hash=$(shasum -a 256 "$asset_path" | awk '{print $1}')
fi
if [[ ! $expected_hash =~ ^[0-9a-f]{64}$ || $actual_hash != "$expected_hash" ]]; then
	printf 'checksum mismatch for %s\n' "$asset_name" >&2
	exit 1
fi

extract_dir=$(mktemp -d "${TMPDIR:-/tmp}/eventctl-verify.XXXXXX")
cleanup() {
	rm -rf -- "$extract_dir"
}
trap cleanup EXIT HUP INT TERM

if [[ $extension == zip ]]; then
	archive_entries=$(unzip -Z1 "$asset_path")
	actual_entries=$(printf '%s\n' "$archive_entries" | LC_ALL=C sort)
	expected_entries=$(printf '%s\n' LICENSE "$binary_name" | LC_ALL=C sort)
	[[ $actual_entries == "$expected_entries" ]] || {
		printf 'unsafe or unexpected archive entries: %s\n' "$archive_entries" >&2
		exit 1
	}
	unzip -q "$asset_path" -d "$extract_dir"
else
	archive_entries=$(tar -tzf "$asset_path")
	actual_entries=$(printf '%s\n' "$archive_entries" | LC_ALL=C sort)
	expected_entries=$(printf '%s\n' LICENSE "$binary_name" | LC_ALL=C sort)
	[[ $actual_entries == "$expected_entries" ]] || {
		printf 'unsafe or unexpected archive entries: %s\n' "$archive_entries" >&2
		exit 1
	}
	tar -xzf "$asset_path" -C "$extract_dir"
fi

binary_path="$extract_dir/$binary_name"
license_path="$extract_dir/LICENSE"
[[ -f $binary_path && ! -L $binary_path && -f $license_path && ! -L $license_path ]] || {
	printf 'archive did not extract one regular binary and LICENSE\n' >&2
	exit 1
}
if ! license_matches_source "$license_path"; then
	printf 'archive LICENSE does not match the tagged source\n' >&2
	exit 1
fi
chmod 0755 "$binary_path"
version_json=$("$binary_path" version --json)

printf '%s' "$version_json" | jq -e --arg version "$version" \
	--arg expected_date "$expected_date" \
	'.version == $version and
   (.commit | type == "string" and test("^([0-9a-f]{40}|[0-9a-f]{64})$")) and
   (.date | type == "string") and
   (if $expected_date == "" then
      (.date | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$"))
    else .date == $expected_date end)' >/dev/null

if [[ -n $expected_commit ]]; then
	actual_commit=$(printf '%s' "$version_json" | jq -r '.commit')
	if [[ $actual_commit != "$expected_commit" ]]; then
		printf 'binary commit %s does not match expected commit %s\n' \
			"$actual_commit" "$expected_commit" >&2
		exit 1
	fi
fi

doctor_json=$("$binary_path" doctor)
printf '%s' "$doctor_json" | jq -e \
	--arg platform "$platform" \
	--arg architecture "$architecture" \
	'.output_version == "pythonhk.eventctl/output/v1" and
   .ok == true and .command == "doctor" and .error == null and
   .result.status == "healthy" and
   .result.operating_system == $platform and
   .result.architecture == $architecture' >/dev/null

printf 'verified and executed %s\n' "$asset_name"
