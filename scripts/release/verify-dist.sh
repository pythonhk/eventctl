#!/usr/bin/env bash
set -Eeuo pipefail

dist_dir=${1:-dist}
version=${2:-}
CDPATH=''
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_license="$script_dir/../../LICENSE"
# Trusted repository-owned toolchain contract.
# shellcheck disable=SC1091
source "$script_dir/tool-versions.env"
syft_creator="Tool: syft-${SYFT_VERSION#v}"

if [[ ! -d $dist_dir ]]; then
	printf 'release directory not found: %s\n' "$dist_dir" >&2
	exit 1
fi
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
	printf 'invalid release version: %s\n' "$version" >&2
	exit 1
fi
if [[ ! -f $dist_dir/SHA256SUMS ]]; then
	printf 'missing checksum contract: %s/SHA256SUMS\n' "$dist_dir" >&2
	exit 1
fi
if [[ ! -f $source_license ]]; then
	printf 'source license not found: %s\n' "$source_license" >&2
	exit 1
fi

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

verify_one() {
	platform=$1
	architecture=$2
	extension=$3
	binary_name=$4
	asset_name="eventctl_${version}_${platform}_${architecture}.${extension}"
	asset_path="$dist_dir/$asset_name"
	sbom_path="$asset_path.spdx.json"

	[[ -f $asset_path ]] || {
		printf 'missing archive: %s\n' "$asset_path" >&2
		return 1
	}
	[[ -f $sbom_path ]] || {
		printf 'missing SPDX SBOM: %s\n' "$sbom_path" >&2
		return 1
	}

	checksum_line=$(awk -v name="$asset_name" '$2 == name || $2 == "*" name { print }' \
		"$dist_dir/SHA256SUMS")
	if [[ -z $checksum_line || $checksum_line == *$'\n'* ]]; then
		printf 'expected exactly one checksum for %s\n' "$asset_name" >&2
		return 1
	fi
	expected_hash=${checksum_line%%[[:space:]]*}
	actual_hash=$(hash_file "$asset_path")
	if [[ ! $expected_hash =~ ^[0-9a-f]{64}$ || $actual_hash != "$expected_hash" ]]; then
		printf 'checksum mismatch for %s\n' "$asset_name" >&2
		return 1
	fi

	if [[ $extension == zip ]]; then
		archive_entries=$(unzip -Z1 "$asset_path")
		license_matches=$(unzip -p "$asset_path" LICENSE | cmp -s - "$source_license" && printf true || printf false)
	else
		archive_entries=$(tar -tzf "$asset_path")
		license_matches=$(tar -xOzf "$asset_path" LICENSE | cmp -s - "$source_license" && printf true || printf false)
	fi
	actual_entries=$(printf '%s\n' "$archive_entries" | LC_ALL=C sort)
	expected_entries=$(printf '%s\n' LICENSE "$binary_name" | LC_ALL=C sort)
	if [[ $actual_entries != "$expected_entries" ]]; then
		printf 'archive %s must contain only LICENSE and %s; got: %s\n' \
			"$asset_name" "$binary_name" "$archive_entries" >&2
		return 1
	fi
	if [[ $license_matches != true ]]; then
		printf 'archive %s does not contain the tagged source LICENSE\n' \
			"$asset_name" >&2
		return 1
	fi

	jq -e \
		--arg asset_name "$asset_name" \
		--arg archive_hash "$actual_hash" \
		--arg syft_creator "$syft_creator" \
		'.spdxVersion == "SPDX-2.3" and
     (.SPDXID | type == "string") and
     .name == $asset_name and
     (.creationInfo.creators | type == "array" and index($syft_creator) != null) and
     (.packages | type == "array" and length > 0) and
     (.SPDXID as $document_id |
      ([.packages[] |
        select(
          .name == $asset_name and
          .versionInfo == ("sha256:" + $archive_hash) and
          .primaryPackagePurpose == "FILE" and
          ([.checksums[]? |
            select(.algorithm == "SHA256" and .checksumValue == $archive_hash)] |
           length) == 1
        )]) as $archive_packages |
      ($archive_packages | length) == 1 and
      ($archive_packages[0].SPDXID | type == "string") and
      ([.relationships[]? |
        select(
          .spdxElementId == $document_id and
          .relationshipType == "DESCRIBES" and
          .relatedSpdxElement == $archive_packages[0].SPDXID
        )] | length) == 1)' \
		"$sbom_path" >/dev/null
}

verify_one darwin amd64 tar.gz eventctl
verify_one darwin arm64 tar.gz eventctl
verify_one linux amd64 tar.gz eventctl
verify_one linux arm64 tar.gz eventctl
verify_one windows amd64 zip eventctl.exe
verify_one windows arm64 zip eventctl.exe

checksum_count=$(wc -l <"$dist_dir/SHA256SUMS" | tr -d '[:space:]')
if [[ $checksum_count != 6 ]]; then
	printf 'SHA256SUMS must contain exactly six archives; got %s lines\n' \
		"$checksum_count" >&2
	exit 1
fi

printf 'validated six archives, checksums, and SPDX SBOMs for %s\n' "$version"
