#!/usr/bin/env bash
set -Eeuo pipefail

CDPATH=''
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# Trusted repository-owned release toolchain contract.
# shellcheck disable=SC1091
source "$script_dir/tool-versions.env"

if [[ $# -ne 1 ]]; then
	printf 'usage: %s ABSOLUTE_BIN_DIRECTORY\n' "${0##*/}" >&2
	exit 2
fi

install_bin_dir=$1
if [[ $install_bin_dir != /* ]]; then
	printf 'ShellCheck install directory must be absolute: %s\n' "$install_bin_dir" >&2
	exit 2
fi
if [[ ! $SHELLCHECK_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	printf 'invalid SHELLCHECK_VERSION in tool-versions.env: %s\n' \
		"$SHELLCHECK_VERSION" >&2
	exit 1
fi
if [[ ! $SHELLCHECK_LINUX_X86_64_ARCHIVE_SHA256 =~ ^[0-9a-f]{64}$ ]]; then
	printf 'invalid ShellCheck archive SHA-256 in tool-versions.env\n' >&2
	exit 1
fi
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
	printf 'the pinned ShellCheck installer supports only Linux x86_64\n' >&2
	exit 1
fi

for required_command in awk curl install sha256sum tar; do
	if ! command -v "$required_command" >/dev/null 2>&1; then
		printf 'required command not found: %s\n' "$required_command" >&2
		exit 127
	fi
done

temp_parent=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
if [[ ! -d $temp_parent ]]; then
	printf 'temporary directory does not exist: %s\n' "$temp_parent" >&2
	exit 1
fi

umask 077
temp_dir=$(mktemp -d "$temp_parent/eventctl-shellcheck-install.XXXXXX")
cleanup() {
	rm -rf -- "$temp_dir"
}
trap cleanup EXIT HUP INT TERM

archive_name="shellcheck-v${SHELLCHECK_VERSION}.linux.x86_64.tar.xz"
archive_path="$temp_dir/$archive_name"
extract_dir="$temp_dir/extract"
download_url="https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/${archive_name}"

if [[ -e $install_bin_dir || -L $install_bin_dir ]]; then
	printf 'ShellCheck install directory must not already exist: %s\n' "$install_bin_dir" >&2
	exit 1
fi

curl \
	--fail \
	--location \
	--max-filesize 16777216 \
	--max-time 60 \
	--proto '=https' \
	--retry 3 \
	--retry-all-errors \
	--show-error \
	--silent \
	--tlsv1.2 \
	--output "$archive_path" \
	"$download_url"

actual_archive_sha256=$(sha256sum -- "$archive_path" | awk '{print $1}')
if [[ $actual_archive_sha256 != "$SHELLCHECK_LINUX_X86_64_ARCHIVE_SHA256" ]]; then
	printf 'ShellCheck archive checksum mismatch: expected %s, found %s\n' \
		"$SHELLCHECK_LINUX_X86_64_ARCHIVE_SHA256" \
		"${actual_archive_sha256:-missing}" >&2
	exit 1
fi

mkdir -p "$extract_dir"
tar -xJf "$archive_path" \
	-C "$extract_dir" \
	"shellcheck-v${SHELLCHECK_VERSION}/shellcheck"
extracted_binary="$extract_dir/shellcheck-v${SHELLCHECK_VERSION}/shellcheck"
if [[ ! -f $extracted_binary || -L $extracted_binary ]]; then
	printf 'verified ShellCheck archive did not contain a regular binary\n' >&2
	exit 1
fi

mkdir -m 0700 "$install_bin_dir"
installed_binary="$install_bin_dir/shellcheck"
install -m 0755 "$extracted_binary" "$installed_binary"

actual_version=$("$installed_binary" --version | awk -F ': ' '$1 == "version" {print $2}')
if [[ $actual_version != "$SHELLCHECK_VERSION" ]]; then
	printf 'ShellCheck version mismatch: expected %s, found %s\n' \
		"$SHELLCHECK_VERSION" "${actual_version:-unknown}" >&2
	exit 1
fi

printf 'ShellCheck %s installed at %s\n' "$actual_version" "$installed_binary"
