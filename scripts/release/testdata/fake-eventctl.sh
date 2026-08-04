#!/usr/bin/env bash
set -Eeuo pipefail

case "${1:-}" in
	version)
		jq -n \
			--arg version "${FIXTURE_VERSION:?}" \
			--arg commit "${FIXTURE_COMMIT:?}" \
			--arg date "${FIXTURE_DATE:?}" \
			'{version: $version, commit: $commit, date: $date}'
		;;
	doctor)
		jq -n \
			--arg operating_system "${FIXTURE_OS:?}" \
			--arg architecture "${FIXTURE_ARCH:?}" \
			'{
      output_version: "pythonhk.eventctl/output/v1",
      ok: true,
      command: "doctor",
      error: null,
      result: {
        status: "healthy",
        operating_system: $operating_system,
        architecture: $architecture
      }
    }'
		;;
	*)
		printf 'unexpected fixture command: %s\n' "${1:-}" >&2
		exit 1
		;;
esac
