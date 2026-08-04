#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${1:-} == --version ]]; then
	printf 'gh version 2.99.0 (fixture)\n'
	exit 0
fi

: "${MOCK_ASSET_TABLE:?}"
: "${MOCK_EDIT_STATE:?}"
: "${MOCK_API_COUNT:?}"
: "${MOCK_TAG_DIGEST:?}"

release_assets_json() {
	cut -f1 "$MOCK_ASSET_TABLE" |
		jq -R -s 'split("\n") | map(select(length > 0) | {name: .})'
}

mutated_asset_table() {
	awk -F '\t' '
    BEGIN { OFS = "\t" }
    NR == 1 { $2 = "sha256:0000000000000000000000000000000000000000000000000000000000000000" }
    { print }
  ' "$MOCK_ASSET_TABLE"
}

case "${1:-}/${2:-}" in
	release/view)
		assets_json=$(release_assets_json)
		if [[ -f $MOCK_EDIT_STATE ]]; then
			jq -n --argjson assets "$assets_json" \
				'{
          databaseId: 123,
          isDraft: false,
          isImmutable: true,
          isPrerelease: false,
          tagName: "v1.2.3",
          assets: $assets
        }'
		else
			jq -n --argjson assets "$assets_json" \
				'{
          databaseId: 123,
          isDraft: true,
          isImmutable: false,
          isPrerelease: false,
          tagName: "v1.2.3",
          assets: $assets
        }'
		fi
		;;
	release/edit)
		: >"$MOCK_EDIT_STATE"
		;;
	api/*)
		api_path=''
		for argument in "$@"; do
			if [[ $argument == repos/* ]]; then
				api_path=$argument
				break
			fi
		done
		case "$api_path" in
			*/releases/123/assets*)
				count=0
				if [[ -f $MOCK_API_COUNT ]]; then
					read -r count <"$MOCK_API_COUNT"
				fi
				count=$((count + 1))
				printf '%s\n' "$count" >"$MOCK_API_COUNT"
				case "${MOCK_ASSET_MUTATION:-none}" in
					always) mutated_asset_table ;;
					after-publish)
						if [[ -f $MOCK_EDIT_STATE ]]; then
							mutated_asset_table
						else
							cat "$MOCK_ASSET_TABLE"
						fi
						;;
					none) cat "$MOCK_ASSET_TABLE" ;;
					*)
						printf 'unexpected asset mutation fixture: %s\n' "$MOCK_ASSET_MUTATION" >&2
						exit 1
						;;
				esac
				;;
			*/git/ref/tags/v1.2.3)
				case "${MOCK_TAG_MUTATION:-none}" in
					none)
						printf 'commit\t%s\n' "$MOCK_TAG_DIGEST"
						;;
					after-publish)
						if [[ -f $MOCK_EDIT_STATE ]]; then
							printf 'commit\t2222222222222222222222222222222222222222\n'
						else
							printf 'commit\t%s\n' "$MOCK_TAG_DIGEST"
						fi
						;;
					*)
						printf 'unexpected tag mutation fixture: %s\n' "$MOCK_TAG_MUTATION" >&2
						exit 1
						;;
				esac
				;;
			*)
				printf 'unexpected fixture API path: %s\n' "$api_path" >&2
				exit 1
				;;
		esac
		;;
	*)
		printf 'unexpected fixture gh command: %s\n' "$*" >&2
		exit 1
		;;
esac
