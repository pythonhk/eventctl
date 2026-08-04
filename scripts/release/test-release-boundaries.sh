#!/usr/bin/env bash
set -Eeuo pipefail

CDPATH=''
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/../.." && pwd)
# shellcheck disable=SC1091
source "$script_dir/tool-versions.env"

temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/eventctl-release-tests.XXXXXX")
cleanup() {
	rm -rf -- "$temp_dir"
}
trap cleanup EXIT HUP INT TERM

assertion_count=0
fail() {
	printf 'not ok - %s\n' "$1" >&2
	exit 1
}

pass() {
	assertion_count=$((assertion_count + 1))
	printf 'ok - %s\n' "$1"
}

expect_success() {
	local label=$1
	shift
	if ! "$@" >"$temp_dir/command.out" 2>&1; then
		cat "$temp_dir/command.out" >&2
		fail "$label"
	fi
	pass "$label"
}

expect_failure() {
	local label=$1
	shift
	if "$@" >"$temp_dir/command.out" 2>&1; then
		cat "$temp_dir/command.out" >&2
		fail "$label"
	fi
	pass "$label"
}

assert_contains() {
	local label=$1
	local needle=$2
	local path=$3
	grep -Fq -- "$needle" "$path" || fail "$label"
	pass "$label"
}

assert_before() {
	local label=$1
	local first=$2
	local second=$3
	local path=$4
	local first_line
	local second_line
	first_line=$(grep -nF -- "$first" "$path" | head -n1 | cut -d: -f1)
	second_line=$(grep -nF -- "$second" "$path" | head -n1 | cut -d: -f1)
	[[ -n $first_line && -n $second_line && $first_line -lt $second_line ]] || fail "$label"
	pass "$label"
}

assert_attestation_pairs() {
	local workflow_job=$1
	local subjects="$temp_dir/attestation-subjects"
	local expected_subjects="$temp_dir/expected-attestation-subjects"
	if ! awk '
    /^[[:space:]]+subject-path:[[:space:]]+/ {
      subject = $0
      sub(/^[[:space:]]+subject-path:[[:space:]]+/, "", subject)
      if (getline sbom_line <= 0 || sbom_line !~ /^[[:space:]]+sbom-path:[[:space:]]+/) {
        failed = 1
        next
      }
      sbom = sbom_line
      sub(/^[[:space:]]+sbom-path:[[:space:]]+/, "", sbom)
      if (sbom != subject ".spdx.json") {
        failed = 1
      }
      print subject
      count++
    }
    END {
      if (failed || count != 6) {
        exit 1
      }
    }
  ' "$workflow_job" >"$subjects"; then
		fail "six hosted SPDX attestations must pair each archive with its own SBOM"
	fi
	# GitHub expressions are intentionally matched literally.
	# shellcheck disable=SC2016
	printf '%s\n' \
		'dist/eventctl_${{ needs.build.outputs.version }}_darwin_amd64.tar.gz' \
		'dist/eventctl_${{ needs.build.outputs.version }}_darwin_arm64.tar.gz' \
		'dist/eventctl_${{ needs.build.outputs.version }}_linux_amd64.tar.gz' \
		'dist/eventctl_${{ needs.build.outputs.version }}_linux_arm64.tar.gz' \
		'dist/eventctl_${{ needs.build.outputs.version }}_windows_amd64.zip' \
		'dist/eventctl_${{ needs.build.outputs.version }}_windows_arm64.zip' |
		LC_ALL=C sort >"$expected_subjects"
	LC_ALL=C sort "$subjects" >"$subjects.sorted"
	cmp -s "$expected_subjects" "$subjects.sorted" ||
		fail "hosted SPDX attestation subjects must equal the six release archives"
	pass "six hosted SPDX attestations pair every release archive with its own SBOM"
}

hash_file() {
	local path=$1
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$path" | awk '{print $1}'
	else
		shasum -a 256 "$path" | awk '{print $1}'
	fi
}

create_release_dist() {
	local dist_dir=$1
	local version=$2
	local stage_dir="$temp_dir/archive-stage"
	local sums_file="$dist_dir/SHA256SUMS"
	local target
	local platform
	local architecture
	local extension
	local binary_name
	local asset_name
	local asset_path
	local archive_hash

	mkdir -p "$dist_dir" "$stage_dir"
	cp "$repo_dir/LICENSE" "$stage_dir/LICENSE"
	printf '#!/usr/bin/env bash\nexit 0\n' >"$stage_dir/eventctl"
	printf '#!/usr/bin/env bash\nexit 0\n' >"$stage_dir/eventctl.exe"
	chmod 0755 "$stage_dir/eventctl" "$stage_dir/eventctl.exe"
	: >"$sums_file"

	for target in \
		darwin/amd64/tar.gz \
		darwin/arm64/tar.gz \
		linux/amd64/tar.gz \
		linux/arm64/tar.gz \
		windows/amd64/zip \
		windows/arm64/zip; do
		IFS=/ read -r platform architecture extension <<<"$target"
		binary_name=eventctl
		if [[ $platform == windows ]]; then
			binary_name=eventctl.exe
		fi
		asset_name="eventctl_${version}_${platform}_${architecture}.${extension}"
		asset_path="$dist_dir/$asset_name"
		if [[ $extension == zip ]]; then
			(
				cd "$stage_dir"
				zip -q "$asset_path" LICENSE "$binary_name"
			)
		else
			tar -C "$stage_dir" -czf "$asset_path" LICENSE "$binary_name"
		fi
		archive_hash=$(hash_file "$asset_path")
		printf '%s  %s\n' "$archive_hash" "$asset_name" >>"$sums_file"
		jq -n \
			--arg asset_name "$asset_name" \
			--arg archive_hash "$archive_hash" \
			--arg creator "Tool: syft-${SYFT_VERSION#v}" \
			'{
          spdxVersion: "SPDX-2.3",
          SPDXID: "SPDXRef-DOCUMENT",
          name: $asset_name,
          creationInfo: {creators: [$creator]},
          packages: [{
            SPDXID: "SPDXRef-ArchivePackage",
            name: $asset_name,
            versionInfo: ("sha256:" + $archive_hash),
            primaryPackagePurpose: "FILE",
            checksums: [{algorithm: "SHA256", checksumValue: $archive_hash}]
          }],
          relationships: [{
            spdxElementId: "SPDXRef-DOCUMENT",
            relationshipType: "DESCRIBES",
            relatedSpdxElement: "SPDXRef-ArchivePackage"
          }]
        }' >"$asset_path.spdx.json"
	done
	LC_ALL=C sort -o "$sums_file" "$sums_file"
}

test_action_pin_parser() {
	local fixture_dir="$temp_dir/action-pins"
	local workflow_file="$fixture_dir/workflow.yml"
	mkdir -p "$fixture_dir"
	printf '%s\n' \
		'steps:' \
		'  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1' \
		>"$workflow_file"
	expect_success "canonical full action pin is accepted" \
		"$script_dir/check-action-pins.sh" "$fixture_dir"

	for variant in \
		'  - uses: actions/checkout@v7' \
		'  - uses : actions/checkout@v7' \
		'  - {uses: actions/checkout@v7}' \
		'  - "uses": actions/checkout@v7'; do
		printf 'steps:\n%s\n' "$variant" >"$workflow_file"
		expect_failure "noncanonical action reference is rejected: $variant" \
			"$script_dir/check-action-pins.sh" "$fixture_dir"
	done
	for hidden_uses in \
		'  - "us\u0065s": actions/setup-go@v7' \
		'  - {"us\u0065s": actions/setup-go@v7}'; do
		printf '%s\n' \
			'steps:' \
			'  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1' \
			"$hidden_uses" \
			>"$workflow_file"
		expect_failure "escaped semantic uses key cannot hide beside a valid pin: $hidden_uses" \
			"$script_dir/check-action-pins.sh" "$fixture_dir"
	done
	printf '%s\n' \
		'steps:' \
		'  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1' \
		"  - ? \"u\\" \
		'          ses"' \
		'        : actions/setup-go@v7' \
		>"$workflow_file"
	expect_failure "multiline semantic uses key cannot hide beside a valid pin" \
		"$script_dir/check-action-pins.sh" "$fixture_dir"
	printf '%s\n' \
		'uses_key: &uses_key uses' \
		'steps:' \
		'  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1' \
		'  - ? *uses_key' \
		'    : actions/setup-go@v7' \
		>"$workflow_file"
	expect_failure "aliased semantic uses key cannot hide beside a valid pin" \
		"$script_dir/check-action-pins.sh" "$fixture_dir"
}

test_sbom_binding() {
	local dist_dir="$temp_dir/dist"
	local sbom="$dist_dir/eventctl_1.2.3_linux_amd64.tar.gz.spdx.json"
	local backup="$temp_dir/linux-amd64.spdx.json"
	local changed="$temp_dir/changed.spdx.json"
	create_release_dist "$dist_dir" 1.2.3
	expect_success "six paired archive SPDX documents are accepted" \
		"$script_dir/verify-dist.sh" "$dist_dir" 1.2.3
	cp "$sbom" "$backup"
	jq '.name = "eventctl_1.2.3_linux_arm64.tar.gz"' "$backup" >"$changed"
	mv "$changed" "$sbom"
	expect_failure "SPDX document name must equal its paired archive" \
		"$script_dir/verify-dist.sh" "$dist_dir" 1.2.3
	cp "$backup" "$sbom"
	jq '.packages[0].versionInfo = "sha256:0000000000000000000000000000000000000000000000000000000000000000"' \
		"$backup" >"$changed"
	mv "$changed" "$sbom"
	expect_failure "SPDX package digest must equal its paired archive" \
		"$script_dir/verify-dist.sh" "$dist_dir" 1.2.3
	cp "$backup" "$sbom"
	jq '.relationships[0].relatedSpdxElement = "SPDXRef-UnrelatedPackage"' \
		"$backup" >"$changed"
	mv "$changed" "$sbom"
	expect_failure "SPDX DESCRIBES relationship must target the paired archive package" \
		"$script_dir/verify-dist.sh" "$dist_dir" 1.2.3
	cp "$backup" "$sbom"
}

create_native_fixture() {
	local fixture_repo=$1
	local fixture_dist=$2
	local commit_date=$3
	local stage_dir="$temp_dir/native-stage"
	mkdir -p "$fixture_repo/scripts/release" "$fixture_dist" "$stage_dir"
	cp "$script_dir/verify-asset.sh" "$fixture_repo/scripts/release/verify-asset.sh"
	cp "$repo_dir/LICENSE" "$fixture_repo/LICENSE"
	git -C "$fixture_repo" init -q
	git -C "$fixture_repo" add LICENSE
	GIT_AUTHOR_DATE="$commit_date" GIT_COMMITTER_DATE="$commit_date" \
		git -C "$fixture_repo" \
		-c user.name='eventctl tests' \
		-c user.email='eventctl-tests@example.invalid' \
		commit -q -m fixture

	cp "$repo_dir/LICENSE" "$stage_dir/LICENSE"
	cp "$script_dir/testdata/fake-eventctl.sh" "$stage_dir/eventctl"
	chmod 0755 "$stage_dir/eventctl"
	tar -C "$stage_dir" -czf \
		"$fixture_dist/eventctl_1.2.3_linux_amd64.tar.gz" \
		LICENSE eventctl
	printf '%s  %s\n' \
		"$(hash_file "$fixture_dist/eventctl_1.2.3_linux_amd64.tar.gz")" \
		'eventctl_1.2.3_linux_amd64.tar.gz' \
		>"$fixture_dist/SHA256SUMS"
}

test_native_metadata() {
	local fixture_repo="$temp_dir/native-repo"
	local fixture_dist="$fixture_repo/dist"
	local commit_date=2030-01-01T00:00:00Z
	local commit_digest
	create_native_fixture "$fixture_repo" "$fixture_dist" "$commit_date"
	commit_digest=$(git -C "$fixture_repo" rev-parse HEAD)
	expect_success "native verifier binds version, commit date, OS, and architecture" \
		env \
		FIXTURE_VERSION=1.2.3 \
		FIXTURE_COMMIT="$commit_digest" \
		FIXTURE_DATE="$commit_date" \
		FIXTURE_OS=linux \
		FIXTURE_ARCH=amd64 \
		"$fixture_repo/scripts/release/verify-asset.sh" \
		"$fixture_dist" 1.2.3 linux amd64 "$commit_digest" "$commit_date"
	expect_failure "binary build date must equal the independently derived commit date" \
		env \
		FIXTURE_VERSION=1.2.3 \
		FIXTURE_COMMIT="$commit_digest" \
		FIXTURE_DATE=2030-01-02T00:00:00Z \
		FIXTURE_OS=linux \
		FIXTURE_ARCH=amd64 \
		"$fixture_repo/scripts/release/verify-asset.sh" \
		"$fixture_dist" 1.2.3 linux amd64 "$commit_digest" "$commit_date"
	expect_failure "native verifier rejects a mismatched runtime architecture" \
		env \
		FIXTURE_VERSION=1.2.3 \
		FIXTURE_COMMIT="$commit_digest" \
		FIXTURE_DATE="$commit_date" \
		FIXTURE_OS=linux \
		FIXTURE_ARCH=arm64 \
		"$fixture_repo/scripts/release/verify-asset.sh" \
		"$fixture_dist" 1.2.3 linux amd64 "$commit_digest" "$commit_date"
}

build_server_asset_table() {
	local dist_dir=$1
	local output_file=$2
	local asset
	for asset in "$dist_dir"/*; do
		printf '%s\tsha256:%s\t%s\n' \
			"$(basename -- "$asset")" \
			"$(hash_file "$asset")" \
			"$(wc -c <"$asset" | tr -d '[:space:]')"
	done | LC_ALL=C sort >"$output_file"
}

run_finalize() {
	local dist_dir=$1
	local expected_digest=$2
	local mutation=$3
	local tag_digest=$4
	local tag_mutation=${5:-none}
	local mock_bin="$temp_dir/mock-bin"
	local asset_table="$temp_dir/server-assets.tsv"
	local edit_state="$temp_dir/release-edited"
	local api_count="$temp_dir/api-count"
	mkdir -p "$mock_bin"
	cp "$script_dir/testdata/mock-gh.sh" "$mock_bin/gh"
	cp "$script_dir/testdata/noop-sleep.sh" "$mock_bin/sleep"
	chmod 0755 "$mock_bin/gh" "$mock_bin/sleep"
	build_server_asset_table "$dist_dir" "$asset_table"
	rm -f -- "$edit_state" "$api_count"
	env \
		PATH="$mock_bin:$PATH" \
		MOCK_ASSET_TABLE="$asset_table" \
		MOCK_EDIT_STATE="$edit_state" \
		MOCK_API_COUNT="$api_count" \
		MOCK_ASSET_MUTATION="$mutation" \
		MOCK_TAG_DIGEST="$tag_digest" \
		MOCK_TAG_MUTATION="$tag_mutation" \
		"$script_dir/finalize-release.sh" \
		v1.2.3 pythonhk/eventctl "$dist_dir" "$expected_digest"
}

test_finalization_boundaries() {
	local dist_dir="$temp_dir/dist"
	local expected_digest=1111111111111111111111111111111111111111
	local wrong_digest=2222222222222222222222222222222222222222
	local edit_state="$temp_dir/release-edited"
	local api_count="$temp_dir/api-count"
	local count
	expect_success "finalization proves matching assets and tag before and after publish" \
		run_finalize "$dist_dir" "$expected_digest" none "$expected_digest"
	[[ -f $edit_state ]] || fail "successful finalization publishes the draft"
	read -r count <"$api_count"
	[[ $count -ge 2 ]] || fail "successful finalization rereads assets after publish"
	pass "successful finalization rereads assets after publish"

	expect_failure "changed draft asset blocks publication" \
		run_finalize "$dist_dir" "$expected_digest" always "$expected_digest"
	[[ ! -e $edit_state ]] || fail "changed draft asset must fail before publication"
	pass "changed draft asset fails before publication"

	expect_failure "remote tag mismatch blocks publication" \
		run_finalize "$dist_dir" "$expected_digest" none "$wrong_digest"
	[[ ! -e $edit_state ]] || fail "remote tag mismatch must fail before publication"
	pass "remote tag mismatch fails before publication"

	expect_failure "post-publication asset mismatch is detected" \
		run_finalize "$dist_dir" "$expected_digest" after-publish "$expected_digest"
	[[ -f $edit_state ]] || fail "post-publication mismatch fixture must reach publication"
	pass "post-publication mismatch is detected after publication"

	expect_failure "post-publication tag rebind is detected" \
		run_finalize "$dist_dir" "$expected_digest" none "$expected_digest" after-publish
	[[ -f $edit_state ]] || fail "post-publication tag rebind fixture must reach publication"
	pass "post-publication tag rebind is detected after publication"
}

test_release_workflow_boundaries() {
	local workflow="$repo_dir/.github/workflows/release.yml"
	local ci_workflow="$repo_dir/.github/workflows/ci.yml"
	local build_job="$temp_dir/release-build.yml"
	local native_job="$temp_dir/release-native-preflight.yml"
	local publish_job="$temp_dir/release-publish.yml"
	local published_job="$temp_dir/release-published-native.yml"
	awk '$0 == "  build:" { copy = 1 }
       copy && $0 == "  native-preflight:" { exit }
       copy { print }' "$workflow" >"$build_job"
	awk '$0 == "  published-native:" { copy = 1 }
       copy { print }' "$workflow" >"$published_job"
	awk '$0 == "  native-preflight:" { copy = 1 }
       copy && $0 == "  publish:" { exit }
       copy { print }' "$workflow" >"$native_job"
	awk '$0 == "  publish:" { copy = 1 }
       copy && $0 == "  published-release-record:" { exit }
       copy { print }' "$workflow" >"$publish_job"

	assert_contains "tag build reruns the exact full Go gate" \
		'scripts/check.sh' "$build_job"
	assert_contains "tag build reruns fuzzing for ten seconds" \
		'FUZZ_TIME: 10s' "$build_job"
	assert_contains "tag build reruns the fuzz harness" \
		'scripts/release/fuzz-smoke.sh' "$build_job"
	assert_contains "tag build reruns ShellCheck" \
		'xargs -0 shellcheck' "$build_job"
	assert_contains "tag build reruns shfmt" \
		'mvdan.cc/sh/v3/cmd/shfmt@' "$build_job"
	assert_contains "tag build reruns actionlint" \
		'github.com/rhysd/actionlint/cmd/actionlint@' "$build_job"
	assert_contains "tag build reruns the action-pin gate" \
		'scripts/release/check-action-pins.sh' "$build_job"
	assert_contains "tag build reruns release-boundary regressions" \
		'scripts/release/test-release-boundaries.sh' "$build_job"
	# GitHub expressions are intentionally matched literally.
	# shellcheck disable=SC2016
	assert_contains "tag build performs a non-snapshot reproducibility proof" \
		'${{ steps.metadata.outputs.version }}" release' "$build_job"
	assert_contains "CI runs release-boundary regressions" \
		'scripts/release/test-release-boundaries.sh' "$ci_workflow"
	assert_contains "tag release reruns native source tests on every release runner" \
		'go test -mod=readonly -count=1 ./...' "$native_job"
	assert_contains "publication waits for native source and binary preflight" \
		'native-preflight' "$publish_job"
	assert_attestation_pairs "$publish_job"

	assert_contains "published native checks depend on immutable record verification" \
		'published-release-record' "$published_job"
	# GitHub expressions are intentionally matched literally.
	# shellcheck disable=SC2016
	assert_before "immutable release verification precedes public asset download" \
		'gh release verify "${GITHUB_REF_NAME}"' \
		'gh release download "${GITHUB_REF_NAME}"' \
		"$published_job"
	assert_before "immutable asset verification precedes binary execution" \
		'gh release verify-asset' \
		'scripts/release/verify-asset.sh' \
		"$published_job"
	assert_before "hosted attestations precede binary execution" \
		'scripts/release/verify-attestations.sh' \
		'scripts/release/verify-asset.sh' \
		"$published_job"
}

test_action_pin_parser
test_sbom_binding
test_native_metadata
test_finalization_boundaries
test_release_workflow_boundaries

printf '# %d release-boundary assertion(s), all passed\n' "$assertion_count"
