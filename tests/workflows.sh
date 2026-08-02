#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
readonly ACTIONLINT_VERSION=1.7.12
readonly CHECKOUT_ACTION='actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4'
readonly RUST_TOOLCHAIN_ACTION='dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c # master'
readonly RUST_CACHE_ACTION='Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2'
readonly UPLOAD_ACTION='actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4'

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

require_file() {
    test -f "$1" && test ! -L "$1" || fail "missing regular workflow: $1"
}

require_literal() {
    grep -F -- "$2" "$1" >/dev/null || fail "$3"
}

require_regex() {
    grep -E -- "$2" "$1" >/dev/null || fail "$3"
}

require_exact_line() {
    exact_count=$(awk -v wanted="$2" '$0 == wanted { count += 1 } END { print count + 0 }' "$1")
    test "$exact_count" -eq 1 || fail "$3"
}

extract_section() {
    awk -v section="$2" '
        $0 == section ":" { found += 1; capture = 1; next }
        capture && /^[^[:space:]#][^:]*:/ { capture = 0 }
        capture && !/^[[:space:]]*#/ { print }
        END { if (found != 1) exit 1 }
    ' "$1"
}

extract_job() {
    awk -v wanted="$2" '
        $0 == "jobs:" { in_jobs = 1; next }
        in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
            key = $0
            sub(/^  /, "", key)
            sub(/:.*/, "", key)
            capture = 0
            if (key == wanted) {
                found += 1
                capture = 1
            }
        }
        capture && !/^[[:space:]]*#/ { print }
        END { if (found != 1) exit 1 }
    ' "$1"
}

extract_named_step() {
    awk -v wanted="$2" '
        $0 == "      - name: " wanted {
            found += 1
            capture = 1
        }
        capture && /^      - / && $0 != "      - name: " wanted { capture = 0 }
        capture && !/^[[:space:]]*#/ { print }
        END { if (found != 1) exit 1 }
    ' "$1"
}

extract_action_step() {
    awk -v wanted="$2" '
        $0 == "      - uses: " wanted || $0 == "        uses: " wanted {
            found += 1
            capture = 1
        }
        capture && /^      - / && $0 != "      - uses: " wanted { capture = 0 }
        capture && !/^[[:space:]]*#/ { print }
        END { if (found != 1) exit 1 }
    ' "$1"
}

check_permissions() {
    workflow=$1
    permissions_file=$2
    extract_section "$workflow" permissions >"$permissions_file" || \
        fail "$workflow must define exactly one top-level permissions section"
    test "$(grep -Ec '^  [A-Za-z0-9_-]+:' "$permissions_file")" -eq 1 || \
        fail "$workflow must grant only contents permission"
    grep -Eq '^  contents:[[:space:]]*read[[:space:]]*$' "$permissions_file" || \
        fail "$workflow must grant contents: read"
    if grep -Eq '^    permissions:' "$workflow"; then
        fail "$workflow must not override permissions at job scope"
    fi
    # The exact top-level block plus the ban on job-level overrides fully
    # defines effective permissions. Unrelated mappings may safely use values
    # such as `write` without being mistaken for permission grants.
}

check_events() {
    workflow=$1
    event_file=$2
    shift 2
    extract_section "$workflow" on >"$event_file" || \
        fail "$workflow must define exactly one top-level on section"
    event_count=$(grep -Ec '^  [A-Za-z0-9_-]+:[[:space:]]*$' "$event_file")
    test "$event_count" -eq "$#" || fail "$workflow has an unexpected trigger set"
    for event in "$@"; do
        grep -Eq "^  $event:[[:space:]]*$" "$event_file" || \
            fail "$workflow is missing the $event trigger"
    done
}

check_job() {
    workflow=$1
    job=$2
    destination=$3
    extract_job "$workflow" "$job" >"$destination" || \
        fail "$workflow is missing the $job job"
}

check_named_step() {
    job_file=$1
    step_name=$2
    destination=$3
    extract_named_step "$job_file" "$step_name" >"$destination" || \
        fail "required named step is missing or duplicated: $step_name"
}

check_action_step() {
    job_file=$1
    action=$2
    destination=$3
    extract_action_step "$job_file" "$action" >"$destination" || \
        fail "required pinned action is missing or duplicated: $action"
}

require_run_step() {
    require_exact_line "$1" "      - run: $2" "$3"
}

require_named_run() {
    job_file=$1
    step_name=$2
    command=$3
    destination=$4
    check_named_step "$job_file" "$step_name" "$destination"
    require_exact_line "$destination" "        run: $command" \
        "$step_name must run exactly: $command"
}

check_checkout() {
    job_file=$1
    destination=$2
    check_action_step "$job_file" "$CHECKOUT_ACTION" "$destination"
    require_exact_line "$destination" '        with:' \
        "checkout must define exactly one with block"
    require_exact_line "$destination" '          persist-credentials: false' \
        "checkout must disable credential persistence"
}

check_toolchain() {
    job_file=$1
    expected_toolchain=$2
    destination=$3
    check_action_step "$job_file" "$RUST_TOOLCHAIN_ACTION" "$destination"
    require_exact_line "$destination" '        with:' \
        "Rust toolchain action must define exactly one with block"
    require_exact_line "$destination" "          toolchain: $expected_toolchain" \
        "Rust toolchain action must select $expected_toolchain explicitly"
}

check_cache() {
    check_action_step "$1" "$RUST_CACHE_ACTION" "$2"
}

check_install_pins() {
    if awk '
        /cargo install/ && $0 !~ /--version[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+--locked/ {
            unpinned = 1
        }
        END { exit unpinned ? 0 : 1 }
    ' "$@"; then
        fail "every cargo-installed CI tool must use an exact version and --locked"
    fi
}

check_action_pins() {
    if awk -v checkout="$CHECKOUT_ACTION" -v toolchain="$RUST_TOOLCHAIN_ACTION" \
        -v cache="$RUST_CACHE_ACTION" -v upload="$UPLOAD_ACTION" '
        /^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*/ {
            action = $0
            sub(/^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*/, "", action)
            if (action != checkout && action != toolchain && action != cache && action != upload) {
                invalid = 1
            }
        }
        END { exit invalid ? 0 : 1 }
    ' "$@"; then
        fail "every workflow action must use an approved immutable commit and version comment"
    fi

    check_action_count "$CHECKOUT_ACTION" 6 "$@"
    check_action_count "$RUST_TOOLCHAIN_ACTION" 6 "$@"
    check_action_count "$RUST_CACHE_ACTION" 6 "$@"
    check_action_count "$UPLOAD_ACTION" 1 "$@"
}

check_action_count() {
    wanted_action=$1
    wanted_count=$2
    shift 2
    actual_count=$(awk -v wanted="$wanted_action" '
        /^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*/ {
            action = $0
            sub(/^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*/, "", action)
            if (action == wanted) count += 1
        }
        END { print count + 0 }
    ' "$@")
    test "$actual_count" -eq "$wanted_count" || \
        fail "unexpected usage count for pinned action: $wanted_action"
}

check_actionlint() {
    command -v actionlint >/dev/null 2>&1 || \
        fail "actionlint $ACTIONLINT_VERSION is required"
    installed_version=$(actionlint -version 2>/dev/null | sed -n '1p') || \
        fail "could not determine actionlint version"
    case $installed_version in
        "$ACTIONLINT_VERSION" | "v$ACTIONLINT_VERSION") ;;
        *) fail "actionlint version mismatch: expected $ACTIONLINT_VERSION, found $installed_version" ;;
    esac
    actionlint "$@" || fail "workflow YAML or GitHub Actions syntax is invalid"
}

check_yaml_key_syntax() {
    if awk '
        FNR == 1 { block_parent = -1 }
        /^[[:space:]]*$/ { next }
        {
            match($0, /[^ ]/)
            indent = RSTART - 1
            if (block_parent >= 0) {
                if (indent > block_parent) next
                block_parent = -1
            }

            key = $0
            sub(/^ */, "", key)
            key_indent = indent
            if (key ~ /^-[[:space:]]+/) {
                sub(/^-[[:space:]]+/, "", key)
                key_indent = indent + 2
            }

            if (key ~ /^(!![^[:space:]]+|!<[^>]+>|![^[:space:]!<][^[:space:]]*)[[:space:]]+[^#].*:/ ||
                key ~ /^[?][[:space:]]+/ ||
                key ~ /^".*"[[:space:]]*:/ ||
                key ~ /^\047.*\047[[:space:]]*:/) {
                forbidden = 1
                exit
            }

            if (key ~ /:[[:space:]]*[>|][-+0-9]*[[:space:]]*(#.*)?$/) {
                block_parent = key_indent
            }
        }
        END { exit forbidden ? 0 : 1 }
    ' "$@"; then
        fail "workflow mapping keys must use plain implicit YAML syntax"
    fi
}

check_blocking_gates() {
    blocking_key="(!!str[[:space:]]+)?['\"]?(if|continue-on-error)['\"]?[[:space:]]*:"
    if grep -Eq "^    $blocking_key|^      -[[:space:]]+$blocking_key|^        $blocking_key" "$@"; then
        fail "release-readiness jobs and steps must be unconditional and blocking"
    fi
}

check_forbidden_publication() {
    if grep -Eis '(cargo[[:space:]]+publish|git[[:space:]]+tag|git[[:space:]]+push|gh[[:space:]]+release|packages:[[:space:]]*write|id-token:[[:space:]]*write|CARGO_REGISTRY_TOKEN|registry[_ -]?token|actions/create-release|softprops/action-gh-release)' "$@" >/dev/null; then
        fail "workflows must not publish, tag, push, release, request publication permissions, or expose registry credentials"
    fi
}

check_contract() (
    check_root=$1
    check_tmp=$2
    mkdir -p "$check_tmp"
    ci="$check_root/.github/workflows/ci.yml"
    fuzz="$check_root/.github/workflows/fuzz.yml"
    release="$check_root/.github/workflows/release-candidate.yml"

    require_file "$ci"
    require_file "$fuzz"
    require_file "$release"
    check_actionlint "$ci" "$fuzz" "$release"
    check_yaml_key_syntax "$ci" "$fuzz" "$release"
    check_blocking_gates "$ci" "$fuzz" "$release"
    check_forbidden_publication "$ci" "$fuzz" "$release"
    check_install_pins "$ci" "$fuzz" "$release"
    check_action_pins "$ci" "$fuzz" "$release"

    require_regex "$ci" '^name:[[:space:]]*CI[[:space:]]*$' "CI workflow name is not exact"
    check_events "$ci" "$check_tmp/ci-events" push pull_request
    check_permissions "$ci" "$check_tmp/ci-permissions"

    check_job "$ci" test "$check_tmp/ci-test"
    require_regex "$check_tmp/ci-test" 'runs-on:[[:space:]]*\$\{\{ matrix\.os \}\}' "test job must run on the OS matrix"
    require_literal "$check_tmp/ci-test" 'fail-fast: false' "test matrix must keep fail-fast disabled"
    require_literal "$check_tmp/ci-test" 'os: [ubuntu-latest, macos-latest, windows-latest]' "test matrix OS list is not exact"
    check_checkout "$check_tmp/ci-test" "$check_tmp/ci-test-checkout"
    check_toolchain "$check_tmp/ci-test" stable "$check_tmp/ci-test-toolchain"
    check_cache "$check_tmp/ci-test" "$check_tmp/ci-test-cache"
    require_run_step "$check_tmp/ci-test" 'cargo test --all-targets --locked' \
        "test job must run locked all-target tests"
    check_named_step "$check_tmp/ci-test" 'Exercise open-source boundary scanner' \
        "$check_tmp/ci-test-boundary"
    require_exact_line "$check_tmp/ci-test-boundary" '        shell: bash' \
        "boundary self-test must use bash on every matrix OS"
    require_exact_line "$check_tmp/ci-test-boundary" '        env:' \
        "boundary self-test must define its Windows environment"
    require_exact_line "$check_tmp/ci-test-boundary" '          MSYS: winsymlinks:nativestrict' \
        "Windows boundary fixtures require native symlinks"
    require_exact_line "$check_tmp/ci-test-boundary" '        run: sh tests/open_source_boundary.sh' \
        "test job must run the boundary self-test"

    check_job "$ci" msrv "$check_tmp/ci-msrv"
    require_regex "$check_tmp/ci-msrv" 'runs-on:[[:space:]]*ubuntu-latest' "MSRV job must run on Ubuntu"
    check_checkout "$check_tmp/ci-msrv" "$check_tmp/ci-msrv-checkout"
    check_toolchain "$check_tmp/ci-msrv" 1.85.0 "$check_tmp/ci-msrv-toolchain"
    check_cache "$check_tmp/ci-msrv" "$check_tmp/ci-msrv-cache"
    require_run_step "$check_tmp/ci-msrv" 'cargo test --all-targets --locked' \
        "MSRV job must run locked all-target tests"

    check_job "$ci" quality "$check_tmp/ci-quality"
    require_literal "$check_tmp/ci-quality" 'name: Formatting, lint, docs, API, policy, package' "quality job name is not exact"
    require_regex "$check_tmp/ci-quality" 'runs-on:[[:space:]]*ubuntu-latest' "quality job must run on Ubuntu"
    check_checkout "$check_tmp/ci-quality" "$check_tmp/ci-quality-checkout"
    check_toolchain "$check_tmp/ci-quality" stable "$check_tmp/ci-quality-toolchain"
    require_exact_line "$check_tmp/ci-quality-toolchain" '          components: clippy,rustfmt' \
        "quality job must install clippy and rustfmt"
    require_named_run "$check_tmp/ci-quality" 'Install pinned nightly' \
        'rustup toolchain install nightly-2026-05-23 --profile minimal' \
        "$check_tmp/ci-quality-nightly"
    check_cache "$check_tmp/ci-quality" "$check_tmp/ci-quality-cache"
    check_named_step "$check_tmp/ci-quality" 'Install pinned policy and API tools' \
        "$check_tmp/ci-quality-tools"
    require_exact_line "$check_tmp/ci-quality-tools" \
        '          cargo install cargo-deny --version 0.20.2 --locked' \
        "quality job must install the pinned cargo-deny"
    require_exact_line "$check_tmp/ci-quality-tools" \
        '          cargo install cargo-public-api --version 0.52.0 --locked' \
        "quality job must install the pinned cargo-public-api"
    check_named_step "$check_tmp/ci-quality" 'Install pinned workflow checker' \
        "$check_tmp/ci-quality-actionlint-install"
    require_exact_line "$check_tmp/ci-quality-actionlint-install" \
        '          go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12' \
        "quality job must install actionlint 1.7.12"
    require_exact_line "$check_tmp/ci-quality-actionlint-install" \
        "          echo \"\$(go env GOPATH)/bin\" >> \"\$GITHUB_PATH\"" \
        "quality job must put the pinned actionlint binary on PATH"
    require_named_run "$check_tmp/ci-quality" 'Verify workflow checker version' \
        "case \"\$(actionlint -version | sed -n '1p')\" in 1.7.12|v1.7.12) ;; *) actionlint -version; exit 1 ;; esac" \
        "$check_tmp/ci-quality-actionlint-version"
    for command in \
        'cargo fmt --all -- --check' \
        'cargo clippy --all-targets --locked -- -D warnings' \
        'cargo test --doc --locked' \
        'RUSTDOCFLAGS="-D missing-docs -D warnings" cargo doc --locked --no-deps' \
        'cargo test --test release_documents --locked' \
        'cargo deny check'
    do
        require_run_step "$check_tmp/ci-quality" "$command" \
            "quality job is missing required run step: $command"
    done
    require_named_run "$check_tmp/ci-quality" 'Exercise release-candidate constructor' \
        'sh tests/release_candidate.sh' "$check_tmp/ci-quality-release-test"
    require_named_run "$check_tmp/ci-quality" 'Verify workflow contracts' \
        'sh tests/workflows.sh' "$check_tmp/ci-quality-workflow-test"
    require_named_run "$check_tmp/ci-quality" 'Exercise public API checker' \
        'sh tests/public_api.sh' "$check_tmp/ci-quality-public-api-test"
    require_named_run "$check_tmp/ci-quality" 'Verify public API snapshot' \
        './ci/check-public-api.sh' "$check_tmp/ci-quality-public-api"
    require_named_run "$check_tmp/ci-quality" 'Exercise cryptographic inventory checker' \
        'sh tests/crypto_inventory.sh' "$check_tmp/ci-quality-inventory-test"
    require_named_run "$check_tmp/ci-quality" 'Verify cryptographic dependency inventory' \
        './ci/check-crypto-inventory.sh' "$check_tmp/ci-quality-inventory"
    require_named_run "$check_tmp/ci-quality" 'Verify current checkout boundary' \
        './ci/check-open-source-boundary.sh --worktree .' "$check_tmp/ci-quality-worktree"
    check_named_step "$check_tmp/ci-quality" 'Verify complete repository export' \
        "$check_tmp/ci-quality-export"
    require_exact_line "$check_tmp/ci-quality-export" \
        "          git archive HEAD | tar -x -C \"\$export_dir/tree\"" \
        "quality job must scan a clean git-archive export"
    require_exact_line "$check_tmp/ci-quality-export" \
        "          ./ci/check-open-source-boundary.sh \"\$export_dir/tree\"" \
        "quality job must scan the clean export boundary"
    check_named_step "$check_tmp/ci-quality" 'Build and verify Cargo package' \
        "$check_tmp/ci-quality-package"
    require_exact_line "$check_tmp/ci-quality-package" \
        "          ./ci/check-cargo-package.sh \"\$PWD\" \"\$package_parent/package\"" \
        "quality job must invoke the reusable Cargo package helper"

    check_job "$ci" fuzz-smoke "$check_tmp/ci-fuzz"
    require_regex "$check_tmp/ci-fuzz" 'runs-on:[[:space:]]*ubuntu-latest' "fuzz-smoke job must run on Ubuntu"
    check_checkout "$check_tmp/ci-fuzz" "$check_tmp/ci-fuzz-checkout"
    check_toolchain "$check_tmp/ci-fuzz" nightly-2026-05-23 "$check_tmp/ci-fuzz-toolchain"
    check_cache "$check_tmp/ci-fuzz" "$check_tmp/ci-fuzz-cache"
    require_named_run "$check_tmp/ci-fuzz" 'Install pinned fuzzing tool' \
        'cargo install cargo-fuzz --version 0.13.2 --locked' "$check_tmp/ci-fuzz-install"
    require_named_run "$check_tmp/ci-fuzz" 'Exercise fuzz runner' \
        'sh tests/fuzz_smoke.sh' "$check_tmp/ci-fuzz-test"
    require_named_run "$check_tmp/ci-fuzz" 'Run bounded fuzz smoke' \
        'sh ci/fuzz-smoke.sh smoke' "$check_tmp/ci-fuzz-run"

    require_regex "$fuzz" '^name:[[:space:]]*Extended fuzzing[[:space:]]*$' "extended fuzz workflow name is not exact"
    check_events "$fuzz" "$check_tmp/fuzz-events" schedule workflow_dispatch
    require_literal "$check_tmp/fuzz-events" "cron: '17 3 * * 1'" "extended fuzz schedule is not exact"
    check_permissions "$fuzz" "$check_tmp/fuzz-permissions"
    check_job "$fuzz" fuzz "$check_tmp/fuzz-job"
    require_regex "$check_tmp/fuzz-job" 'runs-on:[[:space:]]*ubuntu-latest' "extended fuzz job must run on Ubuntu"
    check_checkout "$check_tmp/fuzz-job" "$check_tmp/fuzz-checkout"
    check_toolchain "$check_tmp/fuzz-job" nightly-2026-05-23 "$check_tmp/fuzz-toolchain"
    check_cache "$check_tmp/fuzz-job" "$check_tmp/fuzz-cache"
    require_named_run "$check_tmp/fuzz-job" 'Install pinned fuzzing tool' \
        'cargo install cargo-fuzz --version 0.13.2 --locked' "$check_tmp/fuzz-install"
    require_named_run "$check_tmp/fuzz-job" 'Run bounded extended fuzzing' \
        'sh ci/fuzz-smoke.sh extended' "$check_tmp/fuzz-run"

    require_regex "$release" '^name:[[:space:]]*Build release candidate[[:space:]]*$' "release-candidate workflow name is not exact"
    check_events "$release" "$check_tmp/release-events" workflow_dispatch
    check_permissions "$release" "$check_tmp/release-permissions"
    check_job "$release" rc-built "$check_tmp/release-job"
    require_regex "$check_tmp/release-job" 'runs-on:[[:space:]]*ubuntu-latest' "release-candidate job must run on Ubuntu"
    check_checkout "$check_tmp/release-job" "$check_tmp/release-checkout"
    check_toolchain "$check_tmp/release-job" stable "$check_tmp/release-toolchain"
    require_exact_line "$check_tmp/release-toolchain" '          components: clippy,rustfmt' \
        "release-candidate stable toolchain must include clippy and rustfmt"
    check_named_step "$check_tmp/release-job" 'Install pinned verification toolchains' \
        "$check_tmp/release-verification-toolchains"
    require_exact_line "$check_tmp/release-verification-toolchains" \
        '          rustup toolchain install 1.85.0 --profile minimal' \
        "release-candidate job must install Rust 1.85.0"
    require_exact_line "$check_tmp/release-verification-toolchains" \
        '          rustup toolchain install nightly-2026-05-23 --profile minimal' \
        "release-candidate job must install the pinned nightly"
    check_cache "$check_tmp/release-job" "$check_tmp/release-cache"
    check_named_step "$check_tmp/release-job" 'Install pinned release-readiness tools' \
        "$check_tmp/release-tools"
    for install in \
        '          cargo install cargo-deny --version 0.20.2 --locked' \
        '          cargo install cargo-public-api --version 0.52.0 --locked' \
        '          cargo install cargo-fuzz --version 0.13.2 --locked'
    do
        require_exact_line "$check_tmp/release-tools" "$install" \
            "release-candidate job is missing a pinned tool install"
    done
    require_named_run "$check_tmp/release-job" 'Build release-candidate artifacts' \
        "./ci/check-release-candidate.sh \"\$GITHUB_SHA\" \"\$RUNNER_TEMP/gmcrypto-envelope-lite-rc\"" \
        "$check_tmp/release-build"
    check_action_step "$check_tmp/release-job" "$UPLOAD_ACTION" "$check_tmp/release-upload"
    require_exact_line "$check_tmp/release-upload" '        with:' \
        "release-candidate upload must define exactly one with block"
    require_exact_line "$check_tmp/release-upload" \
        "          name: gmcrypto-envelope-lite-0.1.0-rc-built-\${{ github.sha }}" \
        "release-candidate artifact name must bind the commit"
    require_exact_line "$check_tmp/release-upload" \
        "          path: \${{ runner.temp }}/gmcrypto-envelope-lite-rc/" \
        "release-candidate artifact path is not exact"
    require_exact_line "$check_tmp/release-upload" '          if-no-files-found: error' \
        "release-candidate upload must fail on missing files"
    require_exact_line "$check_tmp/release-upload" '          retention-days: 14' \
        "release-candidate retention must be 14 days"
)

umask 077
tmp=$(mktemp -d "${TMPDIR:-/tmp}/workflow-contract.XXXXXX") || \
    fail "unable to create workflow self-test directory"
cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

check_contract "$repo_root" "$tmp/current"

mkdir -p "$tmp/fixture/.github/workflows"
cp "$repo_root/.github/workflows/ci.yml" \
    "$repo_root/.github/workflows/fuzz.yml" \
    "$repo_root/.github/workflows/release-candidate.yml" \
    "$tmp/fixture/.github/workflows/"

expect_mutation_rejected() {
    label=$1
    fixture_root=$2
    if check_contract "$fixture_root" "$tmp/mutated" >"$tmp/mutation.out" 2>&1; then
        fail "$label mutation was accepted"
    fi
}

expect_valid_mutation_rejected() {
    label=$1
    fixture_root=$2
    if ! actionlint "$fixture_root/.github/workflows/ci.yml" \
        "$fixture_root/.github/workflows/fuzz.yml" \
        "$fixture_root/.github/workflows/release-candidate.yml" \
        >"$tmp/mutation-actionlint.out" 2>&1; then
        cat "$tmp/mutation-actionlint.out" >&2
        fail "$label mutation must remain valid workflow YAML"
    fi
    expect_mutation_rejected "$label" "$fixture_root"
}

expect_valid_mutation_accepted() {
    label=$1
    fixture_root=$2
    if ! actionlint "$fixture_root/.github/workflows/ci.yml" \
        "$fixture_root/.github/workflows/fuzz.yml" \
        "$fixture_root/.github/workflows/release-candidate.yml" \
        >"$tmp/mutation-actionlint.out" 2>&1; then
        cat "$tmp/mutation-actionlint.out" >&2
        fail "$label mutation must remain valid workflow YAML"
    fi
    if ! check_contract "$fixture_root" "$tmp/accepted" \
        >"$tmp/mutation.out" 2>&1; then
        cat "$tmp/mutation.out" >&2
        fail "$label mutation was rejected"
    fi
}

cp "$tmp/fixture/.github/workflows/ci.yml" "$tmp/ci.original"
sed 's/cargo test --all-targets --locked/cargo test --locked/' \
    "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "missing required job command" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

sed 's/^  fuzz-smoke:/  fuzz-renamed:/' \
    "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "missing required job" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

printf '%s\n' '  forbidden-publication:' '    runs-on: ubuntu-latest' \
    '    steps:' '      - run: cargo publish' >>"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "publication command" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    !inserted && $0 == "  contents: read" {
        print "  id-token: write"
        inserted = 1
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "publication permission" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

sed 's/cargo-deny --version 0\.20\.2 --locked/cargo-deny --locked/' \
    "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "unpinned tool" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

sed '/^      - name: Verify workflow contracts$/ { N; d; }' \
    "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "missing workflow self-test wiring" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    !inserted && $0 ~ /^    runs-on:.*matrix\.os/ {
        print "    permissions:"
        print "      contents: write"
        inserted = 1
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "job-level write permission" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    !inserted && $0 ~ /^    runs-on:.*matrix\.os/ {
        print "    permissions: write-all"
        inserted = 1
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "job-level write-all permission" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

printf '%s\n' 'malformed: [unterminated' >>"$tmp/fixture/.github/workflows/ci.yml"
expect_mutation_rejected "malformed workflow YAML" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

sed 's/^      - run: cargo deny check$/      - name: cargo deny check\
        run: echo policy-placeholder/' \
    "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "policy command moved into a step name" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

sed 's/^      - run: cargo deny check$/      - name: Policy placeholder\
        env:\
          POLICY_COMMAND: cargo deny check\
        run: echo policy-placeholder/' \
    "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "policy command moved into step environment" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

sed 's/^      - run: cargo deny check$/      - name: Policy placeholder\
        run: |\
          echo "cargo deny check"/' \
    "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "policy command moved into unrelated multiline script" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

sed 's#actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 #actions/checkout@v4 #' \
    "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "mutable action reference" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

sed 's/persist-credentials: false/persist-credentials: true/' \
    "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "checkout credential persistence" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "  quality:" {
        print "    if: github.ref == \047refs/heads/never-run-quality\047"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "conditional quality job" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "  quality:" { print "    continue-on-error: true" }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "non-blocking quality job" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "      - run: cargo deny check" { print "        continue-on-error: true" }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "non-blocking policy step" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "      - run: cargo deny check" {
        print "        if: github.ref == \047refs/heads/never-run-policy\047"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "conditional policy step" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "  quality:" {
        print "    if : github.ref == \047refs/heads/never-run-quality\047"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "spaced conditional job key" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "      - run: cargo deny check" {
        print "        continue-on-error : true"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "spaced non-blocking step key" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "  quality:" {
        print "    \047if\047: github.ref == \047refs/heads/never-run-quality\047"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "single-quoted conditional job key" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "      - run: cargo deny check" {
        print "        \"continue-on-error\": true"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "double-quoted non-blocking step key" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "  quality:" {
        print "    !!str if: github.ref == \047refs/heads/never-run-quality\047"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "tagged conditional job key" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "  quality:" {
        print "    !<tag:yaml.org,2002:str> if: github.ref == \047refs/heads/never-run-quality\047"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "verbatim-tagged conditional job key" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "  quality:" {
        print "    !gate if: github.ref == \047refs/heads/never-run-quality\047"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "local-tagged conditional job key" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "  quality:" {
        print "    env:"
        print "      !!str OUTPUT_MODE: write"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "tagged unrelated mapping key" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "  quality:" {
        print "    env:"
        print "      ? OUTPUT_MODE"
        print "      : write"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "explicit unrelated mapping key" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "  quality:" {
        print "    env:"
        print "      \047OUTPUT_MODE\047: write"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_rejected "quoted unrelated mapping key" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "  quality:" {
        print "    env:"
        print "      OUTPUT_BANG: \047!gate if:\047"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_accepted "ordinary exclamation mark in a value" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "          go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12" {
        print "          if ! command -v secure-envelope-impossible-command >/dev/null 2>&1; then"
        print "            :"
        print "          fi"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_accepted "ordinary exclamation mark in a run script" "$tmp/fixture"
cp "$tmp/ci.original" "$tmp/fixture/.github/workflows/ci.yml"

awk '
    { print }
    $0 == "  quality:" {
        print "    env:"
        print "      OUTPUT_MODE: write"
    }
' "$tmp/ci.original" >"$tmp/fixture/.github/workflows/ci.yml"
expect_valid_mutation_accepted "unrelated write-valued environment" "$tmp/fixture"

echo "workflow contract tests passed"
