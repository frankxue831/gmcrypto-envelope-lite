#!/bin/sh
set -eu

# Self-test for ci/check-compatibility-gate.sh.
#
# The gate itself takes minutes because it compiles gmcrypto-core twice per
# feature configuration. This test drives the script's control flow against a
# fake cargo and fake sub-gates instead, so it proves the properties that
# matter -- fail-closed behaviour, both feature configurations, the phase-1
# only exclusion, and above all that the candidate override never writes an
# absolute path -- in seconds rather than minutes.

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
shell_under_test=${SHELL_UNDER_TEST:-sh}
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/secure-envelope-compat-gate-test.XXXXXX")
# A path component with a space catches quoting regressions.
mkdir "$fixture_root/workspace with spaces"
fixture=$(CDPATH='' cd -- "$fixture_root/workspace with spaces" && pwd -P)

cleanup() { rm -rf -- "$fixture_root"; }
trap cleanup EXIT HUP INT TERM
fail() { echo "error: $*" >&2; exit 1; }
contains() { grep -F -- "$2" "$1" >/dev/null || fail "expected $1 to contain: $2"; }
lacks() { grep -F -- "$2" "$1" >/dev/null && fail "expected $1 not to contain: $2"; return 0; }
count_matching() { grep -c -F -- "$2" "$1" || true; }

envelope="$fixture/envelope"
core="$fixture/core"
outside="$fixture/outside"
mkdir -p "$envelope/ci" "$envelope/tests" \
    "$core/crates/gmcrypto-core" "$core/crates/gmcrypto-simd" \
    "$fixture/bin" "$outside"

export FAKE_CARGO_LOG="$fixture/cargo.log"
export FAKE_GATE_LOG="$fixture/gate.log"
export PATH="$fixture/bin:$PATH"

# --- fake cargo -------------------------------------------------------------

cat >"$fixture/bin/cargo" <<'FAKE_CARGO'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$FAKE_CARGO_LOG"

if test -n "${FAKE_FAIL_MATCH:-}"; then
    case "$*" in
        *"$FAKE_FAIL_MATCH"*)
            echo "simulated cargo failure: $*" >&2
            exit 1
            ;;
    esac
fi

case "${1:-}" in
    metadata)
        if test "${FAKE_CASE:-}" = patch_ineffective; then
            # Resolution still points at the registry: the override was a no-op.
            printf '{"packages":[{"manifest_path":"/registry/gmcrypto-core/Cargo.toml"}]}\n'
        else
            printf '{"packages":[{"manifest_path":"%s/core/crates/gmcrypto-core/Cargo.toml"}]}\n' \
                "$(dirname -- "$PWD")"
        fi
        ;;
    test)
        echo "test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
        ;;
    *)
        ;;
esac
FAKE_CARGO
chmod +x "$fixture/bin/cargo"

# --- fake sub-gates ---------------------------------------------------------

# Stands in for the real boundary scanner by enforcing the one property the
# real one enforces here: no absolute path may reach the exported manifest.
# This is the regression guard for the trap recorded in gm-crypto-rs
# docs/v1.11.0-gate1-evidence.md section 4.
cat >"$envelope/ci/check-open-source-boundary.sh" <<'FAKE_BOUNDARY'
#!/bin/sh
set -eu
printf 'boundary %s\n' "$*" >>"$FAKE_GATE_LOG"
if grep -Eq '^[a-z-]+ = \{ path = "/' Cargo.toml; then
    echo "error: open-source boundary violation" >&2
    exit 1
fi
FAKE_BOUNDARY

cat >"$envelope/ci/check-crypto-inventory.sh" <<'FAKE_INVENTORY'
#!/bin/sh
printf 'inventory\n' >>"$FAKE_GATE_LOG"
FAKE_INVENTORY

cat >"$envelope/tests/open_source_boundary.sh" <<'FAKE_BOUNDARY_SELFTEST'
#!/bin/sh
printf 'boundary-self-test\n' >>"$FAKE_GATE_LOG"
FAKE_BOUNDARY_SELFTEST

chmod +x "$envelope/ci/check-open-source-boundary.sh" \
    "$envelope/ci/check-crypto-inventory.sh" \
    "$envelope/tests/open_source_boundary.sh"

cp "$repo_root/ci/check-compatibility-gate.sh" "$envelope/ci/"
chmod +x "$envelope/ci/check-compatibility-gate.sh"
gate_script="$envelope/ci/check-compatibility-gate.sh"

# --- fixture repositories ---------------------------------------------------

write_envelope_manifest() {
    printf '[package]\nname = "fixture-envelope"\nversion = "0.0.0"\n\n[dependencies]\ngmcrypto-core = { version = "1.11", features = ["x509"] }\n' \
        >"$1/Cargo.toml"
}
write_envelope_manifest "$envelope"
for target in alpha beta release_documents; do
    printf '// %s\n' "$target" >"$envelope/tests/$target.rs"
done

write_core_workspace() {
    printf '[workspace]\nmembers = ["crates/gmcrypto-core", "crates/gmcrypto-simd"]\n\n[workspace.package]\nversion = "%s"\n' \
        "$2" >"$1/Cargo.toml"
    printf '[package]\nname = "gmcrypto-core"\nversion.workspace = true\n' \
        >"$1/crates/gmcrypto-core/Cargo.toml"
    printf '[package]\nname = "gmcrypto-simd"\nversion.workspace = true\n' \
        >"$1/crates/gmcrypto-simd/Cargo.toml"
}
write_core_workspace "$core" 1.11.0

init_repository() {
    git -C "$1" init --quiet
    git -C "$1" config user.email fixture@example.invalid
    git -C "$1" config user.name Fixture
    git -C "$1" add -A
    git -C "$1" -c commit.gpgsign=false commit --quiet -m fixture
}
init_repository "$envelope"
init_repository "$core"

# --- helpers ----------------------------------------------------------------

run_log="$fixture/run.log"

expect_exit() {
    expected_status=$1
    label=$2
    shift 2
    : >"$FAKE_CARGO_LOG"
    : >"$FAKE_GATE_LOG"
    set +e
    "$@" >"$run_log" 2>&1
    actual_status=$?
    set -e
    test "$actual_status" -eq "$expected_status" || {
        cat "$run_log" >&2
        fail "$label: expected exit $expected_status, got $actual_status"
    }
}

run_gate() {
    "$shell_under_test" "$gate_script" "$@"
}

# --- argument and precondition validation -----------------------------------

expect_exit 2 "no arguments" run_gate
expect_exit 2 "too many arguments" run_gate "$core" /tmp/evidence.md extra
expect_exit 2 "relative evidence path" run_gate "$core" evidence.md
contains "$run_log" usage

expect_exit 1 "core path is not a directory" run_gate "$envelope/Cargo.toml"
expect_exit 1 "core path is not a repository" run_gate "$outside"
contains "$run_log" "not a Git repository"

expect_exit 1 "evidence inside the repository" run_gate "$core" "$envelope/evidence.md"
contains "$run_log" "outside the repository"

printf 'dirty\n' >"$envelope/untracked-file"
expect_exit 1 "dirty envelope worktree" run_gate "$core"
contains "$run_log" "worktree must be clean"
rm -f "$envelope/untracked-file"

missing_member="$fixture/core-missing-simd"
cp -R "$core" "$missing_member"
rm -rf "$missing_member/crates/gmcrypto-simd"
git -C "$missing_member" add -A
git -C "$missing_member" -c commit.gpgsign=false commit --quiet -m "drop simd"
expect_exit 1 "core export missing a workspace member" run_gate "$missing_member"
contains "$run_log" "missing crates/gmcrypto-simd/Cargo.toml"

# --- the passing run --------------------------------------------------------

evidence="$outside/evidence.md"
expect_exit 0 "passing gate" run_gate "$core" "$evidence"
test -f "$evidence" || fail "the gate did not write its evidence file"
contains "$evidence" "**Result: PASS**"
contains "$evidence" "## 1. Phase 1"
contains "$evidence" "## 2. Phase 2"
lacks "$evidence" "**FAIL**"

# Both feature configurations must be exercised, in both phases.
contains "$FAKE_CARGO_LOG" "clippy --all-targets --locked -- -D warnings"
contains "$FAKE_CARGO_LOG" "clippy --all-targets --locked --features aead -- -D warnings"
contains "$FAKE_CARGO_LOG" "clippy --all-targets -- -D warnings"
contains "$FAKE_CARGO_LOG" "clippy --all-targets --features aead -- -D warnings"

# Phase 1 asserts against the committed lockfile; phase 2 must not, so cargo
# may rewrite the disposable one.
contains "$FAKE_CARGO_LOG" "test --all-targets --locked"
contains "$FAKE_CARGO_LOG" "test --lib"

# release_documents is the phase-1-only exclusion: it runs once, and never
# as a phase-2 behavioural target.
test "$(count_matching "$FAKE_CARGO_LOG" 'test --locked --test release_documents')" -eq 1 || \
    fail "release_documents must run exactly once, in phase 1"
lacks "$FAKE_CARGO_LOG" "test --test release_documents --features aead"
for discovered in alpha beta; do
    contains "$FAKE_CARGO_LOG" "test --test $discovered"
    contains "$FAKE_CARGO_LOG" "test --test $discovered --features aead"
done

# The boundary commands stay unchanged across the patch: once per phase.
test "$(count_matching "$FAKE_GATE_LOG" 'boundary --worktree .')" -eq 2 || \
    fail "the boundary scan must run in both phases"
test "$(count_matching "$FAKE_GATE_LOG" 'inventory')" -eq 1 || \
    fail "the cryptographic inventory must run once, before the patch"

# The temporary copy is pinned to the exact candidate so the override resolves
# whatever the declared range is, and both values reach the evidence.
contains "$evidence" 'Declared downstream requirement `1.11`; candidate version `1.11.0`'
contains "$evidence" 'pinned to `=1.11.0`'
# The real checkout must never be touched.
contains "$envelope/Cargo.toml" 'gmcrypto-core = { version = "1.11", features = ["x509"] }'
lacks "$envelope/Cargo.toml" '[patch.crates-io]'

# --- a candidate outside the declared requirement ---------------------------

# A major-version candidate does not satisfy the caret requirement. Without the
# temporary pin the override fails to resolve and the candidate is never tested,
# which is the gap ECOSYSTEM section 8 covers by allowing the gate copy -- and
# only the gate copy -- to change that requirement.
core_next_major="$fixture/core-2x"
mkdir -p "$core_next_major/crates/gmcrypto-core" "$core_next_major/crates/gmcrypto-simd"
write_core_workspace "$core_next_major" 2.0.0
init_repository "$core_next_major"

expect_exit 0 "major-version candidate outside the caret" \
    run_gate "$core_next_major" "$outside/major.md"
contains "$outside/major.md" 'Declared downstream requirement `1.11`; candidate version `2.0.0`'
contains "$outside/major.md" 'pinned to `=2.0.0`'
contains "$outside/major.md" "**Result: PASS**"
contains "$envelope/Cargo.toml" 'gmcrypto-core = { version = "1.11", features = ["x509"] }'

# An unreadable candidate version must fail closed rather than guess.
core_unversioned="$fixture/core-unversioned"
cp -R "$core" "$core_unversioned"
printf '[workspace]\nmembers = ["crates/gmcrypto-core"]\n' >"$core_unversioned/Cargo.toml"
git -C "$core_unversioned" add -A
git -C "$core_unversioned" -c commit.gpgsign=false commit --quiet -m "drop workspace version"
expect_exit 1 "candidate workspace version missing" run_gate "$core_unversioned"
contains "$run_log" "could not read the candidate core workspace version"

# --- fail-closed behaviour --------------------------------------------------

# Injected through `env` rather than an assignment prefix: a prefix on a
# function call persists in the calling shell afterwards, which would silently
# contaminate every later case.
run_gate_with() {
    injected=$1
    shift
    env "$injected" "$shell_under_test" "$gate_script" "$@"
}

expect_exit 1 "phase-1 aead clippy failure" run_gate_with \
    'FAKE_FAIL_MATCH=clippy --all-targets --locked --features aead' \
    "$core" "$outside/never.md"
contains "$run_log" "gate step failed"
test ! -f "$outside/never.md" || fail "evidence must not be written for a failing gate"

expect_exit 1 "phase-2 aead target failure" run_gate_with \
    'FAKE_FAIL_MATCH=test --test beta --features aead' "$core"
contains "$run_log" "gate step failed"

expect_exit 1 "phase-1 release-document failure" run_gate_with \
    'FAKE_FAIL_MATCH=test --locked --test release_documents' "$core"
contains "$run_log" "gate step failed"

expect_exit 1 "candidate override silently ignored" run_gate_with \
    'FAKE_CASE=patch_ineffective' "$core"
contains "$run_log" "did not take effect"

# The passing run must still pass with no injection left over.
expect_exit 0 "passing gate after the failure cases" run_gate "$core" "$outside/final.md"
contains "$outside/final.md" "**Result: PASS**"

# --- the absolute-path regression guard -------------------------------------

# Rewrite the override to an absolute path, exactly the mistake recorded in
# gm-crypto-rs docs/v1.11.0-gate1-evidence.md section 4, and confirm the gate
# refuses it rather than reporting a candidate defect.
absolute_variant="$fixture/absolute-variant.sh"
sed 's|path = "\.\./core/crates/|path = "/absolute/core/crates/|' \
    "$gate_script" >"$envelope/ci/check-compatibility-gate.sh.absolute"
cp "$envelope/ci/check-compatibility-gate.sh.absolute" "$absolute_variant"
rm -f "$envelope/ci/check-compatibility-gate.sh.absolute"
grep -F 'path = "/absolute/core/crates/gmcrypto-core"' "$absolute_variant" >/dev/null || \
    fail "the absolute-path mutation did not apply"
chmod +x "$absolute_variant"

# The mutated copy must still resolve repo_root to the fixture repository.
mkdir -p "$fixture/absolute-repo/ci"
cp -R "$envelope/tests" "$fixture/absolute-repo/tests"
cp "$envelope/Cargo.toml" "$fixture/absolute-repo/Cargo.toml"
cp "$envelope/ci/check-open-source-boundary.sh" \
    "$envelope/ci/check-crypto-inventory.sh" "$fixture/absolute-repo/ci/"
cp "$absolute_variant" "$fixture/absolute-repo/ci/check-compatibility-gate.sh"
chmod +x "$fixture/absolute-repo/ci/check-compatibility-gate.sh"
init_repository "$fixture/absolute-repo"

expect_exit 1 "absolute override path" \
    "$shell_under_test" "$fixture/absolute-repo/ci/check-compatibility-gate.sh" "$core"
contains "$run_log" "open-source boundary violation"

echo "compatibility gate tests passed"
