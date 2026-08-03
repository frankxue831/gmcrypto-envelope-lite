#!/bin/sh
set -eu

# ECOSYSTEM.md section 8 compatibility gate #1, executed rather than hand-run.
#
# Exports this crate and a candidate gmcrypto-core side by side into a
# disposable directory, then runs the gate in the two phases section 8
# specifies:
#
#   phase 1  pristine, --locked, against the committed lockfile
#   phase 2  candidate injected through a [patch.crates-io] path override
#
# Both phases run in every feature configuration the crate ships. The `aead`
# feature enables gmcrypto-core/sm4-aead, which is defined as
# ["dep:gmcrypto-simd"] and so pulls gmcrypto-simd -- and, on x86_64 and
# aarch64, its target-gated cpufeatures detection dependency -- into the
# compiled graph. A default-features-only gate cannot see that path at all.
#
# The override path is relative by construction. An absolute path embeds a
# developer home directory into Cargo.toml, which the boundary scanner exists
# to reject; the resulting failure reads like a candidate defect and is not one.
# See gm-crypto-rs docs/v1.11.0-gate1-evidence.md section 4.
#
# This script calls the existing gates; it does not reimplement them, and it
# never modifies the downstream checkout.

usage() {
    echo "usage: check-compatibility-gate.sh CORE_CHECKOUT [ABSOLUTE_EVIDENCE_FILE]" >&2
    exit 2
}

fail() {
    echo "error: $*" >&2
    exit 1
}

test "$#" -ge 1 && test "$#" -le 2 || usage
core_argument=$1
evidence_argument=${2-}

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)

for required_tool in cargo git tar; do
    command -v "$required_tool" >/dev/null 2>&1 || fail "required tool is unavailable: $required_tool"
done

for required_gate in \
    "$repo_root/ci/check-open-source-boundary.sh" \
    "$repo_root/ci/check-crypto-inventory.sh" \
    "$repo_root/tests/open_source_boundary.sh"
do
    test -f "$required_gate" && test ! -L "$required_gate" || \
        fail "required gate is not a regular file: $required_gate"
done

# --- both sides of the gate -------------------------------------------------

test -d "$core_argument" || fail "core checkout is not a directory"
core_root=$(CDPATH='' cd -- "$core_argument" && pwd -P) || fail "could not resolve core checkout"
git -C "$core_root" rev-parse --git-dir >/dev/null 2>&1 || \
    fail "core checkout is not a Git repository"
core_commit=$(git -C "$core_root" rev-parse HEAD) || fail "could not resolve core HEAD"
core_description=$(git -C "$core_root" describe --all --always --dirty 2>/dev/null || echo unknown)

envelope_commit=$(git -C "$repo_root" rev-parse HEAD) || fail "could not resolve envelope HEAD"
test -z "$(git -C "$repo_root" status --porcelain --untracked-files=all)" || \
    fail "envelope worktree must be clean: the gate runs on an export of HEAD"

if test -n "$evidence_argument"; then
    case "$evidence_argument" in /*) ;; *) usage ;; esac
    evidence_parent=$(dirname -- "$evidence_argument")
    test -d "$evidence_parent" || fail "evidence parent is not a directory"
    evidence_parent=$(CDPATH='' cd -- "$evidence_parent" && pwd -P) || \
        fail "could not resolve evidence parent"
    case "$evidence_parent" in
        "$repo_root" | "$repo_root"/*) fail "evidence file must live outside the repository" ;;
    esac
    evidence_file="$evidence_parent/$(basename -- "$evidence_argument")"
else
    evidence_file=
fi

# --- disposable side-by-side export ----------------------------------------

umask 077
gate_dir=$(mktemp -d "${TMPDIR:-/tmp}/gmcrypto-envelope-gate.XXXXXX") || \
    fail "could not create the gate directory"
# Canonicalize: macOS hands back a symlinked temporary path, and phase 2
# asserts against resolved manifest paths.
gate_dir=$(CDPATH='' cd -- "$gate_dir" && pwd -P)
cleanup() {
    rm -rf "$gate_dir"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

mkdir "$gate_dir/envelope" "$gate_dir/core"

git -C "$repo_root" archive --format=tar -o "$gate_dir/envelope.tar" HEAD || \
    fail "could not export the envelope crate"
tar -xf "$gate_dir/envelope.tar" -C "$gate_dir/envelope" || fail "could not unpack the envelope export"
rm -f "$gate_dir/envelope.tar"

git -C "$core_root" archive --format=tar -o "$gate_dir/core.tar" HEAD || \
    fail "could not export the core candidate"
tar -xf "$gate_dir/core.tar" -C "$gate_dir/core" || fail "could not unpack the core export"
rm -f "$gate_dir/core.tar"

for required_member in Cargo.toml crates/gmcrypto-core/Cargo.toml crates/gmcrypto-simd/Cargo.toml; do
    test -f "$gate_dir/core/$required_member" || \
        fail "core export is missing $required_member"
done

# --- evidence machinery -----------------------------------------------------

evidence_rows="$gate_dir/evidence-rows"
step_log="$gate_dir/step.log"
: >"$evidence_rows"

heading() {
    printf '\n%s\n\n| Configuration | Command | Result |\n|---|---|---|\n' "$1" >>"$evidence_rows"
}

note() {
    printf '\n%s\n' "$1" >>"$evidence_rows"
}

# Sums the per-target "test result: ok. N passed" lines, so the evidence
# records counts the way the hand-run gate records did.
test_summary() {
    awk '
        /^test result:/ { passed += $4; targets += 1 }
        END { if (targets > 0) printf "%d passed across %d target(s)", passed, targets }
    ' "$1"
}

step() {
    step_config=$1
    shift
    printf '  [%-7s] %s\n' "$step_config" "$*" >&2
    if "$@" >"$step_log" 2>&1; then
        step_result=$(test_summary "$step_log")
        if test -n "$step_result"; then
            printf '| %s | `%s` | PASS (%s) |\n' "$step_config" "$*" "$step_result" >>"$evidence_rows"
        else
            printf '| %s | `%s` | PASS |\n' "$step_config" "$*" >>"$evidence_rows"
        fi
    else
        printf '| %s | `%s` | **FAIL** |\n' "$step_config" "$*" >>"$evidence_rows"
        echo "--- failing command output ---" >&2
        cat "$step_log" >&2
        echo "--- end of failing command output ---" >&2
        fail "gate step failed [$step_config]: $*"
    fi
}

# Empty for the default build; word-splits into two arguments for `aead`.
feature_flags_for() {
    case "$1" in
        default) ;;
        aead) printf -- '--features aead' ;;
        *) fail "unknown feature configuration: $1" ;;
    esac
}

readonly FEATURE_CONFIGS='default aead'

cd "$gate_dir/envelope"

behavioral_targets=
for target_source in tests/*.rs; do
    test -f "$target_source" || fail "no integration test sources were discovered"
    target_name=${target_source#tests/}
    target_name=${target_name%.rs}
    test "$target_name" != release_documents || continue
    behavioral_targets="$behavioral_targets $target_name"
done
test -n "$behavioral_targets" || fail "no behavioral integration targets were discovered"

# --- phase 1: pristine ------------------------------------------------------

echo "phase 1 — pristine (committed lockfile, --locked)" >&2
heading '## 1. Phase 1 — pristine (committed lockfile, `--locked`)'

step shared cargo fmt --all -- --check
step shared sh tests/open_source_boundary.sh
step shared ./ci/check-open-source-boundary.sh --worktree .

for config in $FEATURE_CONFIGS; do
    # shellcheck disable=SC2046 # deliberate: empty for default, two words for aead
    step "$config" cargo clippy --all-targets --locked $(feature_flags_for "$config") -- -D warnings
    # shellcheck disable=SC2046
    step "$config" cargo test --all-targets --locked $(feature_flags_for "$config")
    # shellcheck disable=SC2046
    step "$config" cargo test --doc --locked $(feature_flags_for "$config")
done

# Section 8's two named pre-patch validations. Both assert against the
# pristine committed registry lock and neither is weakened; the inventory
# checker pins exact package versions, so it cannot run under the override.
step shared cargo test --locked --test release_documents
step shared ./ci/check-crypto-inventory.sh

note 'Neither pre-patch assertion was weakened. The cryptographic inventory validates both feature-scoped tiers (`ci/crypto-inventory.snapshot` and `ci/crypto-inventory-aead.snapshot`).'

# --- phase 2: candidate injected -------------------------------------------

echo "phase 2 — candidate injected" >&2

# A `[patch]` override only resolves if the patched version still satisfies the
# downstream requirement. A major-version candidate against a caret requirement
# does not, and Cargo then fails to resolve rather than testing the candidate --
# so the charter says to adjust the requirement in the temporary gate copy only.
# Pinning the disposable copy to the exact candidate does that unconditionally,
# with no version-range arithmetic to get wrong. The real checkout is untouched;
# both values go into the evidence so a range mismatch is visible at a glance.
candidate_version=$(awk '
    /^\[workspace\.package\][[:space:]]*$/ { in_section = 1; next }
    /^\[/ { in_section = 0 }
    in_section && /^[[:space:]]*version[[:space:]]*=/ {
        line = $0
        sub(/^[[:space:]]*version[[:space:]]*=[[:space:]]*"/, "", line)
        sub(/".*$/, "", line)
        print line
        found += 1
    }
    END { if (found != 1) exit 2 }
' "$gate_dir/core/Cargo.toml") || fail "could not read the candidate core workspace version"

declared_requirement=$(sed -n 's/^gmcrypto-core = { version = "\([^"]*\)".*/\1/p' Cargo.toml)
test -n "$declared_requirement" || fail "could not read the declared gmcrypto-core requirement"

sed 's/^gmcrypto-core = { version = "[^"]*"/gmcrypto-core = { version = "='"$candidate_version"'"/' \
    Cargo.toml >Cargo.toml.gate || fail "could not rewrite the temporary requirement"
mv Cargo.toml.gate Cargo.toml
grep -F "gmcrypto-core = { version = \"=$candidate_version\"" Cargo.toml >/dev/null || \
    fail "the temporary requirement pin did not apply"

printf '\nDeclared downstream requirement `%s`; candidate version `%s`. The disposable copy was pinned to `=%s` so the override resolves regardless of the declared range — the real downstream checkout is untouched. If the candidate falls outside the declared requirement, that requirement must be bumped downstream before the candidate ships.\n' \
    "$declared_requirement" "$candidate_version" "$candidate_version" >>"$evidence_rows"

cat >>Cargo.toml <<'PATCH_BLOCK'

[patch.crates-io]
# Relative by construction. An absolute path would write a developer home
# directory into this manifest, which the boundary scanner rejects.
gmcrypto-core = { path = "../core/crates/gmcrypto-core" }
gmcrypto-simd = { path = "../core/crates/gmcrypto-simd" }
PATCH_BLOCK

if ! cargo metadata --format-version 1 >"$gate_dir/metadata.json" 2>"$step_log"; then
    cat "$step_log" >&2
    fail "cargo metadata failed under the candidate patch"
fi
grep -F "$gate_dir/core/crates/gmcrypto-core/Cargo.toml" "$gate_dir/metadata.json" >/dev/null || \
    fail "the candidate override did not take effect: gmcrypto-core still resolves to the registry"

heading '## 2. Phase 2 — candidate injected (disposable lockfile, no `--locked`)'

# Formatting and boundary commands stay unchanged across the patch, per
# section 8. They are what proves the relative override left no absolute path
# behind in the manifest.
step shared cargo fmt --all -- --check
step shared sh tests/open_source_boundary.sh
step shared ./ci/check-open-source-boundary.sh --worktree .

for config in $FEATURE_CONFIGS; do
    # shellcheck disable=SC2046
    step "$config" cargo clippy --all-targets $(feature_flags_for "$config") -- -D warnings
    # shellcheck disable=SC2046
    step "$config" cargo test --lib $(feature_flags_for "$config")
    # shellcheck disable=SC2046
    step "$config" cargo test --doc $(feature_flags_for "$config")
    for behavioral_target in $behavioral_targets; do
        # shellcheck disable=SC2046
        step "$config" cargo test --test "$behavioral_target" $(feature_flags_for "$config")
    done
done

note '`release_documents` is the sole deliberate post-patch exclusion named in section 8: it validates registry metadata rather than runtime or API compatibility, and a path package has no registry checksum. All of its assertions ran in phase 1 against the pristine lock.'

# --- verdict ----------------------------------------------------------------

echo "gate PASS" >&2

if test -n "$evidence_file"; then
    {
        printf '# gmcrypto-core candidate — ECOSYSTEM section 8 gate #1 evidence\n\n'
        printf 'Generated by `ci/check-compatibility-gate.sh`. **Result: PASS** — the gate\n'
        printf 'fails closed, so a recorded run is a passing run.\n\n'
        printf '## Tested commits\n\n'
        printf '| Side | Commit | Notes |\n|---|---|---|\n'
        printf '| `gmcrypto-core` candidate | `%s` | %s; exported read-only with `git archive HEAD` |\n' \
            "$core_commit" "$core_description"
        printf '| `gmcrypto-envelope-lite` | `%s` | clean tree; exported read-only with `git archive HEAD` |\n' \
            "$envelope_commit"
        printf '\nRun in a disposable export outside both checkouts. Neither repository is\n'
        printf 'modified: the pin edit and the `[patch]` block exist only in the export.\n\n'
        printf 'Feature configurations covered: `default` and `--features aead`. The `aead`\n'
        printf 'configuration compiles `gmcrypto-core/sm4-aead`, which pulls `gmcrypto-simd`\n'
        printf '(and, on x86_64 and aarch64, its target-gated `cpufeatures` detection\n'
        printf 'dependency) into the graph, so it exercises core surface the default build\n'
        printf 'never reaches.\n'
        cat "$evidence_rows"
        printf '\n## Verdict\n\nPASS — no runtime or API incompatibility. No migration note is required\nbefore this core release ships.\n'
    } >"$evidence_file" || fail "could not write the evidence file"
    echo "evidence written to $evidence_file" >&2
fi
