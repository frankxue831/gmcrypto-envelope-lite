#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
shell_under_test=${SHELL_UNDER_TEST:-sh}
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/secure-envelope-fuzz-smoke-test.XXXXXX")
mkdir "$fixture_root/repository with spaces"
fixture=$(CDPATH='' cd -- "$fixture_root/repository with spaces" && pwd -P)
original_path=$PATH

cleanup() { rm -rf -- "$fixture_root"; }
trap cleanup EXIT HUP INT TERM
fail() { echo "error: $*" >&2; exit 1; }
contains() { grep -F -- "$2" "$1" >/dev/null || fail "expected $1 to contain: $2"; }

mkdir -p "$fixture/ci" "$fixture/fuzz/corpus" "$fixture/rustup-bin" \
    "$fixture/pinned-bin" "$fixture/other-bin" "$fixture/tmp" \
    "$fixture/ambient-stable" "$fixture/ambient-nightly"
cp "$repo_root/ci/fuzz-smoke.sh" "$repo_root/ci/tool-versions.sh" "$fixture/ci/"
for target in transport_parts encoded_envelope typed_headers aead_envelope; do
    mkdir "$fixture/fuzz/corpus/$target"
    printf '%s\n' "$target seed" >"$fixture/fuzz/corpus/$target/seed"
done

for ambient in "$fixture/ambient-stable" "$fixture/ambient-nightly"; do
    cat >"$ambient/cargo" <<'EOF'
#!/bin/sh
touch "$FAKE_AMBIENT_CARGO_MARKER"
exit 99
EOF
    cat >"$ambient/rustc" <<'EOF'
#!/bin/sh
touch "$FAKE_AMBIENT_RUSTC_MARKER"
exit 99
EOF
    chmod +x "$ambient/cargo" "$ambient/rustc"
done

cat >"$fixture/pinned-bin/rustc" <<'EOF'
#!/bin/sh
touch "$FAKE_PINNED_RUSTC_MARKER"
test "$1" = --version || exit 98
test "${FAKE_CASE:-}" != rustc_failure || { echo simulated rustc failure >&2; exit 70; }
echo rustc-pinned
EOF

cat >"$fixture/pinned-bin/cargo" <<'EOF'
#!/bin/sh
set -eu
test "$(command -v cargo)" = "$FAKE_PINNED_CARGO" || { echo "nested cargo was not pinned" >&2; exit 81; }
test "$(command -v rustc)" = "$FAKE_PINNED_RUSTC" || { echo "nested rustc was not pinned" >&2; exit 82; }
touch "$FAKE_NESTED_MARKER"
touch "$FAKE_NESTED_RUSTC_MARKER"
case "$1" in
    test)
        test "$#" -eq 6 || { echo scenario command had unexpected arguments >&2; exit 83; }
        test "$2" = --manifest-path || { echo scenario manifest flag was missing >&2; exit 84; }
        test "$3" = "$FAKE_REPO/fuzz/Cargo.toml" || { echo scenario manifest path was not exact >&2; exit 85; }
        test "$4" = --test && test "$5" = scenarios && test "$6" = --locked || {
            echo scenario test selection was not exact >&2
            exit 86
        }
        printf '%s\n' scenario >>"$FAKE_EVENT_LOG"
        test "${FAKE_CASE:-}" != scenario_failure || { echo simulated scenario failure >&2; exit 80; }
        ;;
    fuzz)
        shift
        case "$1" in
            --version)
                test "${FAKE_CASE:-}" != cargo_unavailable || { echo simulated unavailable cargo-fuzz >&2; exit 72; }
                if test "${FAKE_CASE:-}" = wrong_version; then
                    echo cargo-fuzz 0.13.0
                else
                    echo cargo-fuzz 0.13.2
                fi
                ;;
            run)
                target=$2
                output=$3
                input=$4
                test "$5" = -- || { echo corpus paths were not before the libFuzzer separator >&2; exit 77; }
                shift 5
                printf 'fuzz:%s\n' "$target" >>"$FAKE_EVENT_LOG"
                printf '%s %s\n' "$target" "$*" >>"$FAKE_LOG"
                test -d "$output" && test -w "$output" || { echo output corpus was not writable >&2; exit 73; }
                test "$input" = "$(dirname "$output")/$target-input" || { echo temporary input corpus order was wrong >&2; exit 74; }
                test ! -w "$input" || { echo temporary input corpus was writable >&2; exit 75; }
                cmp "$input/seed" "$FAKE_REPO/fuzz/corpus/$target/seed" >/dev/null || { echo temporary input corpus differed >&2; exit 78; }
                test -w "$FAKE_REPO/fuzz/corpus/$target" && test -w "$FAKE_REPO/fuzz/corpus/$target/seed" || {
                    echo source corpus was not writable >&2
                    exit 79
                }
                printf '%s\n' "$(dirname "$output")" >>"$FAKE_RUN_ROOTS"
                test "${FAKE_CASE:-}" != run_failure || { echo simulated fuzz failure >&2; exit 76; }
                ;;
            *) exit 96 ;;
        esac
        ;;
    *) exit 97 ;;
esac
EOF
chmod +x "$fixture/pinned-bin/cargo" "$fixture/pinned-bin/rustc"
cp "$fixture/pinned-bin/rustc" "$fixture/other-bin/rustc"
chmod +x "$fixture/other-bin/rustc"

cat >"$fixture/rustup-bin/rustup" <<'EOF'
#!/bin/sh
set -eu
touch "$FAKE_RUSTUP_MARKER"
test "${RUSTUP_TOOLCHAIN+x}" != x || { echo ambient toolchain was not unset >&2; exit 90; }
case "$1" in
    which)
        test "$2" = --toolchain && test "$3" = nightly-2026-05-23 || exit 91
        case "$4" in
            cargo)
                test "${FAKE_CASE:-}" != which_cargo || { echo simulated missing cargo >&2; exit 92; }
                echo "$FAKE_PINNED_CARGO"
                ;;
            rustc)
                test "${FAKE_CASE:-}" != which_rustc || { echo simulated missing rustc >&2; exit 93; }
                test "${FAKE_CASE:-}" != mismatched || { echo "$FAKE_OTHER_RUSTC"; exit 0; }
                echo "$FAKE_PINNED_RUSTC"
                ;;
            *) exit 94 ;;
        esac
        ;;
    run)
        test "$2" = nightly-2026-05-23 || exit 95
        case "$3" in
            "$FAKE_PINNED_CARGO"|"$FAKE_PINNED_RUSTC") ;;
            *) echo unpinned tool executed through rustup >&2; exit 89 ;;
        esac
        printf '%s|%s|%s\n' "$2" "$3" "${4:-}" >>"$FAKE_TOOLCHAIN_LOG"
        shift 2
        exec "$@"
        ;;
    *) exit 96 ;;
esac
EOF
chmod +x "$fixture/rustup-bin/rustup"

run_checker() {
    case_name=$1
    ambient=$2
    shift 2
    cargo_marker="$fixture/$case_name.ambient-cargo"
    rustc_marker="$fixture/$case_name.ambient-rustc"
    nested_marker="$fixture/$case_name.nested"
    nested_rustc_marker="$fixture/$case_name.nested-rustc"
    pinned_rustc_marker="$fixture/$case_name.pinned-rustc"
    rustup_marker="$fixture/$case_name.rustup"
    log="$fixture/$case_name.log"
    roots="$fixture/$case_name.roots"
    event_log="$fixture/$case_name.events"
    toolchain_log="$fixture/$case_name.toolchain"
    rm -f "$cargo_marker" "$rustc_marker" "$nested_marker" "$nested_rustc_marker" \
        "$pinned_rustc_marker" "$rustup_marker" "$log" "$roots" "$event_log" "$toolchain_log"
    env PATH="$fixture/rustup-bin:$ambient:$original_path" RUSTUP_TOOLCHAIN=ambient \
        FAKE_CASE="$case_name" FAKE_REPO="$fixture" FAKE_LOG="$log" \
        FAKE_RUN_ROOTS="$roots" FAKE_EVENT_LOG="$event_log" FAKE_TOOLCHAIN_LOG="$toolchain_log" \
        FAKE_PINNED_CARGO="$fixture/pinned-bin/cargo" \
        FAKE_PINNED_RUSTC="$fixture/pinned-bin/rustc" FAKE_OTHER_RUSTC="$fixture/other-bin/rustc" \
        FAKE_AMBIENT_CARGO_MARKER="$cargo_marker" FAKE_AMBIENT_RUSTC_MARKER="$rustc_marker" \
        FAKE_NESTED_MARKER="$nested_marker" FAKE_NESTED_RUSTC_MARKER="$nested_rustc_marker" \
        FAKE_PINNED_RUSTC_MARKER="$pinned_rustc_marker" \
        FAKE_RUSTUP_MARKER="$rustup_marker" TMPDIR="$fixture/tmp" \
        "$shell_under_test" "$fixture/ci/fuzz-smoke.sh" "$@" >"$fixture/$case_name.out" 2>"$fixture/$case_name.err"
}

cksum "$fixture"/fuzz/corpus/*/seed >"$fixture/corpus.before"
ls -ld "$fixture"/fuzz/corpus/* "$fixture"/fuzz/corpus/*/seed >"$fixture/corpus-modes.before"
if ! run_checker pristine_stable "$fixture/ambient-stable"; then cat "$fixture/pristine_stable.err" >&2; fail stable; fi
test ! -e "$fixture/pristine_stable.ambient-cargo" || fail "ambient stable cargo ran"
test ! -e "$fixture/pristine_stable.ambient-rustc" || fail "ambient stable rustc ran"
test -e "$fixture/pristine_stable.nested" || fail "pinned cargo did not verify nested cargo resolution"
test -e "$fixture/pristine_stable.nested-rustc" || fail "pinned cargo did not verify nested rustc resolution"
test -e "$fixture/pristine_stable.pinned-rustc" || fail "pinned rustc did not run"
contains "$fixture/pristine_stable.out" "smoke fuzz run passed"
test "$(cat "$fixture/pristine_stable.events")" = "$(printf '%s\n' scenario fuzz:transport_parts fuzz:encoded_envelope fuzz:typed_headers fuzz:aead_envelope)" || \
    fail "scenario contracts did not run exactly once before all smoke targets"
test "$(grep -Fxc "nightly-2026-05-23|$fixture/pinned-bin/cargo|test" "$fixture/pristine_stable.toolchain")" -eq 1 || \
    fail "scenario contracts did not use the absolute pinned Cargo and declared toolchain exactly once"
test "$(wc -l <"$fixture/pristine_stable.log")" -eq 4 || fail "expected four smoke targets"
test "$(awk '{print $1}' "$fixture/pristine_stable.log")" = "$(printf '%s\n' transport_parts encoded_envelope typed_headers aead_envelope)" || \
    fail "fuzz targets ran out of order"
test "$(sed 's/^[^ ]* //' "$fixture/pristine_stable.log" | sort -u)" = \
    "-runs=256 -seed=424242 -max_len=4096 -rss_limit_mb=512 -timeout=5" || \
    fail "smoke options were not exact and stable"
while IFS= read -r root; do test ! -e "$root" || fail "temporary corpus survived"; done <"$fixture/pristine_stable.roots"
cksum "$fixture"/fuzz/corpus/*/seed >"$fixture/corpus.after"
cmp "$fixture/corpus.before" "$fixture/corpus.after" >/dev/null || fail "tracked corpus changed"
ls -ld "$fixture"/fuzz/corpus/* "$fixture"/fuzz/corpus/*/seed >"$fixture/corpus-modes.after"
cmp "$fixture/corpus-modes.before" "$fixture/corpus-modes.after" >/dev/null || fail "tracked corpus modes changed"
for target in transport_parts encoded_envelope typed_headers aead_envelope; do
    test -w "$fixture/fuzz/corpus/$target" && test -w "$fixture/fuzz/corpus/$target/seed" || \
        fail "success left source corpus non-writable: $target"
done

if ! run_checker pristine_nightly "$fixture/ambient-nightly"; then cat "$fixture/pristine_nightly.err" >&2; fail nightly; fi
test ! -e "$fixture/pristine_nightly.ambient-cargo" || fail "ambient nightly cargo ran"
test ! -e "$fixture/pristine_nightly.ambient-rustc" || fail "ambient nightly rustc ran"

if run_checker invalid "$fixture/ambient-stable" invalid; then fail "invalid mode succeeded"; fi
contains "$fixture/invalid.err" "usage:"
if run_checker extra "$fixture/ambient-stable" smoke extra; then fail "extra arguments succeeded"; fi
contains "$fixture/extra.err" "usage:"
test ! -e "$fixture/invalid.ambient-cargo" && test ! -e "$fixture/extra.ambient-cargo" || fail "tool lookup preceded mode validation"
test ! -e "$fixture/invalid.rustup" && test ! -e "$fixture/extra.rustup" || fail "rustup lookup preceded mode validation"

for failure in which_cargo which_rustc mismatched rustc_failure cargo_unavailable wrong_version scenario_failure run_failure; do
    if run_checker "$failure" "$fixture/ambient-stable"; then fail "$failure succeeded"; fi
done
contains "$fixture/which_cargo.err" "simulated missing cargo"
contains "$fixture/which_cargo.err" "pinned cargo could not be resolved"
contains "$fixture/which_rustc.err" "simulated missing rustc"
contains "$fixture/which_rustc.err" "pinned rustc could not be resolved"
contains "$fixture/mismatched.err" "different toolchain bin directories"
contains "$fixture/rustc_failure.err" "simulated rustc failure"
contains "$fixture/rustc_failure.err" "pinned fuzz toolchain/rustc is unavailable"
contains "$fixture/cargo_unavailable.err" "simulated unavailable cargo-fuzz"
contains "$fixture/cargo_unavailable.err" "cargo-fuzz is unavailable"
contains "$fixture/wrong_version.err" "cargo-fuzz version mismatch: expected cargo-fuzz 0.13.2, found cargo-fuzz 0.13.0"
contains "$fixture/scenario_failure.err" "simulated scenario failure"
contains "$fixture/scenario_failure.err" "fuzz scenario contract suite failed"
test "$(cat "$fixture/scenario_failure.events")" = scenario || fail "scenario failure did not stop before fuzz targets"
test ! -s "$fixture/scenario_failure.log" || fail "scenario failure allowed a fuzz target to run"
contains "$fixture/run_failure.err" "fuzz target failed: transport_parts"
while IFS= read -r root; do test ! -e "$root" || fail "failure temporary corpus survived"; done <"$fixture/run_failure.roots"
cksum "$fixture"/fuzz/corpus/*/seed >"$fixture/corpus.failure"
cmp "$fixture/corpus.before" "$fixture/corpus.failure" >/dev/null || fail "failure changed tracked corpus"
ls -ld "$fixture"/fuzz/corpus/* "$fixture"/fuzz/corpus/*/seed >"$fixture/corpus-modes.failure"
cmp "$fixture/corpus-modes.before" "$fixture/corpus-modes.failure" >/dev/null || fail "failure changed tracked corpus modes"
for target in transport_parts encoded_envelope typed_headers aead_envelope; do
    test -w "$fixture/fuzz/corpus/$target" && test -w "$fixture/fuzz/corpus/$target/seed" || \
        fail "failure left source corpus non-writable: $target"
done

if ! run_checker extended "$fixture/ambient-stable" extended; then cat "$fixture/extended.err" >&2; fail extended; fi
test "$(cat "$fixture/extended.events")" = "$(printf '%s\n' scenario fuzz:transport_parts fuzz:encoded_envelope fuzz:typed_headers fuzz:aead_envelope)" || \
    fail "scenario contracts did not run exactly once before all extended targets"
test "$(grep -Fxc "nightly-2026-05-23|$fixture/pinned-bin/cargo|test" "$fixture/extended.toolchain")" -eq 1 || \
    fail "extended scenario contracts did not use the absolute pinned Cargo and declared toolchain exactly once"
contains "$fixture/extended.log" "-max_total_time=100 -seed=424242 -max_len=4096 -rss_limit_mb=512 -timeout=5"
grep -F -- "-runs=" "$fixture/extended.log" >/dev/null && fail "extended unexpectedly used runs"
test "$(wc -l <"$fixture/extended.log")" -eq 4 || fail "expected four extended targets"

contains "$repo_root/fuzz/corpus/encoded_envelope/full_valid_open" "vvv000|0:|0:|0:"
contains "$repo_root/fuzz/corpus/aead_envelope/full_valid_open" "vvv000|0:|0:|0:"
contains "$repo_root/fuzz/corpus/encoded_envelope/cipher_limit_plus_one" "vvb002|0:|0:|0:"
contains "$repo_root/fuzz/corpus/transport_parts/case_insensitive_duplicate" "D"
contains "$repo_root/fuzz/corpus/typed_headers/case_insensitive_duplicate" "D"
echo "fuzz smoke runner tests passed"
