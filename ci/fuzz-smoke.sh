#!/bin/sh
set -eu

fail() {
    echo "error: $*" >&2
    exit 1
}

case $# in
    0) mode=smoke ;;
    1) mode=$1 ;;
    *) fail "usage: $0 [smoke|extended]" ;;
esac

case "$mode" in
    smoke|extended) ;;
    *) fail "usage: $0 [smoke|extended]" ;;
esac

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=ci/tool-versions.sh
. "$repo_root/ci/tool-versions.sh"
unset RUSTUP_TOOLCHAIN

which_cargo_error=
which_rustc_error=
toolchain_error=
version_error=
run_root=

cleanup() {
    for diagnostic in "$which_cargo_error" "$which_rustc_error" "$toolchain_error" "$version_error"
    do
        test -z "$diagnostic" || rm -f "$diagnostic"
    done
    if test -n "$run_root"; then
        chmod -R u+w "$run_root" 2>/dev/null || true
        rm -rf "$run_root"
    fi
}

trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

which_cargo_error=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-fuzz-which-cargo.XXXXXX") || \
    fail "could not create a pinned cargo resolution diagnostic file"
if ! pinned_cargo=$(rustup which --toolchain "$FUZZ_TOOLCHAIN" cargo 2>"$which_cargo_error"); then
    cat "$which_cargo_error" >&2
    fail "pinned cargo could not be resolved for toolchain: $FUZZ_TOOLCHAIN"
fi
test -x "$pinned_cargo" || fail "resolved pinned cargo is not executable: $pinned_cargo"

which_rustc_error=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-fuzz-which-rustc.XXXXXX") || \
    fail "could not create a pinned rustc resolution diagnostic file"
if ! pinned_rustc=$(rustup which --toolchain "$FUZZ_TOOLCHAIN" rustc 2>"$which_rustc_error"); then
    cat "$which_rustc_error" >&2
    fail "pinned rustc could not be resolved for toolchain: $FUZZ_TOOLCHAIN"
fi
test -x "$pinned_rustc" || fail "resolved pinned rustc is not executable: $pinned_rustc"

pinned_cargo_bin=$(CDPATH='' cd -- "$(dirname -- "$pinned_cargo")" && pwd -P) || \
    fail "could not determine the resolved pinned cargo directory"
pinned_rustc_bin=$(CDPATH='' cd -- "$(dirname -- "$pinned_rustc")" && pwd -P) || \
    fail "could not determine the resolved pinned rustc directory"
test "$pinned_cargo_bin" = "$pinned_rustc_bin" || \
    fail "pinned cargo and rustc resolve to different toolchain bin directories"

PATH="$pinned_cargo_bin:$PATH"
export PATH

toolchain_error=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-fuzz-toolchain.XXXXXX") || \
    fail "could not create a fuzz toolchain diagnostic file"
if ! rustup run "$FUZZ_TOOLCHAIN" "$pinned_rustc" --version > /dev/null 2>"$toolchain_error"; then
    cat "$toolchain_error" >&2
    fail "pinned fuzz toolchain/rustc is unavailable: $FUZZ_TOOLCHAIN"
fi

version_error=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-fuzz-version.XXXXXX") || \
    fail "could not create a cargo-fuzz version diagnostic file"
if ! actual_version=$(rustup run "$FUZZ_TOOLCHAIN" "$pinned_cargo" fuzz --version 2>"$version_error"); then
    cat "$version_error" >&2
    fail "cargo-fuzz is unavailable for pinned toolchain: $FUZZ_TOOLCHAIN"
fi
expected_version="cargo-fuzz $CARGO_FUZZ_VERSION"
test "$actual_version" = "$expected_version" || \
    fail "cargo-fuzz version mismatch: expected $expected_version, found ${actual_version:-missing cargo-fuzz}"

if ! rustup run "$FUZZ_TOOLCHAIN" "$pinned_cargo" test \
    --manifest-path "$repo_root/fuzz/Cargo.toml" --test scenarios --locked; then
    fail "fuzz scenario contract suite failed"
fi

run_root=$(mktemp -d "${TMPDIR:-/tmp}/secure-envelope-fuzz-run.XXXXXX") || \
    fail "could not create a temporary fuzz corpus root"

case "$mode" in
    smoke)
        set -- -runs=256 -seed=424242 -max_len=4096 -rss_limit_mb=512 -timeout=5
        ;;
    extended)
        set -- -max_total_time=100 -seed=424242 -max_len=4096 -rss_limit_mb=512 -timeout=5
        ;;
esac

for target in transport_parts encoded_envelope typed_headers aead_envelope
do
    output_corpus="$run_root/$target-output"
    input_corpus="$run_root/$target-input"
    tracked_corpus="$repo_root/fuzz/corpus/$target"
    test -d "$tracked_corpus" || fail "tracked fuzz corpus is missing: $tracked_corpus"
    mkdir "$output_corpus" "$input_corpus" || fail "could not create temporary fuzz corpora: $target"
    cp -R "$tracked_corpus/." "$input_corpus" || fail "could not copy tracked fuzz corpus: $target"
    chmod -R a-w "$input_corpus" || fail "could not make temporary input corpus read-only: $target"
    (cd "$repo_root" && rustup run "$FUZZ_TOOLCHAIN" "$pinned_cargo" fuzz run "$target" \
        "$output_corpus" "$input_corpus" -- "$@") || fail "fuzz target failed: $target"
done

echo "$mode fuzz run passed"
