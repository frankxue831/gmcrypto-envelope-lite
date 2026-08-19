#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
shell_under_test=${SHELL_UNDER_TEST:-sh}
fixture=$(mktemp -d "${TMPDIR:-/tmp}/secure-envelope-public-api-test.XXXXXX")
fixture=$(CDPATH= cd -- "$fixture" && pwd -P)
original_path=$PATH

cleanup() {
    rm -rf -- "$fixture"
}

trap cleanup EXIT HUP INT TERM

fail() {
    echo "error: $*" >&2
    exit 1
}

assert_contains() {
    file=$1
    expected=$2
    grep -F -- "$expected" "$file" >/dev/null || \
        fail "expected $file to contain: $expected"
}

assert_empty_directory() {
    directory=$1
    test -z "$(find "$directory" -type f -print -quit)" || \
        fail "expected temporary directory to be empty: $directory"
}

assert_ambient_cargo_unused() {
    test ! -e "$last_ambient_marker" || \
        fail "ambient cargo was invoked: $last_ambient_marker"
}

mkdir -p "$fixture/ci" "$fixture/api" "$fixture/rustup-bin" \
    "$fixture/pinned-bin" "$fixture/other-pinned-bin" "$fixture/tmp" \
    "$fixture/ambient-stable-bin" "$fixture/ambient-nightly-bin"

# The checker derives the snapshot filenames from the crate identity in
# Cargo.toml, so derive the same identity here rather than restating it: a
# version bump must not require a coupled edit in this test either.
crate_name=gmcrypto-envelope-lite
crate_version=$(awk '
    /^\[package\][[:space:]]*$/ { in_package = 1; next }
    /^\[/ { in_package = 0 }
    in_package && /^[[:space:]]*version[[:space:]]*=/ {
        line = $0
        sub("^[[:space:]]*version[[:space:]]*=[[:space:]]*\"", "", line)
        sub("\"[[:space:]]*$", "", line)
        print line
        exit
    }
' "$repo_root/Cargo.toml")
test -n "$crate_version" || fail "could not read the crate version for the fixture"
snapshot_basename="$crate_name-$crate_version"

cat >"$fixture/Cargo.toml" <<EOF
[package]
name = "$crate_name"
version = "$crate_version"
edition = "2021"
EOF

cp "$repo_root/ci/check-public-api.sh" "$repo_root/ci/tool-versions.sh" "$fixture/ci/"
cp "$repo_root/api/$snapshot_basename.txt" \
    "$fixture/api/$snapshot_basename.txt"
cp "$repo_root/api/$snapshot_basename.txt" "$fixture/generated.txt"
cp "$repo_root/api/$snapshot_basename-aead.txt" \
    "$fixture/api/$snapshot_basename-aead.txt"
cp "$repo_root/api/$snapshot_basename-aead.txt" "$fixture/generated-aead.txt"

for ambient_dir in "$fixture/ambient-stable-bin" "$fixture/ambient-nightly-bin"; do
    cat >"$ambient_dir/cargo" <<'EOF'
#!/bin/sh
touch "$FAKE_AMBIENT_CARGO_MARKER"
echo "error: ambient cargo invocation" >&2
exit 99
EOF
    chmod +x "$ambient_dir/cargo"
done

cat >"$fixture/pinned-bin/cargo" <<'EOF'
#!/bin/sh
set -eu

nested_cargo=$(command -v cargo)
test "$nested_cargo" = "$FAKE_PINNED_CARGO" || {
    echo "error: nested cargo resolved to $nested_cargo, not $FAKE_PINNED_CARGO" >&2
    exit 81
}
test "$1" = public-api
shift

case "$1" in
    --version)
        if test "${FAKE_PUBLIC_API_UNAVAILABLE:-0}" = 1; then
            echo "simulated missing cargo-public-api" >&2
            exit 72
        fi
        printf '%s\n' "${FAKE_PUBLIC_API_VERSION:-cargo-public-api 0.52.0}"
        ;;
    -ss)
        test "$2" = --color=never
        if test "${FAKE_GENERATOR_FAILURE:-0}" = 1; then
            echo "simulated public API generator failure" >&2
            exit 71
        fi
        case "${3:-}" in
            '')
                cat "$FAKE_GENERATED"
                ;;
            --features)
                test "$4" = aead
                cat "$FAKE_GENERATED_AEAD"
                ;;
            *)
                echo "error: unexpected cargo public-api arguments" >&2
                exit 91
                ;;
        esac
        ;;
    *)
        echo "error: unexpected cargo public-api arguments" >&2
        exit 91
        ;;
esac
EOF

cat >"$fixture/pinned-bin/rustc" <<'EOF'
#!/bin/sh
set -eu

test "$1" = --version
if test "${FAKE_RUSTC_FAILURE:-0}" = 1; then
    echo "simulated missing pinned rustc" >&2
    exit 70
fi
echo "rustc 1.90.0-nightly"
EOF

cp "$fixture/pinned-bin/rustc" "$fixture/other-pinned-bin/rustc"
chmod +x "$fixture/pinned-bin/cargo" "$fixture/pinned-bin/rustc" \
    "$fixture/other-pinned-bin/rustc"

cat >"$fixture/rustup-bin/rustup" <<'EOF'
#!/bin/sh
set -eu

test "${RUSTUP_TOOLCHAIN+x}" != x || {
    echo "error: ambient RUSTUP_TOOLCHAIN was not neutralized" >&2
    exit 90
}

case "$1" in
    which)
        test "$2" = --toolchain
        test "$3" = nightly-2026-05-23
        case "$4" in
            cargo)
                if test "${FAKE_WHICH_CARGO_FAILURE:-0}" = 1; then
                    echo "simulated unresolved pinned cargo" >&2
                    exit 73
                fi
                printf '%s\n' "$FAKE_PINNED_CARGO"
                ;;
            rustc)
                if test "${FAKE_WHICH_RUSTC_FAILURE:-0}" = 1; then
                    echo "simulated unresolved pinned rustc" >&2
                    exit 74
                fi
                printf '%s\n' "${FAKE_RESOLVED_RUSTC:-$FAKE_PINNED_RUSTC}"
                ;;
            *)
                echo "error: unexpected rustup which target" >&2
                exit 93
                ;;
        esac
        ;;
    run)
        test "$2" = nightly-2026-05-23
        shift 2
        test "$1" = "$FAKE_PINNED_CARGO" || test "$1" = "$FAKE_PINNED_RUSTC"
        command=$1
        shift
        exec "$command" "$@"
        ;;
    *)
        echo "error: unexpected rustup command" >&2
        exit 92
        ;;
esac
EOF
chmod +x "$fixture/rustup-bin/rustup"

run_checker() {
    case_name=$1
    ambient_dir=$2
    shift 2
    last_ambient_marker="$fixture/$case_name.ambient-cargo.marker"
    rm -f "$last_ambient_marker"
    env PATH="$fixture/rustup-bin:$ambient_dir:$original_path" \
        FAKE_PINNED_CARGO="$fixture/pinned-bin/cargo" \
        FAKE_PINNED_RUSTC="$fixture/pinned-bin/rustc" \
        FAKE_GENERATED="$fixture/generated.txt" \
        FAKE_GENERATED_AEAD="$fixture/generated-aead.txt" \
        FAKE_AMBIENT_CARGO_MARKER="$last_ambient_marker" TMPDIR="$fixture/tmp" \
        "$@" "$shell_under_test" "$fixture/ci/check-public-api.sh" \
        >"$fixture/$case_name.out" 2>"$fixture/$case_name.err"
}

# Exercise both a stable-like and an unpinned-nightly-like ambient cargo first.
if ! run_checker pristine-stable "$fixture/ambient-stable-bin" RUSTUP_TOOLCHAIN=invalid; then
    cat "$fixture/pristine-stable.err" >&2
    fail "pristine stable-like fixture comparator failed"
fi
assert_ambient_cargo_unused
assert_contains "$fixture/pristine-stable.out" "public API snapshot check passed"

if ! run_checker pristine-nightly "$fixture/ambient-nightly-bin"; then
    cat "$fixture/pristine-nightly.err" >&2
    fail "pristine unpinned-nightly-like fixture comparator failed"
fi
assert_ambient_cargo_unused
assert_contains "$fixture/pristine-nightly.out" "public API snapshot check passed"

if run_checker which-cargo "$fixture/ambient-stable-bin" FAKE_WHICH_CARGO_FAILURE=1; then
    fail "unresolved pinned cargo unexpectedly succeeded"
fi
assert_contains "$fixture/which-cargo.err" "simulated unresolved pinned cargo"
assert_contains "$fixture/which-cargo.err" "error: pinned cargo could not be resolved for toolchain: nightly-2026-05-23"

if run_checker which-rustc "$fixture/ambient-stable-bin" FAKE_WHICH_RUSTC_FAILURE=1; then
    fail "unresolved pinned rustc unexpectedly succeeded"
fi
assert_contains "$fixture/which-rustc.err" "simulated unresolved pinned rustc"
assert_contains "$fixture/which-rustc.err" "error: pinned rustc could not be resolved for toolchain: nightly-2026-05-23"

if run_checker mismatched-bin "$fixture/ambient-stable-bin" \
    FAKE_RESOLVED_RUSTC="$fixture/other-pinned-bin/rustc"; then
    fail "mismatched pinned toolchain bins unexpectedly succeeded"
fi
assert_contains "$fixture/mismatched-bin.err" "error: pinned cargo and rustc resolve to different toolchain bin directories"

if run_checker toolchain "$fixture/ambient-stable-bin" FAKE_RUSTC_FAILURE=1; then
    fail "missing pinned rustc unexpectedly succeeded"
fi
assert_contains "$fixture/toolchain.err" "simulated missing pinned rustc"
assert_contains "$fixture/toolchain.err" "error: pinned public API toolchain/rustc is unavailable: nightly-2026-05-23"

if run_checker unavailable "$fixture/ambient-stable-bin" FAKE_PUBLIC_API_UNAVAILABLE=1; then
    fail "missing cargo-public-api unexpectedly succeeded"
fi
assert_contains "$fixture/unavailable.err" "simulated missing cargo-public-api"
assert_contains "$fixture/unavailable.err" "error: cargo-public-api is unavailable for pinned toolchain: nightly-2026-05-23"

if run_checker version "$fixture/ambient-stable-bin" \
    FAKE_PUBLIC_API_VERSION="cargo-public-api 9.9.9"; then
    fail "wrong cargo-public-api version unexpectedly succeeded"
fi
assert_contains "$fixture/version.err" "error: cargo-public-api version mismatch: expected cargo-public-api 0.52.0, found cargo-public-api 9.9.9"
assert_ambient_cargo_unused

rm "$fixture/api/$snapshot_basename.txt"
if run_checker missing "$fixture/ambient-stable-bin"; then
    fail "missing snapshot unexpectedly succeeded"
fi
assert_contains "$fixture/missing.err" "error: public API snapshot is missing"
cp "$fixture/generated.txt" "$fixture/api/$snapshot_basename.txt"

printf 'intentional snapshot drift\n' >"$fixture/api/$snapshot_basename.txt"
if run_checker drift "$fixture/ambient-stable-bin"; then
    fail "snapshot drift unexpectedly succeeded"
fi
assert_contains "$fixture/drift.err" "error: public API differs from the $crate_version snapshot"
assert_contains "$fixture/drift.out" "-intentional snapshot drift"
cp "$fixture/generated.txt" "$fixture/api/$snapshot_basename.txt"

rm "$fixture/api/$snapshot_basename-aead.txt"
if run_checker missing-aead "$fixture/ambient-stable-bin"; then
    fail "missing AEAD snapshot unexpectedly succeeded"
fi
assert_contains "$fixture/missing-aead.err" "error: AEAD public API snapshot is missing"
cp "$fixture/generated-aead.txt" "$fixture/api/$snapshot_basename-aead.txt"

printf 'intentional aead snapshot drift\n' >"$fixture/api/$snapshot_basename-aead.txt"
if run_checker drift-aead "$fixture/ambient-stable-bin"; then
    fail "AEAD snapshot drift unexpectedly succeeded"
fi
assert_contains "$fixture/drift-aead.err" "error: AEAD public API differs from the $crate_version snapshot"
assert_contains "$fixture/drift-aead.out" "-intentional aead snapshot drift"
cp "$fixture/generated-aead.txt" "$fixture/api/$snapshot_basename-aead.txt"

mv "$fixture/Cargo.toml" "$fixture/manifest.bak"
if run_checker no-manifest "$fixture/ambient-stable-bin"; then
    fail "missing package manifest unexpectedly succeeded"
fi
assert_contains "$fixture/no-manifest.err" "error: package manifest is missing"
mv "$fixture/manifest.bak" "$fixture/Cargo.toml"

# Without a [package] version the snapshot identity is underivable; the checker
# must refuse rather than compare against a truncated path.
cat >"$fixture/Cargo.toml" <<EOF
[package]
name = "$crate_name"
edition = "2021"
EOF
if run_checker no-version "$fixture/ambient-stable-bin"; then
    fail "manifest without a version unexpectedly succeeded"
fi
assert_contains "$fixture/no-version.err" "error: could not read package version"

# The derived identity becomes a path component, so a value carrying a
# separator must be refused rather than resolving outside api/.
cat >"$fixture/Cargo.toml" <<EOF
[package]
name = "$crate_name"
version = "../../../etc/passwd"
edition = "2021"
EOF
if run_checker traversing-version "$fixture/ambient-stable-bin"; then
    fail "manifest with a path-separating version unexpectedly succeeded"
fi
assert_contains "$fixture/traversing-version.err" "error: could not read package version"

cat >"$fixture/Cargo.toml" <<EOF
[package]
name = "$crate_name"
version = "$crate_version"
edition = "2021"
EOF

if run_checker generator "$fixture/ambient-stable-bin" FAKE_GENERATOR_FAILURE=1; then
    fail "generator failure unexpectedly succeeded"
fi
assert_contains "$fixture/generator.err" "simulated public API generator failure"
assert_contains "$fixture/generator.err" "error: public API snapshot generator failed"
assert_empty_directory "$fixture/tmp"

echo "public API checker negative tests passed"
