#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
. "$repo_root/ci/tool-versions.sh"
unset RUSTUP_TOOLCHAIN
which_cargo_error=
which_rustc_error=
toolchain_error=
version_error=
generator_error=
generated=
generator_aead_error=
generated_aead=

fail() {
    echo "error: $*" >&2
    exit 1
}

# The snapshot filenames carry the crate's own identity, so derive it from
# Cargo.toml instead of restating it here: a version bump must not require a
# coupled edit in this script.
package_field() {
    field=$1
    awk -v field="$field" '
        /^\[package\][[:space:]]*$/ { in_package = 1; next }
        /^\[/ { in_package = 0 }
        in_package && $0 ~ "^[[:space:]]*" field "[[:space:]]*=" {
            line = $0
            sub("^[[:space:]]*" field "[[:space:]]*=[[:space:]]*\\\"", "", line)
            if (line !~ "\\\"[[:space:]]*$") exit 2
            sub("\\\"[[:space:]]*$", "", line)
            if (line == "" || line ~ /[\"\\\/]/) exit 2
            print line
            matches += 1
        }
        END { if (matches != 1) exit 2 }
    ' "$repo_root/Cargo.toml"
}

test -f "$repo_root/Cargo.toml" || fail "package manifest is missing"
package_name=$(package_field name) || fail "could not read package name"
package_version=$(package_field version) || fail "could not read package version"
snapshot="$repo_root/api/$package_name-$package_version.txt"
aead_snapshot="$repo_root/api/$package_name-$package_version-aead.txt"

cleanup() {
    rm -f -- "$which_cargo_error" "$which_rustc_error" "$toolchain_error" \
        "$version_error" "$generator_error" "$generated" \
        "$generator_aead_error" "$generated_aead"
}

trap cleanup EXIT HUP INT TERM

which_cargo_error=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-public-api-which-cargo.XXXXXX") || \
    fail "could not create a pinned cargo resolution diagnostic file"
if ! pinned_cargo=$(rustup which --toolchain "$PUBLIC_API_TOOLCHAIN" cargo 2>"$which_cargo_error"); then
    cat "$which_cargo_error" >&2
    fail "pinned cargo could not be resolved for toolchain: $PUBLIC_API_TOOLCHAIN"
fi
test -x "$pinned_cargo" || fail "resolved pinned cargo is not executable: $pinned_cargo"

which_rustc_error=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-public-api-which-rustc.XXXXXX") || \
    fail "could not create a pinned rustc resolution diagnostic file"
if ! pinned_rustc=$(rustup which --toolchain "$PUBLIC_API_TOOLCHAIN" rustc 2>"$which_rustc_error"); then
    cat "$which_rustc_error" >&2
    fail "pinned rustc could not be resolved for toolchain: $PUBLIC_API_TOOLCHAIN"
fi
test -x "$pinned_rustc" || fail "resolved pinned rustc is not executable: $pinned_rustc"

pinned_cargo_bin=$(CDPATH= cd -- "$(dirname -- "$pinned_cargo")" && pwd -P) || \
    fail "could not determine the resolved pinned cargo directory"
pinned_rustc_bin=$(CDPATH= cd -- "$(dirname -- "$pinned_rustc")" && pwd -P) || \
    fail "could not determine the resolved pinned rustc directory"
test "$pinned_cargo_bin" = "$pinned_rustc_bin" || \
    fail "pinned cargo and rustc resolve to different toolchain bin directories"

PATH="$pinned_cargo_bin:$PATH"
export PATH

toolchain_error=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-public-api-toolchain.XXXXXX") || \
    fail "could not create a public API toolchain diagnostic file"
if ! rustup run "$PUBLIC_API_TOOLCHAIN" "$pinned_rustc" --version > /dev/null 2>"$toolchain_error"; then
    cat "$toolchain_error" >&2
    fail "pinned public API toolchain/rustc is unavailable: $PUBLIC_API_TOOLCHAIN"
fi

version_error=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-public-api-version.XXXXXX") || \
    fail "could not create a public API version diagnostic file"
if ! actual_version=$(rustup run "$PUBLIC_API_TOOLCHAIN" \
    "$pinned_cargo" public-api --version 2>"$version_error"); then
    cat "$version_error" >&2
    fail "cargo-public-api is unavailable for pinned toolchain: $PUBLIC_API_TOOLCHAIN"
fi

expected_version="cargo-public-api $CARGO_PUBLIC_API_VERSION"
test "$actual_version" = "$expected_version" || \
    fail "cargo-public-api version mismatch: expected $expected_version, found ${actual_version:-missing cargo-public-api}"
test -f "$snapshot" || fail "public API snapshot is missing"
test -f "$aead_snapshot" || fail "AEAD public API snapshot is missing"

generated=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-public-api.XXXXXX") || \
    fail "could not create a public API snapshot temporary file"
generator_error=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-public-api-generator.XXXXXX") || \
    fail "could not create a public API generator diagnostic file"
if ! (cd "$repo_root" && rustup run "$PUBLIC_API_TOOLCHAIN" \
    "$pinned_cargo" public-api -ss --color=never) >"$generated" 2>"$generator_error"; then
    cat "$generator_error" >&2
    fail "public API snapshot generator failed"
fi

generated_aead=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-public-api-aead.XXXXXX") || \
    fail "could not create an AEAD public API snapshot temporary file"
generator_aead_error=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-public-api-generator-aead.XXXXXX") || \
    fail "could not create an AEAD public API generator diagnostic file"
if ! (cd "$repo_root" && rustup run "$PUBLIC_API_TOOLCHAIN" \
    "$pinned_cargo" public-api -ss --color=never --features aead) \
    >"$generated_aead" 2>"$generator_aead_error"; then
    cat "$generator_aead_error" >&2
    fail "AEAD public API snapshot generator failed"
fi

if ! cmp -s "$snapshot" "$generated"; then
    diff -u "$snapshot" "$generated" || true
    fail "public API differs from the $package_version snapshot"
fi
if ! cmp -s "$aead_snapshot" "$generated_aead"; then
    diff -u "$aead_snapshot" "$generated_aead" || true
    fail "AEAD public API differs from the $package_version snapshot"
fi

echo "public API snapshot check passed"
