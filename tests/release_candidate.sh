#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
script="$repo_root/ci/check-release-candidate.sh"
package_script="$repo_root/ci/check-cargo-package.sh"
contributing="$repo_root/CONTRIBUTING.md"

# The fixture documents must carry the versions the release command pins, so
# they are derived from the same file rather than hardcoded a second time.
. "$repo_root/ci/tool-versions.sh"

fail() {
    echo "error: $*" >&2
    exit 1
}

fixture=$(mktemp -d "${TMPDIR:-/tmp}/secure-envelope-release-test.XXXXXX") || \
    fail "could not create release-candidate self-test directory"
fixture=$(CDPATH='' cd -- "$fixture" && pwd -P) || \
    fail "could not resolve release-candidate self-test directory"
cleanup() {
    rm -rf -- "$fixture"
}
trap cleanup EXIT HUP INT TERM

test -x "$script" || fail "release-candidate command is missing or not executable"
test -x "$package_script" || fail "Cargo package command is missing or not executable"
# The backticks are literal Markdown from the documented requirement.
# shellcheck disable=SC2016
grep -F 'Python 3 available as `python3` is required by `tests/release_candidate.sh`' \
    "$contributing" >/dev/null || \
    fail "CONTRIBUTING.md does not document the release-manifest JSON parser requirement"
command -v python3 >/dev/null 2>&1 || \
    fail "Python 3 executable 'python3' is required to validate release-candidate manifest JSON"

if "$script" >/dev/null 2>&1; then
    fail "release-candidate command accepted missing arguments"
fi

if "$script" HEAD "$repo_root/release-output" >/dev/null 2>&1; then
    fail "release-candidate command accepted an output path inside the repository"
fi

if "$script" refs/heads/not-a-real-release-candidate "$fixture/not-created-by-test" \
    >/dev/null 2>&1; then
    fail "release-candidate command accepted an invalid commit"
fi

if "$package_script" >/dev/null 2>&1; then
    fail "Cargo package command accepted missing arguments"
fi
if "$package_script" relative-source "$fixture/package" >/dev/null 2>&1; then
    fail "Cargo package command accepted a relative source root"
fi
if "$package_script" "$fixture/missing-source" relative-output >/dev/null 2>&1; then
    fail "Cargo package command accepted a relative output directory"
fi
if "$package_script" "$fixture/missing-source" "$fixture/package" >/dev/null 2>&1; then
    fail "Cargo package command accepted a missing source root"
fi
mkdir "$fixture/source"
if "$package_script" "$fixture/source" "$fixture/package" >/dev/null 2>&1; then
    fail "Cargo package command accepted a source root without Cargo.toml"
fi
printf '%s\n' '[package]' 'name = "gmcrypto-envelope-lite"' 'version = "0.4.0"' \
    >"$fixture/source/Cargo.toml"
if "$package_script" "$fixture/source" "$fixture/package" >/dev/null 2>&1; then
    fail "Cargo package command accepted a source root without a boundary scanner"
fi
mkdir "$fixture/source/ci" "$fixture/existing-output"
printf '%s\n' '#!/bin/sh' 'exit 0' >"$fixture/source/ci/check-open-source-boundary.sh"
chmod +x "$fixture/source/ci/check-open-source-boundary.sh"
if "$package_script" "$fixture/source" "$fixture/existing-output" >/dev/null 2>&1; then
    fail "Cargo package command accepted an existing output directory"
fi

real_grep=$(command -v grep)
mkdir "$fixture/fake-bin"
cat >"$fixture/fake-bin/grep" <<'EOF'
#!/bin/sh
if test ! -e "$FAKE_GREP_CALLED"; then
    : >"$FAKE_GREP_CALLED"
    exit 2
fi
exec "$REAL_GREP" "$@"
EOF
cat >"$fixture/fake-bin/cargo" <<'EOF'
#!/bin/sh
if test "$#" -eq 3 && test "$1" = package && test "$2" = --locked && test "$3" = --list; then
    printf '%s\n' \
        LICENSE-APACHE LICENSE-MIT README.md SECURITY.md SECURITY_MODEL.md docs/api-stability.md \
        docs/security/engineering-evidence.md \
        docs/security/cryptographic-dependencies.md src/lib.rs \
        examples/build_request.rs examples/open_response.rs
    exit 0
fi
: >"$FAKE_PACKAGE_BUILD_CALLED"
exit 88
EOF
cat >"$fixture/fake-bin/rustc" <<'EOF'
#!/bin/sh
test "$1" = --version
printf '%s\n' 'rustc fixture'
EOF
cat >"$fixture/fake-bin/rustup" <<'EOF'
#!/bin/sh
set -eu
case "$1" in
    which)
        test "$2" = --toolchain && test "$3" = stable
        case "$4" in
            cargo) printf '%s\n' "$FAKE_SCANNER_CARGO" ;;
            rustc) printf '%s\n' "$FAKE_SCANNER_RUSTC" ;;
            *) exit 91 ;;
        esac
        ;;
    run) shift 2; exec "$@" ;;
    *) exit 92 ;;
esac
EOF
chmod +x "$fixture/fake-bin/grep" "$fixture/fake-bin/cargo" \
    "$fixture/fake-bin/rustc" "$fixture/fake-bin/rustup"
if PATH="$fixture/fake-bin:$PATH" REAL_GREP="$real_grep" \
    FAKE_GREP_CALLED="$fixture/grep-called" \
    FAKE_PACKAGE_BUILD_CALLED="$fixture/package-build-called" \
    FAKE_SCANNER_CARGO="$fixture/fake-bin/cargo" \
    FAKE_SCANNER_RUSTC="$fixture/fake-bin/rustc" \
    "$package_script" "$fixture/source" "$fixture/grep-error-output" >/dev/null 2>&1; then
    fail "Cargo package command accepted a package-list scanner failure"
fi
test ! -e "$fixture/package-build-called" || \
    fail "Cargo package command continued after a package-list scanner failure"

mkdir "$fixture/tool-resolution" "$fixture/tool-resolution/rustup-bin" \
    "$fixture/tool-resolution/ambient-bin" "$fixture/tool-resolution/pinned-bin"
cat >"$fixture/tool-resolution/rustup-bin/rustup" <<'EOF'
#!/bin/sh
set -eu
case "$1" in
    which)
        test "$2" = --toolchain && test "$3" = stable
        case "$4" in
            cargo) printf '%s\n' "$FAKE_PINNED_CARGO" ;;
            rustc) printf '%s\n' "$FAKE_PINNED_RUSTC" ;;
            *) exit 91 ;;
        esac
        ;;
    run)
        test "$2" = stable
        shift 2
        exec "$@"
        ;;
    *) exit 92 ;;
esac
EOF
cat >"$fixture/tool-resolution/ambient-bin/cargo" <<'EOF'
#!/bin/sh
: >"$FAKE_AMBIENT_CARGO_MARKER"
exit 89
EOF
cat >"$fixture/tool-resolution/pinned-bin/cargo" <<'EOF'
#!/bin/sh
: >"$FAKE_PINNED_CARGO_MARKER"
exit 88
EOF
cat >"$fixture/tool-resolution/pinned-bin/rustc" <<'EOF'
#!/bin/sh
test "$1" = --version
printf '%s\n' 'rustc 1.90.0 (fixture)'
EOF
chmod +x "$fixture/tool-resolution/rustup-bin/rustup" \
    "$fixture/tool-resolution/ambient-bin/cargo" \
    "$fixture/tool-resolution/pinned-bin/cargo" \
    "$fixture/tool-resolution/pinned-bin/rustc"

mkdir "$fixture/tool-source" "$fixture/tool-source/ci"
printf '%s\n' '[package]' 'name = "gmcrypto-envelope-lite"' 'version = "0.4.0"' \
    >"$fixture/tool-source/Cargo.toml"
printf '%s\n' '#!/bin/sh' 'exit 0' >"$fixture/tool-source/ci/check-open-source-boundary.sh"
chmod +x "$fixture/tool-source/ci/check-open-source-boundary.sh"
if PATH="$fixture/tool-resolution/rustup-bin:$fixture/tool-resolution/ambient-bin:$PATH" \
    FAKE_PINNED_CARGO="$fixture/tool-resolution/pinned-bin/cargo" \
    FAKE_PINNED_RUSTC="$fixture/tool-resolution/pinned-bin/rustc" \
    FAKE_AMBIENT_CARGO_MARKER="$fixture/ambient-cargo-called" \
    FAKE_PINNED_CARGO_MARKER="$fixture/pinned-cargo-called" \
    "$package_script" "$fixture/tool-source" "$fixture/tool-output" >/dev/null 2>&1; then
    fail "Cargo package command accepted a simulated pinned Cargo failure"
fi
test ! -e "$fixture/ambient-cargo-called" || \
    fail "Cargo package command executed an ambient Cargo shim"
test -e "$fixture/pinned-cargo-called" || \
    fail "Cargo package command did not execute the resolved pinned Cargo"

mkdir "$fixture/wrong-identity" "$fixture/wrong-identity/ci"
printf '%s\n' '[package]' 'name = "different-package"' 'version = "9.9.9"' \
    >"$fixture/wrong-identity/Cargo.toml"
cp "$fixture/tool-source/ci/check-open-source-boundary.sh" "$fixture/wrong-identity/ci/"
rm -f "$fixture/pinned-cargo-called"
if PATH="$fixture/tool-resolution/rustup-bin:$fixture/tool-resolution/ambient-bin:$PATH" \
    FAKE_PINNED_CARGO="$fixture/tool-resolution/pinned-bin/cargo" \
    FAKE_PINNED_RUSTC="$fixture/tool-resolution/pinned-bin/rustc" \
    FAKE_AMBIENT_CARGO_MARKER="$fixture/ambient-cargo-called" \
    FAKE_PINNED_CARGO_MARKER="$fixture/pinned-cargo-called" \
    "$package_script" "$fixture/wrong-identity" "$fixture/identity-output" >/dev/null 2>&1; then
    fail "Cargo package command accepted mismatched package identity"
fi
test ! -e "$fixture/pinned-cargo-called" || \
    fail "Cargo package command invoked Cargo before rejecting package identity"

mkdir "$fixture/symlink-scanner-source" "$fixture/symlink-scanner-source/ci"
cp "$fixture/tool-source/Cargo.toml" "$fixture/symlink-scanner-source/Cargo.toml"
if ln -s /bin/true "$fixture/symlink-scanner-source/ci/check-open-source-boundary.sh" \
    2>/dev/null && test -L "$fixture/symlink-scanner-source/ci/check-open-source-boundary.sh"; then
    rm -f "$fixture/pinned-cargo-called"
    if PATH="$fixture/tool-resolution/rustup-bin:$fixture/tool-resolution/ambient-bin:$PATH" \
        FAKE_PINNED_CARGO="$fixture/tool-resolution/pinned-bin/cargo" \
        FAKE_PINNED_RUSTC="$fixture/tool-resolution/pinned-bin/rustc" \
        FAKE_AMBIENT_CARGO_MARKER="$fixture/ambient-cargo-called" \
        FAKE_PINNED_CARGO_MARKER="$fixture/pinned-cargo-called" \
        "$package_script" "$fixture/symlink-scanner-source" "$fixture/symlink-output" \
        >/dev/null 2>&1; then
        fail "Cargo package command accepted a symlink boundary scanner"
    fi
    test ! -e "$fixture/pinned-cargo-called" || \
        fail "Cargo package command invoked Cargo with a symlink boundary scanner"
else
    rm -f "$fixture/symlink-scanner-source/ci/check-open-source-boundary.sh"
fi

cat >"$fixture/tool-resolution/pinned-bin/cargo" <<'EOF'
#!/bin/sh
test -d "$FAKE_RESERVED_OUTPUT" || : >"$FAKE_MISSING_RESERVATION"
exit 88
EOF
chmod +x "$fixture/tool-resolution/pinned-bin/cargo"
if PATH="$fixture/tool-resolution/rustup-bin:$fixture/tool-resolution/ambient-bin:$PATH" \
    FAKE_PINNED_CARGO="$fixture/tool-resolution/pinned-bin/cargo" \
    FAKE_PINNED_RUSTC="$fixture/tool-resolution/pinned-bin/rustc" \
    FAKE_AMBIENT_CARGO_MARKER="$fixture/ambient-cargo-called" \
    FAKE_RESERVED_OUTPUT="$fixture/reserved-output" \
    FAKE_MISSING_RESERVATION="$fixture/missing-reservation" \
    "$package_script" "$fixture/tool-source" "$fixture/reserved-output" >/dev/null 2>&1; then
    fail "Cargo package command accepted a simulated package failure"
fi
test ! -e "$fixture/missing-reservation" || \
    fail "Cargo package command did not reserve output before package work"
test ! -e "$fixture/reserved-output" || \
    fail "Cargo package command did not clean its unchanged reservation"

cat >"$fixture/tool-resolution/pinned-bin/cargo" <<'EOF'
#!/bin/sh
rmdir "$FAKE_RESERVED_OUTPUT"
mkdir "$FAKE_RESERVED_OUTPUT"
printf '%s\n' 'replacement owned by another process' >"$FAKE_RESERVED_OUTPUT/user-file"
exit 88
EOF
chmod +x "$fixture/tool-resolution/pinned-bin/cargo"
if PATH="$fixture/tool-resolution/rustup-bin:$fixture/tool-resolution/ambient-bin:$PATH" \
    FAKE_PINNED_CARGO="$fixture/tool-resolution/pinned-bin/cargo" \
    FAKE_PINNED_RUSTC="$fixture/tool-resolution/pinned-bin/rustc" \
    FAKE_AMBIENT_CARGO_MARKER="$fixture/ambient-cargo-called" \
    FAKE_RESERVED_OUTPUT="$fixture/replaced-output" \
    "$package_script" "$fixture/tool-source" "$fixture/replaced-output" >/dev/null 2>&1; then
    fail "Cargo package command accepted a replaced output reservation"
fi
test -f "$fixture/replaced-output/user-file" || \
    fail "Cargo package command removed a replacement output directory"

mkdir "$fixture/archive-fixtures" "$fixture/archive-fixtures/valid" \
    "$fixture/archive-fixtures/other"
mkdir -p "$fixture/archive-fixtures/valid/gmcrypto-envelope-lite-0.4.0/src"
printf '%s\n' 'public package content' \
    >"$fixture/archive-fixtures/valid/gmcrypto-envelope-lite-0.4.0/src/lib.rs"
printf '%s\n' '[package]' 'name = "gmcrypto-envelope-lite"' 'version = "0.4.0"' \
    >"$fixture/archive-fixtures/valid/gmcrypto-envelope-lite-0.4.0/Cargo.toml"
tar -czf "$fixture/archive-fixtures/valid.crate" \
    -C "$fixture/archive-fixtures/valid" gmcrypto-envelope-lite-0.4.0
cp -R "$fixture/archive-fixtures/valid" "$fixture/archive-fixtures/internal-identity"
printf '%s\n' '[package]' 'name = "different-package"' 'version = "9.9.9"' \
    >"$fixture/archive-fixtures/internal-identity/gmcrypto-envelope-lite-0.4.0/Cargo.toml"
tar -czf "$fixture/archive-fixtures/internal-identity.crate" \
    -C "$fixture/archive-fixtures/internal-identity" gmcrypto-envelope-lite-0.4.0
mkdir -p "$fixture/archive-fixtures/other/gmcrypto-envelope-lite-0.4.0" \
    "$fixture/archive-fixtures/other/second-root"
printf '%s\n' valid >"$fixture/archive-fixtures/other/gmcrypto-envelope-lite-0.4.0/file"
printf '%s\n' invalid >"$fixture/archive-fixtures/other/second-root/file"
tar -czf "$fixture/archive-fixtures/multi-root.crate" \
    -C "$fixture/archive-fixtures/other" gmcrypto-envelope-lite-0.4.0 second-root
mkdir -p "$fixture/archive-fixtures/special/gmcrypto-envelope-lite-0.4.0"
printf '%s\n' target >"$fixture/archive-fixtures/special/gmcrypto-envelope-lite-0.4.0/target"
special_archive_supported=0
if ln -s target "$fixture/archive-fixtures/special/gmcrypto-envelope-lite-0.4.0/link" \
    2>/dev/null && test -L "$fixture/archive-fixtures/special/gmcrypto-envelope-lite-0.4.0/link"; then
    tar -czf "$fixture/archive-fixtures/special.crate" \
        -C "$fixture/archive-fixtures/special" gmcrypto-envelope-lite-0.4.0
    special_archive_supported=1
else
    rm -f "$fixture/archive-fixtures/special/gmcrypto-envelope-lite-0.4.0/link"
fi
mkdir -p "$fixture/archive-fixtures/wrong/wrong-root"
printf '%s\n' invalid >"$fixture/archive-fixtures/wrong/wrong-root/file"
tar -czf "$fixture/archive-fixtures/wrong-root.crate" \
    -C "$fixture/archive-fixtures/wrong" wrong-root

cat >"$fixture/tool-resolution/pinned-bin/cargo" <<'EOF'
#!/bin/sh
set -eu
test "$(command -v cargo)" = "$FAKE_PINNED_CARGO" || {
    echo "nested Cargo was not pinned" >&2
    exit 81
}
test "$(command -v rustc)" = "$FAKE_PINNED_RUSTC" || {
    echo "nested rustc was not pinned" >&2
    exit 82
}
test "$1" = package && test "$2" = --locked || {
    echo "unexpected fake Cargo arguments: $*" >&2
    exit 80
}
case "${3-}" in
    --list)
        printf '%s\n' \
            LICENSE-APACHE LICENSE-MIT README.md SECURITY.md SECURITY_MODEL.md docs/api-stability.md \
            docs/security/engineering-evidence.md \
            docs/security/cryptographic-dependencies.md src/lib.rs \
            examples/build_request.rs examples/open_response.rs
        ;;
    '')
        test "${FAKE_PACKAGE_CASE:-valid}" != build-failure || exit 88
        mkdir -p "$CARGO_TARGET_DIR/package"
        output_name=${FAKE_CRATE_NAME:-gmcrypto-envelope-lite-0.4.0.crate}
        cp "$FAKE_CRATE" "$CARGO_TARGET_DIR/package/$output_name"
        ;;
    *) echo "unexpected third fake Cargo argument: ${3-}" >&2; exit 83 ;;
esac
EOF
chmod +x "$fixture/tool-resolution/pinned-bin/cargo"

run_fake_package() {
    case_name=$1
    crate_fixture=$2
    shift 2
    fake_output="$fixture/fake-package-$case_name"
    rm -rf "$fake_output"
    env PATH="$fixture/tool-resolution/rustup-bin:$fixture/tool-resolution/ambient-bin:$PATH" \
        FAKE_PINNED_CARGO="$fixture/tool-resolution/pinned-bin/cargo" \
        FAKE_PINNED_RUSTC="$fixture/tool-resolution/pinned-bin/rustc" \
        FAKE_AMBIENT_CARGO_MARKER="$fixture/archive-ambient-cargo-called" \
        FAKE_CRATE="$crate_fixture" "$@" \
        "$package_script" "$fixture/tool-source" "$fake_output" \
        >"$fixture/fake-package-$case_name.out" \
        2>"$fixture/fake-package-$case_name.err"
}

if ! run_fake_package valid "$fixture/archive-fixtures/valid.crate"; then
    sed -n '1,20p' "$fixture/fake-package-valid.err" >&2
    fail "Cargo package command rejected a valid single-root archive fixture"
fi
test -f "$fixture/fake-package-valid/gmcrypto-envelope-lite-0.4.0.crate" || \
    fail "Cargo package command did not produce the exact expected crate"
test "$(find "$fixture/fake-package-valid" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d '[:space:]')" -eq 1 || \
    fail "Cargo package command produced an unexpected artifact set"
test ! -e "$fixture/archive-ambient-cargo-called" || \
    fail "valid package fixture executed ambient Cargo"

if run_fake_package build-failure "$fixture/archive-fixtures/valid.crate" \
    FAKE_PACKAGE_CASE=build-failure; then
    fail "Cargo package command accepted a package-build failure"
fi
test ! -e "$fixture/fake-package-build-failure" || \
    fail "package-build failure left its output reservation"

for archive_case in multi-root wrong-root; do
    if run_fake_package "$archive_case" "$fixture/archive-fixtures/$archive_case.crate"; then
        fail "Cargo package command accepted $archive_case archive"
    fi
    test ! -e "$fixture/fake-package-$archive_case" || \
        fail "$archive_case archive failure left its output reservation"
done
if test "$special_archive_supported" -eq 1; then
    if run_fake_package special "$fixture/archive-fixtures/special.crate"; then
        fail "Cargo package command accepted special-entry archive"
    fi
    test ! -e "$fixture/fake-package-special" || \
        fail "special-entry archive failure left its output reservation"
fi

if run_fake_package crate-name "$fixture/archive-fixtures/valid.crate" \
    FAKE_CRATE_NAME=different-package-0.4.0.crate; then
    fail "Cargo package command accepted a mismatched crate filename"
fi
test ! -e "$fixture/fake-package-crate-name" || \
    fail "crate-name mismatch left its output reservation"
if run_fake_package internal-identity "$fixture/archive-fixtures/internal-identity.crate"; then
    fail "Cargo package command accepted mismatched in-crate package metadata"
fi
test ! -e "$fixture/fake-package-internal-identity" || \
    fail "in-crate identity mismatch left its output reservation"

rc_repo="$fixture/rc-repository"
rc_tools="$fixture/rc-tools"
mkdir -p "$rc_repo/ci" "$rc_repo/tests" "$rc_repo/docs/security" \
    "$rc_repo/docs" "$rc_repo/src" "$rc_repo/examples" \
    "$rc_tools/rustup-bin" "$rc_tools/ambient-bin" \
    "$rc_tools/stable-bin" "$rc_tools/msrv-bin" "$rc_tools/nightly-bin"
cp "$repo_root/ci/check-release-candidate.sh" "$repo_root/ci/check-cargo-package.sh" \
    "$repo_root/ci/tool-versions.sh" "$rc_repo/ci/"
printf '%s\n' \
    '[package]' \
    'name = "gmcrypto-envelope-lite"' \
    'version = "0.4.0"' \
    'edition = "2024"' \
    'publish = false' \
    >"$rc_repo/Cargo.toml"
printf '%s\n' '# fixture lock' >"$rc_repo/Cargo.lock"
printf '%s\n' license >"$rc_repo/LICENSE-APACHE"
printf '%s\n' license >"$rc_repo/LICENSE-MIT"
printf '%s\n' readme >"$rc_repo/README.md"
printf '%s\n' security >"$rc_repo/SECURITY.md"
printf '%s\n' '# Security Model' "**Model version:** $SECURITY_MODEL_VERSION" \
    >"$rc_repo/SECURITY_MODEL.md"
printf '%s\n' '# Release Checklist' "**Template version:** $RELEASE_CHECKLIST_VERSION" \
    >"$rc_repo/RELEASE_CHECKLIST.md"
printf '%s\n' '# API Stability' "**Policy version:** $API_SNAPSHOT_VERSION" \
    >"$rc_repo/docs/api-stability.md"
printf '%s\n' '# Engineering Evidence' "**Evidence version:** $ENGINEERING_EVIDENCE_VERSION" \
    >"$rc_repo/docs/security/engineering-evidence.md"
printf '%s\n' '# Cryptographic Dependencies' "**Inventory version:** $CRYPTO_INVENTORY_VERSION" \
    >"$rc_repo/docs/security/cryptographic-dependencies.md"
printf '%s\n' 'pub fn fixture() {}' >"$rc_repo/src/lib.rs"
printf '%s\n' 'fn main() {}' >"$rc_repo/examples/build_request.rs"
printf '%s\n' 'fn main() {}' >"$rc_repo/examples/open_response.rs"

for stub in check-public-api.sh check-crypto-inventory.sh fuzz-smoke.sh; do
    printf '%s\n' '#!/bin/sh' 'exit 0' >"$rc_repo/ci/$stub"
done
cat >"$rc_repo/ci/check-crypto-inventory.sh" <<'EOF'
#!/bin/sh
test "$(command -v cargo)" = "$FAKE_STABLE_CARGO"
EOF
printf '%s\n' '#!/bin/sh' 'exit 0' >"$rc_repo/ci/check-open-source-boundary.sh"
printf '%s\n' '#!/bin/sh' 'exit 0' >"$rc_repo/tests/release_candidate.sh"
printf '%s\n' '#!/bin/sh' 'exit 0' >"$rc_repo/tests/open_source_boundary.sh"
chmod +x "$rc_repo/ci/"*.sh "$rc_repo/tests/"*.sh

cat >"$rc_tools/rustup-bin/rustup" <<'EOF'
#!/bin/sh
set -eu
case "$1" in
    which)
        test "$2" = --toolchain
        toolchain=$3
        tool=$4
        case "$toolchain:$tool" in
            stable:cargo) printf '%s\n' "$FAKE_STABLE_CARGO" ;;
            stable:rustc) printf '%s\n' "$FAKE_STABLE_RUSTC" ;;
            1.85.0:cargo) printf '%s\n' "$FAKE_MSRV_CARGO" ;;
            1.85.0:rustc) printf '%s\n' "$FAKE_MSRV_RUSTC" ;;
            nightly-2026-05-23:cargo) printf '%s\n' "$FAKE_NIGHTLY_CARGO" ;;
            nightly-2026-05-23:rustc) printf '%s\n' "$FAKE_NIGHTLY_RUSTC" ;;
            *) exit 91 ;;
        esac
        ;;
    run)
        shift 2
        exec "$@"
        ;;
    *) exit 92 ;;
esac
EOF
cat >"$rc_tools/ambient-bin/cargo" <<'EOF'
#!/bin/sh
: >"$FAKE_RC_AMBIENT_CARGO_MARKER"
exit 89
EOF
cat >"$rc_tools/stable-bin/cargo" <<'EOF'
#!/bin/sh
set -eu
test "$(command -v cargo)" = "$FAKE_STABLE_CARGO" || exit 81
test "$(command -v rustc)" = "$FAKE_STABLE_RUSTC" || exit 82

record_gate() {
    printf '%s\n' "stable|$*" >>"$FAKE_RC_CARGO_LOG"
}

if test "$1" = fmt && test "${FAKE_RC_STATE_MUTATION:-}" != "" && \
    test ! -e "$FAKE_RC_STATE_MUTATION_MARKER"; then
    : >"$FAKE_RC_STATE_MUTATION_MARKER"
    case "$FAKE_RC_STATE_MUTATION" in
        tracked) printf '%s\n' 'changed during repository gate' >>"$FAKE_RC_REPO/README.md" ;;
        head) git -C "$FAKE_RC_REPO" commit --allow-empty -qm simulated-head-move ;;
        *) exit 86 ;;
    esac
fi
if test "${FAKE_REPLACE_RC_OUTPUT:-0}" = 1 && test ! -e "$FAKE_RC_REPLACED_MARKER"; then
    : >"$FAKE_RC_REPLACED_MARKER"
    if test -d "$FAKE_RC_OUTPUT"; then
        find "$FAKE_RC_OUTPUT" -mindepth 1 -maxdepth 1 -type f -exec rm -f {} \;
        rmdir "$FAKE_RC_OUTPUT"
    else
        : >"$FAKE_MISSING_RC_RESERVATION"
    fi
    mkdir "$FAKE_RC_OUTPUT"
    printf '%s\n' 'replacement owned by another process' >"$FAKE_RC_OUTPUT/user-file"
    exit 88
fi
case "$*" in
    'deny --version')
        printf '%s\n' 'cargo-deny 0.20.2'
        ;;
    'deny check')
        ;;
    'fmt --all -- --check')
        record_gate "$@"
        test "${FAKE_RC_GATE_FAILURE:-0}" != 1 || exit 87
        ;;
    'clippy --all-targets --locked -- -D warnings' | \
        'clippy --all-targets --locked --features aead -- -D warnings' | \
        'test --all-targets --locked' | \
        'test --all-targets --locked --features aead' | \
        'test --doc --locked' | \
        'test --doc --locked --features aead')
        record_gate "$@"
        ;;
    'doc --locked --no-deps' | 'doc --locked --no-deps --features aead')
        test "${RUSTDOCFLAGS-}" = '-D missing-docs -D warnings' || {
            echo "unexpected RUSTDOCFLAGS for Cargo doc: ${RUSTDOCFLAGS-}" >&2
            exit 84
        }
        record_gate "$@"
        ;;
    'package --locked --list')
        printf '%s\n' \
            LICENSE-APACHE LICENSE-MIT README.md SECURITY.md SECURITY_MODEL.md docs/api-stability.md \
            docs/security/engineering-evidence.md \
            docs/security/cryptographic-dependencies.md src/lib.rs \
            examples/build_request.rs examples/open_response.rs
        ;;
    'package --locked')
        mkdir -p "$CARGO_TARGET_DIR/package"
        cp "$FAKE_RC_CRATE" \
            "$CARGO_TARGET_DIR/package/gmcrypto-envelope-lite-0.4.0.crate"
        ;;
    *) echo "unexpected stable Cargo arguments: $*" >&2; exit 83 ;;
esac
EOF
cat >"$rc_tools/msrv-bin/cargo" <<'EOF'
#!/bin/sh
set -eu
test "$(command -v cargo)" = "$FAKE_MSRV_CARGO" || exit 81
test "$(command -v rustc)" = "$FAKE_MSRV_RUSTC" || exit 82
case "$*" in
    'test --all-targets --locked' | 'test --all-targets --locked --features aead')
        printf '%s\n' "msrv|$*" >>"$FAKE_RC_CARGO_LOG"
        ;;
    *) echo "unexpected MSRV Cargo arguments: $*" >&2; exit 83 ;;
esac
EOF
cat >"$rc_tools/nightly-bin/cargo" <<'EOF'
#!/bin/sh
set -eu
test "$(command -v cargo)" = "$FAKE_NIGHTLY_CARGO" || exit 81
test "$(command -v rustc)" = "$FAKE_NIGHTLY_RUSTC" || exit 82
case "$1:$2" in
    public-api:--version) printf '%s\n' 'cargo-public-api 0.52.0' ;;
    fuzz:--version) printf '%s\n' 'cargo-fuzz 0.13.2' ;;
    *) echo "unexpected nightly Cargo arguments: $*" >&2; exit 83 ;;
esac
EOF
cat >"$rc_tools/stable-bin/rustc" <<'EOF'
#!/bin/sh
test "$1" = --version
printf '%s\n' 'rustc 1.90.0 (fixture stable)'
EOF
cat >"$rc_tools/msrv-bin/rustc" <<'EOF'
#!/bin/sh
test "$1" = --version
printf '%s\n' 'rustc 1.85.0 (fixture msrv)'
EOF
cat >"$rc_tools/nightly-bin/rustc" <<'EOF'
#!/bin/sh
test "$1" = --version
printf '%s\n' 'rustc 1.90.0-nightly (fixture nightly)'
EOF
chmod +x "$rc_tools/rustup-bin/rustup" "$rc_tools/ambient-bin/cargo" \
    "$rc_tools/stable-bin/cargo" "$rc_tools/stable-bin/rustc" \
    "$rc_tools/msrv-bin/cargo" "$rc_tools/msrv-bin/rustc" \
    "$rc_tools/nightly-bin/cargo" "$rc_tools/nightly-bin/rustc"

(cd "$rc_repo" && git init -q && git config user.name fixture && \
    git config user.email fixture@example.invalid && git add . && \
    git commit -qm fixture)
rc_commit=$(git -C "$rc_repo" rev-parse HEAD)

run_fake_rc() {
    output=$1
    shift
    env PATH="$rc_tools/rustup-bin:$rc_tools/ambient-bin:$PATH" \
        FAKE_STABLE_CARGO="$rc_tools/stable-bin/cargo" \
        FAKE_STABLE_RUSTC="$rc_tools/stable-bin/rustc" \
        FAKE_MSRV_CARGO="$rc_tools/msrv-bin/cargo" \
        FAKE_MSRV_RUSTC="$rc_tools/msrv-bin/rustc" \
        FAKE_NIGHTLY_CARGO="$rc_tools/nightly-bin/cargo" \
        FAKE_NIGHTLY_RUSTC="$rc_tools/nightly-bin/rustc" \
        FAKE_RC_CRATE="$fixture/archive-fixtures/valid.crate" \
        FAKE_RC_AMBIENT_CARGO_MARKER="$fixture/rc-ambient-cargo-called" \
        FAKE_RC_OUTPUT="$output" \
        FAKE_RC_REPLACED_MARKER="$fixture/rc-replaced-marker" \
        FAKE_MISSING_RC_RESERVATION="$fixture/missing-rc-reservation" \
        FAKE_RC_REPO="$rc_repo" \
        FAKE_RC_STATE_MUTATION_MARKER="$fixture/rc-state-mutation-marker" \
        FAKE_RC_CARGO_LOG="$fixture/rc-cargo.log" \
        "$@" "$rc_repo/ci/check-release-candidate.sh" "$rc_commit" "$output" \
        >"$fixture/fake-rc.out" 2>"$fixture/fake-rc.err"
}

rc_output="$fixture/rc-output"
: >"$fixture/rc-cargo.log"
if ! run_fake_rc "$rc_output"; then
    sed -n '1,40p' "$fixture/fake-rc.err" >&2
    fail "release-candidate command rejected the complete fake RC fixture"
fi
test ! -e "$fixture/rc-ambient-cargo-called" || \
    fail "release-candidate command executed an ambient Cargo shim"
cat >"$fixture/expected-rc-cargo.log" <<'EOF'
stable|fmt --all -- --check
stable|clippy --all-targets --locked -- -D warnings
stable|clippy --all-targets --locked --features aead -- -D warnings
stable|test --all-targets --locked
stable|test --all-targets --locked --features aead
stable|test --doc --locked
stable|test --doc --locked --features aead
stable|doc --locked --no-deps
stable|doc --locked --no-deps --features aead
msrv|test --all-targets --locked
msrv|test --all-targets --locked --features aead
EOF
if ! cmp -s "$fixture/expected-rc-cargo.log" "$fixture/rc-cargo.log"; then
    diff -u "$fixture/expected-rc-cargo.log" "$fixture/rc-cargo.log" >&2 || true
    fail "release-candidate command did not execute the exact default/AEAD Cargo gate matrix"
fi
for artifact in \
    gmcrypto-envelope-lite-0.4.0-source.tar.gz \
    gmcrypto-envelope-lite-0.4.0.crate rc-manifest.json SHA256SUMS
do
    test -f "$rc_output/$artifact" && test ! -L "$rc_output/$artifact" || \
        fail "fake RC artifact is missing or not regular: $artifact"
done
test "$(find "$rc_output" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d '[:space:]')" -eq 4 || \
    fail "fake RC output does not contain exactly four artifacts"

python3 - \
    "$rc_output/rc-manifest.json" \
    "$rc_commit" \
    "$rc_output/gmcrypto-envelope-lite-0.4.0-source.tar.gz" \
    "$rc_output/gmcrypto-envelope-lite-0.4.0.crate" \
    "$rc_repo/Cargo.lock" <<'PY' || fail "fake RC manifest identity does not match its artifacts"
import hashlib
import json
import os
import sys

manifest_path, expected_commit, source_path, crate_path, lock_path = sys.argv[1:]

with open(manifest_path, encoding="utf-8") as manifest_file:
    manifest = json.load(manifest_file)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as artifact_file:
        for chunk in iter(lambda: artifact_file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition, message):
    if not condition:
        raise SystemExit(message)


require(manifest.get("package") == "gmcrypto-envelope-lite", "package mismatch")
require(manifest.get("version") == "0.4.0", "version mismatch")
require(manifest.get("commit") == expected_commit, "commit mismatch")

source = manifest.get("source_archive", {})
require(source.get("file") == os.path.basename(source_path), "source filename mismatch")
require(source.get("bytes") == os.path.getsize(source_path), "source byte length mismatch")
require(source.get("sha256") == sha256(source_path), "source SHA-256 mismatch")

crate = manifest.get("cargo_package", {})
require(crate.get("file") == os.path.basename(crate_path), "crate filename mismatch")
require(crate.get("bytes") == os.path.getsize(crate_path), "crate byte length mismatch")
require(crate.get("sha256") == sha256(crate_path), "crate SHA-256 mismatch")
require(manifest.get("cargo_lock_sha256") == sha256(lock_path), "Cargo.lock SHA-256 mismatch")
PY
test "$(wc -l <"$rc_output/SHA256SUMS" | tr -d '[:space:]')" -eq 3 || \
    fail "fake RC checksum manifest does not have exactly three entries"
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$rc_output" && sha256sum -c SHA256SUMS >/dev/null) || \
        fail "fake RC checksums are inconsistent"
else
    (cd "$rc_output" && shasum -a 256 -c SHA256SUMS >/dev/null) || \
        fail "fake RC checksums are inconsistent"
fi
gate_failure_rc_output="$fixture/gate-failure-rc-output"
if run_fake_rc "$gate_failure_rc_output" FAKE_RC_GATE_FAILURE=1; then
    fail "release-candidate command accepted a simulated repository-gate failure"
fi
test ! -e "$gate_failure_rc_output" || \
    fail "repository-gate failure left its output reservation"

preexisting_rc_output="$fixture/preexisting-rc-output"
mkdir "$preexisting_rc_output"
printf '%s\n' 'preexisting user content' >"$preexisting_rc_output/user-file"
if run_fake_rc "$preexisting_rc_output"; then
    fail "release-candidate command accepted a preexisting output directory"
fi
grep -F 'preexisting user content' "$preexisting_rc_output/user-file" >/dev/null || \
    fail "release-candidate command changed a preexisting output directory"

cp "$rc_repo/Cargo.toml" "$fixture/rc-Cargo.toml"
sed 's/name = "gmcrypto-envelope-lite"/name = "different-package"/' \
    "$fixture/rc-Cargo.toml" >"$rc_repo/Cargo.toml"
(cd "$rc_repo" && git add Cargo.toml && git commit -qm wrong-identity)
rc_commit=$(git -C "$rc_repo" rev-parse HEAD)
rm -f "$fixture/rc-ambient-cargo-called"
if run_fake_rc "$fixture/wrong-identity-rc-output"; then
    fail "release-candidate command accepted mismatched Cargo identity"
fi
test ! -e "$fixture/rc-ambient-cargo-called" || \
    fail "release-candidate command invoked Cargo before rejecting identity mismatch"
test ! -e "$fixture/wrong-identity-rc-output" || \
    fail "release identity mismatch left an output reservation"
cp "$fixture/rc-Cargo.toml" "$rc_repo/Cargo.toml"
(cd "$rc_repo" && git add Cargo.toml && git commit -qm restore-identity)
rc_commit=$(git -C "$rc_repo" rev-parse HEAD)

rm -f "$fixture/rc-replaced-marker" "$fixture/missing-rc-reservation"
replaced_rc_output="$fixture/replaced-rc-output"
if run_fake_rc "$replaced_rc_output" FAKE_REPLACE_RC_OUTPUT=1; then
    fail "release-candidate command accepted a replaced output reservation"
fi
test ! -e "$fixture/missing-rc-reservation" || \
    fail "release-candidate command did not reserve output before tool execution"
test -f "$replaced_rc_output/user-file" || \
    fail "release-candidate command removed a replacement output directory"

rm -f "$fixture/rc-state-mutation-marker"
tracked_mutation_output="$fixture/tracked-mutation-rc-output"
if run_fake_rc "$tracked_mutation_output" FAKE_RC_STATE_MUTATION=tracked; then
    fail "release-candidate command accepted a tracked-file mutation during a repository gate"
fi
test -e "$fixture/rc-state-mutation-marker" || \
    fail "tracked-file mutation fixture did not run during a repository gate"
test ! -e "$tracked_mutation_output" || \
    fail "tracked-file mutation left a completed release-candidate output"
printf '%s\n' readme >"$rc_repo/README.md"
test -z "$(git -C "$rc_repo" status --porcelain --untracked-files=all)" || \
    fail "tracked-file mutation fixture did not restore a clean repository"

rm -f "$fixture/rc-state-mutation-marker"
head_mutation_output="$fixture/head-mutation-rc-output"
if run_fake_rc "$head_mutation_output" FAKE_RC_STATE_MUTATION=head; then
    fail "release-candidate command accepted a HEAD move during a repository gate"
fi
test -e "$fixture/rc-state-mutation-marker" || \
    fail "HEAD-move fixture did not run during a repository gate"
test ! -e "$head_mutation_output" || \
    fail "HEAD move left a completed release-candidate output"
test "$(git -C "$rc_repo" rev-parse HEAD)" != "$rc_commit" || \
    fail "HEAD-move fixture did not advance the repository commit"

contains_release_mutation() {
    mutation_script=$1
    grep -Ei 'cargo.*publish' "$mutation_script" >/dev/null && return 0
    grep -Ei 'git.*[[:space:]](tag|push)([[:space:]]|$)' "$mutation_script" >/dev/null && return 0
    return 1
}

assert_narrow_sentinel_commit() {
    commit_script=$1
    # The dollar expression is literal shell source inspected by this test.
    # shellcheck disable=SC2016
    commit_line=$(grep -nF 'rm -f -- "$reservation_file"' "$commit_script" | tail -n 1 | cut -d: -f1)
    inactive_line=$(grep -nF 'reservation_active=0' "$commit_script" | tail -n 1 | cut -d: -f1)
    ignore_line=$(grep -nF "trap '' HUP INT TERM" "$commit_script" | tail -n 1 | cut -d: -f1)
    test -n "$commit_line" && test -n "$inactive_line" && test -n "$ignore_line" || \
        fail "release artifact command has no protected sentinel commit"
    test "$ignore_line" -lt "$commit_line" && test "$commit_line" -lt "$inactive_line" || \
        fail "release artifact command does not protect its final sentinel commit"
    post_commit_start=$((commit_line + 1))
    post_commit_end=$((inactive_line - 1))
    if test "$post_commit_start" -le "$post_commit_end"; then
        sed -n "${post_commit_start},${post_commit_end}p" "$commit_script" \
            >"$fixture/post-sentinel-commit"
        if grep -E '(^|[[:space:]])(find|test|path_inode)([[:space:]]|$)' \
            "$fixture/post-sentinel-commit" >/dev/null; then
            fail "release artifact command performs fallible validation after sentinel removal"
        fi
    fi
}

if contains_release_mutation "$script"; then
    fail "release-candidate command contains a publication, tag, or push command"
fi
guard_fixture="$fixture/static-release-guard.sh"
printf '%s\n' '#!/bin/sh' '"/opt/tool bin/cargo" +stable publish --locked' >"$guard_fixture"
contains_release_mutation "$guard_fixture" || \
    fail "release static guard missed a path/toolchain Cargo publish command"
printf '%s\n' '#!/bin/sh' 'git -C repository push origin main' >"$guard_fixture"
contains_release_mutation "$guard_fixture" || \
    fail "release static guard missed a Git-options push command"
printf '%s\n' '#!/bin/sh' '/usr/local/bin/git -c user.name=fixture tag v0.2.0' >"$guard_fixture"
contains_release_mutation "$guard_fixture" || \
    fail "release static guard missed a path/Git-options tag command"
assert_narrow_sentinel_commit "$package_script"
assert_narrow_sentinel_commit "$script"

grep -F '"promotion_state": "rc-built"' "$script" >/dev/null || \
    fail "release-candidate manifest does not state rc-built"
grep -F '"external_gates": "not evaluated in-tree"' "$script" >/dev/null || \
    fail "release-candidate manifest does not keep external gates pending"
grep -F '"cross_platform_ci": "not evaluated by local command"' "$script" >/dev/null || \
    fail "release-candidate manifest overstates cross-platform CI"
grep -F '"repository_gates": {' "$script" >/dev/null || \
    fail "release-candidate manifest does not report repository gates"
for gate in \
    format clippy tests doctests strict_rustdoc msrv dependency_policy public_api \
    crypto_inventory fuzz_smoke release_command_self_test worktree_boundary \
    source_export_boundary cargo_package_boundary
do
    grep -F "\"$gate\": \"passed\"" "$script" >/dev/null || \
        fail "release-candidate manifest does not report a passed gate: $gate"
done
for version_field in \
    security_model_version api_snapshot_version engineering_evidence_version \
    crypto_inventory_version release_checklist_version
do
    grep -F "\"$version_field\"" "$script" >/dev/null || \
        fail "release-candidate manifest omits version field: $version_field"
done

echo "release-candidate command self-test passed"
