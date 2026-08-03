#!/bin/sh
set -eu

usage() {
    echo "usage: $0 COMMIT ABSOLUTE_OUTPUT_DIRECTORY" >&2
    exit 2
}

fail() {
    echo "error: $*" >&2
    exit 1
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        digest_output=$(sha256sum "$1") || fail "could not calculate SHA-256"
    elif command -v shasum >/dev/null 2>&1; then
        digest_output=$(shasum -a 256 "$1") || fail "could not calculate SHA-256"
    else
        fail "no SHA-256 command is available"
    fi
    # Both supported tools put the digest in the first whitespace-delimited field.
    # shellcheck disable=SC2086
    set -- $digest_output
    digest=${1-}
    test "${#digest}" -eq 64 || fail "SHA-256 command returned an invalid digest"
    case "$digest" in *[!0123456789abcdef]*) fail "SHA-256 command returned an invalid digest" ;; esac
    printf '%s\n' "$digest"
}

path_inode() {
    inode_output=$(ls -di "$1" 2>/dev/null) || return 1
    # The inode is the first whitespace-delimited field on supported platforms.
    # shellcheck disable=SC2086
    set -- $inode_output
    inode=${1-}
    case "$inode" in '' | *[!0-9]*) return 1 ;; esac
    printf '%s\n' "$inode"
}

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
            if (line == "" || line ~ /[\"\\]/) exit 2
            print line
            matches += 1
        }
        END { if (matches != 1) exit 2 }
    ' "$repo_root/Cargo.toml"
}

test "$#" -eq 2 || usage
candidate_argument=$1
requested_output=$2
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=ci/tool-versions.sh
. "$repo_root/ci/tool-versions.sh"

case "$requested_output" in /*) ;; *) usage ;; esac
output_parent=$(dirname -- "$requested_output")
output_name=$(basename -- "$requested_output")
test -d "$output_parent" || fail "output parent is not a directory"
test "$output_name" != . && test "$output_name" != .. || fail "invalid output name"
output_parent=$(CDPATH='' cd -- "$output_parent" && pwd -P) || \
    fail "could not resolve output parent"
artifact_dir="$output_parent/$output_name"
case "$artifact_dir" in
    "$repo_root" | "$repo_root"/*) fail "output directory must be outside the repository" ;;
esac
test ! -e "$artifact_dir" && test ! -L "$artifact_dir" || \
    fail "output directory already exists"

candidate=$(git -C "$repo_root" rev-parse --verify --end-of-options \
    "$candidate_argument^{commit}" 2>/dev/null) || fail "candidate commit does not exist"
head_commit=$(git -C "$repo_root" rev-parse HEAD) || fail "could not resolve checked-out HEAD"
test "$candidate" = "$head_commit" || fail "candidate must equal the checked-out HEAD"
test -z "$(git -C "$repo_root" status --porcelain --untracked-files=all)" || \
    fail "worktree must be clean before RC construction"

package_name=gmcrypto-envelope-lite
package_version=0.2.0
manifest_package_name=$(package_field name) || fail "could not read Cargo package name"
manifest_package_version=$(package_field version) || fail "could not read Cargo package version"
test "$manifest_package_name" = "$package_name" || fail "Cargo package name does not match RC identity"
test "$manifest_package_version" = "$package_version" || fail "Cargo package version does not match RC identity"
archive_name="$package_name-$package_version-source.tar.gz"
crate_name="$package_name-$package_version.crate"

for required_executable in \
    "$repo_root/ci/check-open-source-boundary.sh" \
    "$repo_root/ci/check-cargo-package.sh" \
    "$repo_root/ci/check-public-api.sh" \
    "$repo_root/ci/check-crypto-inventory.sh" \
    "$repo_root/ci/fuzz-smoke.sh" \
    "$repo_root/tests/release_candidate.sh" \
    "$repo_root/tests/open_source_boundary.sh"
do
    test -f "$required_executable" && test ! -L "$required_executable" && \
        test -x "$required_executable" || fail "required gate is not a regular executable"
done

umask 077
temporary=
artifact_staging=
reservation_file=
reservation_token=
reservation_inode=
reservation_file_inode=
reservation_active=0
installed_records=

reservation_is_valid() {
    test -d "$artifact_dir" && test ! -L "$artifact_dir" || return 1
    test "$(path_inode "$artifact_dir")" = "$reservation_inode" || return 1
    if test -n "$reservation_file"; then
        test -f "$reservation_file" && test ! -L "$reservation_file" || return 1
        test "$(path_inode "$reservation_file")" = "$reservation_file_inode" || return 1
        test "$(cat "$reservation_file" 2>/dev/null)" = "$reservation_token" || return 1
    fi
}

cleanup() {
    if test "$reservation_active" -eq 1 && reservation_is_valid; then
        if test -n "$installed_records" && test -f "$installed_records"; then
            while IFS='|' read -r installed_name installed_inode
            do
                case "$installed_name" in
                    "$archive_name" | "$crate_name" | rc-manifest.json | SHA256SUMS) ;;
                    *) continue ;;
                esac
                installed_path="$artifact_dir/$installed_name"
                if test -f "$installed_path" && test ! -L "$installed_path" && \
                    test "$(path_inode "$installed_path")" = "$installed_inode"; then
                    rm -f -- "$installed_path"
                fi
            done <"$installed_records"
        fi
        test -z "$reservation_file" || rm -f -- "$reservation_file"
        rmdir "$artifact_dir" 2>/dev/null || true
    fi
    test -z "$artifact_staging" || rm -rf -- "$artifact_staging"
    test -z "$temporary" || rm -rf -- "$temporary"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$artifact_dir" || fail "could not reserve release-candidate output directory"
if reservation_inode=$(path_inode "$artifact_dir"); then
    reservation_active=1
else
    rmdir "$artifact_dir" 2>/dev/null || true
    fail "could not identify output reservation"
fi
reservation_file=$(mktemp "$artifact_dir/.secure-envelope-rc-reservation.XXXXXX") || \
    fail "could not create output reservation sentinel"
reservation_token=$(basename -- "$reservation_file")
printf '%s\n' "$reservation_token" >"$reservation_file" || \
    fail "could not initialize output reservation sentinel"
reservation_file_inode=$(path_inode "$reservation_file") || \
    fail "could not identify output reservation sentinel"

temporary=$(mktemp -d "${TMPDIR:-/tmp}/secure-envelope-rc.XXXXXX") || \
    fail "could not create RC construction directory"
installed_records="$temporary/installed-records"
: >"$installed_records"
original_path=$PATH
unset RUSTUP_TOOLCHAIN

resolve_toolchain() {
    resolve_name=$1
    resolve_label=$2
    if ! resolved_cargo=$(rustup which --toolchain "$resolve_name" cargo \
        2>"$temporary/$resolve_label-which-cargo-error"); then
        cat "$temporary/$resolve_label-which-cargo-error" >&2
        fail "$resolve_label Cargo could not be resolved"
    fi
    if ! resolved_rustc=$(rustup which --toolchain "$resolve_name" rustc \
        2>"$temporary/$resolve_label-which-rustc-error"); then
        cat "$temporary/$resolve_label-which-rustc-error" >&2
        fail "$resolve_label rustc could not be resolved"
    fi
    test -f "$resolved_cargo" && test ! -L "$resolved_cargo" && test -x "$resolved_cargo" || \
        fail "$resolve_label Cargo is not a regular executable"
    test -f "$resolved_rustc" && test ! -L "$resolved_rustc" && test -x "$resolved_rustc" || \
        fail "$resolve_label rustc is not a regular executable"
    resolved_cargo_bin=$(CDPATH='' cd -- "$(dirname -- "$resolved_cargo")" && pwd -P) || \
        fail "could not resolve $resolve_label Cargo directory"
    resolved_rustc_bin=$(CDPATH='' cd -- "$(dirname -- "$resolved_rustc")" && pwd -P) || \
        fail "could not resolve $resolve_label rustc directory"
    test "$resolved_cargo_bin" = "$resolved_rustc_bin" || \
        fail "$resolve_label Cargo and rustc resolve to different directories"
}

resolve_toolchain stable stable
stable_cargo=$resolved_cargo
stable_rustc=$resolved_rustc
stable_bin=$resolved_cargo_bin
resolve_toolchain 1.85.0 msrv
msrv_cargo=$resolved_cargo
msrv_rustc=$resolved_rustc
msrv_bin=$resolved_cargo_bin
resolve_toolchain "$PUBLIC_API_TOOLCHAIN" public-api
public_api_cargo=$resolved_cargo
public_api_rustc=$resolved_rustc
public_api_bin=$resolved_cargo_bin
resolve_toolchain "$FUZZ_TOOLCHAIN" fuzz
fuzz_cargo=$resolved_cargo
fuzz_rustc=$resolved_rustc
fuzz_bin=$resolved_cargo_bin

run_cargo() {
    run_toolchain=$1
    run_bin=$2
    run_executable=$3
    shift 3
    PATH="$run_bin:$original_path" rustup run "$run_toolchain" "$run_executable" "$@"
}

run_rustc() {
    run_toolchain=$1
    run_bin=$2
    run_executable=$3
    shift 3
    PATH="$run_bin:$original_path" rustup run "$run_toolchain" "$run_executable" "$@"
}

rustc_version=$(run_rustc stable "$stable_bin" "$stable_rustc" --version) || \
    fail "stable rustc is unavailable"
msrv_rustc_version=$(run_rustc 1.85.0 "$msrv_bin" "$msrv_rustc" --version) || \
    fail "Rust 1.85.0 is unavailable"
case "$msrv_rustc_version" in 'rustc 1.85.0 '*) ;; *) fail "missing exact Rust 1.85.0 toolchain" ;; esac
run_rustc "$PUBLIC_API_TOOLCHAIN" "$public_api_bin" "$public_api_rustc" --version >/dev/null || \
    fail "pinned public API rustc is unavailable"
fuzz_rustc_version=$(run_rustc "$FUZZ_TOOLCHAIN" "$fuzz_bin" "$fuzz_rustc" --version) || \
    fail "pinned fuzz rustc is unavailable"

actual_public_api=$(run_cargo "$PUBLIC_API_TOOLCHAIN" "$public_api_bin" \
    "$public_api_cargo" public-api --version 2>/dev/null || true)
expected_public_api="cargo-public-api $CARGO_PUBLIC_API_VERSION"
test "$actual_public_api" = "$expected_public_api" || \
    fail "wrong cargo-public-api version: expected $expected_public_api"
actual_fuzz=$(run_cargo "$FUZZ_TOOLCHAIN" "$fuzz_bin" "$fuzz_cargo" \
    fuzz --version 2>/dev/null || true)
expected_fuzz="cargo-fuzz $CARGO_FUZZ_VERSION"
test "$actual_fuzz" = "$expected_fuzz" || fail "wrong cargo-fuzz version: expected $expected_fuzz"
actual_deny=$(run_cargo stable "$stable_bin" "$stable_cargo" deny --version 2>/dev/null || true)
expected_deny="cargo-deny $CARGO_DENY_VERSION"
test "$actual_deny" = "$expected_deny" || fail "wrong cargo-deny version: expected $expected_deny"

grep -F "**Model version:** $SECURITY_MODEL_VERSION" "$repo_root/SECURITY_MODEL.md" >/dev/null || \
    fail "security model version mismatch"
grep -F "**Policy version:** $API_SNAPSHOT_VERSION" "$repo_root/docs/api-stability.md" >/dev/null || \
    fail "API policy version mismatch"
grep -F "**Evidence version:** $ENGINEERING_EVIDENCE_VERSION" \
    "$repo_root/docs/security/engineering-evidence.md" >/dev/null || fail "engineering evidence version mismatch"
grep -F "**Inventory version:** $CRYPTO_INVENTORY_VERSION" \
    "$repo_root/docs/security/cryptographic-dependencies.md" >/dev/null || fail "crypto inventory version mismatch"
grep -F "**Template version:** $RELEASE_CHECKLIST_VERSION" \
    "$repo_root/RELEASE_CHECKLIST.md" >/dev/null || fail "release checklist version mismatch"

(cd "$repo_root" && run_cargo stable "$stable_bin" "$stable_cargo" fmt --all -- --check)
(cd "$repo_root" && run_cargo stable "$stable_bin" "$stable_cargo" clippy --all-targets --locked -- -D warnings)
(cd "$repo_root" && run_cargo stable "$stable_bin" "$stable_cargo" clippy --all-targets --locked --features aead -- -D warnings)
(cd "$repo_root" && run_cargo stable "$stable_bin" "$stable_cargo" test --all-targets --locked)
(cd "$repo_root" && run_cargo stable "$stable_bin" "$stable_cargo" test --all-targets --locked --features aead)
(cd "$repo_root" && run_cargo stable "$stable_bin" "$stable_cargo" test --doc --locked)
(cd "$repo_root" && run_cargo stable "$stable_bin" "$stable_cargo" test --doc --locked --features aead)
(cd "$repo_root" && export RUSTDOCFLAGS="-D missing-docs -D warnings" && \
    run_cargo stable "$stable_bin" "$stable_cargo" doc --locked --no-deps)
(cd "$repo_root" && export RUSTDOCFLAGS="-D missing-docs -D warnings" && \
    run_cargo stable "$stable_bin" "$stable_cargo" doc --locked --no-deps --features aead)
(cd "$repo_root" && run_cargo 1.85.0 "$msrv_bin" "$msrv_cargo" test --all-targets --locked)
(cd "$repo_root" && run_cargo 1.85.0 "$msrv_bin" "$msrv_cargo" test --all-targets --locked --features aead)
(cd "$repo_root" && run_cargo stable "$stable_bin" "$stable_cargo" deny check)
PATH="$stable_bin:$original_path" "$repo_root/ci/check-public-api.sh"
PATH="$stable_bin:$original_path" "$repo_root/ci/check-crypto-inventory.sh"
PATH="$stable_bin:$original_path" "$repo_root/ci/fuzz-smoke.sh" smoke
PATH="$stable_bin:$original_path" "$repo_root/tests/release_candidate.sh"
PATH="$stable_bin:$original_path" "$repo_root/tests/open_source_boundary.sh"
PATH="$stable_bin:$original_path" "$repo_root/ci/check-open-source-boundary.sh" \
    --worktree "$repo_root"

reservation_is_valid || fail "release-candidate output reservation was replaced"
final_head_commit=$(git -C "$repo_root" rev-parse HEAD) || \
    fail "could not re-resolve checked-out HEAD after repository gates"
test "$final_head_commit" = "$candidate" || \
    fail "checked-out HEAD changed during repository gates"
final_worktree_status=$(git -C "$repo_root" status --porcelain --untracked-files=all) || \
    fail "could not re-inspect worktree after repository gates"
test -z "$final_worktree_status" || \
    fail "worktree changed during repository gates"
artifact_staging=$(mktemp -d "$output_parent/.secure-envelope-rc-stage.XXXXXX") || \
    fail "could not create private artifact staging directory"
if ! git -C "$repo_root" archive --format=tar.gz \
    --prefix="$package_name-$package_version/" \
    --output="$artifact_staging/$archive_name" "$candidate"; then
    fail "could not construct source archive"
fi

mkdir "$temporary/export"
git -C "$repo_root" archive --format=tar \
    --prefix="$package_name-$package_version/" \
    --output="$temporary/source-export.tar" "$candidate" || \
    fail "could not construct independent source export"
tar -xf "$temporary/source-export.tar" -C "$temporary/export" || \
    fail "could not unpack independent source export"
source_root="$temporary/export/$package_name-$package_version"
test -d "$source_root" && test ! -L "$source_root" || fail "invalid source export root"
exported_boundary="$source_root/ci/check-open-source-boundary.sh"
exported_package_helper="$source_root/ci/check-cargo-package.sh"
test -f "$exported_boundary" && test ! -L "$exported_boundary" && test -x "$exported_boundary" || \
    fail "exported boundary scanner is not a regular executable"
test -f "$exported_package_helper" && test ! -L "$exported_package_helper" && \
    test -x "$exported_package_helper" || fail "exported package helper is not a regular executable"
"$exported_boundary" "$source_root"

PATH="$stable_bin:$original_path" "$exported_package_helper" \
    "$source_root" "$temporary/package-output"
test -f "$temporary/package-output/$crate_name" && \
    test ! -L "$temporary/package-output/$crate_name" || \
    fail "package helper did not produce the exact expected crate"
test "$(find "$temporary/package-output" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d '[:space:]')" -eq 1 || \
    fail "package helper produced an unexpected artifact set"
cp "$temporary/package-output/$crate_name" "$artifact_staging/$crate_name" || \
    fail "could not stage Cargo package"

source_sha=$(sha256_file "$artifact_staging/$archive_name")
crate_sha=$(sha256_file "$artifact_staging/$crate_name")
lock_sha=$(sha256_file "$source_root/Cargo.lock")
source_bytes=$(wc -c <"$artifact_staging/$archive_name" | tr -d '[:space:]')
crate_bytes=$(wc -c <"$artifact_staging/$crate_name" | tr -d '[:space:]')
manifest="$artifact_staging/rc-manifest.json"
{
    printf '{\n'
    printf '  "schema_version": 1,\n'
    printf '  "promotion_state": "rc-built",\n'
    printf '  "external_gates": "not evaluated in-tree",\n'
    printf '  "cross_platform_ci": "not evaluated by local command",\n'
    printf '  "package": "%s",\n' "$package_name"
    printf '  "version": "%s",\n' "$package_version"
    printf '  "commit": "%s",\n' "$candidate"
    printf '  "source_archive": {"file": "%s", "bytes": %s, "sha256": "%s"},\n' \
        "$archive_name" "$source_bytes" "$source_sha"
    printf '  "cargo_package": {"file": "%s", "bytes": %s, "sha256": "%s"},\n' \
        "$crate_name" "$crate_bytes" "$crate_sha"
    printf '  "cargo_lock_sha256": "%s",\n' "$lock_sha"
    printf '  "repository_gates": {\n'
    printf '    "format": "passed",\n'
    printf '    "clippy": "passed",\n'
    printf '    "tests": "passed",\n'
    printf '    "doctests": "passed",\n'
    printf '    "strict_rustdoc": "passed",\n'
    printf '    "msrv": "passed",\n'
    printf '    "dependency_policy": "passed",\n'
    printf '    "public_api": "passed",\n'
    printf '    "crypto_inventory": "passed",\n'
    printf '    "fuzz_smoke": "passed",\n'
    printf '    "release_command_self_test": "passed",\n'
    printf '    "worktree_boundary": "passed",\n'
    printf '    "source_export_boundary": "passed",\n'
    printf '    "cargo_package_boundary": "passed"\n'
    printf '  },\n'
    printf '  "rustc": "%s",\n' "$rustc_version"
    printf '  "msrv_rustc": "%s",\n' "$msrv_rustc_version"
    printf '  "cargo_deny": "%s",\n' "$CARGO_DENY_VERSION"
    printf '  "cargo_public_api": "%s",\n' "$CARGO_PUBLIC_API_VERSION"
    printf '  "public_api_toolchain": "%s",\n' "$PUBLIC_API_TOOLCHAIN"
    printf '  "cargo_fuzz": "%s",\n' "$CARGO_FUZZ_VERSION"
    printf '  "fuzz_toolchain": "%s",\n' "$FUZZ_TOOLCHAIN"
    printf '  "fuzz_rustc": "%s",\n' "$fuzz_rustc_version"
    printf '  "security_model_version": %s,\n' "$SECURITY_MODEL_VERSION"
    printf '  "api_snapshot_version": %s,\n' "$API_SNAPSHOT_VERSION"
    printf '  "engineering_evidence_version": %s,\n' "$ENGINEERING_EVIDENCE_VERSION"
    printf '  "crypto_inventory_version": %s,\n' "$CRYPTO_INVENTORY_VERSION"
    printf '  "release_checklist_version": %s\n' "$RELEASE_CHECKLIST_VERSION"
    printf '}\n'
} >"$manifest"
manifest_sha=$(sha256_file "$manifest")
{
    printf '%s  %s\n' "$source_sha" "$archive_name"
    printf '%s  %s\n' "$crate_sha" "$crate_name"
    printf '%s  %s\n' "$manifest_sha" rc-manifest.json
} >"$artifact_staging/SHA256SUMS"

for artifact in "$archive_name" "$crate_name" rc-manifest.json SHA256SUMS
do
    test -f "$artifact_staging/$artifact" && test ! -L "$artifact_staging/$artifact" || \
        fail "staged release candidate contains a non-regular artifact"
done
test "$(find "$artifact_staging" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d '[:space:]')" -eq 4 || \
    fail "staged release candidate does not contain exactly four artifacts"

reservation_is_valid || fail "release-candidate output reservation changed before finalization"
test "$(find "$artifact_dir" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d '[:space:]')" -eq 1 || \
    fail "release-candidate output reservation contains unexpected entries"
for artifact in "$archive_name" "$crate_name" rc-manifest.json SHA256SUMS
do
    destination="$artifact_dir/$artifact"
    test ! -e "$destination" && test ! -L "$destination" || \
        fail "release-candidate artifact collided with an existing entry"
    ln "$artifact_staging/$artifact" "$destination" || \
        fail "could not atomically install release-candidate artifact"
    installed_inode=$(path_inode "$destination") || fail "could not identify installed artifact"
    test "$installed_inode" = "$(path_inode "$artifact_staging/$artifact")" || \
        fail "installed artifact identity changed"
    printf '%s|%s\n' "$artifact" "$installed_inode" >>"$installed_records"
done
reservation_is_valid || fail "release-candidate output reservation changed during finalization"
test "$(find "$artifact_dir" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d '[:space:]')" -eq 5 || \
    fail "release-candidate output contains an unexpected pre-final artifact set"
for artifact in "$archive_name" "$crate_name" rc-manifest.json SHA256SUMS
do
    test -f "$artifact_dir/$artifact" && test ! -L "$artifact_dir/$artifact" || \
        fail "installed release-candidate artifact is not a regular file"
done

trap '' HUP INT TERM
if ! rm -f -- "$reservation_file"; then
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    fail "could not commit release-candidate output"
fi
reservation_active=0
echo "release candidate checks passed: $artifact_dir"
