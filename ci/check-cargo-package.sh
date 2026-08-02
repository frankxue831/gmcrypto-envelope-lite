#!/bin/sh
set -eu

usage() {
    echo "usage: $0 ABSOLUTE_SOURCE_ROOT ABSOLUTE_OUTPUT_DIRECTORY" >&2
    exit 2
}

fail() {
    echo "error: $*" >&2
    exit 1
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
    manifest_path=${2:-$source_root/Cargo.toml}
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
    ' "$manifest_path"
}

test "$#" -eq 2 || usage
source_root=$1
requested_output=$2

case "$source_root" in /*) ;; *) usage ;; esac
case "$requested_output" in /*) ;; *) usage ;; esac
test -d "$source_root" || fail "source root is not a directory"
test -f "$source_root/Cargo.toml" && test ! -L "$source_root/Cargo.toml" || \
    fail "source root has no regular Cargo.toml"
boundary_scanner="$source_root/ci/check-open-source-boundary.sh"
test -f "$boundary_scanner" && test ! -L "$boundary_scanner" && \
    test -x "$boundary_scanner" || \
    fail "source root has no regular executable boundary scanner"

package_name=$(package_field name) || fail "could not read package name"
package_version=$(package_field version) || fail "could not read package version"
test "$package_name" = gmcrypto-envelope-lite || fail "unexpected Cargo package name"
test "$package_version" = 0.1.0 || fail "unexpected Cargo package version"
expected_crate="$package_name-$package_version.crate"
expected_root="$package_name-$package_version"

output_parent=$(dirname -- "$requested_output")
output_name=$(basename -- "$requested_output")
test -d "$output_parent" || fail "output parent is not a directory"
test "$output_name" != . && test "$output_name" != .. || fail "invalid output name"
output_parent=$(CDPATH='' cd -- "$output_parent" && pwd -P) || \
    fail "could not resolve output parent"
output_dir="$output_parent/$output_name"
test ! -e "$output_dir" && test ! -L "$output_dir" || \
    fail "output directory already exists"

temporary=
package_staging=
installed_inode=
reservation_inode=
reservation_file=
reservation_token=
reservation_file_inode=
reservation_active=0

reservation_is_valid() {
    test -d "$output_dir" && test ! -L "$output_dir" || return 1
    test "$(path_inode "$output_dir")" = "$reservation_inode" || return 1
    if test -n "$reservation_file"; then
        test -f "$reservation_file" && test ! -L "$reservation_file" || return 1
        test "$(path_inode "$reservation_file")" = "$reservation_file_inode" || return 1
        test "$(cat "$reservation_file" 2>/dev/null)" = "$reservation_token" || return 1
    fi
}

cleanup() {
    if test "$reservation_active" -eq 1 && reservation_is_valid; then
        installed="$output_dir/$expected_crate"
        if test -n "$installed_inode" && test -f "$installed" && test ! -L "$installed" && \
            test "$(path_inode "$installed")" = "$installed_inode"; then
            rm -f -- "$installed"
        fi
        test -z "$reservation_file" || rm -f -- "$reservation_file"
        rmdir "$output_dir" 2>/dev/null || true
    fi
    test -z "$package_staging" || rm -rf -- "$package_staging"
    test -z "$temporary" || rm -rf -- "$temporary"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

umask 077
mkdir "$output_dir" || fail "could not reserve package output directory"
if reservation_inode=$(path_inode "$output_dir"); then
    reservation_active=1
else
    rmdir "$output_dir" 2>/dev/null || true
    fail "could not identify output reservation"
fi
reservation_file=$(mktemp "$output_dir/.secure-envelope-package-reservation.XXXXXX") || \
    fail "could not create output reservation sentinel"
reservation_token=$(basename -- "$reservation_file")
printf '%s\n' "$reservation_token" >"$reservation_file" || \
    fail "could not initialize output reservation sentinel"
reservation_file_inode=$(path_inode "$reservation_file") || \
    fail "could not identify output reservation sentinel"

temporary=$(mktemp -d "${TMPDIR:-/tmp}/secure-envelope-package.XXXXXX") || \
    fail "could not create package verification directory"
unset RUSTUP_TOOLCHAIN
if ! pinned_cargo=$(rustup which --toolchain stable cargo 2>"$temporary/which-cargo-error"); then
    cat "$temporary/which-cargo-error" >&2
    fail "stable Cargo could not be resolved"
fi
if ! pinned_rustc=$(rustup which --toolchain stable rustc 2>"$temporary/which-rustc-error"); then
    cat "$temporary/which-rustc-error" >&2
    fail "stable rustc could not be resolved"
fi
test -f "$pinned_cargo" && test ! -L "$pinned_cargo" && test -x "$pinned_cargo" || \
    fail "resolved stable Cargo is not a regular executable"
test -f "$pinned_rustc" && test ! -L "$pinned_rustc" && test -x "$pinned_rustc" || \
    fail "resolved stable rustc is not a regular executable"
pinned_cargo_bin=$(CDPATH='' cd -- "$(dirname -- "$pinned_cargo")" && pwd -P) || \
    fail "could not resolve stable Cargo directory"
pinned_rustc_bin=$(CDPATH='' cd -- "$(dirname -- "$pinned_rustc")" && pwd -P) || \
    fail "could not resolve stable rustc directory"
test "$pinned_cargo_bin" = "$pinned_rustc_bin" || \
    fail "stable Cargo and rustc resolve to different directories"
PATH="$pinned_cargo_bin:$PATH"
export PATH
if ! rustup run stable "$pinned_rustc" --version >/dev/null 2>"$temporary/rustc-error"; then
    cat "$temporary/rustc-error" >&2
    fail "resolved stable rustc is unavailable"
fi

run_cargo() {
    rustup run stable "$pinned_cargo" "$@"
}

export CARGO_TARGET_DIR="$temporary/target"
package_files="$temporary/package-files"
if ! (cd "$source_root" && run_cargo package --locked --list) >"$package_files"; then
    fail "could not list Cargo package contents"
fi

if grep -Ei '(^|/)(\.github|ci|tests|tools|fuzz|api|\.worktrees|docs/superpowers)(/|$)|(^|/)(deny\.toml|RELEASE_CHECKLIST\.md)$|\.(pem|der|key|p12|pfx|pk8)$' \
    "$package_files" >"$temporary/prohibited"; then
    package_scan_status=0
else
    package_scan_status=$?
fi
case "$package_scan_status" in
    0) fail "excluded material is present in the Cargo package" ;;
    1) ;;
    *) fail "could not scan Cargo package contents" ;;
esac

for required in \
    LICENSE-APACHE LICENSE-MIT README.md SECURITY.md SECURITY_MODEL.md docs/api-stability.md \
    docs/security/engineering-evidence.md docs/security/cryptographic-dependencies.md \
    src/lib.rs examples/build_request.rs examples/open_response.rs
do
    grep -Fx -- "$required" "$package_files" >/dev/null || \
        fail "required package file is missing: $required"
done

if ! (cd "$source_root" && run_cargo package --locked); then
    fail "Cargo package construction failed"
fi
if ! find "$CARGO_TARGET_DIR/package" -maxdepth 1 -type f -name '*.crate' -print \
    >"$temporary/crates"; then
    fail "could not inspect Cargo package output"
fi
test "$(wc -l <"$temporary/crates" | tr -d '[:space:]')" -eq 1 || \
    fail "expected exactly one Cargo package"
IFS= read -r crate <"$temporary/crates"
test "$(basename -- "$crate")" = "$expected_crate" || \
    fail "Cargo package filename does not match package identity"

if ! tar -tzf "$crate" >"$temporary/members"; then
    fail "could not inspect Cargo package archive"
fi
test -s "$temporary/members" || fail "Cargo package archive is empty"
if ! awk -v expected="$expected_root" '
    /^\// { unsafe = 1; exit }
    /(^|\/)\.\.?(\/|$)/ { unsafe = 1; exit }
    index($0, "/") == 0 { unsafe = 1; exit }
    {
        root = $0
        sub(/\/.*/, "", root)
        if (root != expected) { unsafe = 1; exit }
    }
    END { exit unsafe ? 1 : 0 }
' "$temporary/members"; then
    fail "Cargo package archive has an unsafe or mismatched root"
fi
if ! tar -tvzf "$crate" >"$temporary/member-details"; then
    fail "could not inspect Cargo package entry types"
fi
if ! awk 'substr($0, 1, 1) != "-" && substr($0, 1, 1) != "d" { exit 1 }' \
    "$temporary/member-details"; then
    fail "Cargo package archive contains a special entry"
fi

mkdir "$temporary/unpacked"
if ! tar -xzf "$crate" -C "$temporary/unpacked"; then
    fail "could not unpack Cargo package"
fi
if ! find "$temporary/unpacked" -mindepth 1 -maxdepth 1 -print >"$temporary/roots"; then
    fail "could not inspect unpacked Cargo package"
fi
test "$(wc -l <"$temporary/roots" | tr -d '[:space:]')" -eq 1 || \
    fail "expected exactly one unpacked package root"
IFS= read -r crate_root <"$temporary/roots"
test "$(basename -- "$crate_root")" = "$expected_root" || \
    fail "unpacked package root does not match package identity"
test -d "$crate_root" && test ! -L "$crate_root" || \
    fail "unpacked package root is not a regular directory"
crate_manifest="$crate_root/Cargo.toml"
test -f "$crate_manifest" && test ! -L "$crate_manifest" || \
    fail "unpacked Cargo package has no regular Cargo.toml"
crate_package_name=$(package_field name "$crate_manifest") || \
    fail "could not read unpacked Cargo package name"
crate_package_version=$(package_field version "$crate_manifest") || \
    fail "could not read unpacked Cargo package version"
test "$crate_package_name" = "$package_name" || \
    fail "unpacked Cargo package name does not match package identity"
test "$crate_package_version" = "$package_version" || \
    fail "unpacked Cargo package version does not match package identity"
"$boundary_scanner" "$crate_root"

package_staging=$(mktemp -d "$output_parent/.secure-envelope-package-stage.XXXXXX") || \
    fail "could not create private package staging directory"
cp "$crate" "$package_staging/$expected_crate" || fail "could not stage Cargo package"
test -f "$package_staging/$expected_crate" && test ! -L "$package_staging/$expected_crate" || \
    fail "staged Cargo package is not a regular file"

reservation_is_valid || fail "package output reservation was replaced"
test "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d '[:space:]')" -eq 1 || \
    fail "package output reservation contains unexpected entries"
test ! -e "$output_dir/$expected_crate" && test ! -L "$output_dir/$expected_crate" || \
    fail "Cargo package output collided with an existing entry"
ln "$package_staging/$expected_crate" "$output_dir/$expected_crate" || \
    fail "could not atomically install Cargo package"
installed_inode=$(path_inode "$output_dir/$expected_crate") || \
    fail "could not identify installed Cargo package"
test "$installed_inode" = "$(path_inode "$package_staging/$expected_crate")" || \
    fail "installed Cargo package identity changed"
reservation_is_valid || fail "package output reservation changed during finalization"
test "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d '[:space:]')" -eq 2 || \
    fail "package output contains an unexpected artifact set"
test -f "$output_dir/$expected_crate" && test ! -L "$output_dir/$expected_crate" || \
    fail "installed Cargo package is not a regular file"
test "$(path_inode "$output_dir/$expected_crate")" = "$installed_inode" || \
    fail "installed Cargo package changed before commit"

trap '' HUP INT TERM
if ! rm -f -- "$reservation_file"; then
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    fail "could not commit Cargo package output"
fi
reservation_active=0
echo "Cargo package check passed"
