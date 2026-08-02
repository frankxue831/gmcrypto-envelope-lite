#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
inventory="$repo_root/docs/security/cryptographic-dependencies.md"
snapshot="$repo_root/ci/crypto-inventory.snapshot"
boundary_packages='base64@0.22.1 cmov@0.5.4 cpubits@0.1.1 crypto-bigint@0.7.5 ctutils@0.4.2 getrandom@0.4.3 gmcrypto-core@1.11.0 rand_core@0.10.1 spin@0.10.1 subtle@2.6.1 zeroize@1.9.0 zeroize_derive@1.5.0'

fail() {
    echo "error: $*" >&2
    exit 1
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        fail "no SHA-256 command is available"
    fi
}

valid_checksum() {
    test "${#1}" -eq 64 || return 1
    case "$1" in
        *[!0-9a-f]* | '') return 1 ;;
    esac
}

lock_checksum() {
    package=$1
    version=$2
    awk -v package="$package" -v version="$version" '
        function report() {
            if (name == package && package_version == version) {
                print checksum
            }
        }
        /^\[\[package\]\]$/ {
            report()
            name = package_version = checksum = ""
            next
        }
        /^name = / {
            name = $3
            gsub(/"/, "", name)
            next
        }
        /^version = / {
            package_version = $3
            gsub(/"/, "", package_version)
            next
        }
        /^checksum = / {
            checksum = $3
            gsub(/"/, "", checksum)
        }
        END { report() }
    ' "$repo_root/Cargo.lock"
}

single_lock_checksum() {
    package=$1
    version=$2
    matches=$(lock_checksum "$package" "$version")
    match_count=$(printf '%s\n' "$matches" | awk 'NF { count += 1 } END { print count + 0 }')
    test "$match_count" -eq 1 || fail "Cargo.lock has no single checksum for $package $version"
    valid_checksum "$matches" || fail "Cargo.lock has an invalid checksum for $package $version"
    printf '%s\n' "$matches"
}

test -f "$inventory" || fail "cryptographic dependency inventory is missing"
test -f "$snapshot" || fail "cryptographic dependency snapshot is missing"

lock_field_count=$(grep -c '^- Reviewed Cargo.lock SHA-256: ' "$inventory" || true)
test "$lock_field_count" -eq 1 || fail "inventory has no single Cargo.lock SHA-256 field"
expected_lock=$(sed -n 's/^- Reviewed Cargo.lock SHA-256: `\([0-9a-f][0-9a-f]*\)`$/\1/p' "$inventory")
valid_checksum "$expected_lock" || fail "inventory has an invalid Cargo.lock SHA-256"
actual_lock=$(sha256_file "$repo_root/Cargo.lock")
test "$actual_lock" = "$expected_lock" || fail "Cargo.lock differs from the reviewed inventory"

backend_field_count=$(grep -c '^- Backend registry checksum: ' "$inventory" || true)
test "$backend_field_count" -eq 1 || fail "inventory has no single Backend registry checksum field"
documented_backend_checksum=$(sed -n 's/^- Backend registry checksum: `\([0-9a-f][0-9a-f]*\)`$/\1/p' "$inventory")
valid_checksum "$documented_backend_checksum" || fail "inventory has an invalid Backend registry checksum"
locked_backend_checksum=$(single_lock_checksum gmcrypto-core 1.11.0)
test "$locked_backend_checksum" = "$documented_backend_checksum" || fail "gmcrypto-core registry checksum differs from the inventory"
grep -F 'gmcrypto-core = { version = "1.11", features = ["x509"] }' \
    "$repo_root/Cargo.toml" >/dev/null || fail "gmcrypto-core manifest requirement or features changed"

expected_view=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-expected-view.XXXXXX")
actual_view=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-actual-view.XXXXXX")
expected_names=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-expected-names.XXXXXX")
boundary_names=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-boundary-names.XXXXXX")
document_rows=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-document-rows.XXXXXX")
document_view=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-document-view.XXXXXX")
snapshot_view=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-snapshot-view.XXXXXX")
trap 'rm -f -- "$expected_view" "$actual_view" "$expected_names" "$boundary_names" "$document_rows" "$document_view" "$snapshot_view"' EXIT HUP INT TERM

awk -F'|' '
    /^#/ || /^$/ { next }
    NF != 5 { exit 1 }
    $1 == "" || $2 == "" || $3 == "" || $4 !~ /^[0-9a-f]+$/ || length($4) != 64 { exit 1 }
    $5 != "reviewed-no-unsafe-source" && $5 != "reviewed-unsafe-present" { exit 1 }
' "$snapshot" || fail "cryptographic dependency snapshot has an invalid row"
snapshot_row_count=$(grep -v '^#' "$snapshot" | sed '/^$/d' | wc -l | tr -d ' ')
inventory_table_line_count=$(grep -c '^|' "$inventory" || true)
test "$inventory_table_line_count" -eq "$((snapshot_row_count + 2))" ||
    fail "human-readable cryptographic dependency table is invalid"
grep -v '^#' "$snapshot" | sed '/^$/d' | cut -d'|' -f1 | LC_ALL=C sort >"$expected_names"
if test "$(uniq -d "$expected_names" | wc -l | tr -d ' ')" -ne 0; then
    fail "cryptographic dependency snapshot has duplicate packages"
fi
for package_version in $boundary_packages; do
    printf '%s\n' "${package_version%@*}"
done | LC_ALL=C sort >"$boundary_names"
cmp -s "$boundary_names" "$expected_names" || fail "cryptographic dependency snapshot has missing or unexpected packages"

if ! awk -F'|' '
    function trim(value) {
        sub(/^[[:space:]]+/, "", value)
        sub(/[[:space:]]+$/, "", value)
        return value
    }
    /^\| `/ {
        name = trim($2)
        version = trim($3)
        features = trim($4)
        checksum = trim($5)
        status = trim($6)
        gsub(/`/, "", name)
        gsub(/`/, "", version)
        gsub(/`/, "", features)
        gsub(/`/, "", checksum)
        gsub(/[[:space:]]*,[[:space:]]*/, ",", features)
        if (name == "" || version == "" || features == "" || checksum !~ /^[0-9a-f]+$/ || length(checksum) != 64) {
            exit 1
        }
        if (status == "reviewed: no unsafe source") {
            status = "reviewed-no-unsafe-source"
        } else if (status == "reviewed: unsafe source present") {
            status = "reviewed-unsafe-present"
        } else {
            exit 1
        }
        print name "|" version "|" features "|" checksum "|" status
        rows += 1
    }
    END {
        if (rows == 0) {
            exit 1
        }
    }
' "$inventory" >"$document_rows"; then
    fail "human-readable cryptographic dependency table is invalid"
fi
LC_ALL=C sort "$document_rows" >"$document_view"
grep -v '^#' "$snapshot" | sed '/^$/d' | LC_ALL=C sort >"$snapshot_view"
cmp -s "$document_view" "$snapshot_view" || fail "human-readable cryptographic dependency table differs from the reviewed snapshot"

feature_list() {
    package=$1
    version=$2
    if ! feature_tree=$(cd "$repo_root" && cargo tree --locked -e features -i "$package@$version"); then
        fail "cargo tree has no single resolved feature graph for $package $version"
    fi
    resolved_features=$(printf '%s\n' "$feature_tree" |
        sed -n "s/.*$package feature \"\([^\"]*\)\".*/\1/p" |
        LC_ALL=C sort -u |
        paste -sd, -)
    if test -z "$resolved_features"; then
        printf '%s\n' none
    else
        printf '%s\n' "$resolved_features"
    fi
}

for package_version in $boundary_packages; do
    package=${package_version%@*}
    version=${package_version#*@}
    features=$(feature_list "$package" "$version")
    checksum=$(single_lock_checksum "$package" "$version")
    printf '%s|%s|%s|%s\n' "$package" "$version" "$features" "$checksum" >>"$actual_view"
done
LC_ALL=C sort -o "$actual_view" "$actual_view"
grep -v '^#' "$snapshot" | sed '/^$/d' | cut -d'|' -f1-4 | LC_ALL=C sort >"$expected_view"
cmp -s "$expected_view" "$actual_view" || fail "resolved cryptographic dependency package, feature, or checksum differs from the reviewed snapshot"

echo "cryptographic dependency inventory check passed"
