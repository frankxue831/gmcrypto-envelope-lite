#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
scanner="$repo_root/ci/check-open-source-boundary.sh"

umask 077
if ! tmp=$(mktemp -d "${TMPDIR:-/tmp}/open-source-boundary-test.XXXXXX"); then
    echo "FAIL: unable to create self-test directory" >&2
    exit 1
fi

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

sha256_of_file() {
    digest_file=$1
    if command -v sha256sum >/dev/null 2>&1; then
        if ! digest_output=$(sha256sum <"$digest_file" 2>/dev/null); then
            fail "unable to calculate SHA-256 test fixture"
        fi
    elif command -v shasum >/dev/null 2>&1; then
        if ! digest_output=$(shasum -a 256 <"$digest_file" 2>/dev/null); then
            fail "unable to calculate SHA-256 test fixture"
        fi
    else
        fail "no SHA-256 tool available for self-test"
    fi
    # The digest is the first whitespace-delimited field from either tool.
    # shellcheck disable=SC2086
    set -- $digest_output
    [ "${#1}" -eq 64 ] || fail "invalid SHA-256 test fixture output"
    printf '%s' "$1"
}

[ -x "$scanner" ] || fail "open-source boundary scanner is missing or not executable"

# Windows Git Bash copies `ln -s` sources instead of linking unless MSYS
# winsymlinks is configured, and some filesystems cannot host FIFOs. Probe
# each fixture kind through the same predicate the scanner uses, and skip
# only the checks whose fixture cannot exist in this environment.
special_fixture_supported() {
    fixture_kind=$1
    fixture_dir="$tmp/probe-$fixture_kind"
    rm -rf "$fixture_dir" || return 1
    mkdir -p "$fixture_dir" || return 1
    case $fixture_kind in
        symlink)
            printf '%s\n' probe >"$fixture_dir/probe-target" || return 1
            ln -s probe-target "$fixture_dir/probe-link" 2>/dev/null || return 1
            ;;
        fifo)
            mkfifo "$fixture_dir/probe.fifo" 2>/dev/null || return 1
            ;;
        *) return 1 ;;
    esac
    special_listing=$(find "$fixture_dir" ! -type d ! -type f -print 2>/dev/null) || return 1
    [ -n "$special_listing" ]
}

if special_fixture_supported symlink; then
    symlink_fixtures=1
else
    symlink_fixtures=0
    echo "SKIP: symlink fixtures are unsupported here; skipping symlink checks" >&2
fi
if special_fixture_supported fifo; then
    fifo_fixtures=1
else
    fifo_fixtures=0
    echo "SKIP: FIFO fixtures are unsupported here; skipping FIFO checks" >&2
fi

new_export() {
    name=$1
    root="$tmp/$name"
    mkdir -p "$root/src" "$root/nested directory"
    printf '%s\n' 'neutral public source' >"$root/src/lib.rs"
    printf '%s\n' 'hidden neutral file' >"$root/.untracked-hidden"
    printf '%s\n' 'path with spaces is supported' >"$root/nested directory/file name.txt"
    printf '%s\n' "$root"
}

expect_accept() {
    label=$1
    root=$2
    shift 2
    output="$tmp/output"
    if ! "$@" "$scanner" "$root" >"$output" 2>&1; then
        sed -n '1,20p' "$output" >&2
        fail "$label: expected acceptance"
    fi
}

expect_reject() {
    label=$1
    root=$2
    shift 2
    output="$tmp/output"
    if "$@" "$scanner" "$root" >"$output" 2>&1; then
        fail "$label: expected rejection"
    fi
}

expect_worktree_accept() {
    label=$1
    root=$2
    output="$tmp/output"
    if ! "$scanner" --worktree "$root" >"$output" 2>&1; then
        sed -n '1,20p' "$output" >&2
        fail "$label: expected acceptance"
    fi
}

expect_worktree_reject() {
    label=$1
    root=$2
    output="$tmp/output"
    if "$scanner" --worktree "$root" >"$output" 2>&1; then
        fail "$label: expected rejection"
    fi
}

root=$(new_export neutral)
before="$tmp/before.cksum"
after="$tmp/after.cksum"
find "$root" -type f -exec cksum {} \; | LC_ALL=C sort >"$before"
expect_accept "neutral export" "$root" env
find "$root" -type f -exec cksum {} \; | LC_ALL=C sort >"$after"
cmp "$before" "$after" >/dev/null || fail "scanner modified export contents"

root=$(new_export "root with spaces")
expect_accept "export root with spaces" "$root" env

root="$tmp/export-root-with-trailing-newline
"
mkdir -p "$root/src"
printf '%s\n' 'neutral public source' >"$root/src/lib.rs"
expect_accept "export root with trailing newline" "$root" env

root=$(new_export public-pem)
printf '%s\n' '-----BEGIN PUBLIC KEY-----' 'public fixture' '-----END PUBLIC KEY-----' >"$root/public.pem"
expect_accept "public PEM fixture" "$root" env

root=$(new_export risky-container-extension)
printf '%s\n' 'synthetic non-PEM key container' >"$root/src/fixture.DeR"
expect_reject "high-risk DER container extension" "$root" env

root=$(new_export mac-path)
printf '/%s/%s/alice/project\n' 'Users' 'local' >"$root/src/path.txt"
expect_reject "macOS user path" "$root" env

root=$(new_export unix-path)
printf '/%s/alice/project\n' 'home' >"$root/src/path.txt"
expect_reject "Unix home path" "$root" env

root=$(new_export windows-path)
printf '%s:\\%s\\alice\\project\n' 'C' 'Users' >"$root/src/path.txt"
expect_reject "Windows user path" "$root" env

outside="$tmp/outside.txt"
printf '%s\n' outside >"$outside"
if [ "$symlink_fixtures" -eq 1 ]; then
    root=$(new_export symlink)
    ln -s "$outside" "$root/nested directory/outside link"
    expect_reject "symlink outside excluded directories" "$root" env
fi

root=$(new_export complete-root-target)
mkdir -p "$root/target"
printf '/%s/alice/project\n' 'home' >"$root/target/path.txt"
expect_reject "complete export root target directory" "$root" env

root=$(new_export complete-root-git)
mkdir -p "$root/.git"
printf '/%s/alice/project\n' 'home' >"$root/.git/path.txt"
expect_reject "complete export root git directory" "$root" env

root=$(new_export complete-nested-target)
mkdir -p "$root/src/target"
printf '/%s/alice/project\n' 'home' >"$root/src/target/path.txt"
expect_reject "complete export nested target directory" "$root" env

root=$(new_export complete-nested-git)
mkdir -p "$root/src/.git"
printf '/%s/alice/project\n' 'home' >"$root/src/.git/path.txt"
expect_reject "complete export nested git directory" "$root" env

root=$(new_export worktree-root-exclusions)
mkdir -p "$root/.git/objects" "$root/target/debug"
if [ "$symlink_fixtures" -eq 1 ]; then
    ln -s "$outside" "$root/.git/objects/outside"
    ln -s "$outside" "$root/target/debug/outside"
fi
printf '/%s/alice/project\n' 'home' >"$root/.git/metadata"
printf '/%s/alice/project\n' 'home' >"$root/target/build.txt"
expect_worktree_accept "worktree root metadata and build directories" "$root"

root=$(new_export worktree-metadata)
printf '/%s/%s/alice/repository\n' 'Users' 'local' >"$root/.git"
expect_worktree_accept "worktree metadata file" "$root"

root=$(new_export worktree-nested-target)
mkdir -p "$root/src/target"
printf '/%s/alice/project\n' 'home' >"$root/src/target/path.txt"
expect_worktree_reject "worktree nested target directory" "$root"

root=$(new_export worktree-nested-git)
mkdir -p "$root/src/.git"
printf '/%s/alice/project\n' 'home' >"$root/src/.git/path.txt"
expect_worktree_reject "worktree nested git directory" "$root"

for literal_root_name in 'worktree-root-*' 'worktree-root-?' 'worktree-root-['; do
    root=$(new_export "$literal_root_name")
    mkdir -p "$root/.git" "$root/target"
    printf '/%s/alice/project\n' 'home' >"$root/.git/path.txt"
    printf '/%s/alice/project\n' 'home' >"$root/target/path.txt"
    expect_reject "complete mode with literal-pattern root" "$root" env
    expect_worktree_accept "worktree exact prune with literal-pattern root" "$root"

    mkdir -p "$root/src/.git" "$root/src/target"
    printf '/%s/alice/project\n' 'home' >"$root/src/.git/path.txt"
    printf '/%s/alice/project\n' 'home' >"$root/src/target/path.txt"
    expect_worktree_reject "worktree nested paths with literal-pattern root" "$root"
done

if [ "$symlink_fixtures" -eq 1 ]; then
    root=$(new_export worktree-target-symlink)
    ln -s "$outside" "$root/target"
    expect_worktree_reject "worktree root target symlink" "$root"

    root=$(new_export worktree-git-symlink)
    ln -s "$outside" "$root/.git"
    expect_worktree_reject "worktree root git symlink" "$root"
fi

if [ "$fifo_fixtures" -eq 1 ]; then
    root=$(new_export fifo)
    mkfifo "$root/src/blocking.fifo"
    expect_reject "FIFO ordinary-file impostor" "$root" env
fi

for variant in plain encrypted; do
    root=$(new_export "private-$variant")
    if [ "$variant" = plain ]; then
        middle='PRIVATE KEY'
    else
        middle='ENCRYPTED PRIVATE KEY'
    fi
    printf '%s%s%s\n' '-----BEGIN ' "$middle" '-----' >"$root/src/fixture.pem"
    expect_reject "$variant private PEM marker" "$root" env
done

root=$(new_export binary-private)
binary_begin='-----BEGIN '
binary_kind='PRIVATE KEY'
printf '\000%s%s%s\n' "$binary_begin" "$binary_kind" '-----' >"$root/src/binary.dat"
expect_reject "binary private PEM marker" "$root" env

root=$(new_export external-policy-clean)
policy="$tmp/clean-policy.txt"
printf '\n\r\n' >"$policy"
OPEN_SOURCE_DENYLIST_FILE="$policy" expect_accept "blank denylist entries" "$root" env

root=$(new_export trailing-newline-policy)
policy="$tmp/policy-with-trailing-newline
"
printf '\n' >"$policy"
OPEN_SOURCE_DENYLIST_FILE="$policy" expect_accept "denylist path with trailing newline" "$root" env

root=$(new_export external-policy-match)
policy="$tmp/external-policy.txt"
token=$(printf '%s%s' 'release-boundary-' 'sentinel')
printf '%s\n' "$token" >"$policy"
printf '%s\n' "$token" >"$root/.untracked-hidden"
output="$tmp/output"
if OPEN_SOURCE_DENYLIST_FILE="$policy" "$scanner" "$root" >"$output" 2>&1; then
    fail "external denylist token: expected rejection"
fi
if grep -F "$token" "$output" >/dev/null 2>&1; then
    fail "external denylist token was leaked in scanner output"
fi

root=$(new_export policy-filename)
token=$(printf '%s%s' 'filename-boundary-' 'sentinel')
policy="$tmp/path-policy.txt"
printf '%s\n' "$token" >"$policy"
printf '%s\n' neutral >"$root/src/item-$token.txt"
output="$tmp/output"
if OPEN_SOURCE_DENYLIST_FILE="$policy" "$scanner" "$root" >"$output" 2>&1; then
    fail "denylist token in filename: expected rejection"
fi
grep -F "$token" "$output" >/dev/null 2>&1 && fail "filename denylist token leaked"

root=$(new_export policy-directory)
token=$(printf '%s%s' 'directory-boundary-' 'sentinel')
policy="$tmp/directory-policy.txt"
printf '%s\n' "$token" >"$policy"
mkdir -p "$root/src/$token"
output="$tmp/output"
if OPEN_SOURCE_DENYLIST_FILE="$policy" "$scanner" "$root" >"$output" 2>&1; then
    fail "denylist token in directory: expected rejection"
fi
grep -F "$token" "$output" >/dev/null 2>&1 && fail "directory denylist token leaked"

root=$(new_export policy-newline-filename)
token=$(printf '%s%s' 'newline-boundary-' 'sentinel')
policy="$tmp/newline-path-policy.txt"
printf '%s\n' "$token" >"$policy"
newline_file="$root/src/item-$token
.txt"
printf '%s\n' neutral >"$newline_file"
output="$tmp/output"
if OPEN_SOURCE_DENYLIST_FILE="$policy" "$scanner" "$root" >"$output" 2>&1; then
    fail "denylist token in newline filename: expected rejection"
fi
grep -F "$token" "$output" >/dev/null 2>&1 && fail "newline filename token leaked"

root=$(new_export policy-literal-glob)
token='literal-*?[]\-sentinel'
policy="$tmp/literal-glob-policy.txt"
printf '%s\n' "$token" >"$policy"
mkdir -p "$root/src/literal-XX-sentinel"
OPEN_SOURCE_DENYLIST_FILE="$policy" expect_accept "literal glob near miss" "$root" env
mkdir -p "$root/src/$token"
output="$tmp/output"
if OPEN_SOURCE_DENYLIST_FILE="$policy" "$scanner" "$root" >"$output" 2>&1; then
    fail "literal glob denylist path: expected rejection"
fi
grep -F "$token" "$output" >/dev/null 2>&1 && fail "literal glob token leaked"

root=$(new_export policy-worktree-exclusions)
token=$(printf '%s%s' 'worktree-path-' 'sentinel')
policy="$tmp/worktree-path-policy.txt"
printf '%s\n' "$token" >"$policy"
mkdir -p "$root/.git/$token" "$root/target/$token"
OPEN_SOURCE_DENYLIST_FILE="$policy" "$scanner" --worktree "$root" >"$tmp/output" 2>&1 || \
    fail "worktree root exclusions were scanned by denylist"
if OPEN_SOURCE_DENYLIST_FILE="$policy" "$scanner" "$root" >"$tmp/output" 2>&1; then
    fail "complete mode ignored denylist in root exclusions"
fi
rm -rf "$root/.git" "$root/target"
mkdir -p "$root/src/.git/$token" "$root/src/target/$token"
if OPEN_SOURCE_DENYLIST_FILE="$policy" "$scanner" --worktree "$root" >"$tmp/output" 2>&1; then
    fail "worktree mode ignored denylist in nested paths"
fi

root=$(new_export external-policy-crlf)
policy="$tmp/crlf-policy.txt"
token=$(printf '%s%s' 'crlf-boundary-' 'sentinel')
printf '%s\r\n' "$token" >"$policy"
printf '%s\n' "$token" >"$root/src/lib.rs"
output="$tmp/output"
if OPEN_SOURCE_DENYLIST_FILE="$policy" "$scanner" "$root" >"$output" 2>&1; then
    fail "CRLF denylist token: expected rejection"
fi
if grep -F "$token" "$output" >/dev/null 2>&1; then
    fail "CRLF denylist token was leaked in scanner output"
fi

root=$(new_export hash-policy-match)
hashed_file="$root/src/fingerprint-with-newline
"
printf '%s\n' 'fingerprinted export content' >"$hashed_file"
digest=$(sha256_of_file "$hashed_file")
policy="$tmp/hash-match-policy.txt"
printf 'sha256:%s\n' "$digest" >"$policy"
output="$tmp/output"
if OPEN_SOURCE_DENYLIST_FILE="$policy" "$scanner" "$root" >"$output" 2>&1; then
    fail "SHA-256 denylist match: expected rejection"
fi
if grep -F "$digest" "$output" >/dev/null 2>&1; then
    fail "SHA-256 denylist digest was leaked in scanner output"
fi

root=$(new_export hash-policy-clean)
clean_hash_source="$tmp/clean-hash-source"
printf '%s\n' 'content absent from export' >"$clean_hash_source"
digest=$(sha256_of_file "$clean_hash_source")
policy="$tmp/hash-clean-policy.txt"
printf 'sha256:%s\n' "$digest" >"$policy"
OPEN_SOURCE_DENYLIST_FILE="$policy" expect_accept "clean SHA-256 denylist" "$root" env

root=$(new_export hash-policy-malformed)
policy="$tmp/hash-malformed-policy.txt"
printf '%s%s\n' 'sha256:' 'not-a-valid-digest' >"$policy"
output="$tmp/output"
if OPEN_SOURCE_DENYLIST_FILE="$policy" "$scanner" "$root" >"$output" 2>&1; then
    fail "malformed SHA-256 denylist entry: expected rejection"
fi
grep -F 'scan failure' "$output" >/dev/null 2>&1 || \
    fail "malformed SHA-256 denylist entry did not report scan failure"

root=$(new_export hash-tool-failure)
digest=$(sha256_of_file "$root/src/lib.rs")
policy="$tmp/hash-tool-failure-policy.txt"
printf 'sha256:%s\n' "$digest" >"$policy"
mkdir -p "$tmp/hash-error-bin"
printf '%s\n' '#!/bin/sh' 'exit 2' >"$tmp/hash-error-bin/sha256sum"
chmod +x "$tmp/hash-error-bin/sha256sum"
output="$tmp/output"
if PATH="$tmp/hash-error-bin:$PATH" OPEN_SOURCE_DENYLIST_FILE="$policy" \
    "$scanner" "$root" >"$output" 2>&1; then
    fail "SHA-256 tool failure: expected rejection"
fi
grep -F 'scan failure' "$output" >/dev/null 2>&1 || \
    fail "SHA-256 tool failure did not report scan failure"
if grep -F "$digest" "$output" >/dev/null 2>&1; then
    fail "SHA-256 tool failure leaked denylist digest"
fi

root=$(new_export policy-sibling-prefix)
sibling="$root-other"
mkdir -p "$sibling"
policy="$sibling/policy.txt"
printf '\n' >"$policy"
OPEN_SOURCE_DENYLIST_FILE="$policy" expect_accept "denylist in sibling prefix directory" "$root" env
token=$(printf '%s%s' 'sibling-boundary-' 'sentinel')
printf '%s\n' "$token" >"$policy"
printf '%s\n' "$token" >"$root/.untracked-hidden"
output="$tmp/output"
if OPEN_SOURCE_DENYLIST_FILE="$policy" "$scanner" "$root" >"$output" 2>&1; then
    fail "sibling-prefix denylist token: expected rejection"
fi
if grep -F "$token" "$output" >/dev/null 2>&1; then
    fail "sibling-prefix denylist token was leaked in scanner output"
fi

root=$(new_export policy-inside)
policy="$root/policy.txt"
printf '\n' >"$policy"
if OPEN_SOURCE_DENYLIST_FILE="$policy" "$scanner" "$root" >"$tmp/output" 2>&1; then
    fail "denylist inside export: expected rejection"
fi

mkdir -p "$tmp/root-policy-bin"
# The generated helper expands the marker only when the scanner invokes it.
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' ': > "$FIND_CALLED_MARKER"' 'exit 2' >"$tmp/root-policy-bin/find"
chmod +x "$tmp/root-policy-bin/find"
output="$tmp/output"
find_called="$tmp/find-called"
if PATH="$tmp/root-policy-bin:$PATH" FIND_CALLED_MARKER="$find_called" \
    "$scanner" / >"$output" 2>&1; then
    fail "filesystem root: expected rejection"
fi
grep -F 'scan failure' "$output" >/dev/null 2>&1 || \
    fail "filesystem root did not report scan failure"
[ ! -e "$find_called" ] || fail "filesystem root reached filesystem inventory"

root=$(new_export grep-error)
mkdir -p "$tmp/grep-error-bin"
printf '%s\n' '#!/bin/sh' 'exit 2' >"$tmp/grep-error-bin/grep"
chmod +x "$tmp/grep-error-bin/grep"
if PATH="$tmp/grep-error-bin:$PATH" "$scanner" "$root" >"$tmp/output" 2>&1; then
    fail "grep failure: expected rejection"
fi
grep -F 'scan failure' "$tmp/output" >/dev/null 2>&1 || fail "grep failure did not report scan failure"

root=$(new_export find-error)
mkdir -p "$tmp/find-error-bin"
printf '%s\n' '#!/bin/sh' 'exit 2' >"$tmp/find-error-bin/find"
chmod +x "$tmp/find-error-bin/find"
if PATH="$tmp/find-error-bin:$PATH" "$scanner" "$root" >"$tmp/output" 2>&1; then
    fail "find failure: expected rejection"
fi
grep -F 'scan failure' "$tmp/output" >/dev/null 2>&1 || fail "find failure did not report scan failure"

echo "open-source boundary self-test passed"
