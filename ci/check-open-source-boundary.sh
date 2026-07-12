#!/usr/bin/env sh
set -eu

fail_boundary() {
    echo "error: open-source boundary violation" >&2
    exit 1
}

fail_scan() {
    echo "error: open-source boundary scan failure" >&2
    exit 2
}

usage() {
    echo "usage: check-open-source-boundary.sh [--worktree] EXPORT_ROOT" >&2
    exit 2
}

canonicalize_directory() {
    canonical_input=$1
    if canonical_with_sentinel=$(
        CDPATH='' cd -P -- "$canonical_input" 2>/dev/null &&
            printf '%s_' "$PWD"
    ); then
        :
    else
        return 1
    fi

    case $canonical_with_sentinel in
        *_) canonical_directory=${canonical_with_sentinel%_} ;;
        *) return 1 ;;
    esac
}

case $# in
    1)
        scan_mode=complete
        root_input=$1
        ;;
    2)
        [ "$1" = --worktree ] || usage
        scan_mode=worktree
        root_input=$2
        ;;
    *) usage ;;
esac

[ -d "$root_input" ] || usage
if ! canonicalize_directory "$root_input"; then
    fail_scan
fi
root=$canonical_directory
[ "$root" != / ] || fail_scan

umask 077
if ! scan_tmp=$(mktemp -d "${TMPDIR:-/tmp}/open-source-boundary.XXXXXX" 2>/dev/null); then
    fail_scan
fi

cleanup() {
    rm -rf "$scan_tmp"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

policy_is_set=0
if [ "${OPEN_SOURCE_DENYLIST_FILE+x}" = x ]; then
    policy_is_set=1
    policy_input=$OPEN_SOURCE_DENYLIST_FILE
    if [ ! -f "$policy_input" ] || [ -L "$policy_input" ] || [ ! -r "$policy_input" ]; then
        fail_scan
    fi

    case $policy_input in
        */*)
            policy_name=${policy_input##*/}
            policy_dir_input=${policy_input%/*}
            [ -n "$policy_name" ] || fail_scan
            [ -n "$policy_dir_input" ] || policy_dir_input=/
            ;;
        *)
            policy_name=$policy_input
            policy_dir_input=.
            ;;
    esac
    if ! canonicalize_directory "$policy_dir_input"; then
        fail_scan
    fi
    policy_dir=$canonical_directory
    if [ "$policy_dir" = / ]; then
        policy=/$policy_name
    else
        policy=$policy_dir/$policy_name
    fi

    case $policy in
        "$root" | "$root"/*) fail_boundary ;;
    esac
    if ! cat "$policy" >/dev/null 2>"$scan_tmp/policy-errors"; then
        fail_scan
    fi
fi

find_special_entries() (
    if ! CDPATH='' cd -P -- "$root"; then
        exit 2
    fi
    if [ "$scan_mode" = worktree ]; then
        find . \
            \( -path './.git' \( -type f -o -type d \) -prune \) -o \
            \( -path './target' -type d -prune \) -o \
            \( ! -type d ! -type f -print \)
    else
        find . ! -type d ! -type f -print
    fi
)

if find_special_entries >"$scan_tmp/special" 2>"$scan_tmp/find-errors"; then
    :
else
    fail_scan
fi
[ ! -s "$scan_tmp/special" ] || fail_boundary

run_file_exec() (
    file_script=$1
    shift
    if ! CDPATH='' cd -P -- "$root"; then
        exit 2
    fi
    if [ "$scan_mode" = worktree ]; then
        find . \
            \( -path './.git' \( -type f -o -type d \) -prune \) -o \
            \( -path './target' -type d -prune \) -o \
            \( -type f -exec sh -c "$file_script" sh "$@" {} + \)
    else
        find . -type f -exec sh -c "$file_script" sh "$@" {} +
    fi
)

run_path_exec() (
    path_script=$1
    shift
    if ! CDPATH='' cd -P -- "$root"; then
        exit 2
    fi
    if [ "$scan_mode" = worktree ]; then
        find . \
            \( -path './.git' \( -type f -o -type d \) -prune \) -o \
            \( -path './target' -type d -prune \) -o \
            \( \( -type d -o -type f \) -exec sh -c "$path_script" sh "$@" {} + \)
    else
        find . \( -type d -o -type f \) -exec sh -c "$path_script" sh "$@" {} +
    fi
)

reset_sentinels() {
    rm -f "$scan_tmp/match" "$scan_tmp/failure" || fail_scan
}

# Expanded by the child shell invoked for each file batch.
# shellcheck disable=SC2016
extension_child='
match_file=$1
failure_file=$2
shift 2
for candidate do
    case $candidate in
        *.[dD][eE][rR] | *.[kK][eE][yY] | *.[pP]12 | *.[pP][fF][xX] | *.[pP][kK]8)
            if ! : >"$match_file"; then
                : >"$failure_file" || exit 2
            fi
            ;;
    esac
done
'

reset_sentinels
if run_file_exec "$extension_child" "$scan_tmp/match" "$scan_tmp/failure" \
    >"$scan_tmp/find-output" 2>"$scan_tmp/find-errors"; then
    :
else
    fail_scan
fi
[ ! -e "$scan_tmp/failure" ] || fail_scan
[ ! -e "$scan_tmp/match" ] || fail_boundary

# Expanded by the child shell invoked for each file batch.
# shellcheck disable=SC2016
grep_child='
scan_kind=$1
expression=$2
match_file=$3
failure_file=$4
shift 4
for candidate do
    if [ "$scan_kind" = fixed ]; then
        if grep -F -- "$expression" "$candidate" >/dev/null 2>/dev/null; then
            grep_status=0
        else
            grep_status=$?
        fi
    else
        if grep -E -- "$expression" "$candidate" >/dev/null 2>/dev/null; then
            grep_status=0
        else
            grep_status=$?
        fi
    fi
    case $grep_status in
        0)
            if ! : >"$match_file"; then
                : >"$failure_file" || exit 2
            fi
            ;;
        1) ;;
        *) : >"$failure_file" || exit 2 ;;
    esac
done
'

scan_file_contents() {
    scan_kind=$1
    expression=$2
    reset_sentinels
    if run_file_exec "$grep_child" "$scan_kind" "$expression" \
        "$scan_tmp/match" "$scan_tmp/failure" \
        >"$scan_tmp/find-output" 2>"$scan_tmp/find-errors"; then
        :
    else
        fail_scan
    fi
    [ ! -e "$scan_tmp/failure" ] || fail_scan
    [ ! -e "$scan_tmp/match" ] || fail_boundary
}

# Expanded by the child shell invoked for each path batch.
# shellcheck disable=SC2016
path_child='
needle=$1
match_file=$2
failure_file=$3
shift 3
for candidate do
    [ "$candidate" != . ] || continue
    relative_path=${candidate#./}
    case $relative_path in
        *"$needle"*)
            if ! : >"$match_file"; then
                : >"$failure_file" || exit 2
            fi
            ;;
    esac
done
'

scan_relative_paths() {
    needle=$1
    reset_sentinels
    if run_path_exec "$path_child" "$needle" "$scan_tmp/match" "$scan_tmp/failure" \
        >"$scan_tmp/find-output" 2>"$scan_tmp/find-errors"; then
        :
    else
        fail_scan
    fi
    [ ! -e "$scan_tmp/failure" ] || fail_scan
    [ ! -e "$scan_tmp/match" ] || fail_boundary
}

mac_user_root='/''Users''/'
unix_user_root='/''home''/'
windows_drive='[[:alpha:]]:'
windows_separator='[\\/]'
windows_users='[Uu][Ss][Ee][Rr][Ss]'
windows_user_root=$windows_drive$windows_separator$windows_users$windows_separator
pem_begin='BEGIN '
pem_private='PRIVATE KEY'
pem_expression=$pem_begin'.*'$pem_private

scan_file_contents fixed "$mac_user_root"
scan_file_contents fixed "$unix_user_root"
scan_file_contents regex "$windows_user_root"
scan_file_contents regex "$pem_expression"

# Expanded by the child shell invoked for each file batch.
# shellcheck disable=SC2016
hash_child='
hash_tool=$1
expected_digest=$2
match_file=$3
failure_file=$4
shift 4
for candidate do
    if [ "$hash_tool" = sha256sum ]; then
        if digest_output=$(sha256sum <"$candidate" 2>/dev/null); then
            digest_status=0
        else
            digest_status=$?
        fi
    else
        if digest_output=$(shasum -a 256 <"$candidate" 2>/dev/null); then
            digest_status=0
        else
            digest_status=$?
        fi
    fi
    if [ "$digest_status" -ne 0 ]; then
        : >"$failure_file" || exit 2
        continue
    fi
    set -- $digest_output
    actual_digest=${1-}
    if [ "${#actual_digest}" -ne 64 ]; then
        : >"$failure_file" || exit 2
        continue
    fi
    case $actual_digest in
        *[!0123456789abcdef]*)
            : >"$failure_file" || exit 2
            continue
            ;;
    esac
    if [ "$actual_digest" = "$expected_digest" ]; then
        if ! : >"$match_file"; then
            : >"$failure_file" || exit 2
        fi
    fi
done
'

scan_file_digest() {
    expected_digest=$1
    if command -v sha256sum >/dev/null 2>&1; then
        hash_tool=sha256sum
    elif command -v shasum >/dev/null 2>&1; then
        hash_tool=shasum
    else
        fail_scan
    fi

    reset_sentinels
    if run_file_exec "$hash_child" "$hash_tool" "$expected_digest" \
        "$scan_tmp/match" "$scan_tmp/failure" \
        >"$scan_tmp/find-output" 2>"$scan_tmp/find-errors"; then
        :
    else
        fail_scan
    fi
    [ ! -e "$scan_tmp/failure" ] || fail_scan
    [ ! -e "$scan_tmp/match" ] || fail_boundary
}

if [ "$policy_is_set" -eq 1 ]; then
    carriage_return=$(printf '\r')
    while IFS= read -r policy_entry || [ -n "$policy_entry" ]; do
        case $policy_entry in
            *"$carriage_return") policy_entry=${policy_entry%"$carriage_return"} ;;
        esac
        [ -n "$policy_entry" ] || continue
        case $policy_entry in
            sha256:*)
                expected_digest=${policy_entry#sha256:}
                [ "${#expected_digest}" -eq 64 ] || fail_scan
                case $expected_digest in
                    *[!0123456789abcdefABCDEF]*) fail_scan ;;
                esac
                if ! expected_digest=$(printf '%s' "$expected_digest" | tr 'A-F' 'a-f'); then
                    fail_scan
                fi
                scan_file_digest "$expected_digest"
                ;;
            *)
                scan_relative_paths "$policy_entry"
                scan_file_contents fixed "$policy_entry"
                ;;
        esac
    done <"$policy"
fi

echo "open-source boundary scan passed"
