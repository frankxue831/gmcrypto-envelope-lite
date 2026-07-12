#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd)
output_dir="$repo_root/tests/public-fixtures"
lock_dir="$repo_root/tests/.public-fixtures.lock"
private_temporary=
publication_temporary=
staging_dir=
previous_output=
failed_output=
lock_owned=0
publication_started=0
publication_complete=0

path_exists() {
    [ -e "$1" ] || [ -L "$1" ]
}

fail() {
    echo "error: $*" >&2
    exit 1
}

cleanup() {
    cleanup_status=0
    publication_cleanup_status=0

    if [ -n "$private_temporary" ] && path_exists "$private_temporary"; then
        if ! rm -rf "${private_temporary:?}"; then
            echo "error: failed to remove temporary private key material" >&2
            cleanup_status=1
        fi
    fi

    if [ -n "$publication_temporary" ] && [ "$publication_complete" -eq 0 ]; then
        if path_exists "$previous_output"; then
            if path_exists "$output_dir"; then
                if ! mv "$output_dir" "$failed_output"; then
                    echo "error: failed to remove incomplete public fixture output" >&2
                    publication_cleanup_status=1
                fi
            fi

            if ! path_exists "$output_dir" && [ "$publication_cleanup_status" -eq 0 ]; then
                if ! mv "$previous_output" "$output_dir"; then
                    echo "error: failed to restore the previous public fixture output" >&2
                    publication_cleanup_status=1
                fi
            fi
        elif [ "$publication_started" -eq 1 ] && path_exists "$output_dir"; then
            if ! mv "$output_dir" "$failed_output"; then
                echo "error: failed to remove incomplete public fixture output" >&2
                publication_cleanup_status=1
            fi
        fi
    fi

    if [ -n "$publication_temporary" ] && [ "$publication_cleanup_status" -eq 0 ]; then
        if ! rm -rf "${publication_temporary:?}"; then
            echo "error: failed to remove temporary public fixture material" >&2
            publication_cleanup_status=1
        fi
    elif [ -n "$publication_temporary" ]; then
        echo "error: preserved public-only recovery material at $publication_temporary" >&2
    fi

    if [ "$publication_cleanup_status" -ne 0 ]; then
        cleanup_status=1
    fi

    if [ "$lock_owned" -eq 1 ]; then
        if rmdir "$lock_dir"; then
            lock_owned=0
        else
            echo "error: failed to release owned public fixture publication lock" >&2
            cleanup_status=1
        fi
    fi

    return "$cleanup_status"
}

on_exit() {
    exit_status=$?
    trap - 0
    trap '' HUP INT TERM

    if cleanup; then
        :
    elif [ "$exit_status" -eq 0 ]; then
        exit_status=1
    fi

    exit "$exit_status"
}

trap on_exit 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

private_temporary=$(mktemp -d)
publication_temporary=$(mktemp -d "$repo_root/tests/.public-fixtures-publish.XXXXXX")
staging_dir="$publication_temporary/public-fixtures"
previous_output="$publication_temporary/previous-output"
failed_output="$publication_temporary/failed-output"

if mkdir "$lock_dir" 2>/dev/null; then
    lock_owned=1
elif path_exists "$lock_dir"; then
    fail "public fixture publication lock already exists: $lock_dir; if no generator is running, remove the stale lock manually"
else
    fail "could not create public fixture publication lock: $lock_dir"
fi

openssl_config="$private_temporary/openssl.cnf"
{
    printf '%s\n' \
        '[ req ]' \
        'distinguished_name = public_test_subject' \
        'prompt = no' \
        '' \
        '[ public_test_subject ]' \
        'CN = Secure Envelope SDK Public Test Peer' \
        '' \
        '[ public_test_peer ]' \
        'basicConstraints = critical,CA:FALSE' \
        'keyUsage = critical,digitalSignature,keyEncipherment' \
        'subjectKeyIdentifier = hash' \
        'authorityKeyIdentifier = keyid:always'
} >"$openssl_config"

reject_unexpected_entries() {
    directory=$1

    for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
        if ! path_exists "$entry"; then
            continue
        fi

        case $entry in
            "$directory/test-peer-public.pem" | "$directory/test-peer-certificate.pem")
                if [ -L "$entry" ] || [ ! -f "$entry" ]; then
                    fail "expected public fixture is not a regular file: $entry"
                fi
                ;;
            *)
                fail "unexpected entry in public fixture directory: $entry"
                ;;
        esac
    done
}

validate_exact_fixture_set() {
    fixture_directory=$1

    for fixture in \
        "$fixture_directory/test-peer-public.pem" \
        "$fixture_directory/test-peer-certificate.pem"
    do
        if [ -L "$fixture" ] || [ ! -f "$fixture" ]; then
            fail "expected public fixture is not a regular file: $fixture"
        fi
    done

    reject_unexpected_entries "$fixture_directory"
}

scan_for_private_material() {
    fixture=$1

    if grep -E 'PRIVATE KEY|ENCRYPTED PRIVATE' "$fixture" >/dev/null; then
        fail "private key material found in public fixture: $fixture"
    else
        scan_status=$?
    fi

    case $scan_status in
        1)
            ;;
        *)
            fail "could not scan public fixture for private key material: $fixture"
            ;;
    esac
}

mkdir -p "$staging_dir"

openssl genpkey \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:SM2 \
    -out "$private_temporary/private.pem"

openssl pkey \
    -in "$private_temporary/private.pem" \
    -pubout \
    -out "$staging_dir/test-peer-public.pem"

openssl req \
    -new \
    -x509 \
    -sm3 \
    -config "$openssl_config" \
    -extensions public_test_peer \
    -key "$private_temporary/private.pem" \
    -subj "/CN=Secure Envelope SDK Public Test Peer" \
    -days 36500 \
    -out "$staging_dir/test-peer-certificate.pem"

validate_exact_fixture_set "$staging_dir"

scan_for_private_material "$staging_dir/test-peer-public.pem"
scan_for_private_material "$staging_dir/test-peer-certificate.pem"

openssl pkey \
    -pubin \
    -in "$staging_dir/test-peer-public.pem" \
    -noout

openssl x509 \
    -in "$staging_dir/test-peer-certificate.pem" \
    -noout

certificate_subject=$(openssl x509 \
    -in "$staging_dir/test-peer-certificate.pem" \
    -noout \
    -subject \
    -nameopt RFC2253)
if [ "$certificate_subject" != 'subject=CN=Secure Envelope SDK Public Test Peer' ]; then
    fail "public certificate fixture has an unexpected subject"
fi

certificate_issuer=$(openssl x509 \
    -in "$staging_dir/test-peer-certificate.pem" \
    -noout \
    -issuer \
    -nameopt RFC2253)
if [ "$certificate_issuer" != 'issuer=CN=Secure Envelope SDK Public Test Peer' ]; then
    fail "public certificate fixture has an unexpected issuer"
fi

basic_constraints=$(openssl x509 \
    -in "$staging_dir/test-peer-certificate.pem" \
    -noout \
    -ext basicConstraints)
basic_constraints_header=$(printf '%s\n' "$basic_constraints" | sed -n '1p')
basic_constraints_value=$(printf '%s\n' "$basic_constraints" | sed -n '2s/^[[:space:]]*//p')
if [ "$basic_constraints_header" != 'X509v3 Basic Constraints: critical' ] || \
    [ "$basic_constraints_value" != 'CA:FALSE' ]; then
    fail "public certificate fixture must have critical CA:FALSE basic constraints"
fi

key_usage=$(openssl x509 \
    -in "$staging_dir/test-peer-certificate.pem" \
    -noout \
    -ext keyUsage)
key_usage_header=$(printf '%s\n' "$key_usage" | sed -n '1p')
key_usage_value=$(printf '%s\n' "$key_usage" | sed -n '2s/^[[:space:]]*//p')
if [ "$key_usage_header" != 'X509v3 Key Usage: critical' ] || \
    [ "$key_usage_value" != 'Digital Signature, Key Encipherment' ]; then
    fail "public certificate fixture has an unexpected key usage"
fi

subject_key_identifier=$(openssl x509 \
    -in "$staging_dir/test-peer-certificate.pem" \
    -noout \
    -ext subjectKeyIdentifier | sed -n '2s/^[[:space:]]*//p')
authority_key_identifier=$(openssl x509 \
    -in "$staging_dir/test-peer-certificate.pem" \
    -noout \
    -ext authorityKeyIdentifier | sed -n '2s/^[[:space:]]*//p')
if [ -z "$subject_key_identifier" ] || \
    [ "$subject_key_identifier" != "$authority_key_identifier" ]; then
    fail "public certificate fixture must have matching subject and authority key identifiers"
fi

signature_algorithm=$(openssl x509 \
    -in "$staging_dir/test-peer-certificate.pem" \
    -noout \
    -text | sed -n 's/^[[:space:]]*Signature Algorithm: //p' | sed -n '1p')
if [ "$signature_algorithm" != 'SM2-with-SM3' ]; then
    fail "public certificate fixture must use SM2-with-SM3"
fi

openssl x509 \
    -in "$staging_dir/test-peer-certificate.pem" \
    -pubkey \
    -noout \
    -out "$private_temporary/certificate-public.pem"

if ! cmp -s "$staging_dir/test-peer-public.pem" "$private_temporary/certificate-public.pem"; then
    fail "public key fixture does not match certificate public key"
fi

if [ -L "$output_dir" ]; then
    fail "public fixture output path must not be a symbolic link: $output_dir"
fi

if path_exists "$output_dir"; then
    if [ ! -d "$output_dir" ]; then
        fail "public fixture output path must be a directory: $output_dir"
    fi
    reject_unexpected_entries "$output_dir"
    mv "$output_dir" "$previous_output"
fi

publication_started=1
mv "$staging_dir" "$output_dir"
validate_exact_fixture_set "$output_dir"
publication_complete=1
