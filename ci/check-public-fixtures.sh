#!/bin/sh
set -eu

# `tools/generate-public-test-fixtures.sh` asserts these invariants at the moment
# it mints the fixtures, and nothing re-checked them afterwards. A fixture edited
# by hand, regenerated with different options, or swapped in a pull request would
# keep whatever properties it happened to arrive with -- the generator's
# assertions only ever described one historical run on someone's laptop. This
# re-runs them against the committed bytes, which are what the test suite and the
# published export actually carry.

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
fixture_dir="$repo_root/tests/public-fixtures"
certificate="$fixture_dir/test-peer-certificate.pem"
public_key="$fixture_dir/test-peer-public.pem"
certificate_public_key=

fail() {
    echo "error: $*" >&2
    exit 1
}

cleanup() {
    test -z "$certificate_public_key" || rm -f -- "$certificate_public_key"
}

trap cleanup EXIT HUP INT TERM

command -v openssl >/dev/null || fail "openssl is required to check the public fixtures"

test -d "$fixture_dir" || fail "public fixture directory is missing: $fixture_dir"
test ! -L "$fixture_dir" || fail "public fixture directory must not be a symbolic link"

for path in "$certificate" "$public_key"; do
    test -e "$path" || fail "public fixture is missing: $path"
    test ! -L "$path" || fail "public fixture must be a regular file, not a symbolic link: $path"
    test -f "$path" || fail "public fixture is not a regular file: $path"
done

# The fixture set is exact. An unexpected entry here would ship bytes that no
# invariant below describes.
entries=$(ls -A "$fixture_dir" | sort | tr '\n' ' ')
test "$entries" = "test-peer-certificate.pem test-peer-public.pem " || \
    fail "unexpected entries in the public fixture directory: $entries"

# These fixtures are published; private material must never reach them.
if grep -l -e 'PRIVATE KEY' -e 'ENCRYPTED' "$certificate" "$public_key" >/dev/null 2>&1; then
    fail "public fixtures must not contain private key material"
fi

openssl pkey -pubin -in "$public_key" -noout 2>/dev/null || \
    fail "public key fixture does not parse as a public key"
openssl x509 -in "$certificate" -noout 2>/dev/null || \
    fail "certificate fixture does not parse as a certificate"

certificate_subject=$(openssl x509 -in "$certificate" -noout -subject -nameopt RFC2253)
test "$certificate_subject" = 'subject=CN=Secure Envelope SDK Public Test Peer' || \
    fail "public certificate fixture has an unexpected subject: $certificate_subject"

certificate_issuer=$(openssl x509 -in "$certificate" -noout -issuer -nameopt RFC2253)
test "$certificate_issuer" = 'issuer=CN=Secure Envelope SDK Public Test Peer' || \
    fail "public certificate fixture has an unexpected issuer: $certificate_issuer"

basic_constraints=$(openssl x509 -in "$certificate" -noout -ext basicConstraints)
basic_constraints_header=$(printf '%s\n' "$basic_constraints" | sed -n '1p')
basic_constraints_value=$(printf '%s\n' "$basic_constraints" | sed -n '2s/^[[:space:]]*//p')
if test "$basic_constraints_header" != 'X509v3 Basic Constraints: critical' || \
    test "$basic_constraints_value" != 'CA:FALSE'; then
    fail "public certificate fixture must have critical CA:FALSE basic constraints"
fi

key_usage=$(openssl x509 -in "$certificate" -noout -ext keyUsage)
key_usage_header=$(printf '%s\n' "$key_usage" | sed -n '1p')
key_usage_value=$(printf '%s\n' "$key_usage" | sed -n '2s/^[[:space:]]*//p')
if test "$key_usage_header" != 'X509v3 Key Usage: critical' || \
    test "$key_usage_value" != 'Digital Signature, Key Encipherment'; then
    fail "public certificate fixture has an unexpected key usage: $key_usage_value"
fi

subject_key_identifier=$(openssl x509 -in "$certificate" -noout \
    -ext subjectKeyIdentifier | sed -n '2s/^[[:space:]]*//p')
authority_key_identifier=$(openssl x509 -in "$certificate" -noout \
    -ext authorityKeyIdentifier | sed -n '2s/^[[:space:]]*//p')
if test -z "$subject_key_identifier" || \
    test "$subject_key_identifier" != "$authority_key_identifier"; then
    fail "public certificate fixture must have matching subject and authority key identifiers"
fi

signature_algorithm=$(openssl x509 -in "$certificate" -noout -text | \
    sed -n 's/^[[:space:]]*Signature Algorithm: //p' | sed -n '1p')
test "$signature_algorithm" = 'SM2-with-SM3' || \
    fail "public certificate fixture must use SM2-with-SM3, found: ${signature_algorithm:-none}"

certificate_public_key=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-fixture-public-key.XXXXXX") || \
    fail "could not create a certificate public key temporary file"
openssl x509 -in "$certificate" -pubkey -noout -out "$certificate_public_key" 2>/dev/null || \
    fail "could not extract the public key from the certificate fixture"
cmp -s "$public_key" "$certificate_public_key" || \
    fail "public key fixture does not match the certificate public key"

echo "public test fixture check passed"
