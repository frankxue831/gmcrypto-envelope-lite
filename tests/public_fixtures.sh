#!/bin/sh
set -eu

# Negative tests for ci/check-public-fixtures.sh. The checker exists to catch a
# fixture that was edited, regenerated differently, or swapped out, so every one
# of its refusals needs a case here: a checker whose failure paths are never
# exercised is indistinguishable from one that always passes.

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/secure-envelope-public-fixtures-test.XXXXXX")
fixture_dir="$fixture/tests/public-fixtures"
checker="$fixture/ci/check-public-fixtures.sh"

cleanup() {
    chmod -R u+w "$fixture" 2>/dev/null || true
    rm -rf "$fixture"
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

reset_fixtures() {
    rm -rf "$fixture/tests"
    mkdir -p "$fixture_dir"
    cp "$repo_root/tests/public-fixtures/test-peer-certificate.pem" \
        "$repo_root/tests/public-fixtures/test-peer-public.pem" \
        "$fixture_dir/"
}

# Runs the checker, returning its exit status and capturing both streams.
run_checker() {
    label=$1
    "$checker" >"$fixture/$label.out" 2>"$fixture/$label.err"
}

expect_rejection() {
    label=$1
    message=$2
    if run_checker "$label"; then
        fail "$label unexpectedly succeeded"
    fi
    assert_contains "$fixture/$label.err" "$message"
}

mkdir -p "$fixture/ci"
cp "$repo_root/ci/check-public-fixtures.sh" "$checker"
chmod +x "$checker"

reset_fixtures
if ! run_checker pristine; then
    cat "$fixture/pristine.err" >&2
    fail "pristine committed fixtures unexpectedly failed the checker"
fi
assert_contains "$fixture/pristine.out" "public test fixture check passed"

reset_fixtures
rm -rf "$fixture/tests"
expect_rejection missing_directory "public fixture directory is missing"

reset_fixtures
rm "$fixture_dir/test-peer-certificate.pem"
expect_rejection missing_certificate "public fixture is missing"

reset_fixtures
printf 'stray\n' >"$fixture_dir/unexpected.pem"
expect_rejection unexpected_entry "unexpected entries in the public fixture directory"

reset_fixtures
rm "$fixture_dir/test-peer-public.pem"
ln -s "$fixture_dir/test-peer-certificate.pem" "$fixture_dir/test-peer-public.pem"
expect_rejection symlinked_fixture "must be a regular file, not a symbolic link"

# A published fixture carrying private material is the failure that matters most.
# The header is assembled from parts so this file does not itself trip the
# open-source boundary scanner, which rejects a literal PEM private-key header
# anywhere in the tree; ci/check-open-source-boundary.sh splits the same literal
# for the same reason.
reset_fixtures
pem_begin='BEGIN '
pem_private='PRIVATE KEY'
{
    printf -- '-----%s%s-----\n' "$pem_begin" "$pem_private"
    printf 'bm90LWEtcmVhbC1rZXk=\n'
    printf -- '-----END %s-----\n' "$pem_private"
} >>"$fixture_dir/test-peer-public.pem"
expect_rejection private_material "must not contain private key material"

reset_fixtures
printf 'not a certificate\n' >"$fixture_dir/test-peer-certificate.pem"
expect_rejection unparseable_certificate "does not parse as a certificate"

reset_fixtures
printf 'not a public key\n' >"$fixture_dir/test-peer-public.pem"
expect_rejection unparseable_public_key "does not parse as a public key"

# A public key that parses cleanly but belongs to a different key pair: the
# generator compared these at mint time, so nothing else would notice a swap.
reset_fixtures
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$fixture/other-private.pem" 2>/dev/null || \
    fail "could not generate a differing key pair for the mismatch case"
openssl pkey -in "$fixture/other-private.pem" -pubout \
    -out "$fixture_dir/test-peer-public.pem" 2>/dev/null || \
    fail "could not write a differing public key for the mismatch case"
expect_rejection mismatched_public_key "does not match the certificate public key"

reset_fixtures
if ! run_checker restored; then
    cat "$fixture/restored.err" >&2
    fail "checker did not pass again after the fixtures were restored"
fi

echo "public fixture checker negative tests passed"
