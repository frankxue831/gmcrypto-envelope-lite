#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
fixture_root=

fail() {
    echo "error: $*" >&2
    exit 1
}

make_fixture() {
    fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/secure-envelope-inventory-test.XXXXXX")
    fixture="$fixture_root/repo"
    mkdir -p "$fixture"
    cp "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" "$fixture/"
    cp -R "$repo_root/src" "$repo_root/docs" "$repo_root/ci" "$fixture/"
    output=$("$fixture/ci/check-crypto-inventory.sh" 2>&1) || fail "unmodified fixture checker failed: $output"
}

cleanup_fixture() {
    test -z "$fixture_root" || rm -rf -- "$fixture_root"
    fixture_root=
}

expect_contains() {
    file=$1
    marker=$2
    grep -F -- "$marker" "$file" >/dev/null || fail "expected mutation marker is missing: $marker"
}

expect_failure() {
    description=$1
    diagnostic=$2
    if output=$("$fixture/ci/check-crypto-inventory.sh" 2>&1); then
        fail "$description was accepted"
    fi
    printf '%s\n' "$output" | grep -F "$diagnostic" >/dev/null ||
        fail "$description failed without expected diagnostic: $diagnostic; output: $output"
}

replace_text() {
    file=$1
    old=$2
    new=$3
    sed "s/$old/$new/" "$file" >"$fixture/replacement.tmp"
    mv "$fixture/replacement.tmp" "$file"
    expect_contains "$file" "$new"
}

trap 'cleanup_fixture' EXIT HUP INT TERM

make_fixture
replace_text "$fixture/docs/security/cryptographic-dependencies.md" \
    'Backend registry checksum: `4e81a6030cdbef95407ef7924aa2b60469d1263e094b667295cd3d787c2c3095`' \
    'Backend registry checksum: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`'
expect_failure "altered documented backend checksum" "gmcrypto-core registry checksum differs from the inventory"
cleanup_fixture

make_fixture
replace_text "$fixture/docs/security/cryptographic-dependencies.md" \
    'Reviewed Cargo.lock SHA-256: `cb0ee0fc8572307aeccea2a43815e461b52e626d9e077130f335232af0736feb`' \
    'Reviewed Cargo.lock SHA-256: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`'
expect_failure "stale documented lock hash" "Cargo.lock differs from the reviewed inventory"
cleanup_fixture

make_fixture
printf '%s\n' 'unexpected|0.0.0|none|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|reviewed-no-unsafe-source' >>"$fixture/ci/crypto-inventory.snapshot"
expect_contains "$fixture/ci/crypto-inventory.snapshot" 'unexpected|0.0.0|none'
expect_failure "unexpected reviewed package data" "human-readable cryptographic dependency table is invalid"
cleanup_fixture

make_fixture
replace_text "$fixture/ci/crypto-inventory.snapshot" \
    'ctutils|0.4.2|default,subtle|' \
    'ctutils|0.4.2|subtle|'
expect_failure "altered reviewed feature data" "human-readable cryptographic dependency table differs from the reviewed snapshot"
cleanup_fixture

make_fixture
printf '%s\n' '- Backend registry checksum: `d93a065728aef78f84e82e2b3de88dc9ef8d504b35351657b0000ee9fe682d6d`' >>"$fixture/docs/security/cryptographic-dependencies.md"
expect_contains "$fixture/docs/security/cryptographic-dependencies.md" '- Backend registry checksum:'
expect_failure "duplicate backend checksum field" "inventory has no single Backend registry checksum field"
cleanup_fixture

make_fixture
printf '%s\n' '- Reviewed Cargo.lock SHA-256: `c0bf1eb1197d63c32e09abb007436a9998a698072facfe1fd4815fe2cffacf3e`' >>"$fixture/docs/security/cryptographic-dependencies.md"
expect_contains "$fixture/docs/security/cryptographic-dependencies.md" '- Reviewed Cargo.lock SHA-256:'
expect_failure "duplicate lock hash field" "inventory has no single Cargo.lock SHA-256 field"
cleanup_fixture

make_fixture
replace_text "$fixture/docs/security/cryptographic-dependencies.md" \
    '| `ctutils` | `0.4.2` |' \
    '| `ctutils` | `0.4.9` |'
expect_failure "doc-only dependency version drift" "human-readable cryptographic dependency table differs from the reviewed snapshot"
cleanup_fixture

make_fixture
replace_text "$fixture/docs/security/cryptographic-dependencies.md" \
    '| `ctutils` | `0.4.2` | `default`, `subtle` |' \
    '| `ctutils` | `0.4.2` | `subtle` |'
expect_failure "doc-only dependency feature drift" "human-readable cryptographic dependency table differs from the reviewed snapshot"
cleanup_fixture

make_fixture
replace_text "$fixture/docs/security/cryptographic-dependencies.md" \
    '`72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6`' \
    '`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`'
expect_failure "doc-only dependency checksum drift" "human-readable cryptographic dependency table differs from the reviewed snapshot"
cleanup_fixture

make_fixture
replace_text "$fixture/docs/security/cryptographic-dependencies.md" \
    '| reviewed: no unsafe source | Standard-padded encoded envelope fields' \
    '| reviewed: unsafe source present | Standard-padded encoded envelope fields'
expect_failure "doc-only unsafe status drift" "human-readable cryptographic dependency table differs from the reviewed snapshot"
cleanup_fixture

make_fixture
replace_text "$fixture/ci/crypto-inventory.snapshot" \
    '|reviewed-no-unsafe-source' \
    '|reviewed-unsafe-present'
expect_failure "snapshot-only unsafe status drift" "human-readable cryptographic dependency table differs from the reviewed snapshot"
cleanup_fixture

make_fixture
printf '%s\n' '| malformed | row | with | invalid | fields | extra |' >>"$fixture/docs/security/cryptographic-dependencies.md"
expect_contains "$fixture/docs/security/cryptographic-dependencies.md" '| malformed | row |'
expect_failure "malformed human-readable dependency row" "human-readable cryptographic dependency table is invalid"
cleanup_fixture

make_fixture
rm "$fixture/ci/crypto-inventory-aead.snapshot"
test ! -e "$fixture/ci/crypto-inventory-aead.snapshot" || \
    fail "AEAD snapshot removal mutation did not apply"
expect_failure "missing AEAD snapshot" "AEAD cryptographic dependency snapshot is missing"
cleanup_fixture

make_fixture
replace_text "$fixture/ci/crypto-inventory-aead.snapshot" \
    'cpufeatures|0.2.17|default|59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280|' \
    'cpufeatures|0.2.17|default|aaaa|'
expect_failure "invalid AEAD snapshot checksum" "AEAD cryptographic dependency snapshot has an invalid row"
cleanup_fixture

make_fixture
replace_text "$fixture/ci/crypto-inventory-aead.snapshot" \
    'gmcrypto-simd|1.11.0|none|' \
    'unexpected-simd|1.11.0|none|'
expect_failure "unexpected AEAD package name" "AEAD cryptographic dependency snapshot has missing or unexpected packages"
cleanup_fixture

make_fixture
replace_text "$fixture/ci/crypto-inventory-aead.snapshot" \
    'gmcrypto-simd|1.11.0|none|' \
    'gmcrypto-simd|1.12.0|none|'
replace_text "$fixture/docs/security/cryptographic-dependencies.md" \
    '| `gmcrypto-simd` | `1.11.0` | `none` |' \
    '| `gmcrypto-simd` | `1.12.0` | `none` |'
expect_failure "re-versioned AEAD package" "AEAD cryptographic dependency snapshot has missing, unexpected, or re-versioned packages"
cleanup_fixture

make_fixture
replace_text "$fixture/ci/crypto-inventory-aead.snapshot" \
    'gmcrypto-core|1.11.0|default,sm4-aead,x509|' \
    'gmcrypto-core|1.11.0|default,x509|'
expect_failure "AEAD snapshot feature drift" "human-readable cryptographic dependency table differs from the reviewed snapshot"
cleanup_fixture

make_fixture
replace_text "$fixture/docs/security/cryptographic-dependencies.md" \
    '| `gmcrypto-simd` | `1.11.0` | `none` |' \
    '| `gmcrypto-simd` | `1.11.0` | `default` |'
expect_failure "doc-only AEAD feature drift" "human-readable cryptographic dependency table differs from the reviewed snapshot"
cleanup_fixture

make_fixture
replace_text "$fixture/ci/crypto-inventory-aead.snapshot" \
    'cpufeatures|0.2.17|default|' \
    'cpufeatures|0.2.17|none|'
replace_text "$fixture/docs/security/cryptographic-dependencies.md" \
    '| `cpufeatures` | `0.2.17` | `default` |' \
    '| `cpufeatures` | `0.2.17` | `none` |'
expect_failure "resolved AEAD feature drift" "resolved AEAD cryptographic dependency package, feature, or checksum differs from the reviewed snapshot"
cleanup_fixture

make_fixture
replace_text "$fixture/ci/crypto-inventory-aead.snapshot" \
    '59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
replace_text "$fixture/docs/security/cryptographic-dependencies.md" \
    '59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
expect_failure "resolved AEAD checksum drift" "resolved AEAD cryptographic dependency package, feature, or checksum differs from the reviewed snapshot"
cleanup_fixture

make_fixture
replace_text "$fixture/Cargo.toml" \
    'aead = \["gmcrypto-core\/sm4-aead"\]' \
    'aead = []'
expect_failure "altered aead feature definition" "aead feature definition changed"
cleanup_fixture

echo "cryptographic inventory negative tests passed"
