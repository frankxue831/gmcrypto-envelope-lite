# SM4-GCM AEAD Envelope Mode Design

**Status:** Approved on 2026-08-02

**Date:** 2026-08-02

**Target repository:** this repository (`gmcrypto-envelope-lite`)

**Target version:** 0.2.0

## 1. Purpose

Add an authenticated-encryption envelope mode built on SM4-GCM, behind an opt-in `aead` feature, so that new integrations get ciphertext integrity from the payload cipher itself rather than from the SM2 signature alone.

The mode is additive. The SM4-CBC envelope and `AuthenticationMode::LegacyPlaintext` remain first-class and supported indefinitely, because they are this crate's compatibility surface with deployed protocols. Documentation steers new integrations toward AEAD; nothing steers existing ones away from CBC.

This phase produces a specification only. It does not change code, does not publish anything, and does not make the repository public.

## 2. Current baseline

Facts verified at design time against commit `8c59c06` with GitHub Actions CI run 30736644656 green on that exact commit and a clean working tree:

- The envelope is `SecureEnvelope { cipher, wrapped_session_key, signature }` — three standard-padded Base64 strings.
- `envelope_crypto::seal` draws a fresh random 16-byte session key per envelope, encrypts with `sm4::mode_cbc` under a fixed configured IV, SM2-wraps the session key to `keys.remote_encryption`, and SM2-signs `authentication_mode().authentication_input(context, plaintext)` with `keys.local_signing`.
- `envelope_crypto::open` bounds the encoded and decoded ciphertext, unwraps the session key, CBC-decrypts, re-bounds the plaintext, then verifies the SM2 signature. Every inbound failure collapses to `Error::InvalidEnvelope`.
- `AuthenticationMode` has two variants: `LegacyPlaintext` (signs the exact plaintext) and `ContextBound { domain_separator }` (signs a version-1 transcript of domain separator, protocol context, and plaintext, each `u64` big-endian length-prefixed by `auth::push_field`).
- `KeyMaterial` assigns four directional roles: `local_signing`, `local_decryption`, `remote_verification`, `remote_encryption`.
- `ClientConfig` requires `iv`, `authentication_mode`, both signer IDs, and the five identity fields; `max_plaintext_bytes` defaults to 16 MiB.
- `gmcrypto-core` 1.11.0 is consumed as `{ version = "1.11", features = ["x509"] }`. Its `sm4-aead` feature is off.
- `gmcrypto-core`'s AEAD API under `sm4-aead`:
  - `sm4::mode_gcm::encrypt(key: &[u8; 16], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Option<(Vec<u8>, [u8; 16])>`
  - `sm4::mode_gcm::decrypt(key, nonce, aad, ciphertext, tag: &[u8; 16]) -> Option<Vec<u8>>`, which verifies the tag **before** performing CTR decryption, so no failure-path plaintext is ever materialized.
  - `sm4::mode_ccm::{encrypt, decrypt}` with a combined `ciphertext ‖ tag` buffer; CCM's CBC-MAC pass requires plaintext, so it must decrypt before verifying.
- `sm4-aead` is defined as `["dep:gmcrypto-simd"]` and is atomic: it cannot be narrowed to GCM only or CCM only.
- Enabling `sm4-aead` adds exactly two packages to `Cargo.lock`: `gmcrypto-simd` 1.11.0 (`31a7928890d12bd4064aba2664435fc62b2a6a487f8c2611d26856f31d5ceca4`) and `cpufeatures` 0.2.17 (`59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280`, which depends on the already-locked `libc`). Verified by probing a `git archive` copy of the tree in a scratch directory.
- Both packages enter `Cargo.lock` when the feature is merely **declared**, even while it is off, because Cargo locks the maximal feature graph. Compilation of their code still requires `--features aead`.
- `gmcrypto-simd` 1.11.0 is `MIT OR Apache-2.0` (accepted by `deny.toml`), sets `unsafe_code = "warn"` rather than `forbid`, and contains roughly 51 unsafe occurrences across AVX2/NEON SM4 S-box and GHASH `clmul`/`pmull` backends. `cpufeatures` 0.2.17 is `MIT OR Apache-2.0` with roughly 9 unsafe occurrences. Both classify as `reviewed-unsafe-present`.
- `sm4::mode_gcm`'s GHASH multiplication calls `gmcrypto_simd::ghash::ghash_mul`; `sm4::mode_ccm` does not use the SIMD crate.
- `ci/check-crypto-inventory.sh` hardcodes a `boundary_packages` list with exact `package@version` pairs and greps for the literal manifest line `gmcrypto-core = { version = "1.11", features = ["x509"] }`.
- `ci/check-public-api.sh` runs `cargo public-api -ss` with default features against the single snapshot `api/gmcrypto-envelope-lite-0.1.0.txt`.
- CI runs `cargo test --all-targets --locked` with default features on three platforms plus a 1.85 MSRV job.
- `deny.toml` sets `[graph] all-features = true`, so `cargo deny check` will resolve the AEAD graph as soon as the feature exists.
- `ci/check-open-source-boundary.sh` scans for special files, private-looking paths, PEM private keys, and denylist entries. Nothing in this design requires changing it.

## 3. Goals

- Ship SM4-GCM authenticated encryption behind an opt-in `aead` feature.
- Keep the SM4-CBC envelope and `AuthenticationMode::LegacyPlaintext` unchanged, supported, and fully tested.
- Pin the envelope mode in `ClientConfig` so it is never inferred from incoming bytes, with no negotiation and no fallback.
- Leave `SecureEnvelope`, `ProtocolAdapter`, and `HeaderSchema` structurally unchanged so existing adapters and deployed header mappings keep working.
- Extend the cryptographic dependency inventory to represent the AEAD-only packages as a distinct, feature-scoped boundary.
- Preserve the invariant that unverified or oversize plaintext is never returned, and that every inbound failure is an indistinguishable `Error::InvalidEnvelope`.

## 4. Non-goals

- SM4-CCM. The wire format reserves an algorithm identifier for it; no CCM code ships in 0.2.0.
- Replay protection, freshness, and request/response correlation. These remain application concerns, as under CBC.
- Streaming or incremental AEAD. The envelope stays single-shot over a bounded plaintext.
- Changing `KeyMaterial`, key roles, or key loading.
- Changing the SM2 signature's role. It is not replaced by the AEAD tag.
- Making the repository public, publishing to crates.io, or altering boundary-scanner behavior.
- Re-litigating the three settled pillars: additive, CBC stays first-class, no downgrade surface.

## 5. Design principles

### 5.1 Additive by construction, not by promise

The AEAD payload is framed inside the existing `cipher` field rather than added as a fourth envelope field. A fourth field would have required a new nonce/tag header in `HeaderSchema` and a corresponding change in every deployed adapter mapping. Framing inside `cipher` keeps the additive property structural.

### 5.2 The mode is a configuration fact, not a wire fact

`ClientConfig` alone determines whether a client seals and opens AEAD or CBC. Inbound bytes never select a code path. An AEAD client rejects a CBC envelope; a CBC client rejects an AEAD envelope. There is no negotiation, no sniffing, and no fallback.

### 5.3 Orthogonal axes stay orthogonal

`AuthenticationMode` governs what the signature covers. The envelope mode governs how the payload is encrypted. Folding AEAD into `AuthenticationMode` would have coupled two independent decisions and forced AEAD to imply a particular signature transcript.

### 5.4 Fail closed and indistinguishably

Frame parse failures, tag failures, signature failures, and bound violations all return `Error::InvalidEnvelope`. No new error variant is introduced, so the AEAD path cannot become an oracle that the CBC path is not.

### 5.5 Bind what is not already bound

AAD contents are justified individually. Fields already bound by an existing mechanism are excluded rather than duplicated (see §7.2); the one deliberate redundancy is the nonce, which is authenticated again only because it rides inside the frame header (§7.1).

## 6. Wire format

### 6.1 AEAD cipher frame

Under `EnvelopeMode::Aead`, the `cipher` field carries standard-padded Base64 of:

```
offset  size  field
0       1     frame version   = 0x01
1       1     algorithm id    = 0x01 (SM4-GCM-128, 12-byte nonce, 16-byte tag)
2       12    nonce
14      n     ciphertext      (n == plaintext length; GCM adds no padding)
14+n    16    tag
```

Constants: `AEAD_FRAME_HEADER_BYTES = 14`, `AEAD_NONCE_BYTES = 12`, `AEAD_TAG_BYTES = 16`, `AEAD_FRAME_OVERHEAD_BYTES = 30`. The minimum valid frame is 30 bytes, corresponding to empty plaintext.

`wrapped_session_key` and `signature` are unchanged: an SM2-encrypted 16-byte session key and an SM2/SM3 signature, both Base64.

### 6.2 Algorithm identifier

`0x01` is SM4-GCM-128. `0x02` is reserved for SM4-CCM and is rejected in 0.2.0. Unknown identifiers are rejected. The identifier exists so that CCM can be added later without a format break; it is **not** a negotiation field. A client accepts only the identifier its configuration pins.

### 6.3 Rejecting the other mode

An AEAD client applies, in order: length at least 30, `frame[0] == 0x01`, `frame[1] ==` the configured algorithm identifier. A CBC ciphertext is a multiple of 16 bytes of SM4 output with no structure at those offsets, so it fails the frame check with overwhelming probability and fails the tag check otherwise. A CBC client fed an AEAD frame decrypts garbage, fails PKCS#7 unpadding or the plaintext bound, and otherwise fails signature verification. Both directions yield `Error::InvalidEnvelope`.

## 7. Additional authenticated data

### 7.1 Contents

```
AAD = len | b"gmcrypto-envelope-lite/aead-aad/v1"
    | len | frame_header                 (the 14 bytes of §6.1: version, algorithm id, nonce)
    | len | domain_separator             (empty under LegacyPlaintext)
    | len | protocol_context             (empty under LegacyPlaintext)
```

Each `len` is a `u64` big-endian byte length, using the same `auth::push_field` helper as the signed transcript. The leading domain label keeps an AAD from ever being confusable with a `ContextBound` signed transcript; structurally, an AAD also always begins with `0x00` (the high byte of the label length) while a version-1 transcript begins with `0x01`. The nonce inside the frame header is already bound by GCM itself through counter derivation; authenticating the 14-byte header as one unit is simply cheaper and less error-prone than excising 12 bytes of it, and the redundancy is harmless.

The AAD is computed by a new `AuthenticationMode::aead_aad(&self, context, frame_header)`, which mirrors `authentication_input`'s mode/context matching exactly: `LegacyPlaintext` requires a legacy context, `ContextBound` requires a bound context, and any mismatch is `Error::AuthenticationContext`. This is what makes AEAD compose with both authentication modes without either mode silently accepting the other's context.

### 7.2 What is deliberately excluded, and why

- **Signer IDs.** SM2 `verify_with_id` folds the signer ID into ZA, so the sender's identity is already bound to the signature. The recipient is already bound because the session key is SM2-encrypted to exactly one public key. Reflecting an A-to-B envelope back to A already fails on ZA mismatch. Adding signer IDs to the AAD would duplicate existing binding.
- **The signature.** It is verified independently on the same open path. Binding it into the tag converts one hard failure into a different hard failure and adds an ordering dependency for no gain.
- **Certificate identifiers.** `SecureClient::open_response` already rejects a mismatched remote signing-certificate claim before any cryptographic work.

## 8. Nonce strategy

A fresh 12-byte nonce is drawn from `getrandom` for every seal and carried in the frame.

Nonce uniqueness is already guaranteed by a different mechanism: every seal draws a fresh random session key, so `(key, nonce)` cannot repeat even with a constant nonce. The random nonce is defense in depth, because the failure it guards against — GCM keystream reuse under a repeated `(key, nonce)` pair — is catastrophic, silent, and would be introduced by any future change that reuses a session key.

The nonce is carried in the frame rather than inside the SM2-wrapped blob, so `wrapped_session_key` stays exactly 16 bytes and the existing unwrap-length check is unchanged. GCM nonces are public by design; there is nothing to gain by hiding it.

The 12-byte length is GCM's canonical nonce per NIST SP 800-38D, which avoids the extra GHASH derivation that non-canonical lengths require.

## 9. Public API

All AEAD API is behind `#[cfg(feature = "aead")]`.

### 9.1 New types

```rust
#[non_exhaustive]
pub enum EnvelopeMode {
    LegacyCbc,
    Aead(AeadAlgorithm),
}

#[non_exhaustive]
pub enum AeadAlgorithm {
    Sm4Gcm,
}
```

Both derive `Clone, Copy, Debug, PartialEq, Eq`. Neither type exists without the feature: with `aead` off, `ClientConfig` has no `envelope_mode` field, accessor, or builder method. `cargo public-api` output carries no version strings, so the 0.2.0 default-feature snapshot must be byte-identical in content to the 0.1.0 snapshot; only its filename changes.

### 9.2 `ClientConfig`

- New accessor `envelope_mode(&self) -> EnvelopeMode`.
- New builder method `envelope_mode(self, value: EnvelopeMode)`.
- Default is `LegacyCbc`, so every existing configuration builds and behaves identically.
- Validation rule: setting `iv` together with `EnvelopeMode::Aead` is `Error::Configuration { field: "iv" }`. The fixed IV is meaningless under GCM, and silently ignoring a set field invites the belief that it still protects something.
- Validation rule: `EnvelopeMode::LegacyCbc` continues to require `iv`, unchanged.

### 9.3 `SecureClient`

Unchanged. `seal`, `open`, `build_request`, `build_json_request`, `open_response`, and `open_json_response` keep their exact signatures. The mode is read from configuration, which is what keeps the downgrade surface closed.

### 9.4 `Error`

Unchanged. No new variant. All AEAD failures map to existing variants: `InvalidEnvelope` for inbound failures, `Encryption` for outbound randomness or encryption failures, `MessageTooLarge` for the encoded-input bound, `AuthenticationContext` for mode/context mismatch, `Configuration` for builder misuse.

### 9.5 `KeyMaterial`

Unchanged. AEAD alters the payload cipher, not key roles. The session key is still SM2-wrapped to `remote_encryption`; the signature is still produced by `local_signing` and verified against `remote_verification`.

## 10. Data flow

### 10.1 Seal, AEAD mode

1. Reject plaintext over `max_plaintext_bytes` with `MessageTooLarge`.
2. Build the signed transcript via `authentication_mode().authentication_input(context, plaintext)`; a mode/context mismatch is `AuthenticationContext`.
3. Draw a fresh 16-byte session key and a fresh 12-byte nonce; both failures are `Encryption`.
4. Assemble the 14-byte frame header and compute the AAD via `aead_aad`.
5. `sm4::mode_gcm::encrypt(&session_key, &nonce, &aad, plaintext)`; `None` is `Encryption`.
6. SM2-wrap the session key to `remote_encryption`; SM2-sign the transcript with `local_signing`.
7. Emit `cipher = Base64(frame_header ‖ ciphertext ‖ tag)`, plus the wrapped key and signature.

### 10.2 Open, AEAD mode

1. Bound the encoded `cipher` length against `base64_len(max_plaintext_bytes + 30)`, computed with the same checked, saturating arithmetic as the existing CBC bound helpers; over-bound is `MessageTooLarge`.
2. Bound the auxiliary encoded fields; strict-decode all three fields. Any failure is `InvalidEnvelope`.
3. Reject a decoded frame shorter than 30 bytes, a frame version other than `0x01`, or an algorithm identifier other than the configured one.
4. Reject a ciphertext body longer than `max_plaintext_bytes`.
5. SM2-unwrap the session key; reject a length other than 16.
6. Recompute the AAD from the received frame header and the caller-supplied context; a mode/context mismatch maps to `InvalidEnvelope`, exactly as the CBC open path maps `authentication_input` failures.
7. `sm4::mode_gcm::decrypt(...)`; `None` is `InvalidEnvelope`. Core verifies the tag before decrypting, so no plaintext exists on this failure path.
8. Verify the SM2 signature over `authentication_input(context, plaintext)` against `remote_verification` and `expected_remote_signer_id`.
9. Only then return the plaintext.

Step 7 preceding step 8 is intentional and preserves the existing invariant: nothing that failed authentication is returned, and the AEAD tag is checked before the plaintext is materialized at all.

Throughout both flows the session key, any materialized plaintext, and the signed transcript remain under `Zeroizing` guards, matching the CBC path.

### 10.3 Module organization

`src/envelope_crypto.rs` is already 872 lines, most of it tests. Rather than growing one module further, split it:

- `src/envelope_crypto/mod.rs` — shared bounds, Base64 helpers, session-key generation, SM2 wrap/unwrap and sign/verify, and the mode dispatch in `seal`/`open`.
- `src/envelope_crypto/cbc.rs` — the CBC payload path, moved unchanged.
- `src/envelope_crypto/aead.rs` — the AEAD payload path and frame codec, behind `#[cfg(feature = "aead")]`.

Each payload module exposes the same narrow internal interface: encrypt plaintext into a payload, and decrypt a payload into plaintext. The dispatch layer owns everything the two modes share, so neither mode can drift on bounds checking or key handling.

## 11. Dependency boundary and the inventory re-review

Turning on `sm4-aead` trips `ci/check-crypto-inventory.sh` by design. The re-review is part of implementation, not a follow-up.

### 11.1 Two-tier boundary

The inventory becomes two scoped boundaries:

- **Default boundary** — the twelve packages compiled under default features. Its table and `ci/crypto-inventory.snapshot` keep their current meaning, including the statement that no SIMD unsafe is compiled into a default build.
- **AEAD boundary** — the resolution delta under `--features aead`: `gmcrypto-simd` 1.11.0 and `cpufeatures` 0.2.17, both `reviewed-unsafe-present`, plus an **overriding `gmcrypto-core` row**, because its resolved enabled-feature set becomes `default`, `sm4-aead`, `x509` under the feature (same registry checksum, same `reviewed: no unsafe source` status — the unsafe SIMD code is precisely what `gmcrypto-simd` quarantines out of it). Recorded in a new `ci/crypto-inventory-aead.snapshot` and a matching second table in `docs/security/cryptographic-dependencies.md`. Without the override row, an overlay check would fail on `gmcrypto-core`'s feature column, since the default snapshot records `default,x509`.

Keeping them separate preserves a claim that a flat table would blur: the default build's compiled cryptographic boundary still contains no SIMD unsafe code.

### 11.2 Checker changes

`ci/check-crypto-inventory.sh` becomes feature-aware while keeping its single CI entry point:

- One invocation of `./ci/check-crypto-inventory.sh` performs two resolution passes in sequence. The default pass validates the default boundary against `ci/crypto-inventory.snapshot` exactly as today. The AEAD pass resolves `cargo tree --locked -e features --features aead` and validates it against the **overlay** of the AEAD snapshot on the default snapshot: two rows added, and the `gmcrypto-core` row replaced by its aead-resolved feature set. The AEAD snapshot is never validated in isolation, because its packages never appear without the default twelve.
- The existing manifest grep for `gmcrypto-core = { version = "1.11", features = ["x509"] }` stays as-is — that line does not change — and the script gains a companion grep asserting the feature definition is exactly `aead = ["gmcrypto-core/sm4-aead"]`. The `boundary_packages` list is split into a default list and an AEAD-only list.
- The `Reviewed Cargo.lock SHA-256` field is refreshed once, since the lockfile changes even for default builds.

### 11.3 What the inventory must say

The `gmcrypto-core` row keeps `reviewed: no unsafe source`, which stays true of that package. The narrative section gains an entry recording:

- that `sm4-aead` is atomic and pulls `gmcrypto-simd`, which is `unsafe_code = "warn"` and quarantines the AVX2/NEON and GHASH `clmul`/`pmull` code that lets `gmcrypto-core` keep `forbid`;
- that both new packages are locked unconditionally but compiled only under `--features aead`;
- that the source-scan status is scoped to the exact registry checksums recorded, and is not an audit or a safety proof;
- that no constant-time claim is made for the SIMD backends.

`deny.toml` needs no change: both licenses are already allowed, and `[graph] all-features = true` means `cargo deny check` will cover the AEAD graph automatically.

`ci/check-open-source-boundary.sh` needs no change.

## 12. Feature gate and build matrix

The feature is named `aead`:

```toml
[features]
default = []
aead = ["gmcrypto-core/sm4-aead"]
```

It is named `aead` rather than `sm4-aead` because it gates SDK API in addition to forwarding a backend feature, and the shorter name reads correctly at the call site.

CI additions:

- `cargo test --all-targets --locked --features aead` on all three platforms and on the 1.85 MSRV job.
- `cargo clippy --all-targets --locked --features aead -- -D warnings`.
- `cargo doc` and doctests run for both feature states.
- A second public API snapshot, `api/gmcrypto-envelope-lite-0.2.0-aead.txt`, generated with `--features aead`; `ci/check-public-api.sh` verifies both snapshots and both filenames follow the 0.2.0 bump.
- The feature-aware inventory check from §11.2.

## 13. Testing strategy

TDD throughout: each behavior below is expressed as a failing test before its implementation.

### 13.1 Known-answer tests

SM4-GCM known-answer vectors added to `tests/standard_vectors.rs` under the feature, following the file's convention of naming each test after its published source. The vector is RFC 8998 Appendix A.1 — key `0123456789ABCDEFFEDCBA9876543210`, 12-byte IV, 20-byte AAD, 64-byte patterned plaintext, full 16-byte tag — which `gmcrypto-core` 1.11.0 reproduces byte-for-byte (verified at design time against the published ciphertext and tag). GB/T appendices do not cover GCM. Structural cases without a published vector — empty plaintext, unaligned lengths, empty AAD — belong to the round-trip and negative suites of §13.2 and §13.3, not to invented constants. The vector pins the algorithm independently of our framing.

### 13.2 Round-trip and composition

- Round trip in both directions with distinct directional roles, mirroring the existing CBC test.
- Round trip under `LegacyPlaintext` and under `ContextBound`.
- Exact UTF-8 preservation, empty plaintext, and the configured plaintext boundary.
- Every seal produces a distinct session key, nonce, and ciphertext for identical plaintext.
- `ContextBound` domain separator and protocol context are covered by the AAD: a mismatch on either side fails.
- A wrong context *kind* fails with `AuthenticationContext` outbound and `InvalidEnvelope` inbound.

### 13.3 Negative tests

Each returns `InvalidEnvelope` and is indistinguishable from the others:

- Tag tampering, including a truncated tag and an all-zero tag.
- Ciphertext tampering at the first, middle, and last byte.
- Nonce tampering.
- Frame version tampering, algorithm identifier tampering, and the reserved `0x02` CCM identifier.
- Frames of 29 bytes and below, and a frame truncated mid-tag.
- Non-canonical or invalid Base64 in any of the three fields.
- Malformed and wrong-length wrapped session keys.
- Wrong decryption key, wrong verification key, tampered signature.
- Encoded and decoded ciphertext over the configured bound, including the `MessageTooLarge` versus `InvalidEnvelope` split at the encoded bound.
- Opening an envelope sealed under a larger `max_plaintext_bytes` than the opener allows.

### 13.4 Downgrade tests

These are the tests that prove pillar three:

- An AEAD-configured client rejects a CBC envelope produced by a CBC-configured client.
- A CBC-configured client rejects an AEAD envelope.
- Sealing the same plaintext under a CBC configuration and an otherwise-identical AEAD configuration (the two necessarily also differ in `iv`, which only the CBC side may set per §9.2) produces envelopes that each client rejects from the other.
- No API path exists that selects a mode from envelope bytes; asserted by the absence of any mode parameter on `seal`/`open` and by the public API snapshots.

### 13.5 Configuration tests

- `iv` set together with `EnvelopeMode::Aead` is `Error::Configuration { field: "iv" }`.
- `EnvelopeMode::LegacyCbc` still requires `iv`.
- Omitting `envelope_mode` yields `LegacyCbc`.

### 13.6 Fuzzing

A new `aead_envelope` target in `fuzz/fuzz_targets/`, mirroring `encoded_envelope`: it drives arbitrary bytes through an AEAD-configured client's `open_response` and asserts a known-good corpus entry still opens. `fuzz/Cargo.toml` enables the `aead` feature on the path dependency and adds the `[[bin]]` entry; `fuzz/Cargo.lock` absorbs the same two-package delta, which is acceptable because the crypto inventory deliberately covers only the root `Cargo.lock`. The hardcoded target list in `ci/fuzz-smoke.sh` (`for target in ...`) gains the new name. Corpus seeds cover a full valid open, the 30-byte frame floor, a 29-byte frame, each cipher/wrapped-key/signature length boundary at ±1, and cryptographic mutations of the nonce, tag, and frame header. `tests/fuzz_smoke.sh` gains matching self-test coverage.

### 13.7 Documentation tests

A "choosing a mode" table in `README.md` under **Authentication modes**, plus a new section on envelope modes, both compiled as doctests where they contain code. The table states plainly that CBC remains supported for compatibility and that AEAD is the recommended default for new integrations.

## 14. Release and versioning

The AEAD work lands as 0.2.0, leaving the parked, `rc-built` 0.1.0 artifact and its review evidence intact and immutable. This touches:

- `Cargo.toml` version.
- `CHANGELOG.md` — a 0.2.0 entry.
- `RELEASE_CHECKLIST.md` and `tests/release_documents.rs` — version identity.
- `api/gmcrypto-envelope-lite-0.2.0.txt` and `api/gmcrypto-envelope-lite-0.2.0-aead.txt`, with `ci/check-public-api.sh` updated for both paths.
- `docs/security/engineering-evidence.md` and `SECURITY_MODEL.md` — AEAD claims and non-claims.
- Version counters in `ci/tool-versions.sh` where the corresponding documents change.

Publication remains parked and the repository remains private; this section describes version identity inside the repository only.

## 15. Verification

Before any push, the full local battery must pass in both feature states where applicable:

```
cargo test --all-targets --locked
cargo test --all-targets --locked --features aead
cargo test --doc --locked
cargo test --doc --locked --features aead
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --locked --features aead -- -D warnings
RUSTDOCFLAGS="-D missing-docs -D warnings" cargo doc --locked --no-deps
RUSTDOCFLAGS="-D missing-docs -D warnings" cargo doc --locked --no-deps --features aead
cargo deny check
sh tests/open_source_boundary.sh
sh tests/release_candidate.sh
sh tests/workflows.sh
sh tests/public_api.sh
sh tests/crypto_inventory.sh
sh tests/fuzz_smoke.sh
./ci/check-public-api.sh
./ci/check-crypto-inventory.sh
./ci/check-open-source-boundary.sh --worktree .
./ci/check-cargo-package.sh "$PWD" "$package_parent/package"
sh ci/fuzz-smoke.sh smoke
```

Pushes go only to `origin`. The repository stays private, nothing is published, and boundary-scanner behavior is unchanged.

## 16. Risks and accepted trade-offs

- **The compiled crypto boundary gains unsafe code under `aead`.** `gmcrypto-simd` sets `unsafe_code = "warn"` and carries roughly 51 unsafe sites. This is unavoidable: `sm4-aead` is atomic and CCM-only would pay the same cost. Mitigated by the two-tier inventory, which keeps the default build's claim exact, and by recording that no constant-time claim is made for the SIMD backends.
- **The lockfile changes for default builds.** Merely declaring the feature adds two packages. Accepted; the reviewed lockfile hash is refreshed once and the reason is recorded in the inventory narrative.
- **The AEAD tag does not authenticate the sender.** The session key is encrypted to a public key, so anyone can produce a valid tag. The SM2 signature therefore remains mandatory under AEAD and is not weakened or made optional. Documented explicitly so no integrator concludes that AEAD makes the signature redundant.
- **Two payload modes double part of the test matrix.** Accepted deliberately: CBC is the compatibility surface and must stay fully tested, not merely retained.
- **Replay is still out of scope.** AEAD authenticates a message; it does not make it fresh. Stated in the mode table so the recommendation does not overpromise.
- **Signature transferability is unchanged.** A legitimate recipient can relay a decrypted plaintext with its original signature. This is inherent to sign-then-encrypt and is not made better or worse by AEAD; `ContextBound` remains the mitigation.
- **`max_plaintext_bytes` may exceed GCM's plaintext ceiling.** `gmcrypto-core` rejects plaintexts above 2^36 − 32 bytes (the NIST SP 800-38D counter-wrap bound), so a configuration above that ceiling fails at seal time with `Encryption` rather than `MessageTooLarge`. Unreachable in practice — it requires a single ~68 GB in-memory buffer — and recorded here so the error mapping is not later read as a bug.

## 17. Acceptance criteria

1. `EnvelopeMode` and `AeadAlgorithm` exist behind the `aead` feature; `ClientConfig` pins the mode and defaults to `LegacyCbc`.
2. `SecureEnvelope`, `ProtocolAdapter`, `HeaderSchema`, `KeyMaterial`, and the `SecureClient` method signatures are unchanged.
3. AEAD seal and open round-trip under both authentication modes, with the frame and AAD exactly as specified in §6 and §7.
4. Every negative and downgrade test in §13.3 and §13.4 passes and returns `InvalidEnvelope`.
5. CBC behavior is byte-identical to 0.1.0; all existing tests pass unmodified.
6. The two-tier cryptographic inventory, both snapshots, and the feature-aware checker pass.
7. Both public API snapshots are generated, committed, and verified.
8. The `aead_envelope` fuzz target builds, has a seeded corpus, and passes the bounded smoke run.
9. `README.md` carries a "choosing a mode" table that keeps CBC first-class while steering new integrations to AEAD.
10. The full §15 battery passes locally before any push.
