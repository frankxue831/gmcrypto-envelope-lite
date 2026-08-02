# SM4-GCM AEAD Envelope Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the opt-in `aead` feature: an SM4-GCM envelope mode pinned by `ClientConfig`, per `docs/superpowers/specs/2026-08-02-sm4-gcm-aead-envelope-design.md`.

**Architecture:** The AEAD payload is framed inside the existing `SecureEnvelope.cipher` field (`0x01` version ‖ `0x01` algorithm ‖ 12-byte nonce ‖ ciphertext ‖ 16-byte tag), so `SecureEnvelope`, `ProtocolAdapter`, `HeaderSchema`, and `KeyMaterial` are unchanged. A new `EnvelopeMode` config axis dispatches inside `envelope_crypto` (split into `mod.rs`/`cbc.rs`/`aead.rs`). The crypto inventory becomes two feature-scoped tiers; the release identity moves to 0.2.0.

**Tech Stack:** Rust 2024 (MSRV 1.85), gmcrypto-core 1.11 (`x509` + newly `sm4-aead`), POSIX sh check scripts, cargo-fuzz.

**Branch:** work happens on the existing local tracking branch `aead-envelope-mode` in this isolated worktree, based on `origin/aead-envelope-mode`. `main` contains a squash-equivalent merge of the design and plan. Nothing is pushed until the final task, when the branch is pushed to `origin aead-envelope-mode`.

## Global Constraints

- Feature definition must be exactly `aead = ["gmcrypto-core/sm4-aead"]`; the dependency line `gmcrypto-core = { version = "1.11", features = ["x509"] }` must NOT change (a CI grep pins it).
- Default-features public API must stay byte-identical to `api/gmcrypto-envelope-lite-0.1.0.txt` content through every task (all new API is `#[cfg(feature = "aead")]`).
- Frame constants: header 14 bytes (`0x01` version, `0x01` = SM4-GCM, 12-byte nonce), tag 16 bytes, overhead 30 bytes; algorithm id `0x02` is reserved for CCM and rejected.
- AAD label: `gmcrypto-envelope-lite/aead-aad/v1`; all AAD/transcript fields are u64 big-endian length-prefixed.
- Encoded `cipher` input above the public bound intentionally returns `Error::MessageTooLarge`; every other inbound AEAD parse, cryptographic, decoded-bound, context, and downgrade failure returns `Error::InvalidEnvelope`. Outbound failures use existing variants only. No new `Error` variant.
- `SecureClient::seal`/`open` signatures unchanged; the mode comes only from `ClientConfig`; no inference from bytes.
- Crate lints: `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`; CI runs clippy `-D warnings` and rustdoc `-D missing-docs -D warnings`. Docs on always-present items must not intra-doc-link feature-gated items (plain text only), or the default-features doc build breaks.
- `cargo fmt --all` before every commit. Push only to `origin`; never flip the repo public; never `cargo publish`; never change `ci/check-open-source-boundary.sh`.
- KAT source of truth: RFC 8998 Appendix A.1 (verified: gmcrypto-core 1.11.0 reproduces it byte-for-byte).

---

### Task 1: Declare the `aead` feature and re-baseline the lockfile hash

The feature is declared but stays off by default. Cargo locks the maximal feature graph, so `Cargo.lock` gains `gmcrypto-simd` 1.11.0 and `cpufeatures` 0.2.17 even while the feature is off. The inventory's recorded lock hash and its self-test fixture literal must follow in the same commit, keeping `ci/check-crypto-inventory.sh` green (the two-tier inventory itself is Task 10; the checker validates only the default resolution, which is unchanged).

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock` (via cargo, not by hand)
- Modify: `docs/security/cryptographic-dependencies.md` (one line: lock hash)
- Modify: `tests/crypto_inventory.sh` (one literal: lock hash)
- Modify: `tests/release_documents.rs` (reviewed lock-hash assertion)

**Interfaces:**
- Consumes: nothing.
- Produces: cargo feature `aead` (off by default) that later tasks compile against with `--features aead`.

- [ ] **Step 1: Declare the feature**

In `Cargo.toml`, insert between the `[lib]` table and `[dependencies]`:

```toml
[features]
default = []
aead = ["gmcrypto-core/sm4-aead"]
```

- [ ] **Step 2: Minimally refresh the lockfile**

```bash
cargo metadata --format-version 1 >/dev/null
```

Expected stderr: `Locking 2 packages to latest Rust 1.85 compatible versions` — `Adding cpufeatures v0.2.17`, `Adding gmcrypto-simd v1.11.0`. Then `git diff Cargo.lock` must show ONLY: the `cpufeatures` package block (checksum `59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280`), the `gmcrypto-simd` package block (checksum `31a7928890d12bd4064aba2664435fc62b2a6a487f8c2611d26856f31d5ceca4`), and `gmcrypto-simd` added to `gmcrypto-core`'s dependency list. If anything else changed (version drift of unrelated packages), restore `git checkout Cargo.lock` and investigate — do not commit a broad re-resolve.

- [ ] **Step 3: Verify the checker now fails on the stale hash**

```bash
./ci/check-crypto-inventory.sh
```

Expected: FAIL with `error: Cargo.lock differs from the reviewed inventory`.

- [ ] **Step 4: Record the new lock hash in both places**

```bash
shasum -a 256 Cargo.lock
```

Call the output `<NEWHASH>`. In `docs/security/cryptographic-dependencies.md` replace the value in:

```
- Reviewed Cargo.lock SHA-256: `284474aa170fcfa7a3cad31f3d3264d6fb7c6ceac49a99a213dc104e0ef23476`
```

with `<NEWHASH>`. In `tests/crypto_inventory.sh`, the same old literal `284474aa170fcfa7a3cad31f3d3264d6fb7c6ceac49a99a213dc104e0ef23476` appears once (the "stale documented lock hash" mutation); replace it with `<NEWHASH>`. In `tests/release_documents.rs`, replace the same literal in the reviewed inventory marker with `<NEWHASH>`.

- [ ] **Step 5: Verify green**

```bash
./ci/check-crypto-inventory.sh && sh tests/crypto_inventory.sh && cargo test --test release_documents --locked 2>&1 | tail -3 && cargo test --all-targets --locked 2>&1 | tail -3
```

Expected: `cryptographic dependency inventory check passed`, the self-test's final `ok`-style success, and the full test suite passing.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock docs/security/cryptographic-dependencies.md tests/crypto_inventory.sh tests/release_documents.rs
git commit -m "feat: declare the off-by-default aead feature

Locks gmcrypto-simd 1.11.0 and cpufeatures 0.2.17 (Cargo locks the
maximal feature graph even for disabled features) and re-baselines the
reviewed Cargo.lock hash. The two-tier inventory review lands separately.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Split `envelope_crypto` into `mod.rs` + `cbc.rs` (pure move)

Zero behavior change: same functions, same order of checks, same errors. The only code motion beyond the move is hoisting the outbound plaintext-limit check into the dispatch `seal` (it runs at the same point in the same order) and extracting four shared helpers that Task 5 will reuse. All existing tests move unmodified in their assertions.

**Files:**
- Delete: `src/envelope_crypto.rs`
- Create: `src/envelope_crypto/mod.rs`
- Create: `src/envelope_crypto/cbc.rs`

**Interfaces:**
- Consumes: existing crate items (`ClientConfig`, `KeyMaterial`, `SecureEnvelope`, `AuthenticationContext`, `Error`).
- Produces (used by Tasks 5–6):
  - `envelope_crypto::seal(config: &ClientConfig, keys: &KeyMaterial, plaintext: &[u8], context: &AuthenticationContext) -> Result<SecureEnvelope>` (dispatch; owns the `MessageTooLarge` outbound check)
  - `envelope_crypto::open(config: &ClientConfig, keys: &KeyMaterial, envelope: &SecureEnvelope, context: &AuthenticationContext) -> Result<Vec<u8>>` (dispatch)
  - mod-private helpers callable from child modules via `super::`: `generate_session_key() -> Result<Zeroizing<[u8; SESSION_KEY_BYTES]>>`, `unwrap_session_key(keys: &KeyMaterial, wrapped: &[u8]) -> Result<Zeroizing<[u8; SESSION_KEY_BYTES]>>`, `decode_base64(&str) -> Result<Vec<u8>>`, `base64_len(usize) -> usize`, consts `SESSION_KEY_BYTES: usize = 16`, `MAX_AUXILIARY_BASE64_BYTES: usize = 16 * 1024`
  - `#[cfg(test)] pub(crate) mod test_support` with: `pub(crate) struct Peers { pub(crate) sender_config, sender_keys, receiver_config, receiver_keys }`, `peers(mode, max) -> Peers`, `config(name, local_signer_id, expected_remote_signer_id, mode, max) -> ClientConfig`, `key_material(u8, u8, u8, u8) -> KeyMaterial`, `raw_private_key(u8) -> Sm2PrivateKey`, `legacy_context() -> AuthenticationContext`, `assert_invalid_envelope(crate::Result<Vec<u8>>)`, `wrapped_plaintext_for_receiver(&[u8]) -> String`, consts `IV`, `SENDER_SIGNER_ID`, `RECEIVER_SIGNER_ID`, `SENDER_SIGNING`, `SENDER_DECRYPTION`, `RECEIVER_SIGNING`, `RECEIVER_DECRYPTION`, `UNRELATED_KEY`

- [ ] **Step 1: Create `src/envelope_crypto/mod.rs`**

```rust
//! Envelope-mode dispatch plus the helpers every payload mode shares.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use gmcrypto_core::sm2;
use zeroize::Zeroizing;

use crate::message::SecureEnvelope;
use crate::{AuthenticationContext, ClientConfig, Error, KeyMaterial, Result};

mod cbc;

const SESSION_KEY_BYTES: usize = 16;
const MAX_AUXILIARY_BASE64_BYTES: usize = 16 * 1024;

pub(crate) fn seal(
    config: &ClientConfig,
    keys: &KeyMaterial,
    plaintext: &[u8],
    context: &AuthenticationContext,
) -> Result<SecureEnvelope> {
    let plaintext_limit = config.max_plaintext_bytes();
    if plaintext.len() > plaintext_limit {
        return Err(Error::MessageTooLarge {
            limit: plaintext_limit,
        });
    }

    cbc::seal(config, keys, plaintext, context)
}

pub(crate) fn open(
    config: &ClientConfig,
    keys: &KeyMaterial,
    envelope: &SecureEnvelope,
    context: &AuthenticationContext,
) -> Result<Vec<u8>> {
    cbc::open(config, keys, envelope, context)
}

fn generate_session_key() -> Result<Zeroizing<[u8; SESSION_KEY_BYTES]>> {
    let mut session_key = Zeroizing::new([0_u8; SESSION_KEY_BYTES]);
    getrandom::fill(&mut *session_key).map_err(|_| Error::Encryption)?;
    Ok(session_key)
}

fn unwrap_session_key(
    keys: &KeyMaterial,
    wrapped_session_key: &[u8],
) -> Result<Zeroizing<[u8; SESSION_KEY_BYTES]>> {
    let unwrapped = Zeroizing::new(
        sm2::decrypt(&keys.local_decryption, wrapped_session_key)
            .map_err(|_| Error::InvalidEnvelope)?,
    );
    if unwrapped.len() != SESSION_KEY_BYTES {
        return Err(Error::InvalidEnvelope);
    }

    let mut session_key = Zeroizing::new([0_u8; SESSION_KEY_BYTES]);
    session_key.copy_from_slice(unwrapped.as_slice());
    Ok(session_key)
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    STANDARD.decode(value).map_err(|_| Error::InvalidEnvelope)
}

fn base64_len(binary_len: usize) -> usize {
    binary_len
        .checked_add(2)
        .map(|bytes| bytes / 3)
        .and_then(|groups| groups.checked_mul(4))
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
pub(crate) mod test_support {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use getrandom::SysRng;
    use gmcrypto_core::sm2::{self, Sm2PrivateKey};
    use gmcrypto_core::spki;

    use crate::{
        AuthenticationContext, AuthenticationMode, ClientConfig, Error, KeyMaterial, PrivateKey,
        PublicKey,
    };

    pub(crate) const IV: [u8; 16] = *b"0123456789abcdef";
    pub(crate) const SENDER_SIGNER_ID: &[u8] = b"sender-directional-id";
    pub(crate) const RECEIVER_SIGNER_ID: &[u8] = b"receiver-directional-id";

    pub(crate) const SENDER_SIGNING: u8 = 1;
    pub(crate) const SENDER_DECRYPTION: u8 = 2;
    pub(crate) const RECEIVER_SIGNING: u8 = 3;
    pub(crate) const RECEIVER_DECRYPTION: u8 = 4;
    pub(crate) const UNRELATED_KEY: u8 = 5;

    pub(crate) struct Peers {
        pub(crate) sender_config: ClientConfig,
        pub(crate) sender_keys: KeyMaterial,
        pub(crate) receiver_config: ClientConfig,
        pub(crate) receiver_keys: KeyMaterial,
    }

    pub(crate) fn peers(mode: AuthenticationMode, max_plaintext_bytes: usize) -> Peers {
        Peers {
            sender_config: config(
                "sender",
                SENDER_SIGNER_ID,
                RECEIVER_SIGNER_ID,
                mode.clone(),
                max_plaintext_bytes,
            ),
            sender_keys: key_material(
                SENDER_SIGNING,
                SENDER_DECRYPTION,
                RECEIVER_SIGNING,
                RECEIVER_DECRYPTION,
            ),
            receiver_config: config(
                "receiver",
                RECEIVER_SIGNER_ID,
                SENDER_SIGNER_ID,
                mode,
                max_plaintext_bytes,
            ),
            receiver_keys: key_material(
                RECEIVER_SIGNING,
                RECEIVER_DECRYPTION,
                SENDER_SIGNING,
                SENDER_DECRYPTION,
            ),
        }
    }

    pub(crate) fn config(
        name: &str,
        local_signer_id: &[u8],
        expected_remote_signer_id: &[u8],
        mode: AuthenticationMode,
        max_plaintext_bytes: usize,
    ) -> ClientConfig {
        ClientConfig::builder()
            .local_identity_id(format!("{name}-identity"))
            .api_version("test-v1")
            .local_certificate_id(format!("{name}-signing-certificate"))
            .expected_remote_signing_certificate_id(format!("{name}-remote-signing-certificate"))
            .remote_encryption_certificate_id(format!("{name}-remote-encryption-certificate"))
            .local_signer_id(local_signer_id)
            .expected_remote_signer_id(expected_remote_signer_id)
            .authentication_mode(mode)
            .iv(IV)
            .max_plaintext_bytes(max_plaintext_bytes)
            .build()
            .expect("valid test configuration")
    }

    pub(crate) fn key_material(
        local_signing: u8,
        local_decryption: u8,
        remote_verification: u8,
        remote_encryption: u8,
    ) -> KeyMaterial {
        KeyMaterial::new(
            private_key(local_signing),
            private_key(local_decryption),
            public_key(remote_verification),
            public_key(remote_encryption),
        )
    }

    fn private_key(scalar: u8) -> PrivateKey {
        PrivateKey {
            inner: raw_private_key(scalar),
        }
    }

    fn public_key(scalar: u8) -> PublicKey {
        let der = spki::encode(&raw_private_key(scalar).public_key());
        PublicKey::from_der(&der).expect("runtime SPKI public key")
    }

    pub(crate) fn raw_private_key(scalar: u8) -> Sm2PrivateKey {
        let mut bytes = [0_u8; 32];
        bytes[31] = scalar;
        Sm2PrivateKey::from_bytes_be(&bytes).expect("small nonzero SM2 scalar")
    }

    pub(crate) fn legacy_context() -> AuthenticationContext {
        AuthenticationContext::legacy()
    }

    pub(crate) fn assert_invalid_envelope(result: crate::Result<Vec<u8>>) {
        assert!(matches!(result, Err(Error::InvalidEnvelope)));
    }

    pub(crate) fn wrapped_plaintext_for_receiver(bytes: &[u8]) -> String {
        let receiver_public = raw_private_key(RECEIVER_DECRYPTION).public_key();
        let mut rng = SysRng;
        STANDARD.encode(
            sm2::encrypt(&receiver_public, bytes, &mut rng).expect("wrap test bytes for receiver"),
        )
    }
}
```

- [ ] **Step 2: Create `src/envelope_crypto/cbc.rs`**

Header and function bodies below; the tests module moves from the old file. The `seal` body is the old one minus the hoisted limit check and with `generate_session_key()`; `open` uses `super::unwrap_session_key`.

```rust
//! The compatibility SM4-CBC payload mode.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use getrandom::SysRng;
use gmcrypto_core::{sm2, sm4};
use zeroize::Zeroizing;

use super::{
    MAX_AUXILIARY_BASE64_BYTES, base64_len, decode_base64, generate_session_key,
    unwrap_session_key,
};
use crate::message::SecureEnvelope;
use crate::{AuthenticationContext, ClientConfig, Error, KeyMaterial, Result};

const SM4_BLOCK_BYTES: usize = 16;

pub(super) fn seal(
    config: &ClientConfig,
    keys: &KeyMaterial,
    plaintext: &[u8],
    context: &AuthenticationContext,
) -> Result<SecureEnvelope> {
    let authentication_input = config
        .authentication_mode()
        .authentication_input(context, plaintext)?;

    let session_key = generate_session_key()?;

    let cipher = sm4::mode_cbc::encrypt(&session_key, config.iv(), plaintext);
    let mut rng = SysRng;
    let wrapped_session_key = sm2::encrypt(&keys.remote_encryption, &session_key[..], &mut rng)
        .map_err(|_| Error::Encryption)?;
    let signature = sm2::sign_with_id(
        &keys.local_signing,
        config.local_signer_id(),
        authentication_input.as_slice(),
        &mut rng,
    )
    .map_err(|_| Error::Encryption)?;

    Ok(SecureEnvelope {
        cipher: STANDARD.encode(cipher),
        wrapped_session_key: STANDARD.encode(wrapped_session_key),
        signature: STANDARD.encode(signature),
    })
}

pub(super) fn open(
    config: &ClientConfig,
    keys: &KeyMaterial,
    envelope: &SecureEnvelope,
    context: &AuthenticationContext,
) -> Result<Vec<u8>> {
    let plaintext_limit = config.max_plaintext_bytes();
    let max_cipher_bytes = padded_cipher_len(plaintext_limit);
    let max_cipher_base64_bytes = base64_len(max_cipher_bytes);

    if envelope.cipher.len() > max_cipher_base64_bytes {
        return Err(Error::MessageTooLarge {
            limit: plaintext_limit,
        });
    }
    if envelope.wrapped_session_key.len() > MAX_AUXILIARY_BASE64_BYTES
        || envelope.signature.len() > MAX_AUXILIARY_BASE64_BYTES
    {
        return Err(Error::InvalidEnvelope);
    }

    let cipher = decode_base64(&envelope.cipher)?;
    if cipher.len() > max_cipher_bytes {
        return Err(Error::InvalidEnvelope);
    }
    let wrapped_session_key = decode_base64(&envelope.wrapped_session_key)?;
    let signature = decode_base64(&envelope.signature)?;

    let session_key = unwrap_session_key(keys, &wrapped_session_key)?;

    let plaintext = Zeroizing::new(
        sm4::mode_cbc::decrypt(&session_key, config.iv(), &cipher).ok_or(Error::InvalidEnvelope)?,
    );
    if plaintext.len() > plaintext_limit {
        return Err(Error::InvalidEnvelope);
    }

    let authentication_input = config
        .authentication_mode()
        .authentication_input(context, plaintext.as_slice())
        .map_err(|_| Error::InvalidEnvelope)?;
    if !sm2::verify_with_id(
        &keys.remote_verification,
        config.expected_remote_signer_id(),
        authentication_input.as_slice(),
        &signature,
    ) {
        return Err(Error::InvalidEnvelope);
    }

    Ok(plaintext.to_vec())
}

fn padded_cipher_len(plaintext_limit: usize) -> usize {
    plaintext_limit
        .checked_div(SM4_BLOCK_BYTES)
        .and_then(|blocks| blocks.checked_add(1))
        .and_then(|blocks| blocks.checked_mul(SM4_BLOCK_BYTES))
        .unwrap_or(usize::MAX)
}
```

- [ ] **Step 3: Move the tests module into `cbc.rs`**

Append the entire `#[cfg(test)] mod tests { ... }` block from the old `src/envelope_crypto.rs` (lines 134–872) to `cbc.rs` **verbatim in its assertions**, replacing only the module preamble (imports and helper definitions, old lines 136–265) with:

```rust
#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use gmcrypto_core::sm2;
    use zeroize::Zeroizing;

    use crate::envelope_crypto::test_support::{
        RECEIVER_DECRYPTION, RECEIVER_SIGNER_ID, RECEIVER_SIGNING, SENDER_DECRYPTION,
        SENDER_SIGNER_ID, SENDER_SIGNING, UNRELATED_KEY, assert_invalid_envelope, config,
        key_material, legacy_context, peers, raw_private_key, wrapped_plaintext_for_receiver,
    };
    use crate::envelope_crypto::{open, seal};
    use crate::message::SecureEnvelope;
    use crate::{AuthenticationContext, AuthenticationMode, Error};
```

All `#[test]` functions (old lines 267–871) stay byte-identical. Delete the old `src/envelope_crypto.rs`. `src/lib.rs` needs no change (`mod envelope_crypto;` resolves to the directory).

- [ ] **Step 4: Verify identical behavior**

```bash
cargo test --all-targets --locked 2>&1 | tail -5
cargo fmt --all -- --check && cargo clippy --all-targets --locked -- -D warnings
```

Expected: same test count as before the split, all passing; fmt and clippy clean. If clippy flags an unused import in either file, remove that import — nothing else.

- [ ] **Step 5: Commit**

```bash
git add src/envelope_crypto src/envelope_crypto.rs
git commit -m "refactor: split envelope_crypto into dispatch and cbc modules

Pure move: same checks in the same order with the same errors. The
outbound plaintext-limit check hoists into the dispatch seal, and the
session-key and Base64 helpers move to the module root for reuse by the
upcoming AEAD payload mode.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: `EnvelopeMode`, `AeadAlgorithm`, and `ClientConfig` plumbing

**Files:**
- Modify: `src/client_config.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces (used by Tasks 5–9, 12):
  - `pub enum EnvelopeMode { LegacyCbc, Aead(AeadAlgorithm) }` and `pub enum AeadAlgorithm { Sm4Gcm }`, both `#[cfg(feature = "aead")]`, `#[non_exhaustive]`, deriving `Clone, Copy, Debug, PartialEq, Eq`, exported from the crate root.
  - `ClientConfig::envelope_mode(&self) -> EnvelopeMode` (cfg-gated), defaulting to `EnvelopeMode::LegacyCbc`.
  - `ClientConfigBuilder::envelope_mode(self, value: EnvelopeMode) -> Self` (cfg-gated).
  - Build rule: `Aead` + `iv` set → `Error::Configuration { field: "iv" }`; `Aead` without `iv` stores an inert all-zero IV; `LegacyCbc` (and the no-feature build) requires `iv` exactly as today.

- [ ] **Step 1: Write the failing tests**

Append to `src/client_config.rs`:

```rust
#[cfg(all(test, feature = "aead"))]
mod tests {
    use super::{AeadAlgorithm, ClientConfig, ClientConfigBuilder, EnvelopeMode};
    use crate::{AuthenticationMode, Error};

    fn base_builder() -> ClientConfigBuilder {
        ClientConfig::builder()
            .local_identity_id("identity")
            .api_version("version")
            .local_certificate_id("certificate")
            .expected_remote_signing_certificate_id("certificate")
            .remote_encryption_certificate_id("certificate")
            .local_signer_id(b"signer".to_vec())
            .expected_remote_signer_id(b"signer".to_vec())
            .authentication_mode(AuthenticationMode::LegacyPlaintext)
    }

    #[test]
    fn envelope_mode_defaults_to_legacy_cbc_and_still_requires_an_iv() {
        let config = base_builder()
            .iv(*b"0123456789abcdef")
            .build()
            .expect("legacy configuration");
        assert_eq!(config.envelope_mode(), EnvelopeMode::LegacyCbc);

        let missing_iv = base_builder().build().expect_err("legacy mode without IV");
        assert!(matches!(missing_iv, Error::Configuration { field: "iv" }));
    }

    #[test]
    fn aead_mode_builds_without_an_iv_and_rejects_a_configured_iv() {
        let config = base_builder()
            .envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm))
            .build()
            .expect("AEAD configuration");
        assert_eq!(
            config.envelope_mode(),
            EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm)
        );

        let with_iv = base_builder()
            .envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm))
            .iv(*b"0123456789abcdef")
            .build()
            .expect_err("AEAD mode with a configured IV");
        assert!(matches!(with_iv, Error::Configuration { field: "iv" }));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --locked --features aead --lib client_config 2>&1 | tail -5`
Expected: COMPILE ERROR — `EnvelopeMode` / `envelope_mode` not found.

- [ ] **Step 3: Implement**

In `src/client_config.rs`, after the `ClientIdentity` impl and before `pub struct ClientConfig`, add:

```rust
/// Selects how the envelope payload is encrypted.
///
/// The mode is pinned by immutable client configuration and never
/// inferred from incoming bytes: a client seals and opens only its
/// configured mode, with no negotiation and no fallback.
#[cfg(feature = "aead")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvelopeMode {
    /// The compatibility SM4-CBC payload with the configured fixed IV.
    LegacyCbc,
    /// An authenticated-encryption payload using the selected algorithm.
    Aead(AeadAlgorithm),
}

/// Authenticated-encryption algorithms available to [`EnvelopeMode::Aead`].
#[cfg(feature = "aead")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadAlgorithm {
    /// SM4-GCM with a 12-byte random nonce and a full 16-byte tag.
    Sm4Gcm,
}
```

Add to the `ClientConfig` struct: `#[cfg(feature = "aead")] envelope_mode: EnvelopeMode,` and to its impl:

```rust
    /// Returns the configured envelope mode.
    #[cfg(feature = "aead")]
    #[must_use]
    pub fn envelope_mode(&self) -> EnvelopeMode {
        self.envelope_mode
    }
```

Add to `ClientConfigBuilder` struct: `#[cfg(feature = "aead")] envelope_mode: Option<EnvelopeMode>,` and to its impl:

```rust
    /// Sets the envelope mode; the default is the compatibility SM4-CBC mode.
    #[cfg(feature = "aead")]
    #[must_use]
    pub fn envelope_mode(mut self, value: EnvelopeMode) -> Self {
        self.envelope_mode = Some(value);
        self
    }
```

In `build()`, replace `let iv = self.iv.ok_or(Error::Configuration { field: "iv" })?;` with:

```rust
        #[cfg(feature = "aead")]
        let envelope_mode = self.envelope_mode.unwrap_or(EnvelopeMode::LegacyCbc);
        #[cfg(feature = "aead")]
        let iv = match envelope_mode {
            EnvelopeMode::LegacyCbc => self.iv.ok_or(Error::Configuration { field: "iv" })?,
            EnvelopeMode::Aead(_) => {
                if self.iv.is_some() {
                    return Err(Error::Configuration { field: "iv" });
                }
                // Inert filler: the AEAD payload path never reads the IV.
                [0_u8; 16]
            }
        };
        #[cfg(not(feature = "aead"))]
        let iv = self.iv.ok_or(Error::Configuration { field: "iv" })?;
```

and add `#[cfg(feature = "aead")] envelope_mode,` to the `Ok(ClientConfig { ... })` literal. Append to the `ClientConfig::iv` accessor doc (plain text, no intra-doc links): `Under an AEAD envelope mode (feature `aead`) the stored value is all zeroes and is not used by sealing or opening.` Append to the builder `iv` setter's `# Security` doc: `Setting an IV together with an AEAD envelope mode is a configuration error.`

In `src/lib.rs`, after the existing `pub use client_config::{...};` line add:

```rust
#[cfg(feature = "aead")]
pub use client_config::{AeadAlgorithm, EnvelopeMode};
```

- [ ] **Step 4: Verify both feature states**

```bash
cargo test --locked --features aead --lib client_config 2>&1 | tail -4
cargo test --all-targets --locked 2>&1 | tail -3
cargo test --all-targets --locked --features aead 2>&1 | tail -3
cargo clippy --all-targets --locked -- -D warnings && cargo clippy --all-targets --locked --features aead -- -D warnings
./ci/check-public-api.sh
```

Expected: both new tests pass; full suites pass in both states; clippy clean twice; the public API check still passes (all additions are feature-gated).

- [ ] **Step 5: Commit**

```bash
git add src/client_config.rs src/lib.rs
git commit -m "feat: pin the envelope mode in ClientConfig behind the aead feature

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: `AuthenticationMode::aead_aad`

**Files:**
- Modify: `src/auth.rs`

**Interfaces:**
- Consumes: `push_field`, `ContextKind` (private to `auth.rs`).
- Produces (used by Task 5): `#[cfg(feature = "aead")] pub fn AuthenticationMode::aead_aad(&self, context: &AuthenticationContext, frame_header: &[u8; 14]) -> Result<Vec<u8>>` — layout `len|label ‖ len|frame_header ‖ len|domain_separator ‖ len|protocol_context`, label `gmcrypto-envelope-lite/aead-aad/v1`, empty domain/context under `LegacyPlaintext`, `Error::AuthenticationContext` on kind mismatch.

- [ ] **Step 1: Write the failing tests**

Append to `src/auth.rs`:

```rust
#[cfg(all(test, feature = "aead"))]
mod tests {
    use super::{AuthenticationContext, AuthenticationMode};
    use crate::Error;

    fn expected_aad(fields: [&[u8]; 4]) -> Vec<u8> {
        let mut aad = Vec::new();
        for field in fields {
            let length = u64::try_from(field.len()).expect("test field length");
            aad.extend_from_slice(&length.to_be_bytes());
            aad.extend_from_slice(field);
        }
        aad
    }

    #[test]
    fn aead_aad_is_length_prefixed_label_header_domain_and_context() {
        let header = [7_u8; 14];

        let legacy = AuthenticationMode::LegacyPlaintext
            .aead_aad(&AuthenticationContext::legacy(), &header)
            .expect("legacy AAD");
        assert_eq!(
            legacy,
            expected_aad([
                &b"gmcrypto-envelope-lite/aead-aad/v1"[..],
                &header[..],
                &b""[..],
                &b""[..],
            ])
        );
        assert_eq!(
            legacy[0], 0x00,
            "an AAD must never begin with the transcript version byte"
        );

        let mode = AuthenticationMode::context_bound(b"domain/v1").expect("domain");
        let context = AuthenticationContext::context_bound(b"operation=aad").expect("context");
        assert_eq!(
            mode.aead_aad(&context, &header).expect("bound AAD"),
            expected_aad([
                &b"gmcrypto-envelope-lite/aead-aad/v1"[..],
                &header[..],
                &b"domain/v1"[..],
                &b"operation=aad"[..],
            ])
        );
    }

    #[test]
    fn aead_aad_rejects_context_kinds_that_do_not_match_the_mode() {
        let header = [0_u8; 14];
        let bound = AuthenticationContext::context_bound(b"operation=aad").expect("context");
        assert!(matches!(
            AuthenticationMode::LegacyPlaintext.aead_aad(&bound, &header),
            Err(Error::AuthenticationContext)
        ));

        let mode = AuthenticationMode::context_bound(b"domain/v1").expect("domain");
        assert!(matches!(
            mode.aead_aad(&AuthenticationContext::legacy(), &header),
            Err(Error::AuthenticationContext)
        ));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --locked --features aead --lib auth 2>&1 | tail -4`
Expected: COMPILE ERROR — no method `aead_aad`.

- [ ] **Step 3: Implement**

In `src/auth.rs`, next to the existing constants add:

```rust
#[cfg(feature = "aead")]
const AEAD_AAD_LABEL: &[u8] = b"gmcrypto-envelope-lite/aead-aad/v1";
```

In `impl AuthenticationMode`, after `authentication_input`, add:

```rust
    /// Builds the additional authenticated data for one AEAD envelope.
    ///
    /// The layout is four fields, each preceded by its unsigned 64-bit
    /// big-endian byte length: a fixed domain label, the 14-byte cipher
    /// frame header, the configured domain separator, and the protocol
    /// context. Under [`AuthenticationMode::LegacyPlaintext`] the last
    /// two fields are empty.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AuthenticationContext`] when the context kind
    /// does not match this mode, mirroring
    /// [`AuthenticationMode::authentication_input`].
    #[cfg(feature = "aead")]
    pub fn aead_aad(
        &self,
        context: &AuthenticationContext,
        frame_header: &[u8; 14],
    ) -> Result<Vec<u8>> {
        self.validate()?;

        let (domain_separator, protocol_context): (&[u8], &[u8]) = match (self, &context.kind) {
            (Self::LegacyPlaintext, ContextKind::Legacy) => (&[], &[]),
            (Self::ContextBound { domain_separator }, ContextKind::Bound(bound)) => {
                (domain_separator.as_slice(), bound.as_slice())
            }
            _ => return Err(Error::AuthenticationContext),
        };

        let capacity = (4 * size_of::<u64>())
            .checked_add(AEAD_AAD_LABEL.len())
            .and_then(|length| length.checked_add(frame_header.len()))
            .and_then(|length| length.checked_add(domain_separator.len()))
            .and_then(|length| length.checked_add(protocol_context.len()))
            .ok_or(Error::AuthenticationContext)?;
        let mut aad = Vec::with_capacity(capacity);
        push_field(&mut aad, AEAD_AAD_LABEL)?;
        push_field(&mut aad, frame_header)?;
        push_field(&mut aad, domain_separator)?;
        push_field(&mut aad, protocol_context)?;
        Ok(aad)
    }
```

- [ ] **Step 4: Verify**

Run: `cargo test --locked --features aead --lib auth 2>&1 | tail -4` → PASS; then `cargo test --all-targets --locked 2>&1 | tail -3` (default state untouched) and both clippy runs.

- [ ] **Step 5: Commit**

```bash
git add src/auth.rs
git commit -m "feat: add the AEAD additional-authenticated-data transcript

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: AEAD seal/open and mode dispatch

**Files:**
- Create: `src/envelope_crypto/aead.rs`
- Modify: `src/envelope_crypto/mod.rs` (dispatch + `mod aead;` + test-support additions)

**Interfaces:**
- Consumes: Task 2 helpers, Task 3 `EnvelopeMode`/`AeadAlgorithm`, Task 4 `aead_aad`, `gmcrypto_core::sm4::mode_gcm::{encrypt, decrypt}`.
- Produces (used by Tasks 6–9):
  - `aead::seal(config, keys, plaintext, context, algorithm: AeadAlgorithm) -> Result<SecureEnvelope>` and `aead::open(config, keys, envelope, context, algorithm: AeadAlgorithm) -> Result<Vec<u8>>`, both `pub(super)`, dispatched from `envelope_crypto::{seal, open}` on `config.envelope_mode()`.
  - Frame consts in `aead.rs`: `FRAME_VERSION: u8 = 0x01`, `ALGORITHM_SM4_GCM: u8 = 0x01`, `FRAME_HEADER_BYTES = 14`, `NONCE_BYTES = 12`, `TAG_BYTES = 16`, `FRAME_OVERHEAD_BYTES = 30`.
  - `test_support::aead_peers(mode: AuthenticationMode, max_plaintext_bytes: usize) -> Peers` and `test_support::aead_config(name, local_signer_id, expected_remote_signer_id, mode, max) -> ClientConfig` (both `#[cfg(feature = "aead")]`), identical to `peers`/`config` except `.envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm))` and no `.iv(...)`.

- [ ] **Step 1: Write the failing round-trip tests**

Create `src/envelope_crypto/aead.rs` containing only a tests module for now:

```rust
//! The SM4-GCM authenticated-encryption payload mode.

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use gmcrypto_core::sm2;
    use zeroize::Zeroizing;

    use crate::envelope_crypto::test_support::{
        RECEIVER_DECRYPTION, aead_peers, assert_invalid_envelope, legacy_context, raw_private_key,
    };
    use crate::envelope_crypto::{open, seal};
    use crate::{AuthenticationContext, AuthenticationMode, Error};

    const FRAME_HEADER_BYTES: usize = 14;
    const FRAME_OVERHEAD_BYTES: usize = 30;

    #[test]
    fn aead_round_trips_in_both_directions_with_distinct_roles() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 256);
        let context = legacy_context();
        let request = b"aead request payload \x00 with binary bytes";

        let envelope = seal(&peers.sender_config, &peers.sender_keys, request, &context)
            .expect("sender seals");
        let frame = STANDARD.decode(&envelope.cipher).expect("cipher Base64");
        assert_eq!(frame.len(), request.len() + FRAME_OVERHEAD_BYTES);
        assert_eq!(frame[0], 0x01, "frame version");
        assert_eq!(frame[1], 0x01, "SM4-GCM algorithm id");
        assert_eq!(
            open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &envelope,
                &context,
            )
            .expect("receiver opens"),
            request
        );

        let response = b"aead response uses inverse directional roles";
        let reply = seal(
            &peers.receiver_config,
            &peers.receiver_keys,
            response,
            &context,
        )
        .expect("receiver seals");
        assert_eq!(
            open(&peers.sender_config, &peers.sender_keys, &reply, &context)
                .expect("sender opens"),
            response
        );
    }

    #[test]
    fn aead_context_bound_round_trip_rejects_wrong_or_mismatched_contexts() {
        let mode = AuthenticationMode::context_bound(b"example/aead/v1").expect("domain");
        let peers = aead_peers(mode, 256);
        let context =
            AuthenticationContext::context_bound(b"operation=pay&id=17").expect("bound context");
        let envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"context-bound aead payload",
            &context,
        )
        .expect("seal context-bound payload");

        assert_eq!(
            open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &envelope,
                &context,
            )
            .expect("matching context opens"),
            b"context-bound aead payload"
        );

        let different =
            AuthenticationContext::context_bound(b"operation=pay&id=18").expect("other context");
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &envelope,
            &different,
        ));
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &envelope,
            &legacy_context(),
        ));

        let seal_error = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"wrong context kind",
            &legacy_context(),
        )
        .expect_err("outbound context mismatch must be specific");
        assert!(matches!(seal_error, Error::AuthenticationContext));
    }

    #[test]
    fn aead_round_trips_empty_boundary_and_unicode_plaintext() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 64);
        for plaintext in [
            &b""[..],
            &[0xa5_u8; 64][..],
            "你好，secure envelope 🔐 — café".as_bytes(),
        ] {
            let envelope = seal(
                &peers.sender_config,
                &peers.sender_keys,
                plaintext,
                &legacy_context(),
            )
            .expect("seal boundary payload");
            assert_eq!(
                open(
                    &peers.receiver_config,
                    &peers.receiver_keys,
                    &envelope,
                    &legacy_context(),
                )
                .expect("open boundary payload"),
                plaintext
            );
        }
    }

    #[test]
    fn every_aead_seal_uses_a_fresh_session_key_and_nonce() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 128);
        let plaintext = b"same payload";
        let first = seal(
            &peers.sender_config,
            &peers.sender_keys,
            plaintext,
            &legacy_context(),
        )
        .expect("first seal");
        let second = seal(
            &peers.sender_config,
            &peers.sender_keys,
            plaintext,
            &legacy_context(),
        )
        .expect("second seal");

        let first_frame = STANDARD.decode(&first.cipher).expect("first frame");
        let second_frame = STANDARD.decode(&second.cipher).expect("second frame");
        assert_ne!(
            first_frame[2..FRAME_HEADER_BYTES],
            second_frame[2..FRAME_HEADER_BYTES],
            "nonces must differ"
        );
        assert_ne!(first.cipher, second.cipher);

        let receiver_private = raw_private_key(RECEIVER_DECRYPTION);
        let first_wrapped = STANDARD
            .decode(first.wrapped_session_key)
            .expect("first wrapped key Base64");
        let second_wrapped = STANDARD
            .decode(second.wrapped_session_key)
            .expect("second wrapped key Base64");
        let first_key = Zeroizing::new(
            sm2::decrypt(&receiver_private, &first_wrapped).expect("unwrap first session key"),
        );
        let second_key = Zeroizing::new(
            sm2::decrypt(&receiver_private, &second_wrapped).expect("unwrap second session key"),
        );
        assert_ne!(*first_key, *second_key);
    }

    #[test]
    fn aead_seal_rejects_plaintext_over_the_configured_limit() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 8);
        let error = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"123456789",
            &legacy_context(),
        )
        .expect_err("oversized outbound plaintext");
        assert!(matches!(error, Error::MessageTooLarge { limit: 8 }));
    }
}
```

- [ ] **Step 2: Wire the module and test support, verify compile failure**

In `src/envelope_crypto/mod.rs` add after `mod cbc;`:

```rust
#[cfg(feature = "aead")]
mod aead;
```

In `test_support` (same file) add at the end of the module:

```rust
    #[cfg(feature = "aead")]
    pub(crate) fn aead_peers(mode: AuthenticationMode, max_plaintext_bytes: usize) -> Peers {
        Peers {
            sender_config: aead_config(
                "sender",
                SENDER_SIGNER_ID,
                RECEIVER_SIGNER_ID,
                mode.clone(),
                max_plaintext_bytes,
            ),
            sender_keys: key_material(
                SENDER_SIGNING,
                SENDER_DECRYPTION,
                RECEIVER_SIGNING,
                RECEIVER_DECRYPTION,
            ),
            receiver_config: aead_config(
                "receiver",
                RECEIVER_SIGNER_ID,
                SENDER_SIGNER_ID,
                mode,
                max_plaintext_bytes,
            ),
            receiver_keys: key_material(
                RECEIVER_SIGNING,
                RECEIVER_DECRYPTION,
                SENDER_SIGNING,
                SENDER_DECRYPTION,
            ),
        }
    }

    #[cfg(feature = "aead")]
    pub(crate) fn aead_config(
        name: &str,
        local_signer_id: &[u8],
        expected_remote_signer_id: &[u8],
        mode: AuthenticationMode,
        max_plaintext_bytes: usize,
    ) -> ClientConfig {
        ClientConfig::builder()
            .local_identity_id(format!("{name}-identity"))
            .api_version("test-v1")
            .local_certificate_id(format!("{name}-signing-certificate"))
            .expected_remote_signing_certificate_id(format!("{name}-remote-signing-certificate"))
            .remote_encryption_certificate_id(format!("{name}-remote-encryption-certificate"))
            .local_signer_id(local_signer_id)
            .expected_remote_signer_id(expected_remote_signer_id)
            .authentication_mode(mode)
            .envelope_mode(crate::EnvelopeMode::Aead(crate::AeadAlgorithm::Sm4Gcm))
            .max_plaintext_bytes(max_plaintext_bytes)
            .build()
            .expect("valid AEAD test configuration")
    }
```

Run: `cargo test --locked --features aead --lib envelope_crypto::aead 2>&1 | tail -4`
Expected: FAIL — the round-trip test panics or fails because the dispatch still routes to `cbc::seal`, which requires an IV the AEAD config doesn't have… concretely, `cbc::seal` will run with the zero IV and `open` succeeds via CBC. The failing assertions are the frame checks (`frame[0] == 0x01`, length). Confirm the failure message mentions the frame assertion, not a compile error (compile errors here mean the wiring above is wrong).

- [ ] **Step 3: Implement `aead.rs` seal/open and the dispatch**

Replace the top of `src/envelope_crypto/aead.rs` (above the tests module) with:

```rust
//! The SM4-GCM authenticated-encryption payload mode.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use getrandom::SysRng;
use gmcrypto_core::{sm2, sm4};
use zeroize::Zeroizing;

use super::{
    MAX_AUXILIARY_BASE64_BYTES, base64_len, decode_base64, generate_session_key,
    unwrap_session_key,
};
use crate::client_config::AeadAlgorithm;
use crate::message::SecureEnvelope;
use crate::{AuthenticationContext, ClientConfig, Error, KeyMaterial, Result};

const FRAME_VERSION: u8 = 0x01;
const ALGORITHM_SM4_GCM: u8 = 0x01;
const FRAME_HEADER_BYTES: usize = 14;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const FRAME_OVERHEAD_BYTES: usize = FRAME_HEADER_BYTES + TAG_BYTES;

fn algorithm_byte(algorithm: AeadAlgorithm) -> u8 {
    match algorithm {
        AeadAlgorithm::Sm4Gcm => ALGORITHM_SM4_GCM,
    }
}

pub(super) fn seal(
    config: &ClientConfig,
    keys: &KeyMaterial,
    plaintext: &[u8],
    context: &AuthenticationContext,
    algorithm: AeadAlgorithm,
) -> Result<SecureEnvelope> {
    let authentication_input = config
        .authentication_mode()
        .authentication_input(context, plaintext)?;

    let session_key = generate_session_key()?;
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| Error::Encryption)?;

    let mut frame_header = [0_u8; FRAME_HEADER_BYTES];
    frame_header[0] = FRAME_VERSION;
    frame_header[1] = algorithm_byte(algorithm);
    frame_header[2..].copy_from_slice(&nonce);
    let aad = config.authentication_mode().aead_aad(context, &frame_header)?;

    let (ciphertext, tag) =
        sm4::mode_gcm::encrypt(&session_key, &nonce, &aad, plaintext).ok_or(Error::Encryption)?;

    let frame_len = FRAME_OVERHEAD_BYTES
        .checked_add(ciphertext.len())
        .ok_or(Error::Encryption)?;
    let mut frame = Vec::with_capacity(frame_len);
    frame.extend_from_slice(&frame_header);
    frame.extend_from_slice(&ciphertext);
    frame.extend_from_slice(&tag);

    let mut rng = SysRng;
    let wrapped_session_key = sm2::encrypt(&keys.remote_encryption, &session_key[..], &mut rng)
        .map_err(|_| Error::Encryption)?;
    let signature = sm2::sign_with_id(
        &keys.local_signing,
        config.local_signer_id(),
        authentication_input.as_slice(),
        &mut rng,
    )
    .map_err(|_| Error::Encryption)?;

    Ok(SecureEnvelope {
        cipher: STANDARD.encode(frame),
        wrapped_session_key: STANDARD.encode(wrapped_session_key),
        signature: STANDARD.encode(signature),
    })
}

pub(super) fn open(
    config: &ClientConfig,
    keys: &KeyMaterial,
    envelope: &SecureEnvelope,
    context: &AuthenticationContext,
    algorithm: AeadAlgorithm,
) -> Result<Vec<u8>> {
    let plaintext_limit = config.max_plaintext_bytes();
    let max_frame_bytes = plaintext_limit
        .checked_add(FRAME_OVERHEAD_BYTES)
        .unwrap_or(usize::MAX);

    if envelope.cipher.len() > base64_len(max_frame_bytes) {
        return Err(Error::MessageTooLarge {
            limit: plaintext_limit,
        });
    }
    if envelope.wrapped_session_key.len() > MAX_AUXILIARY_BASE64_BYTES
        || envelope.signature.len() > MAX_AUXILIARY_BASE64_BYTES
    {
        return Err(Error::InvalidEnvelope);
    }

    let frame = decode_base64(&envelope.cipher)?;
    let wrapped_session_key = decode_base64(&envelope.wrapped_session_key)?;
    let signature = decode_base64(&envelope.signature)?;

    if frame.len() < FRAME_OVERHEAD_BYTES {
        return Err(Error::InvalidEnvelope);
    }
    if frame[0] != FRAME_VERSION || frame[1] != algorithm_byte(algorithm) {
        return Err(Error::InvalidEnvelope);
    }
    let (header_bytes, body) = frame.split_at(FRAME_HEADER_BYTES);
    let ciphertext_len = body.len() - TAG_BYTES;
    if ciphertext_len > plaintext_limit {
        return Err(Error::InvalidEnvelope);
    }
    let (ciphertext, tag_bytes) = body.split_at(ciphertext_len);
    let mut frame_header = [0_u8; FRAME_HEADER_BYTES];
    frame_header.copy_from_slice(header_bytes);
    let mut tag = [0_u8; TAG_BYTES];
    tag.copy_from_slice(tag_bytes);
    let nonce = &frame_header[2..];

    let session_key = unwrap_session_key(keys, &wrapped_session_key)?;
    let aad = config
        .authentication_mode()
        .aead_aad(context, &frame_header)
        .map_err(|_| Error::InvalidEnvelope)?;
    let plaintext = Zeroizing::new(
        sm4::mode_gcm::decrypt(&session_key, nonce, &aad, ciphertext, &tag)
            .ok_or(Error::InvalidEnvelope)?,
    );

    let authentication_input = config
        .authentication_mode()
        .authentication_input(context, plaintext.as_slice())
        .map_err(|_| Error::InvalidEnvelope)?;
    if !sm2::verify_with_id(
        &keys.remote_verification,
        config.expected_remote_signer_id(),
        authentication_input.as_slice(),
        &signature,
    ) {
        return Err(Error::InvalidEnvelope);
    }

    Ok(plaintext.to_vec())
}
```

In `src/envelope_crypto/mod.rs`, add the cfg-gated import and dispatch branches:

```rust
#[cfg(feature = "aead")]
use crate::client_config::EnvelopeMode;
```

In `seal`, between the limit check and `cbc::seal(...)`:

```rust
    #[cfg(feature = "aead")]
    if let EnvelopeMode::Aead(algorithm) = config.envelope_mode() {
        return aead::seal(config, keys, plaintext, context, algorithm);
    }
```

In `open`, before `cbc::open(...)`:

```rust
    #[cfg(feature = "aead")]
    if let EnvelopeMode::Aead(algorithm) = config.envelope_mode() {
        return aead::open(config, keys, envelope, context, algorithm);
    }
```

- [ ] **Step 4: Verify**

```bash
cargo test --locked --features aead --lib envelope_crypto 2>&1 | tail -5
cargo test --all-targets --locked 2>&1 | tail -3
cargo test --all-targets --locked --features aead 2>&1 | tail -3
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --locked --features aead -- -D warnings
```

Expected: all pass in both states.

- [ ] **Step 5: Commit**

```bash
git add src/envelope_crypto
git commit -m "feat: SM4-GCM AEAD payload mode with config-pinned dispatch

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 6: AEAD negative and downgrade test matrix

An encoded `cipher` input above the public bound returns `Error::MessageTooLarge`; all other inbound AEAD parse, cryptographic, decoded-bound, context, and downgrade failures must be indistinguishable as `Error::InvalidEnvelope`. The two mode-crossing directions must both reject.

**Files:**
- Modify: `src/envelope_crypto/aead.rs` (tests module only)

**Interfaces:**
- Consumes: Task 5's `seal`/`open` dispatch and `test_support::{peers, aead_peers, key_material, ...}` (add `peers`, `key_material`, `SENDER_SIGNING`, `SENDER_DECRYPTION`, `RECEIVER_SIGNING`, `UNRELATED_KEY`, `wrapped_plaintext_for_receiver` to the test imports).
- Produces: the test names cited by the engineering-evidence map in Task 12.

- [ ] **Step 1: Add the tampering helper and negative tests (write all, watch them fail only if the implementation is wrong — these should pass immediately if Task 5 is correct; any failure is a Task 5 bug to fix now)**

Append inside the `tests` module of `aead.rs`:

```rust
    fn valid_envelope(peers: &crate::envelope_crypto::test_support::Peers) -> SecureEnvelope {
        seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"aead negative-matrix payload",
            &legacy_context(),
        )
        .expect("seal valid AEAD envelope")
    }

    fn with_mutated_frame(
        valid: &SecureEnvelope,
        mutate: impl FnOnce(&mut Vec<u8>),
    ) -> SecureEnvelope {
        let mut frame = STANDARD.decode(&valid.cipher).expect("cipher Base64");
        mutate(&mut frame);
        SecureEnvelope {
            cipher: STANDARD.encode(frame),
            ..valid.clone()
        }
    }

    #[test]
    fn aead_frame_version_algorithm_and_reserved_ccm_ids_are_rejected() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = valid_envelope(&peers);

        for mutated in [
            with_mutated_frame(&valid, |frame| frame[0] ^= 0x01),
            with_mutated_frame(&valid, |frame| frame[0] = 0x00),
            with_mutated_frame(&valid, |frame| frame[1] = 0x02),
            with_mutated_frame(&valid, |frame| frame[1] = 0x7f),
        ] {
            assert_invalid_envelope(open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &mutated,
                &legacy_context(),
            ));
        }
    }

    #[test]
    fn aead_short_and_truncated_frames_are_rejected() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = valid_envelope(&peers);

        let mut floor_minus_one = vec![0_u8; 29];
        floor_minus_one[0] = 0x01;
        floor_minus_one[1] = 0x01;
        for mutated in [
            SecureEnvelope {
                cipher: STANDARD.encode(floor_minus_one),
                ..valid.clone()
            },
            SecureEnvelope {
                cipher: String::new(),
                ..valid.clone()
            },
            with_mutated_frame(&valid, |frame| {
                frame.pop();
            }),
            with_mutated_frame(&valid, |frame| frame.truncate(FRAME_HEADER_BYTES)),
        ] {
            assert_invalid_envelope(open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &mutated,
                &legacy_context(),
            ));
        }
    }

    #[test]
    fn aead_nonce_ciphertext_and_tag_tampering_are_indistinguishable() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = valid_envelope(&peers);

        for mutated in [
            with_mutated_frame(&valid, |frame| frame[2] ^= 0x01),
            // Cover first, middle, and last ciphertext bytes independently.
            with_mutated_frame(&valid, |frame| frame[FRAME_HEADER_BYTES] ^= 0x01),
            with_mutated_frame(&valid, |frame| {
                let ciphertext_len = frame.len() - FRAME_OVERHEAD_BYTES;
                let middle = FRAME_HEADER_BYTES + ciphertext_len / 2;
                frame[middle] ^= 0x01;
            }),
            with_mutated_frame(&valid, |frame| {
                let tag_start = frame.len() - TAG_BYTES;
                let last_ciphertext = tag_start - 1;
                frame[last_ciphertext] ^= 0x01;
            }),
            with_mutated_frame(&valid, |frame| {
                let last = frame.len() - 1;
                frame[last] ^= 0x01;
            }),
            with_mutated_frame(&valid, |frame| {
                let tag_start = frame.len() - 16;
                frame[tag_start..].fill(0);
            }),
        ] {
            assert_invalid_envelope(open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &mutated,
                &legacy_context(),
            ));
        }
    }

    #[test]
    fn aead_domain_separator_and_context_are_covered_by_the_aad() {
        let sender_mode =
            AuthenticationMode::context_bound(b"example/request/v1").expect("sender domain");
        let receiver_mode =
            AuthenticationMode::context_bound(b"example/response/v1").expect("receiver domain");
        let peers = aead_peers(sender_mode, 256);
        let mismatched_receiver_config = crate::envelope_crypto::test_support::aead_config(
            "receiver",
            crate::envelope_crypto::test_support::RECEIVER_SIGNER_ID,
            crate::envelope_crypto::test_support::SENDER_SIGNER_ID,
            receiver_mode,
            256,
        );
        let context =
            AuthenticationContext::context_bound(b"operation=pay&id=17").expect("bound context");
        let envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"domain-separated aead payload",
            &context,
        )
        .expect("seal with sender domain");

        assert_invalid_envelope(open(
            &mismatched_receiver_config,
            &peers.receiver_keys,
            &envelope,
            &context,
        ));
    }

    #[test]
    fn aead_oversized_encoded_and_decoded_ciphers_split_the_public_bounds() {
        // Limit 17: max frame is 47 bytes, whose Base64 length is 64.
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 17);
        let encoded_too_large = SecureEnvelope {
            cipher: "!".repeat(65),
            wrapped_session_key: "not Base64".to_owned(),
            signature: "not Base64".to_owned(),
        };
        let encoded_error = open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &encoded_too_large,
            &legacy_context(),
        )
        .expect_err("encoded cipher is over its public bound");
        assert!(matches!(encoded_error, Error::MessageTooLarge { limit: 17 }));

        // A 48-byte frame still encodes to 64 Base64 characters, but its
        // 18-byte ciphertext body exceeds the 17-byte limit.
        let mut decoded_frame = vec![0_u8; 48];
        decoded_frame[0] = 0x01;
        decoded_frame[1] = 0x01;
        let decoded_too_large = SecureEnvelope {
            cipher: STANDARD.encode(decoded_frame),
            wrapped_session_key: "not Base64".to_owned(),
            signature: "not Base64".to_owned(),
        };
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &decoded_too_large,
            &legacy_context(),
        ));
    }

    #[test]
    fn aead_open_never_returns_plaintext_sealed_beyond_the_local_limit() {
        let sealing_peers = aead_peers(AuthenticationMode::LegacyPlaintext, 18);
        let opening_peers = aead_peers(AuthenticationMode::LegacyPlaintext, 17);
        let envelope = seal(
            &sealing_peers.sender_config,
            &sealing_peers.sender_keys,
            &[b'z'; 18],
            &legacy_context(),
        )
        .expect("seal within the sender's limit");

        assert_invalid_envelope(open(
            &opening_peers.receiver_config,
            &opening_peers.receiver_keys,
            &envelope,
            &legacy_context(),
        ));
    }

    #[test]
    fn aead_wrapped_key_signature_and_wrong_key_failures_match_cbc_semantics() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = valid_envelope(&peers);

        let malformed_wrapped = SecureEnvelope {
            wrapped_session_key: STANDARD.encode(b"not SM2 DER"),
            ..valid.clone()
        };
        let wrong_length_wrapped = SecureEnvelope {
            wrapped_session_key: wrapped_plaintext_for_receiver(b"not-16-bytes"),
            ..valid.clone()
        };
        let mut tampered_signature_bytes =
            STANDARD.decode(&valid.signature).expect("signature Base64");
        let final_byte = tampered_signature_bytes.len() - 1;
        tampered_signature_bytes[final_byte] ^= 1;
        let tampered_signature = SecureEnvelope {
            signature: STANDARD.encode(tampered_signature_bytes),
            ..valid.clone()
        };
        let non_canonical = SecureEnvelope {
            cipher: "AA".to_owned(),
            ..valid.clone()
        };
        let invalid_base64_wrapped = SecureEnvelope {
            wrapped_session_key: "!!!!".to_owned(),
            ..valid.clone()
        };
        let invalid_base64_signature = SecureEnvelope {
            signature: "!!!!".to_owned(),
            ..valid.clone()
        };
        for mutated in [
            malformed_wrapped,
            wrong_length_wrapped,
            tampered_signature,
            non_canonical,
            invalid_base64_wrapped,
            invalid_base64_signature,
        ] {
            assert_invalid_envelope(open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &mutated,
                &legacy_context(),
            ));
        }

        let wrong_decryption = key_material(
            RECEIVER_SIGNING,
            UNRELATED_KEY,
            SENDER_SIGNING,
            SENDER_DECRYPTION,
        );
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &wrong_decryption,
            &valid,
            &legacy_context(),
        ));
        let wrong_verification = key_material(
            RECEIVER_SIGNING,
            RECEIVER_DECRYPTION,
            UNRELATED_KEY,
            SENDER_DECRYPTION,
        );
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &wrong_verification,
            &valid,
            &legacy_context(),
        ));
    }

    #[test]
    fn aead_and_cbc_clients_reject_each_other_s_envelopes() {
        let cbc = crate::envelope_crypto::test_support::peers(
            AuthenticationMode::LegacyPlaintext,
            128,
        );
        let aead = aead_peers(AuthenticationMode::LegacyPlaintext, 128);

        let cbc_envelope = seal(
            &cbc.sender_config,
            &cbc.sender_keys,
            b"cbc payload",
            &legacy_context(),
        )
        .expect("CBC seal");
        assert_invalid_envelope(open(
            &aead.receiver_config,
            &aead.receiver_keys,
            &cbc_envelope,
            &legacy_context(),
        ));

        let aead_envelope = seal(
            &aead.sender_config,
            &aead.sender_keys,
            b"aead payload",
            &legacy_context(),
        )
        .expect("AEAD seal");
        assert_invalid_envelope(open(
            &cbc.receiver_config,
            &cbc.receiver_keys,
            &aead_envelope,
            &legacy_context(),
        ));
    }
```

Extend the tests module's imports to cover the added names: `SecureEnvelope` (`use crate::message::SecureEnvelope;`), and from `test_support`: `key_material, wrapped_plaintext_for_receiver, RECEIVER_SIGNING, SENDER_SIGNING, SENDER_DECRYPTION, UNRELATED_KEY`.

- [ ] **Step 2: Run and fix**

Run: `cargo test --locked --features aead --lib envelope_crypto::aead 2>&1 | tail -6`
Expected: ALL PASS. A failure here means a Task 5 implementation bug (e.g., wrong check order); fix the implementation, never the assertion.

- [ ] **Step 3: Full both-state verification + commit**

```bash
cargo test --all-targets --locked 2>&1 | tail -3
cargo test --all-targets --locked --features aead 2>&1 | tail -3
cargo fmt --all -- --check && cargo clippy --all-targets --locked --features aead -- -D warnings
git add src/envelope_crypto/aead.rs
git commit -m "test: AEAD negative matrix and mode-downgrade rejection

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7: RFC 8998 Appendix A.1 known-answer test

**Files:**
- Modify: `tests/standard_vectors.rs`

**Interfaces:**
- Consumes: `gmcrypto_core::sm4::mode_gcm` (exists only under the feature).
- Produces: the KAT name cited by Task 12's evidence map: `sm4_gcm_matches_rfc_8998_appendix_a_1`.

- [ ] **Step 1: Write the test (verified bytes — gmcrypto-core 1.11.0 reproduces this vector byte-for-byte; confirmed at design time)**

Append to `tests/standard_vectors.rs`:

```rust
#[cfg(feature = "aead")]
#[test]
fn sm4_gcm_matches_rfc_8998_appendix_a_1() {
    use gmcrypto_core::sm4::mode_gcm;

    let key: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let nonce = [
        0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd,
    ];
    let aad = [
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
        0xef, 0xab, 0xad, 0xda, 0xd2,
    ];
    let plaintext = [
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
        0xbb, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa,
    ];
    let expected_ciphertext = [
        0x17, 0xf3, 0x99, 0xf0, 0x8c, 0x67, 0xd5, 0xee, 0x19, 0xd0, 0xdc, 0x99, 0x69, 0xc4, 0xbb,
        0x7d, 0x5f, 0xd4, 0x6f, 0xd3, 0x75, 0x64, 0x89, 0x06, 0x91, 0x57, 0xb2, 0x82, 0xbb, 0x20,
        0x07, 0x35, 0xd8, 0x27, 0x10, 0xca, 0x5c, 0x22, 0xf0, 0xcc, 0xfa, 0x7c, 0xbf, 0x93, 0xd4,
        0x96, 0xac, 0x15, 0xa5, 0x68, 0x34, 0xcb, 0xcf, 0x98, 0xc3, 0x97, 0xb4, 0x02, 0x4a, 0x26,
        0x91, 0x23, 0x3b, 0x8d,
    ];
    let expected_tag = [
        0x83, 0xde, 0x35, 0x41, 0xe4, 0xc2, 0xb5, 0x81, 0x77, 0xe0, 0x65, 0xa9, 0xbf, 0x7b, 0x62,
        0xec,
    ];

    let (ciphertext, tag) =
        mode_gcm::encrypt(&key, &nonce, &aad, &plaintext).expect("standard-vector encryption");
    assert_eq!(ciphertext, expected_ciphertext);
    assert_eq!(tag, expected_tag);

    assert_eq!(
        mode_gcm::decrypt(&key, &nonce, &aad, &expected_ciphertext, &expected_tag)
            .expect("standard-vector decryption"),
        plaintext
    );

    let mut wrong_tag = expected_tag;
    wrong_tag[0] ^= 0x01;
    assert!(mode_gcm::decrypt(&key, &nonce, &aad, &expected_ciphertext, &wrong_tag).is_none());
}
```

- [ ] **Step 2: Run both states**

Run: `cargo test --locked --features aead --test standard_vectors 2>&1 | tail -4` → 4 tests pass (3 existing + 1 new). `cargo test --locked --test standard_vectors 2>&1 | tail -4` → 3 tests pass (KAT compiled out).

- [ ] **Step 3: Commit**

```bash
git add tests/standard_vectors.rs
git commit -m "test: pin SM4-GCM against RFC 8998 appendix A.1

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 8: Client-level integration tests (`tests/aead_envelope.rs`)

**Files:**
- Create: `tests/aead_envelope.rs`

**Interfaces:**
- Consumes: public API only — `SecureClient`, `ClientConfig`, `EnvelopeMode`, `AeadAlgorithm`, `HeaderProtocolAdapter`, `HeaderSchema`, `KeyMaterial::shared`, `PrivateKey`, `PublicKey`.
- Produces: evidence-map citations for Task 12 (`secure_client_round_trips_aead_envelopes_through_a_header_adapter`, `aead_and_cbc_secure_clients_reject_each_other_s_envelopes`).

- [ ] **Step 1: Write the file**

```rust
#![cfg(feature = "aead")]

use std::sync::Arc;

use gmcrypto_core::sm2::Sm2PrivateKey;
use gmcrypto_core::{pkcs8, spki};
use gmcrypto_envelope_lite::{
    AeadAlgorithm, AuthenticationContext, AuthenticationMode, CipherLocation, ClientConfig,
    ClientConfigBuilder, EnvelopeMode, HeaderProtocolAdapter, HeaderSchema, KeyMaterial,
    PrivateKey, PublicKey, ResponseParts, SecureClient,
};

const PASSWORD: &[u8] = b"integration password";

fn key_material() -> KeyMaterial {
    let mut scalar = [0_u8; 32];
    scalar[31] = 9;
    let private = Sm2PrivateKey::from_bytes_be(&scalar).expect("test private key");
    let encrypted =
        pkcs8::encrypt(&private, PASSWORD, &[3_u8; 16], 1, &[4_u8; 16]).expect("encrypted key");
    let public = spki::encode(&private.public_key());
    KeyMaterial::shared(
        PrivateKey::from_encrypted_der(&encrypted, PASSWORD).expect("private key"),
        PublicKey::from_der(&public).expect("public key"),
    )
}

fn base_builder() -> ClientConfigBuilder {
    ClientConfig::builder()
        .local_identity_id("integration-identity")
        .api_version("integration-v1")
        .local_certificate_id("integration-certificate")
        .expected_remote_signing_certificate_id("integration-certificate")
        .remote_encryption_certificate_id("integration-encryption-certificate")
        .local_signer_id(b"integration-signer")
        .expected_remote_signer_id(b"integration-signer")
        .authentication_mode(AuthenticationMode::LegacyPlaintext)
}

fn schema() -> HeaderSchema {
    HeaderSchema::builder()
        .local_identity_header("X-It-Local-Identity")
        .operation_header("X-It-Operation")
        .request_id_header("X-It-Request-Id")
        .request_time_header("X-It-Request-Time")
        .api_version_header("X-It-Api-Version")
        .local_certificate_header("X-It-Local-Certificate")
        .remote_signing_certificate_header("X-It-Remote-Signing-Certificate")
        .remote_encryption_certificate_header("X-It-Remote-Encryption-Certificate")
        .request_signature_header("X-It-Request-Signature")
        .request_wrapped_key_header("X-It-Request-Wrapped-Key")
        .request_cipher(CipherLocation::Body)
        .response_signature_header("X-It-Response-Signature")
        .response_wrapped_key_header("X-It-Response-Wrapped-Key")
        .response_remote_signing_certificate_header("X-It-Response-Remote-Signing-Certificate")
        .response_cipher(CipherLocation::Body)
        .legacy_authentication()
        .build()
        .expect("complete integration schema")
}

fn aead_client() -> SecureClient {
    let config = base_builder()
        .envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm))
        .build()
        .expect("AEAD configuration");
    SecureClient::new(
        config,
        key_material(),
        Arc::new(HeaderProtocolAdapter::new(schema())),
    )
}

fn cbc_client() -> SecureClient {
    let config = base_builder()
        .iv(*b"0123456789abcdef")
        .build()
        .expect("CBC configuration");
    SecureClient::new(
        config,
        key_material(),
        Arc::new(HeaderProtocolAdapter::new(schema())),
    )
}

#[test]
fn secure_client_round_trips_aead_envelopes_through_a_header_adapter() {
    let client = aead_client();
    let plaintext = b"adapter-mapped aead payload";
    let envelope = client
        .seal(plaintext, &AuthenticationContext::legacy())
        .expect("seal");

    // The unchanged header adapter carries the AEAD envelope like any other:
    // the frame lives inside the existing cipher field.
    let response = ResponseParts::new(
        [
            ("X-It-Response-Signature", envelope.signature.clone()),
            (
                "X-It-Response-Wrapped-Key",
                envelope.wrapped_session_key.clone(),
            ),
            (
                "X-It-Response-Remote-Signing-Certificate",
                "integration-certificate".to_owned(),
            ),
        ],
        envelope.cipher.clone(),
    );
    assert_eq!(
        client.open_response(response).expect("open response"),
        plaintext
    );
}

#[test]
fn aead_and_cbc_secure_clients_reject_each_other_s_envelopes() {
    let aead = aead_client();
    let cbc = cbc_client();
    let context = AuthenticationContext::legacy();

    let aead_envelope = aead.seal(b"aead payload", &context).expect("AEAD seal");
    assert!(cbc.open(&aead_envelope, &context).is_err());

    let cbc_envelope = cbc.seal(b"cbc payload", &context).expect("CBC seal");
    assert!(aead.open(&cbc_envelope, &context).is_err());
}
```

- [ ] **Step 2: Run both states**

Run: `cargo test --locked --features aead --test aead_envelope 2>&1 | tail -4` → 2 pass. `cargo test --locked --test aead_envelope 2>&1 | tail -3` → 0 tests (file compiled out); confirm no compile error.

- [ ] **Step 3: Commit**

```bash
git add tests/aead_envelope.rs
git commit -m "test: client-level AEAD adapter round trip and mode rejection

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 9: Fuzz target, corpus, and fuzz-script contracts

**Files:**
- Modify: `fuzz/Cargo.toml`, `fuzz/Cargo.lock` (via cargo), `fuzz/fuzz_targets/support.rs`, `fuzz/tests/scenarios.rs`, `ci/fuzz-smoke.sh`, `tests/fuzz_smoke.sh`
- Create: `fuzz/fuzz_targets/aead_envelope.rs`, `fuzz/corpus/aead_envelope/` (19 seed files)

**Interfaces:**
- Consumes: crate public API with the feature on; existing `support.rs` machinery (`fields`, `select_value`, `text`, `schema`).
- Produces: fuzz target `aead_envelope`; `support::{AEAD_CIPHER_LIMIT, aead_client, aead_valid_envelope, aead_encoded_values}`.

- [ ] **Step 1: Enable the feature for the fuzz workspace**

In `fuzz/Cargo.toml` change the path dependency to:

```toml
gmcrypto-envelope-lite = { path = "..", features = ["aead"] }
```

and append:

```toml
[[bin]]
name = "aead_envelope"
path = "fuzz_targets/aead_envelope.rs"
test = false
doc = false
bench = false
```

Then `cd fuzz && cargo metadata --format-version 1 >/dev/null && cd ..` — expected: `fuzz/Cargo.lock` gains exactly `gmcrypto-simd` 1.11.0 and `cpufeatures` 0.2.17 (root inventory only covers the root lockfile, so no inventory change).

- [ ] **Step 2: Extend `support.rs`**

Append to `fuzz/fuzz_targets/support.rs` (near the existing limit consts):

```rust
pub const AEAD_FRAME_OVERHEAD_BYTES: usize = 30;
// An AEAD frame at the 64-byte plaintext limit is 94 bytes; Base64 rounds up by triples.
pub const AEAD_CIPHER_LIMIT: usize = (MAX_PLAINTEXT_BYTES + AEAD_FRAME_OVERHEAD_BYTES)
    .div_ceil(3)
    * 4;
```

and at the end of the file:

```rust
pub fn aead_client() -> &'static SecureClient {
    static CLIENT: OnceLock<SecureClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let mut scalar = [0_u8; 32];
        scalar[31] = 7;
        let private = Sm2PrivateKey::from_bytes_be(&scalar).expect("valid public test scalar");
        let encrypted = pkcs8::encrypt(&private, TEST_PASSWORD, &[7_u8; 16], 1, &[8_u8; 16])
            .expect("runtime-only encrypted fuzz key");
        let public = spki::encode(&private.public_key());
        let config = ClientConfig::builder()
            .local_identity_id("fuzz-identity")
            .api_version("fuzz-v1")
            .local_certificate_id("fuzz-certificate")
            .expected_remote_signing_certificate_id("fuzz-certificate")
            .remote_encryption_certificate_id("fuzz-encryption-certificate")
            .local_signer_id(b"fuzz-signer")
            .expected_remote_signer_id(b"fuzz-signer")
            .authentication_mode(AuthenticationMode::LegacyPlaintext)
            .envelope_mode(gmcrypto_envelope_lite::EnvelopeMode::Aead(
                gmcrypto_envelope_lite::AeadAlgorithm::Sm4Gcm,
            ))
            .max_plaintext_bytes(MAX_PLAINTEXT_BYTES)
            .build()
            .expect("fixed AEAD fuzz configuration");
        let keys = KeyMaterial::shared(
            PrivateKey::from_encrypted_der(&encrypted, TEST_PASSWORD)
                .expect("runtime-only fuzz private key"),
            PublicKey::from_der(&public).expect("runtime-only fuzz public key"),
        );
        SecureClient::new(
            config,
            keys,
            Arc::new(HeaderProtocolAdapter::new(schema().clone())),
        )
    })
}

pub fn aead_valid_envelope() -> &'static SecureEnvelope {
    static ENVELOPE: OnceLock<SecureEnvelope> = OnceLock::new();
    ENVELOPE.get_or_init(|| {
        aead_client()
            .seal(VALID_PLAINTEXT, &AuthenticationContext::legacy())
            .expect("runtime-generated valid AEAD fuzz envelope")
    })
}

pub fn aead_encoded_values(data: &[u8]) -> (String, String, String) {
    let [signature_raw, wrapped_raw, cipher_raw] = fields(data);
    let selectors = data.get(..6).unwrap_or_default();
    let envelope = aead_valid_envelope();
    (
        select_value(
            selectors.first(),
            selectors.get(3),
            signature_raw,
            &envelope.signature,
            AUXILIARY_LIMIT,
        ),
        select_value(
            selectors.get(1),
            selectors.get(4),
            wrapped_raw,
            &envelope.wrapped_session_key,
            AUXILIARY_LIMIT,
        ),
        select_value(
            selectors.get(2),
            selectors.get(5),
            cipher_raw,
            &envelope.cipher,
            AEAD_CIPHER_LIMIT,
        ),
    )
}
```

- [ ] **Step 3: Create `fuzz/fuzz_targets/aead_envelope.rs`**

```rust
#![no_main]

mod support;

use gmcrypto_envelope_lite::ResponseParts;
use libfuzzer_sys::fuzz_target;

const FULL_VALID: &[u8] = include_bytes!("../corpus/aead_envelope/full_valid_open");

fuzz_target!(|data: &[u8]| {
    let (signature, wrapped_key, cipher) = support::aead_encoded_values(data);
    let response = ResponseParts::new(
        [
            ("X-Fuzz-Response-Signature", signature),
            ("X-Fuzz-Response-Wrapped-Key", wrapped_key),
            (
                "X-Fuzz-Response-Remote-Signing-Certificate",
                "fuzz-certificate".to_owned(),
            ),
        ],
        cipher,
    );
    let opened = support::aead_client().open_response(response);
    if data == FULL_VALID {
        assert_eq!(
            opened.expect("full valid AEAD envelope opens"),
            support::VALID_PLAINTEXT
        );
    }
});
```

- [ ] **Step 4: Create the corpus seeds**

```bash
mkdir -p fuzz/corpus/aead_envelope
cd fuzz/corpus/aead_envelope
printf 'vvv000|0:|0:|0:\n'  > full_valid_open
printf 'rrr000|1:!|1:!|1:!\n' > raw_malformed
printf 'vvb000|0:|0:|0:\n'  > cipher_limit_minus_one
printf 'vvb001|0:|0:|0:\n'  > cipher_limit
printf 'vvb002|0:|0:|0:\n'  > cipher_limit_plus_one
printf 'vbv000|0:|0:|0:\n'  > wrapped_key_limit_minus_one
printf 'vbv010|0:|0:|0:\n'  > wrapped_key_limit
printf 'vbv020|0:|0:|0:\n'  > wrapped_key_limit_plus_one
printf 'bvv000|0:|0:|0:\n'  > signature_limit_minus_one
printf 'bvv100|0:|0:|0:\n'  > signature_limit
printf 'bvv200|0:|0:|0:\n'  > signature_limit_plus_one
printf 'vvm000|0:|0:|0:\n'  > cryptographic_mutation_cipher
printf 'vmv000|0:|0:|0:\n'  > cryptographic_mutation_wrapped_key
printf 'mvv000|0:|0:|0:\n'  > cryptographic_mutation_signature
# The mutation selector flips the Base64 character indexed by the first raw
# cipher byte: char 8 lands in the nonce region, char 40 in the tag region
# of the 60-character valid AEAD cipher (13-byte plaintext, 43-byte frame).
printf 'vvm000|0:|0:|1:\010\n' > cryptographic_mutation_nonce
printf 'vvm000|0:|0:|1:(\n'  > cryptographic_mutation_tag
printf 'vvr000|0:|0:|40:AQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' > frame_floor
printf 'vvr000|0:|0:|40:AQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' > frame_floor_minus_one
printf 'vvr000|0:|0:|44:AQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' > reserved_ccm_algorithm
cd ../../..
```

First verify the three raw Base64 strings decode to the intended frames:

```bash
python3 - <<'EOF'
import base64
assert base64.b64decode("AQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == bytes([1, 1] + [0] * 28)
assert base64.b64decode("AQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") == bytes([1, 1] + [0] * 27)
assert base64.b64decode("AQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") == bytes([1, 2] + [0] * 30)
print("corpus frames ok")
EOF
```

Expected: `corpus frames ok`. (`frame_floor` is a structurally valid 30-byte SM4-GCM frame that reaches the tag check and fails there; `frame_floor_minus_one` is 29 bytes and fails the floor; `reserved_ccm_algorithm` is a 32-byte frame carrying the reserved `0x02` id and fails the algorithm pin.)

- [ ] **Step 5: Mirror the corpus contracts in `fuzz/tests/scenarios.rs`**

Read the encoded-envelope portions of `fuzz/tests/scenarios.rs` first (the `ENCODED_CASES` list, `every_tracked_seed_has_a_contract_case`, and any test driving `support::encoded_values`), then mirror them:

```rust
const AEAD_FULL_VALID: &[u8] = include_bytes!("../corpus/aead_envelope/full_valid_open");

const AEAD_CASES: &[(&str, &[u8])] = &[
    (
        "cipher_limit",
        include_bytes!("../corpus/aead_envelope/cipher_limit"),
    ),
    (
        "cipher_limit_minus_one",
        include_bytes!("../corpus/aead_envelope/cipher_limit_minus_one"),
    ),
    (
        "cipher_limit_plus_one",
        include_bytes!("../corpus/aead_envelope/cipher_limit_plus_one"),
    ),
    (
        "cryptographic_mutation_cipher",
        include_bytes!("../corpus/aead_envelope/cryptographic_mutation_cipher"),
    ),
    (
        "cryptographic_mutation_nonce",
        include_bytes!("../corpus/aead_envelope/cryptographic_mutation_nonce"),
    ),
    (
        "cryptographic_mutation_signature",
        include_bytes!("../corpus/aead_envelope/cryptographic_mutation_signature"),
    ),
    (
        "cryptographic_mutation_tag",
        include_bytes!("../corpus/aead_envelope/cryptographic_mutation_tag"),
    ),
    (
        "cryptographic_mutation_wrapped_key",
        include_bytes!("../corpus/aead_envelope/cryptographic_mutation_wrapped_key"),
    ),
    ("frame_floor", include_bytes!("../corpus/aead_envelope/frame_floor")),
    (
        "frame_floor_minus_one",
        include_bytes!("../corpus/aead_envelope/frame_floor_minus_one"),
    ),
    ("full_valid_open", AEAD_FULL_VALID),
    ("raw_malformed", include_bytes!("../corpus/aead_envelope/raw_malformed")),
    (
        "reserved_ccm_algorithm",
        include_bytes!("../corpus/aead_envelope/reserved_ccm_algorithm"),
    ),
    (
        "signature_limit",
        include_bytes!("../corpus/aead_envelope/signature_limit"),
    ),
    (
        "signature_limit_minus_one",
        include_bytes!("../corpus/aead_envelope/signature_limit_minus_one"),
    ),
    (
        "signature_limit_plus_one",
        include_bytes!("../corpus/aead_envelope/signature_limit_plus_one"),
    ),
    (
        "wrapped_key_limit",
        include_bytes!("../corpus/aead_envelope/wrapped_key_limit"),
    ),
    (
        "wrapped_key_limit_minus_one",
        include_bytes!("../corpus/aead_envelope/wrapped_key_limit_minus_one"),
    ),
    (
        "wrapped_key_limit_plus_one",
        include_bytes!("../corpus/aead_envelope/wrapped_key_limit_plus_one"),
    ),
];
```

Add `assert_corpus_names("aead_envelope", AEAD_CASES.iter().map(|(name, _)| *name));` inside `every_tracked_seed_has_a_contract_case`, and add a contract test (adapt the response-header names to whatever the existing encoded-envelope contract test uses — they are the `X-Fuzz-Response-*` names):

```rust
#[test]
fn curated_aead_seeds_open_reject_and_hit_the_cipher_limit() {
    let open_with = |seed: &[u8]| {
        let (signature, wrapped_key, cipher) = support::aead_encoded_values(seed);
        support::aead_client().open_response(ResponseParts::new(
            [
                ("X-Fuzz-Response-Signature", signature),
                ("X-Fuzz-Response-Wrapped-Key", wrapped_key),
                (
                    "X-Fuzz-Response-Remote-Signing-Certificate",
                    "fuzz-certificate".to_owned(),
                ),
            ],
            cipher,
        ))
    };

    assert_eq!(
        open_with(AEAD_FULL_VALID).expect("full valid AEAD seed opens"),
        support::VALID_PLAINTEXT
    );
    for (name, seed) in AEAD_CASES {
        if *name == "full_valid_open" {
            continue;
        }
        assert!(open_with(seed).is_err(), "{name} must be rejected");
    }

    let (_, _, at_limit) = support::aead_encoded_values(
        b"vvb001|0:|0:|0:",
    );
    assert_eq!(at_limit.len(), support::AEAD_CIPHER_LIMIT);
    let (_, _, over_limit) = support::aead_encoded_values(
        b"vvb002|0:|0:|0:",
    );
    assert_eq!(over_limit.len(), support::AEAD_CIPHER_LIMIT + 1);
}
```

- [ ] **Step 6: Extend the smoke scripts**

`ci/fuzz-smoke.sh`: change `for target in transport_parts encoded_envelope typed_headers` to `for target in transport_parts encoded_envelope typed_headers aead_envelope`.

`tests/fuzz_smoke.sh`: add `aead_envelope` to every target enumeration (lines 20, 194, 233 loops and the two `printf '%s\n' scenario fuzz:...` expectation lists at lines 179 and 239, appending `fuzz:aead_envelope`), change both `-eq 3` target-count assertions (lines 183 and 245) to `-eq 4` and their messages from `three` to `four`, extend the ordered-target assertion at line 184 with `aead_envelope`, and append a corpus-content assertion next to line 247:

```sh
contains "$repo_root/fuzz/corpus/aead_envelope/full_valid_open" "vvv000|0:|0:|0:"
```

- [ ] **Step 7: Verify**

```bash
(cd fuzz && cargo test --locked 2>&1 | tail -4)
sh tests/fuzz_smoke.sh
```

Expected: scenario tests pass including the new AEAD contract; the fuzz-runner self-test passes with four targets. If `cargo-fuzz` and the pinned nightly are installed locally, also run `sh ci/fuzz-smoke.sh smoke` (several minutes); otherwise defer to Task 14's battery.

- [ ] **Step 8: Commit**

```bash
git add fuzz ci/fuzz-smoke.sh tests/fuzz_smoke.sh
git commit -m "test: bounded fuzz target and corpus for the AEAD envelope

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 10: Two-tier cryptographic dependency inventory

The AEAD boundary is the resolution delta under `--features aead`: `gmcrypto-simd`, `cpufeatures`, plus an overriding `gmcrypto-core` row whose feature set becomes `default,sm4-aead,x509`. One checker entry point runs both passes.

**Files:**
- Create: `ci/crypto-inventory-aead.snapshot`
- Modify: `ci/check-crypto-inventory.sh`, `docs/security/cryptographic-dependencies.md`, `tests/crypto_inventory.sh`, `tests/release_documents.rs`, `tests/release_candidate.sh`, `ci/tool-versions.sh`

**Interfaces:**
- Consumes: Task 1's lockfile.
- Produces: the inventory gate all later tasks and CI rely on.

- [ ] **Step 1: Write the AEAD snapshot**

Create `ci/crypto-inventory-aead.snapshot`:

```
# name|version|enabled-features|registry-checksum|unsafe-source-scan-status
cpufeatures|0.2.17|none|59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280|reviewed-unsafe-present
gmcrypto-core|1.11.0|default,sm4-aead,x509|4e81a6030cdbef95407ef7924aa2b60469d1263e094b667295cd3d787c2c3095|reviewed-no-unsafe-source
gmcrypto-simd|1.11.0|none|31a7928890d12bd4064aba2664435fc62b2a6a487f8c2611d26856f31d5ceca4|reviewed-unsafe-present
```

Before committing to these feature strings, verify each against the real resolution:

```bash
cargo tree --locked --features aead -e features -i gmcrypto-simd@1.11.0 | sed -n 's/.*gmcrypto-simd feature "\([^"]*\)".*/\1/p' | sort -u
cargo tree --locked --features aead -e features -i cpufeatures@0.2.17 | sed -n 's/.*cpufeatures feature "\([^"]*\)".*/\1/p' | sort -u
cargo tree --locked --features aead -e features -i gmcrypto-core@1.11.0 | sed -n 's/.*gmcrypto-core feature "\([^"]*\)".*/\1/p' | sort -u
```

Expected: empty, empty, and `default`/`sm4-aead`/`x509`. If gmcrypto-simd or cpufeatures print features, put that comma-joined sorted list in the snapshot instead of `none`.

- [ ] **Step 2: Rewrite `ci/check-crypto-inventory.sh` for two passes**

Keep `fail`, `sha256_file`, `valid_checksum`, `lock_checksum`, `single_lock_checksum` unchanged. Apply these changes:

a. Header additions:

```sh
aead_snapshot="$repo_root/ci/crypto-inventory-aead.snapshot"
aead_boundary_packages='cpufeatures@0.2.17 gmcrypto-core@1.11.0 gmcrypto-simd@1.11.0'
```

b. After the existing `test -f "$snapshot" || ...` line: `test -f "$aead_snapshot" || fail "AEAD cryptographic dependency snapshot is missing"`.

c. After the existing manifest grep, add:

```sh
grep -F 'aead = ["gmcrypto-core/sm4-aead"]' \
    "$repo_root/Cargo.toml" >/dev/null || fail "aead feature definition changed"
```

d. Run the row-validity awk over both snapshot files (same awk body, once per file; the aead failure message: `AEAD cryptographic dependency snapshot has an invalid row`).

e. Row-count arithmetic: compute `snapshot_row_count` and `aead_row_count`; the table check becomes

```sh
test "$inventory_table_line_count" -eq "$((snapshot_row_count + aead_row_count + 4))" ||
    fail "human-readable cryptographic dependency table is invalid"
```

f. Names check: extend the existing per-snapshot duplicate/name checks — validate the default snapshot against `boundary_packages` exactly as today, and the AEAD snapshot names against `aead_boundary_packages` the same way (sorted `cmp`).

g. Doc-vs-snapshot check: build `snapshot_view` from the **concatenation** of both snapshots:

```sh
{ grep -v '^#' "$snapshot"; grep -v '^#' "$aead_snapshot"; } | sed '/^$/d' | LC_ALL=C sort >"$snapshot_view"
```

(The doc's row extractor already collects rows from every table.)

h. `feature_list` gains a mode argument:

```sh
feature_list() {
    package=$1
    version=$2
    tree_mode=${3:-default}
    if [ "$tree_mode" = aead ]; then
        set -- --features aead
    else
        set --
    fi
    if ! feature_tree=$(cd "$repo_root" && cargo tree --locked "$@" -e features -i "$package@$version"); then
        fail "cargo tree has no single resolved feature graph for $package $version"
    fi
    ...unchanged tail...
}
```

i. Resolution pass 1 (unchanged): default packages vs default snapshot. Resolution pass 2: build the expected overlay (default snapshot minus its `gmcrypto-core` line, plus every AEAD snapshot line), then resolve each overlay package with `feature_list "$package" "$version" aead`:

```sh
overlay_expected=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-aead-expected.XXXXXX")
overlay_actual=$(mktemp "${TMPDIR:-/tmp}/secure-envelope-aead-actual.XXXXXX")
# extend the trap cleanup list with both files
{ grep -v '^#' "$snapshot" | sed '/^$/d' | grep -v '^gmcrypto-core|'; \
  grep -v '^#' "$aead_snapshot" | sed '/^$/d'; } | LC_ALL=C sort >"$overlay_expected"
while IFS='|' read -r package version _rest; do
    features=$(feature_list "$package" "$version" aead)
    checksum=$(single_lock_checksum "$package" "$version")
    printf '%s|%s|%s|%s\n' "$package" "$version" "$features" "$checksum" >>"$overlay_actual"
done <"$overlay_expected"
LC_ALL=C sort -o "$overlay_actual" "$overlay_actual"
cut -d'|' -f1-4 <"$overlay_expected" >"$overlay_expected.view"
cmp -s "$overlay_expected.view" "$overlay_actual" || \
    fail "resolved AEAD cryptographic dependency package, feature, or checksum differs from the reviewed snapshot"
```

(Adjust temp-file handling to the script's existing mktemp+trap style, including the `.view` file.)

- [ ] **Step 3: Update the inventory document**

In `docs/security/cryptographic-dependencies.md`:

a. `**Inventory version:** 1` → `**Inventory version:** 2`.

b. After the existing table's closing paragraph (`The direct manifest request is ...`), insert:

```markdown
## AEAD feature boundary

The rows below are compiled only under the opt-in `aead` feature (`aead = ["gmcrypto-core/sm4-aead"]`). They are locked in `Cargo.lock` unconditionally because Cargo locks the maximal feature graph, but a default build compiles none of this code. The `gmcrypto-core` row here overrides the default-boundary row's enabled-feature set; its registry checksum and scan status are identical. `ci/check-crypto-inventory.sh` validates this table as an overlay on the default boundary using `cargo tree --locked --features aead`.

| Dependency | Resolved version | Enabled features | Registry checksum | Source-scan status | SDK responsibility |
| --- | --- | --- | --- | --- | --- |
| `gmcrypto-core` | `1.11.0` | `default`, `sm4-aead`, `x509` | `4e81a6030cdbef95407ef7924aa2b60469d1263e094b667295cd3d787c2c3095` | reviewed: no unsafe source | Adds SM4-GCM sealing and opening for the AEAD envelope mode |
| `gmcrypto-simd` | `1.11.0` | `none` | `31a7928890d12bd4064aba2664435fc62b2a6a487f8c2611d26856f31d5ceca4` | reviewed: unsafe source present | GHASH carryless-multiply and SIMD SM4 S-box backends quarantined out of `gmcrypto-core` |
| `cpufeatures` | `0.2.17` | `none` | `59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280` | reviewed: unsafe source present | Runtime CPU-capability detection for SIMD backend selection |

The `sm4-aead` feature is atomic in `gmcrypto-core` and is defined as `["dep:gmcrypto-simd"]`: enabling GCM alone or CCM alone is not possible, and the SIMD crate is the AVX2/NEON and GHASH `clmul`/`pmull` quarantine that lets `gmcrypto-core` keep `unsafe_code = "forbid"` while `gmcrypto-simd` itself sets `unsafe_code = "warn"`. `cpufeatures` depends on the already-locked `libc`, which remains outside this cryptographic boundary as platform plumbing. No constant-time claim is made for the SIMD backends. Each source-scan status remains limited to the exact registry checksum in its row and is not an audit or a safety proof.
```

(If Step 1's verification produced non-`none` feature lists, mirror them here.)

- [ ] **Step 4: Extend the checker self-test**

Append to `tests/crypto_inventory.sh` before the final success line, following the existing `make_fixture`/`expect_failure`/`cleanup_fixture` idiom:

```sh
make_fixture
rm "$fixture/ci/crypto-inventory-aead.snapshot"
expect_failure "missing AEAD snapshot" "AEAD cryptographic dependency snapshot is missing"
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
replace_text "$fixture/Cargo.toml" \
    'aead = \["gmcrypto-core\/sm4-aead"\]' \
    'aead = []'
expect_failure "altered aead feature definition" "aead feature definition changed"
cleanup_fixture
```

(Adjust the `replace_text` escaping to match its `sed` usage: the third case needs the brackets escaped exactly as shown or use a distinct marker string — verify each mutation actually applied via the built-in `expect_contains`.)

- [ ] **Step 5: Version counters and release-document expectations**

- `ci/tool-versions.sh`: `CRYPTO_INVENTORY_VERSION=1` → `2`.
- `tests/release_documents.rs`: the assertion containing `"**Inventory version:** 1"` → `"**Inventory version:** 2"`.
- `tests/release_candidate.sh`: update its hardcoded cryptographic-inventory fixture document from `**Inventory version:** 1` to `**Inventory version:** 2`, because it copies `ci/tool-versions.sh` into the fixture.

- [ ] **Step 6: Verify**

```bash
./ci/check-crypto-inventory.sh
sh tests/crypto_inventory.sh
cargo test --test release_documents --locked 2>&1 | tail -3
sh tests/release_candidate.sh
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add ci/crypto-inventory-aead.snapshot ci/check-crypto-inventory.sh docs/security/cryptographic-dependencies.md tests/crypto_inventory.sh tests/release_documents.rs tests/release_candidate.sh ci/tool-versions.sh
git commit -m "docs: two-tier cryptographic inventory for the aead feature

The AEAD boundary is validated as an overlay: gmcrypto-simd and
cpufeatures plus the gmcrypto-core row whose resolved feature set
becomes default,sm4-aead,x509 under --features aead.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 11: CI matrix and workflow contracts

**Files:**
- Modify: `.github/workflows/ci.yml`, `tests/workflows.sh`

**Interfaces:**
- Consumes: everything previous (CI now exercises it).
- Produces: CI coverage for `--features aead` in test, MSRV, and quality jobs.

- [ ] **Step 1: Extend `ci.yml`**

- `test` job: after `- run: cargo test --all-targets --locked` add `      - run: cargo test --all-targets --locked --features aead`.
- `msrv` job: same addition after its `cargo test` line.
- `quality` job: after `- run: cargo clippy --all-targets --locked -- -D warnings` add `      - run: cargo clippy --all-targets --locked --features aead -- -D warnings`; after `- run: cargo test --doc --locked` add `      - run: cargo test --doc --locked --features aead`; after the `RUSTDOCFLAGS` doc line add `      - run: RUSTDOCFLAGS="-D missing-docs -D warnings" cargo doc --locked --no-deps --features aead`.

- [ ] **Step 2: Extend the workflow contracts**

In `tests/workflows.sh`:

- After the `require_run_step "$check_tmp/ci-test" 'cargo test --all-targets --locked'` block add:

```sh
    require_run_step "$check_tmp/ci-test" 'cargo test --all-targets --locked --features aead' \
        "test job must run locked all-target tests with the aead feature"
```

- Same addition for `"$check_tmp/ci-msrv"` with message `"MSRV job must run locked all-target tests with the aead feature"`.
- In the quality job's `for command in ... do require_run_step ... done` list, add three entries:

```sh
        'cargo clippy --all-targets --locked --features aead -- -D warnings' \
        'cargo test --doc --locked --features aead' \
        'RUSTDOCFLAGS="-D missing-docs -D warnings" cargo doc --locked --no-deps --features aead' \
```

- [ ] **Step 3: Verify and commit**

```bash
sh tests/workflows.sh
git add .github/workflows/ci.yml tests/workflows.sh
git commit -m "ci: run tests, clippy, and docs under --features aead

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

Expected before commit: `tests/workflows.sh` passes (it runs actionlint; it must be the pinned 1.7.12 locally — if actionlint is missing locally, install `actionlint@v1.7.12` first; do not skip the check).

---

### Task 12: Documentation — README mode table, security model v2, evidence map v2

**Files:**
- Modify: `README.md`, `SECURITY_MODEL.md`, `docs/security/engineering-evidence.md`, `tests/release_documents.rs`, `tests/release_candidate.sh`, `ci/tool-versions.sh`

**Interfaces:**
- Consumes: test names from Tasks 5–8.
- Produces: the "choosing a mode" table required by spec §13.7 and acceptance criterion 9.

- [ ] **Step 1: README**

a. In **Authentication modes**, replace the sentence `Do not copy this fixed-IV CBC design into a new protocol. A new protocol should use a reviewed AEAD construction with a unique nonce or IV for every message. This crate does not provide an AEAD envelope profile.` with:

```markdown
Do not copy this fixed-IV CBC design into a new protocol. New integrations should enable the opt-in `aead` feature and select the SM4-GCM envelope mode described under "Choosing an envelope mode"; without that feature this crate provides no AEAD envelope profile.
```

b. Insert a new section immediately after **Authentication modes** (before **Constructing a client**):

````markdown
## Choosing an envelope mode

The envelope mode is pinned by `ClientConfig` and never inferred from incoming bytes: there is no negotiation and no fallback, and a client rejects envelopes of the other mode outright. `AuthenticationMode` (what the SM2 signature covers) is an independent axis and composes with both modes.

| | `EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm)` — feature `aead` | `EnvelopeMode::LegacyCbc` — default |
| --- | --- | --- |
| Payload cipher | SM4-GCM with a fresh random 12-byte nonce per envelope | SM4-CBC with the configured fixed IV |
| Ciphertext integrity | AEAD tag, verified before any plaintext is produced | none from the cipher; only the SM2 signature, after decryption |
| Bound metadata | frame header, domain separator, and protocol context in the AAD | signed transcript only |
| Replay protection | none — application concern | none — application concern |
| Intended use | new integrations | existing deployed wires, supported indefinitely |

The SM2 signature remains mandatory under AEAD: the session key is encrypted to a public key, so the tag alone proves nothing about who sealed the envelope. An AEAD configuration must not set `iv`:

```no_run
# #[cfg(feature = "aead")] {
use gmcrypto_envelope_lite::{AeadAlgorithm, AuthenticationMode, ClientConfig, EnvelopeMode};

let config = ClientConfig::builder()
    .local_identity_id("demo-client")
    .api_version("example-v1")
    .local_certificate_id("example-local-signing-certificate")
    .expected_remote_signing_certificate_id("example-remote-signing-certificate")
    .remote_encryption_certificate_id("example-remote-encryption-certificate")
    .local_signer_id(b"demo-local-signer")
    .expected_remote_signer_id(b"demo-remote-signer")
    .authentication_mode(AuthenticationMode::LegacyPlaintext)
    .envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm))
    .build();
assert!(config.is_ok());
# }
```
````

- [ ] **Step 2: SECURITY_MODEL.md → version 2**

a. `**Model version:** 1` → `**Model version:** 2`; `for `gmcrypto-envelope-lite` 0.1.x` → `for `gmcrypto-envelope-lite` 0.2.x`.

b. In **Outbound envelopes**, append the paragraph:

```markdown
Under the opt-in `aead` feature and a configured AEAD envelope mode, sealing instead encrypts with SM4-GCM under a fresh random 12-byte nonce, authenticating a length-prefixed AAD of a fixed domain label, the cipher frame header, the configured domain separator, and the protocol context. Session-key freshness — not the nonce — is the primary defense against `(key, nonce)` reuse; the random nonce is defense in depth. The SM2 signature over the authentication input remains mandatory, because an AEAD tag under a session key encrypted to a public key proves nothing about the sender.
```

c. In **Inbound envelopes**, append:

```markdown
Under an AEAD envelope mode, plaintext is returned only after encoded-size checks, strict Base64 decoding, frame version and algorithm-identifier pinning against the configuration, ciphertext-length validation, session-key unwrapping, AAD reconstruction, GCM tag verification (which precedes any plaintext materialization), and signature verification. The envelope mode is never inferred from inbound bytes: an AEAD client rejects CBC envelopes outright and a CBC client rejects AEAD frames.
```

d. In **Explicit non-claims**, replace `- It does not provide an AEAD envelope profile. The fixed-IV SM4-CBC construction exists only for legacy wire compatibility and can reveal plaintext-prefix equality under key reuse.` with:

```markdown
- Without the opt-in `aead` feature it provides no AEAD envelope profile; the fixed-IV SM4-CBC construction exists only for legacy wire compatibility and can reveal plaintext-prefix equality under key reuse. The `aead` feature's SM4-GCM mode does not add replay protection or freshness, and it compiles `gmcrypto-simd` and `cpufeatures`, which contain unsafe code reviewed only as recorded in the cryptographic dependency inventory.
```

- [ ] **Step 3: engineering-evidence.md → version 2**

`**Evidence version:** 1` → `**Evidence version:** 2`; append table rows:

```markdown
| AEAD envelopes round-trip under both authentication modes with fresh keys and nonces | `src/envelope_crypto/aead.rs::tests::aead_round_trips_in_both_directions_with_distinct_roles`; `src/envelope_crypto/aead.rs::tests::every_aead_seal_uses_a_fresh_session_key_and_nonce` | Required test |
| AEAD frame pinning, tampering, bounds, and wrong keys return only InvalidEnvelope | `src/envelope_crypto/aead.rs::tests::aead_frame_version_algorithm_and_reserved_ccm_ids_are_rejected`; `src/envelope_crypto/aead.rs::tests::aead_nonce_ciphertext_and_tag_tampering_are_indistinguishable`; `src/envelope_crypto/aead.rs::tests::aead_wrapped_key_signature_and_wrong_key_failures_match_cbc_semantics` | Required semantic-negative gate |
| The envelope mode is config-pinned with no downgrade path | `src/envelope_crypto/aead.rs::tests::aead_and_cbc_clients_reject_each_other_s_envelopes`; `tests/aead_envelope.rs::aead_and_cbc_secure_clients_reject_each_other_s_envelopes` | Required test |
| The AAD binds the frame header, domain separator, and protocol context | `src/auth.rs::tests::aead_aad_is_length_prefixed_label_header_domain_and_context`; `src/envelope_crypto/aead.rs::tests::aead_domain_separator_and_context_are_covered_by_the_aad` | Required test |
| SM4-GCM matches the public standard vector | `tests/standard_vectors.rs::sm4_gcm_matches_rfc_8998_appendix_a_1` | Non-removable KAT gate |
```

- [ ] **Step 4: Version counters and assertions**

`ci/tool-versions.sh`: `SECURITY_MODEL_VERSION=2`, `ENGINEERING_EVIDENCE_VERSION=2`. `tests/release_documents.rs`: `"**Model version:** 1"` → `"**Model version:** 2"`, replace its old `does not provide an AEAD envelope profile` marker with `Without the opt-in \`aead\` feature it provides no AEAD envelope profile`, and `"**Evidence version:** 1"` → `"**Evidence version:** 2"`. `tests/release_candidate.sh`: update its hardcoded security-model and engineering-evidence fixture documents from version 1 to version 2, because it copies `ci/tool-versions.sh` into the fixture.

- [ ] **Step 5: Verify**

```bash
cargo test --doc --locked 2>&1 | tail -3
cargo test --doc --locked --features aead 2>&1 | tail -3
cargo test --test release_documents --locked 2>&1 | tail -3
sh tests/release_candidate.sh
RUSTDOCFLAGS="-D missing-docs -D warnings" cargo doc --locked --no-deps
RUSTDOCFLAGS="-D missing-docs -D warnings" cargo doc --locked --no-deps --features aead
```

Expected: README doctests compile in BOTH states (the cfg-block trick compiles the snippet out without the feature); release-document tests pass; both doc builds clean.

- [ ] **Step 6: Commit**

```bash
git add README.md SECURITY_MODEL.md docs/security/engineering-evidence.md tests/release_documents.rs tests/release_candidate.sh ci/tool-versions.sh
git commit -m "docs: envelope-mode table, security model v2, evidence map v2

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 13: Version 0.2.0 and the dual public-API snapshot

Everything version-coupled moves in one commit so the battery is green at its end. Known 0.1.0 identity sites: `Cargo.toml`, `ci/check-public-api.sh` (path + message), `ci/check-cargo-package.sh:60`, `ci/check-release-candidate.sh:88`, `.github/workflows/release-candidate.yml:36`, `tests/workflows.sh:469`, `tests/public_api.sh` (numerous), `api/gmcrypto-envelope-lite-0.1.0.txt`, `RELEASE_CHECKLIST.md:1`, `README.md` (§Release status), `CHANGELOG.md` (new entry), `docs/api-stability.md` (§Baseline).

**Files:**
- Modify: all of the above, plus `Cargo.lock` (own version line), `docs/security/cryptographic-dependencies.md` + `tests/crypto_inventory.sh` + `tests/release_documents.rs` (lock hash refresh again), `ci/tool-versions.sh` (`API_SNAPSHOT_VERSION=2`), and `tests/release_candidate.sh` (fixture counter and version identity)
- Create: `api/gmcrypto-envelope-lite-0.2.0.txt` (rename), `api/gmcrypto-envelope-lite-0.2.0-aead.txt` (generated)

- [ ] **Step 1: Bump the version**

`Cargo.toml`: `version = "0.1.0"` → `version = "0.2.0"`. Run `cargo metadata --format-version 1 >/dev/null`; `git diff Cargo.lock` must show only the crate's own `version` line.

- [ ] **Step 2: Refresh the lock hash (again)**

`shasum -a 256 Cargo.lock` → `<NEWHASH2>`; update the `Reviewed Cargo.lock SHA-256` line in `docs/security/cryptographic-dependencies.md`, the same literal in `tests/crypto_inventory.sh`, and the reviewed inventory marker in `tests/release_documents.rs` (Task 1 planted the previous value in all three).

- [ ] **Step 3: Snapshots**

```bash
git mv api/gmcrypto-envelope-lite-0.1.0.txt api/gmcrypto-envelope-lite-0.2.0.txt
rustup run nightly-2026-05-23 cargo public-api -ss --color=never > /tmp/default-api.txt
diff /tmp/default-api.txt api/gmcrypto-envelope-lite-0.2.0.txt
rustup run nightly-2026-05-23 cargo public-api -ss --color=never --features aead > api/gmcrypto-envelope-lite-0.2.0-aead.txt
```

Expected: the diff is empty (`cargo public-api` output carries no version strings, so the renamed snapshot's content is already exact). The aead snapshot must contain the default snapshot plus only `AeadAlgorithm`, `EnvelopeMode`, `ClientConfig::envelope_mode`, `ClientConfigBuilder::envelope_mode`, `AuthenticationMode::aead_aad`, and their derived impls — eyeball the diff between the two files and reject anything else.

- [ ] **Step 4: Two-snapshot checker**

In `ci/check-public-api.sh`:
- `snapshot=".../gmcrypto-envelope-lite-0.1.0.txt"` → `-0.2.0.txt`, add `aead_snapshot="$repo_root/api/gmcrypto-envelope-lite-0.2.0-aead.txt"` and `test -f "$aead_snapshot" || fail "AEAD public API snapshot is missing"` next to the existing presence check.
- Duplicate the generate-and-compare block for the aead pass: a second mktemp pair (`generated_aead`, its error file, both added to `cleanup`), the generator invocation gaining `--features aead`, and the comparisons:

```sh
if ! (cd "$repo_root" && rustup run "$PUBLIC_API_TOOLCHAIN" \
    "$pinned_cargo" public-api -ss --color=never --features aead) \
    >"$generated_aead" 2>"$generator_aead_error"; then
    cat "$generator_aead_error" >&2
    fail "AEAD public API snapshot generator failed"
fi
if ! cmp -s "$snapshot" "$generated"; then
    diff -u "$snapshot" "$generated" || true
    fail "public API differs from the 0.2.0 snapshot"
fi
if ! cmp -s "$aead_snapshot" "$generated_aead"; then
    diff -u "$aead_snapshot" "$generated_aead" || true
    fail "AEAD public API differs from the 0.2.0 snapshot"
fi
```

- [ ] **Step 5: Checker self-test**

In `tests/public_api.sh`:
- Fixture setup: copy both snapshots and seed both generated files:

```sh
cp "$repo_root/api/gmcrypto-envelope-lite-0.2.0.txt" \
    "$fixture/api/gmcrypto-envelope-lite-0.2.0.txt"
cp "$repo_root/api/gmcrypto-envelope-lite-0.2.0.txt" "$fixture/generated.txt"
cp "$repo_root/api/gmcrypto-envelope-lite-0.2.0-aead.txt" \
    "$fixture/api/gmcrypto-envelope-lite-0.2.0-aead.txt"
cp "$repo_root/api/gmcrypto-envelope-lite-0.2.0-aead.txt" "$fixture/generated-aead.txt"
```

- Fake pinned cargo `-ss` branch becomes:

```sh
    -ss)
        test "$2" = --color=never
        if test "${FAKE_GENERATOR_FAILURE:-0}" = 1; then
            echo "simulated public API generator failure" >&2
            exit 71
        fi
        case "${3:-}" in
            '')
                cat "$FAKE_GENERATED"
                ;;
            --features)
                test "$4" = aead
                cat "$FAKE_GENERATED_AEAD"
                ;;
            *)
                echo "error: unexpected cargo public-api arguments" >&2
                exit 91
                ;;
        esac
        ;;
```

- `run_checker` env gains `FAKE_GENERATED_AEAD="$fixture/generated-aead.txt"`.
- Update every `gmcrypto-envelope-lite-0.1.0.txt` reference to `-0.2.0.txt` and the drift-message assertion to `public API differs from the 0.2.0 snapshot`.
- Add two cases mirroring the existing missing/drift cases for the aead snapshot (`rm .../gmcrypto-envelope-lite-0.2.0-aead.txt` → `AEAD public API snapshot is missing`; overwrite it with `intentional aead snapshot drift` → `AEAD public API differs from the 0.2.0 snapshot`, restoring from `generated-aead.txt` after).

- [ ] **Step 6: Remaining identity sites**

- `ci/check-cargo-package.sh`: `test "$package_version" = 0.1.0` → `0.2.0`.
- `ci/check-release-candidate.sh`: `package_version=0.1.0` → `0.2.0`.
- `.github/workflows/release-candidate.yml`: artifact `name: gmcrypto-envelope-lite-0.1.0-rc-built-${{ github.sha }}` → `-0.2.0-rc-built-`.
- `tests/workflows.sh` line 469: same string change.
- `tests/release_candidate.sh`: replace every `0.1.0` fixture literal with `0.2.0` (`sed -i '' 's/0\.1\.0/0.2.0/g' tests/release_candidate.sh` on macOS, then review the diff — every hit is a fixture identity), and update its hardcoded model, policy, evidence, and inventory fixture document versions from 1 to 2 because it copies `ci/tool-versions.sh` into the fixture.
- `RELEASE_CHECKLIST.md` title: `# 0.1.0 Release Candidate External Gate Checklist` → `# 0.2.0 ...`.
- `README.md` §Release status: `Version 0.1.0 is a release candidate: ...` → `Version 0.2.0 is unreleased and in development; the 0.1.0 release-candidate artifact set remains recorded at promotion state rc-built. Publishing is enabled in the manifest, and publication happens only after the external gates in the release checklist pass.` Leave the charter sentence about the 0.1.0 RC suite (line 11) unchanged — it is a historical charter reference.
- `docs/api-stability.md` §Baseline: replace the paragraph with:

```markdown
The canonical 0.2.0 snapshots are `api/gmcrypto-envelope-lite-0.2.0.txt` (default features) and `api/gmcrypto-envelope-lite-0.2.0-aead.txt` (`--features aead`), generated by the pinned `cargo-public-api` version in `ci/tool-versions.sh` with simplified level two and color disabled. This level omits blanket and auto-trait noise while retaining derived public trait implementations, which remain part of the tracked semver surface. The default-features snapshot is content-identical to the retired 0.1.0 snapshot: every 0.2.0 addition is gated behind `aead`.
```

and `**Policy version:** 1` → `**Policy version:** 2`. Update `Within 0.1.x` to `Within 0.2.x`. In **Extensible public enums**, replace the non-exhaustive list and its matching assertion sentence with one that includes the feature-gated `EnvelopeMode` and `AeadAlgorithm`; this text must remain plain text rather than an intra-doc link from an always-present item.
- `tests/release_documents.rs`: `"**Policy version:** 1"` → `"**Policy version:** 2"`; add a `Within 0.2.x` marker; replace the API-stability assertion marker `api/gmcrypto-envelope-lite-0.1.0.txt` with both `api/gmcrypto-envelope-lite-0.2.0.txt` and `api/gmcrypto-envelope-lite-0.2.0-aead.txt`; and update the non-exhaustive-enum marker to include `EnvelopeMode` and `AeadAlgorithm`.
- `ci/tool-versions.sh`: `API_SNAPSHOT_VERSION=2`.
- `CHANGELOG.md`: under `## [Unreleased]` add:

```markdown
### Added

- Opt-in `aead` feature: an SM4-GCM authenticated-encryption envelope mode (`EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm)`) pinned by `ClientConfig`, framed inside the existing `cipher` field (version, algorithm id, 12-byte random nonce, ciphertext, 16-byte tag) so `SecureEnvelope`, `ProtocolAdapter`, `HeaderSchema`, and `KeyMaterial` are unchanged. The AAD binds the frame header, domain separator, and protocol context; the SM2 signature remains mandatory. There is no mode negotiation: an AEAD client rejects CBC envelopes outright and vice versa. Enabling the feature compiles `gmcrypto-simd` and `cpufeatures`, recorded in a second, feature-scoped cryptographic-inventory tier.
- SM4-GCM known-answer test pinned to RFC 8998 Appendix A.1, an `aead_envelope` fuzz target with a curated corpus, and CI coverage (`cargo test/clippy/doc --features aead`) on all platforms plus MSRV.

### Changed

- Version identity moved to 0.2.0; the public API surface under default features is content-identical to the 0.1.0 snapshot. Security model, engineering evidence, API-stability policy, and cryptographic inventory documents advanced to version 2.
```

- [ ] **Step 7: Verify the affected battery slice**

```bash
cargo test --all-targets --locked 2>&1 | tail -3
cargo test --all-targets --locked --features aead 2>&1 | tail -3
sh tests/public_api.sh && ./ci/check-public-api.sh
sh tests/crypto_inventory.sh && ./ci/check-crypto-inventory.sh
sh tests/workflows.sh && sh tests/release_candidate.sh
cargo test --test release_documents --locked 2>&1 | tail -3
```

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock CHANGELOG.md README.md RELEASE_CHECKLIST.md \
  ci/check-cargo-package.sh ci/check-public-api.sh ci/check-release-candidate.sh ci/tool-versions.sh \
  docs/api-stability.md docs/security/cryptographic-dependencies.md \
  tests/crypto_inventory.sh tests/public_api.sh tests/release_candidate.sh tests/release_documents.rs tests/workflows.sh \
  .github/workflows/release-candidate.yml \
  api/gmcrypto-envelope-lite-0.2.0.txt api/gmcrypto-envelope-lite-0.2.0-aead.txt
git commit -m "release: move version identity to 0.2.0 with dual API snapshots

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 14: Full local battery, then push

- [ ] **Step 1: Run the complete battery (spec §15)**

```bash
set -e
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
package_parent=$(mktemp -d)
./ci/check-cargo-package.sh "$PWD" "$package_parent/package"
rm -rf "$package_parent"
sh ci/fuzz-smoke.sh smoke
```

Expected: every command succeeds. Fix any failure at its owning task's standard (implementation, never assertions) and re-run the full list from the top.

- [ ] **Step 2: Push the branch (only to origin; do not touch main, do not publish)**

```bash
git push origin aead-envelope-mode
```

- [ ] **Step 3: Confirm CI**

```bash
gh run list --repo frankxue831/gmcrypto-envelope-lite --branch aead-envelope-mode --limit 3
```

Watch until the CI and fuzz workflows for the pushed head SHA report `success`. Report the run IDs. Merging to `main` is the owner's decision and is out of scope for this plan.
