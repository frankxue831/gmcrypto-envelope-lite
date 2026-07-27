# Open-Source Extensible Secure Envelope SDK Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the protocol-specific façade with a neutral, extensible secure-envelope SDK that supports per-request operations, directional credentials, safe protocol adapters, custom headers, explicit authentication coverage, and a verifiable open-source release boundary.

**Architecture:** Build the new API beside the legacy API so every intermediate commit remains testable, then remove the legacy surface and proprietary artifacts in one controlled cutover. `SecureClient` owns immutable configuration and role-specific keys, delegates only field mapping to `ProtocolAdapter`, and retains control of header collision checks and all cryptographic verification. A data-driven `HeaderProtocolAdapter` supports deployed legacy mappings supplied from a separate private repository, while custom adapters can use context-bound authentication for new protocols.

**Tech Stack:** Rust 1.85+, edition 2024, `gmcrypto-core = 1.9.0`, Serde, Base64, getrandom, zeroize, thiserror, Cargo tests, POSIX shell, GitHub Actions

---

## File map

| Path | Responsibility |
| --- | --- |
| `src/auth.rs` | Authentication modes, explicit contexts, and versioned transcript framing. |
| `src/client_config.rs` | Neutral client identity, directional signer IDs, IV, and size configuration. |
| `src/error.rs` | Redacted SDK errors plus public constructible adapter errors. |
| `src/keys.rs` | SDK-owned private/public key wrappers and role-specific key material. |
| `src/header.rs` | SDK-owned header names, values, collections, and case-insensitive uniqueness. |
| `src/message.rs` | Envelopes, metadata, request contexts, request/response parts, and parsed responses. |
| `src/adapter.rs` | `ProtocolAdapter`, `HeaderSchema`, and `HeaderProtocolAdapter`. |
| `src/envelope_crypto.rs` | Private SM2/SM3 + SM4-CBC composition and opaque inbound failures. |
| `src/client.rs` | `SecureClient` build/open orchestration and final header enforcement. |
| `src/request.rs` | Fluent byte/JSON request builder. |
| `src/lib.rs` | Neutral public exports and crate documentation. |
| `tests/support/mod.rs` | Runtime-only deterministic test-key construction; never production code. |
| `tests/auth_and_config.rs` | Authentication transcript and configuration validation. |
| `tests/key_roles.rs` | Key parsing, explicit sharing, and directional role behavior. |
| `tests/transport_types.rs` | Header, metadata, context, and transport-part invariants. |
| `tests/protocol_adapter.rs` | Schema validation and neutral header mapping. |
| `src/envelope_crypto.rs` tests | Private round trips, context binding, tampering, limits, and opaque failures without exposing primitive functions. |
| `tests/secure_client.rs` | End-to-end adapter orchestration and custom-header protection. |
| `tests/client_convenience.rs` | JSON, fluent builders, concurrency, and replacement-client rotation. |
| `tests/public-fixtures/` | Newly generated public certificate and public-key fixtures only. |
| `tools/generate-public-test-fixtures.sh` | Reproducibly regenerates disposable public fixtures without retaining a private key. |
| `ci/check-open-source-boundary.sh` | Scans complete exports and packages with optional external private policy. |
| `README.md` | Neutral usage, security limits, transport requirements, and migration guide. |
| `LICENSE` | Canonical Apache License 2.0 terms. |
| `.github/workflows/ci.yml` | Cross-platform tests and public release-boundary checks. |

## Task 1: Add authentication, configuration, and error contracts

**Files:**
- Modify: `Cargo.toml`
- Create: `src/auth.rs`
- Create: `src/client_config.rs`
- Modify: `src/error.rs`
- Modify: `src/lib.rs`
- Modify: existing Rust integration tests and examples only to update the library crate import
- Create: `tests/auth_and_config.rs`

- [ ] **Step 1: Write failing transcript and configuration tests**

Create `tests/auth_and_config.rs` with exact transcript coverage and explicit legacy/context validation:

```rust
use secure_envelope_lite::{
    AuthenticationContext, AuthenticationMode, ClientConfig, Error,
};

fn config_builder() -> secure_envelope_lite::ClientConfigBuilder {
    ClientConfig::builder()
        .local_identity_id("demo-client")
        .api_version("1")
        .local_certificate_id("local-signing-v1")
        .expected_remote_signing_certificate_id("remote-signing-v1")
        .remote_encryption_certificate_id("remote-encryption-v1")
        .local_signer_id(b"local-sm2-id")
        .expected_remote_signer_id(b"remote-sm2-id")
        .iv(*b"example-iv-00001")
        .authentication_mode(AuthenticationMode::LegacyPlaintext)
}

#[test]
fn context_bound_transcript_is_versioned_and_length_delimited() {
    let mode = AuthenticationMode::context_bound(b"example-domain").unwrap();
    let context = AuthenticationContext::context_bound(b"operation=demo").unwrap();
    let input = mode.authentication_input(&context, b"payload").unwrap();

    let mut expected = vec![1];
    expected.extend_from_slice(&(14_u64).to_be_bytes());
    expected.extend_from_slice(b"example-domain");
    expected.extend_from_slice(&(14_u64).to_be_bytes());
    expected.extend_from_slice(b"operation=demo");
    expected.extend_from_slice(&(7_u64).to_be_bytes());
    expected.extend_from_slice(b"payload");
    assert_eq!(&*input, &expected);
}

#[test]
fn authentication_modes_reject_the_wrong_context_kind() {
    let legacy = AuthenticationMode::LegacyPlaintext;
    let bound = AuthenticationMode::context_bound(b"example-domain").unwrap();
    assert!(legacy
        .authentication_input(
            &AuthenticationContext::context_bound(b"context").unwrap(),
            b"payload",
        )
        .is_err());
    assert!(bound
        .authentication_input(&AuthenticationContext::legacy(), b"payload")
        .is_err());
}

#[test]
fn config_requires_directional_signer_ids_and_explicit_mode() {
    let config = config_builder().build().unwrap();
    assert_eq!(config.local_signer_id(), b"local-sm2-id");
    assert_eq!(config.expected_remote_signer_id(), b"remote-sm2-id");

    let error = config_builder()
        .expected_remote_signer_id(Vec::<u8>::new())
        .build()
        .unwrap_err();
    assert!(matches!(error, Error::Configuration {
        field: "expected_remote_signer_id"
    }));
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `cargo test --test auth_and_config`

Expected: FAIL because the neutral crate alias and authentication/configuration types do not exist.

- [ ] **Step 3: Implement the authentication types and transcript framing**

Add `src/auth.rs`. Keep constructors validated, distinguish the legacy marker from context bytes, and own context-bound signing input in `Zeroizing<Vec<u8>>`:

```rust
use zeroize::Zeroizing;

use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthenticationMode {
    LegacyPlaintext,
    ContextBound { domain_separator: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationContext {
    kind: ContextKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ContextKind {
    Legacy,
    Bound(Vec<u8>),
}

impl AuthenticationMode {
    pub fn context_bound(domain_separator: impl Into<Vec<u8>>) -> Result<Self> {
        let domain_separator = domain_separator.into();
        if domain_separator.is_empty() {
            return Err(Error::Configuration { field: "domain_separator" });
        }
        Ok(Self::ContextBound { domain_separator })
    }

    pub fn authentication_input(
        &self,
        context: &AuthenticationContext,
        plaintext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        match (self, &context.kind) {
            (Self::LegacyPlaintext, ContextKind::Legacy) => {
                Ok(Zeroizing::new(plaintext.to_vec()))
            }
            (Self::ContextBound { domain_separator }, ContextKind::Bound(context)) => {
                let mut input = Zeroizing::new(Vec::with_capacity(
                    1 + 24 + domain_separator.len() + context.len() + plaintext.len(),
                ));
                input.push(1);
                push_field(&mut input, domain_separator)?;
                push_field(&mut input, context)?;
                push_field(&mut input, plaintext)?;
                Ok(input)
            }
            _ => Err(Error::AuthenticationContext),
        }
    }
}

impl AuthenticationContext {
    #[must_use]
    pub fn legacy() -> Self {
        Self { kind: ContextKind::Legacy }
    }

    pub fn context_bound(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(Error::AuthenticationContext);
        }
        Ok(Self { kind: ContextKind::Bound(bytes) })
    }
}

fn push_field(target: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len = u64::try_from(value.len()).map_err(|_| Error::AuthenticationContext)?;
    target.extend_from_slice(&len.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}
```

- [ ] **Step 4: Implement neutral client configuration and adapter-safe errors**

Add `src/client_config.rs` with `ClientIdentity`, `ClientConfig`, and a consuming builder. Required fields match the test; `max_plaintext_bytes` defaults to 16 MiB; signer IDs must contain 1–8191 bytes; IV is exactly `[u8; 16]`; and header-bound strings reuse a validator that rejects empty/CR/LF values.

```rust
pub const DEFAULT_MAX_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIdentity {
    local_identity_id: String,
    api_version: String,
    local_certificate_id: String,
    expected_remote_signing_certificate_id: String,
    remote_encryption_certificate_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfig {
    identity: ClientIdentity,
    local_signer_id: Vec<u8>,
    expected_remote_signer_id: Vec<u8>,
    authentication_mode: AuthenticationMode,
    iv: [u8; 16],
    max_plaintext_bytes: usize,
}
```

Implement public read-only getters, `ClientIdentity::new`, `ClientConfig::builder`, and every consuming setter used by the tests. No builder field has an implicit protocol-specific value; only the message-size limit has a default.

Extend `src/error.rs` with these public categories while retaining legacy variants until Task 9:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterErrorKind {
    InvalidMapping,
    MissingField,
    DuplicateField,
    InvalidField,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("protocol adapter failed: {kind:?}")]
pub struct AdapterError {
    kind: AdapterErrorKind,
}

impl AdapterError {
    #[must_use]
    pub const fn new(kind: AdapterErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> AdapterErrorKind {
        self.kind
    }
}

pub type AdapterResult<T> = std::result::Result<T, AdapterError>;
```

Add `AuthenticationContext`, `InvalidHeader`, `HeaderConflict`, `ProtocolAdapter`, and `InvalidEnvelope` variants to `Error`. None may carry caller values or dependency errors.

Change only `[lib].name` in `Cargo.toml` from the legacy crate identifier to `secure_envelope_lite`; keep the package name unchanged until Task 9. Use `apply_patch` to update every existing Rust test, example, and doctest import to `secure_envelope_lite`, without changing behavior. Export the new types from `src/lib.rs`. This makes neutral integration tests compile while all legacy behavior remains available during the additive phase.

- [ ] **Step 5: Run focused and existing tests**

Run: `cargo test --test auth_and_config`

Expected: PASS.

Run: `cargo test --all-targets`

Expected: PASS, proving the additive phase has not broken the legacy API.

- [ ] **Step 6: Commit the contracts**

```bash
git add Cargo.toml src/auth.rs src/client_config.rs src/error.rs src/lib.rs tests examples
git commit -m "feat: add neutral authentication and client config"
```

## Task 2: Introduce role-specific SDK-owned key material

**Files:**
- Modify: `src/keys.rs`
- Modify: `src/crypto.rs`
- Create: `tests/support/mod.rs`
- Create: `tests/key_roles.rs`

- [ ] **Step 1: Add runtime-only neutral test key helpers**

Create `tests/support/mod.rs`; deterministic salt/IV and low PBKDF iteration count are explicitly test-only:

```rust
use gmcrypto_core::sm2::Sm2PrivateKey;
use gmcrypto_core::{pkcs8, spki};

pub const TEST_PASSWORD: &[u8] = b"public-test-password";

pub struct TestKeyPair {
    pub encrypted_private_der: Vec<u8>,
    pub public_der: Vec<u8>,
}

pub fn test_key_pair(discriminator: u8) -> TestKeyPair {
    assert_ne!(discriminator, 0);
    let mut scalar = [0_u8; 32];
    scalar[31] = discriminator;
    let private = Option::<Sm2PrivateKey>::from(Sm2PrivateKey::from_bytes_be(&scalar))
        .expect("small non-zero test scalar is valid");
    let salt = [discriminator; 16];
    let iv = [discriminator.wrapping_add(1); 16];
    let encrypted_private_der =
        pkcs8::encrypt(&private, TEST_PASSWORD, &salt, 1, &iv).expect("test PKCS#8");
    let public_der = spki::encode(&private.public_key());
    TestKeyPair { encrypted_private_der, public_der }
}
```

- [ ] **Step 2: Write failing role-specific key tests**

Create `tests/key_roles.rs`:

```rust
mod support;

use secure_envelope_lite::{KeyMaterial, PrivateKey, PublicKey};

#[test]
fn role_specific_keys_accept_four_independent_slots() {
    let signing = support::test_key_pair(1);
    let decryption = support::test_key_pair(2);
    let verification = support::test_key_pair(3);
    let encryption = support::test_key_pair(4);

    let material = KeyMaterial::new(
        PrivateKey::from_encrypted_der(
            &signing.encrypted_private_der,
            support::TEST_PASSWORD,
        )
        .unwrap(),
        PrivateKey::from_encrypted_der(
            &decryption.encrypted_private_der,
            support::TEST_PASSWORD,
        )
        .unwrap(),
        PublicKey::from_der(&verification.public_der).unwrap(),
        PublicKey::from_der(&encryption.public_der).unwrap(),
    );
    assert!(!material.uses_shared_roles());
}

#[test]
fn shared_roles_are_an_explicit_convenience() {
    let pair = support::test_key_pair(5);
    let material = KeyMaterial::shared(
        PrivateKey::from_encrypted_der(&pair.encrypted_private_der, support::TEST_PASSWORD)
            .unwrap(),
        PublicKey::from_der(&pair.public_der).unwrap(),
    );
    assert!(material.uses_shared_roles());
}

#[test]
fn private_and_public_keys_load_from_pem_and_files() {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    let pair = support::test_key_pair(6);
    let private_pem = gmcrypto_core::pem::encode(
        "ENCRYPTED PRIVATE KEY",
        &pair.encrypted_private_der,
    );
    let public_pem = gmcrypto_core::pem::encode("PUBLIC KEY", &pair.public_der);
    PrivateKey::from_encrypted_pem(private_pem.as_bytes(), support::TEST_PASSWORD).unwrap();
    PublicKey::from_pem(public_pem.as_bytes()).unwrap();

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("secure-envelope-test-{unique}"));
    fs::create_dir(&directory).unwrap();
    let private_path = directory.join("private.pem");
    let public_path = directory.join("public.pem");
    fs::write(&private_path, private_pem).unwrap();
    fs::write(&public_path, public_pem).unwrap();
    PrivateKey::from_encrypted_file(&private_path, support::TEST_PASSWORD).unwrap();
    PublicKey::from_file(&public_path).unwrap();
    fs::remove_dir_all(directory).unwrap();
}
```

- [ ] **Step 3: Run the focused test and verify it fails**

Run: `cargo test --test key_roles`

Expected: FAIL because `PrivateKey`, `PublicKey`, and role-specific `KeyMaterial` do not exist.

- [ ] **Step 4: Refactor key parsing behind SDK-owned wrappers**

In `src/keys.rs`, implement:

```rust
pub struct PrivateKey {
    pub(crate) inner: Sm2PrivateKey,
}

#[derive(Clone, Copy)]
pub struct PublicKey {
    pub(crate) inner: Sm2PublicKey,
    source: PeerKeySource,
}

pub struct KeyMaterial {
    pub(crate) local_signing: Sm2PrivateKey,
    pub(crate) local_decryption: Sm2PrivateKey,
    pub(crate) remote_verification: Sm2PublicKey,
    pub(crate) remote_encryption: Sm2PublicKey,
    remote_verification_source: PeerKeySource,
    remote_encryption_source: PeerKeySource,
    shared_roles: bool,
}

impl KeyMaterial {
    #[must_use]
    pub fn new(
        local_signing: PrivateKey,
        local_decryption: PrivateKey,
        remote_verification: PublicKey,
        remote_encryption: PublicKey,
    ) -> Self {
        let remote_verification_source = remote_verification.source;
        let remote_encryption_source = remote_encryption.source;
        Self {
            local_signing: local_signing.inner,
            local_decryption: local_decryption.inner,
            remote_verification: remote_verification.inner,
            remote_encryption: remote_encryption.inner,
            remote_verification_source,
            remote_encryption_source,
            shared_roles: false,
        }
    }

    #[must_use]
    pub fn shared(local: PrivateKey, remote: PublicKey) -> Self {
        Self {
            local_signing: local.inner.clone(),
            local_decryption: local.inner,
            remote_verification: remote.inner,
            remote_encryption: remote.inner,
            remote_verification_source: remote.source,
            remote_encryption_source: remote.source,
            shared_roles: true,
        }
    }

    #[must_use]
    pub fn uses_shared_roles(&self) -> bool {
        self.shared_roles
    }

    #[must_use]
    pub fn remote_verification_source(&self) -> PeerKeySource {
        self.remote_verification_source
    }

    #[must_use]
    pub fn remote_encryption_source(&self) -> PeerKeySource {
        self.remote_encryption_source
    }
}
```

Move encrypted PKCS#8 PEM/DER/file loaders to `PrivateKey`; move SPKI/certificate PEM/DER/file loaders and `source()` to `PublicKey`. Shared-role convenience loaders use explicit `shared_from_pem`, `shared_from_der`, and `shared_from_files` names; compatibility aliases are removed at the breaking cutover.

Update legacy `src/crypto.rs` to use `local_signing`, `local_decryption`, `remote_verification`, and `remote_encryption` in their correct operations. Do not expose any `gmcrypto-core` type.

- [ ] **Step 5: Run key and regression tests**

Run: `cargo test --test key_roles --test key_loading`

Expected: PASS.

Run: `cargo test --all-targets`

Expected: PASS.

- [ ] **Step 6: Commit directional keys**

```bash
git add src/keys.rs src/crypto.rs tests/support/mod.rs tests/key_roles.rs
git commit -m "refactor: separate directional key roles"
```

## Task 3: Add neutral headers and transport message types

**Files:**
- Create: `src/header.rs`
- Create: `src/message.rs`
- Modify: `src/lib.rs`
- Create: `tests/transport_types.rs`

- [ ] **Step 1: Write failing header and request-context tests**

Create `tests/transport_types.rs`:

```rust
use secure_envelope_lite::{
    Error, HeaderName, HeaderValue, RequestContext, RequestMetadata, RequestParts,
    ResponseParts,
};

#[test]
fn names_are_case_insensitive_but_preserve_wire_casing() {
    let first = HeaderName::new("X-Demo-Trace").unwrap();
    let second = HeaderName::new("x-demo-trace").unwrap();
    assert_eq!(first, second);
    assert_eq!(first.as_str(), "X-Demo-Trace");
}

#[test]
fn invalid_header_syntax_is_rejected_without_echoing_values() {
    assert!(matches!(HeaderName::new("bad header"), Err(Error::InvalidHeader)));
    assert!(matches!(HeaderValue::new("safe\r\ninjected"), Err(Error::InvalidHeader)));
}

#[test]
fn request_parts_reject_case_insensitive_duplicates() {
    let error = RequestParts::new(
        [("X-Field", "one"), ("x-field", "two")],
        "body",
    )
    .unwrap_err();
    assert!(matches!(error, Error::HeaderConflict));
}

#[test]
fn request_context_separates_protocol_metadata_from_extensions() {
    let metadata = RequestMetadata::new("request-1", "2026-07-12T00:00:00Z").unwrap();
    let context = RequestContext::builder("demo-operation")
        .metadata(metadata)
        .header("X-Demo-Trace", "trace-1")
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(context.protocol().operation(), "demo-operation");
    assert_eq!(context.additional_headers().len(), 1);
}

#[test]
fn response_parts_preserve_duplicate_input_for_adapter_validation() {
    let response = ResponseParts::new(
        [("X-Result", "one"), ("x-result", "two")],
        "body",
    );
    assert_eq!(response.headers().count(), 2);
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `cargo test --test transport_types`

Expected: FAIL because neutral header/message types do not exist.

- [ ] **Step 3: Implement SDK-owned validated headers**

Add `src/header.rs`. `HeaderName::new` accepts only non-empty ASCII RFC token characters; equality and hashing use an ASCII-lowercase canonical form while `as_str` preserves original casing. `HeaderValue::new` accepts UTF-8 strings but rejects CR, LF, NUL, DEL, and other C0 controls except horizontal tab. Implement a private `HeaderCollection` with checked insertion and public iteration.

The core validation predicate is:

```rust
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
                | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}
```

- [ ] **Step 4: Implement neutral message and context types**

Add `src/message.rs` with private fields and validated constructors:

```rust
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecureEnvelope {
    pub cipher: String,
    pub wrapped_session_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolRequestContext {
    operation: String,
    metadata: RequestMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestContext {
    protocol: ProtocolRequestContext,
    additional_headers: Vec<(HeaderName, HeaderValue)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestParts {
    headers: Vec<(HeaderName, HeaderValue)>,
    body: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseParts {
    headers: Vec<(String, String)>,
    body: String,
}
```

`RequestParts::new` performs checked conversion and uniqueness validation. Add a crate-private `append_checked` used later by `SecureClient`. `ResponseParts` intentionally preserves raw pairs. Move metadata generation logic into this module and retain caller-supplied construction. Implement `RequestContext::builder(operation)` plus `pub(crate) RequestContext::from_parts(operation, metadata, headers)` for the fluent request builder; both paths must run identical operation/header validation.

Export the neutral types from `src/lib.rs`.

- [ ] **Step 5: Run focused and regression tests**

Run: `cargo test --test transport_types`

Expected: PASS.

Run: `cargo test --all-targets`

Expected: PASS.

- [ ] **Step 6: Commit transport types**

```bash
git add src/header.rs src/message.rs src/lib.rs tests/transport_types.rs
git commit -m "feat: add neutral transport message types"
```

## Task 4: Implement the protocol adapter boundary

**Files:**
- Create: `src/adapter.rs`
- Modify: `src/message.rs`
- Modify: `src/lib.rs`
- Create: `tests/protocol_adapter.rs`

- [ ] **Step 1: Write failing neutral schema tests**

Create `tests/protocol_adapter.rs` around a fictitious mapping:

```rust
use secure_envelope_lite::{
    AuthenticationContext, CipherLocation, ClientIdentity, HeaderProtocolAdapter,
    HeaderSchema, ProtocolAdapter, ProtocolRequestContext, RequestMetadata, ResponseParts,
    SecureEnvelope,
};

fn schema() -> HeaderSchema {
    HeaderSchema::builder()
        .static_request_header("Content-Type", "application/octet-stream")
        .unwrap()
        .local_identity_header("X-Demo-Client")
        .operation_header("X-Demo-Operation")
        .request_id_header("X-Demo-Request-Id")
        .request_time_header("X-Demo-Time")
        .api_version_header("X-Demo-Version")
        .local_certificate_header("X-Demo-Local-Certificate")
        .remote_signing_certificate_header("X-Demo-Remote-Signing-Certificate")
        .remote_encryption_certificate_header("X-Demo-Remote-Encryption-Certificate")
        .request_signature_header("X-Demo-Signature")
        .request_wrapped_key_header("X-Demo-Wrapped-Key")
        .request_cipher(CipherLocation::Body)
        .response_signature_header("X-Demo-Signature")
        .response_wrapped_key_header("X-Demo-Wrapped-Key")
        .response_remote_signing_certificate_header("X-Demo-Remote-Certificate")
        .response_cipher(CipherLocation::Body)
        .legacy_authentication()
        .build()
        .unwrap()
}

#[test]
fn adapter_maps_only_semantic_protocol_values() {
    let adapter = HeaderProtocolAdapter::new(schema());
    let identity = ClientIdentity::new(
        "demo-client",
        "1",
        "local-v1",
        "remote-sign-v1",
        "remote-encrypt-v1",
    )
    .unwrap();
    let context = ProtocolRequestContext::new(
        "demo-operation",
        RequestMetadata::new("request-1", "2026-07-12T00:00:00Z").unwrap(),
    )
    .unwrap();
    let envelope = SecureEnvelope {
        cipher: "Y2lwaGVy".into(),
        wrapped_session_key: "a2V5".into(),
        signature: "c2ln".into(),
    };
    let request = adapter.build_request(&identity, &context, &envelope).unwrap();
    assert_eq!(request.header("x-demo-operation"), Some("demo-operation"));
    assert_eq!(request.body(), "Y2lwaGVy");
    assert_eq!(
        adapter
            .request_authentication_context(&identity, &context)
            .unwrap(),
        AuthenticationContext::legacy(),
    );
}

#[test]
fn response_parser_rejects_mapped_duplicates() {
    let adapter = HeaderProtocolAdapter::new(schema());
    let response = ResponseParts::new(
        [
            ("X-Demo-Signature", "one"),
            ("x-demo-signature", "two"),
            ("X-Demo-Wrapped-Key", "key"),
            ("X-Demo-Remote-Certificate", "remote-sign-v1"),
        ],
        "cipher",
    );
    assert!(adapter.parse_response(response).is_err());
}
```

- [ ] **Step 2: Run the adapter test and verify it fails**

Run: `cargo test --test protocol_adapter`

Expected: FAIL because adapter and schema types are undefined.

- [ ] **Step 3: Define the object-safe adapter contract**

Add `src/adapter.rs`:

```rust
pub trait ProtocolAdapter: Send + Sync {
    fn request_authentication_context(
        &self,
        identity: &ClientIdentity,
        context: &ProtocolRequestContext,
    ) -> AdapterResult<AuthenticationContext>;

    fn build_request(
        &self,
        identity: &ClientIdentity,
        context: &ProtocolRequestContext,
        envelope: &SecureEnvelope,
    ) -> AdapterResult<RequestParts>;

    fn parse_response(&self, response: ResponseParts) -> AdapterResult<ParsedResponse>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CipherLocation {
    Body,
    Header(HeaderName),
}
```

Implement `ParsedResponse` in `src/message.rs` with private fields plus getters and a public validated constructor usable by external adapters.

- [ ] **Step 4: Implement validated `HeaderSchema` and `HeaderProtocolAdapter`**

The schema builder requires every semantic mapping shown in the test. At `build`, gather every mapped header name for each direction and reject case-insensitive collisions. `CipherLocation::Header` participates in the same collision set. Static request headers are checked against dynamic mappings.

`HeaderProtocolAdapter`:

- returns `AuthenticationContext::legacy()` for the initial data-driven legacy profile;
- constructs `RequestParts` exclusively from semantic identity/context/envelope input;
- supports ciphertext in the body or a configured header;
- matches response names case-insensitively;
- rejects duplicate required response fields;
- ignores unknown response headers; and
- returns a `ParsedResponse` containing the remote signing-certificate claim and legacy context.

Do not pass caller additional headers into this module.

- [ ] **Step 5: Run adapter and regression tests**

Run: `cargo test --test protocol_adapter`

Expected: PASS.

Run: `cargo test --all-targets`

Expected: PASS.

- [ ] **Step 6: Commit the adapter layer**

```bash
git add src/adapter.rs src/message.rs src/lib.rs tests/protocol_adapter.rs
git commit -m "feat: add validated protocol adapter boundary"
```

## Task 5: Implement the secure-envelope cryptographic core

**Files:**
- Create: `src/envelope_crypto.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write failing directional round-trip and opaque-error tests**

Create `src/envelope_crypto.rs` with a `#[cfg(test)]` module first, add private `mod envelope_crypto;` to `src/lib.rs`, and reference the not-yet-implemented `seal`/`open` functions so the focused unit test fails before implementation. Use local test helpers to build four distinct SM2 role keys without exposing primitive functions publicly:

```rust
#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use gmcrypto_core::sm2::Sm2PrivateKey;
    use gmcrypto_core::spki;

    use super::{open, seal};
    use crate::{
        AuthenticationContext, AuthenticationMode, ClientConfig, Error, KeyMaterial,
        PrivateKey, PublicKey,
    };

    fn key_pair(discriminator: u8) -> (PrivateKey, PublicKey) {
        let mut scalar = [0_u8; 32];
        scalar[31] = discriminator;
        let inner = Option::<Sm2PrivateKey>::from(Sm2PrivateKey::from_bytes_be(&scalar))
            .expect("test scalar");
        let public = PublicKey::from_der(&spki::encode(&inner.public_key())).unwrap();
        (PrivateKey { inner }, public)
    }

    fn peers(
        mode: AuthenticationMode,
    ) -> (ClientConfig, KeyMaterial, ClientConfig, KeyMaterial) {
        let (sender_sign, sender_sign_public) = key_pair(11);
        let (sender_decrypt, sender_decrypt_public) = key_pair(12);
        let (receiver_sign, receiver_sign_public) = key_pair(13);
        let (receiver_decrypt, receiver_decrypt_public) = key_pair(14);
        let sender_keys = KeyMaterial::new(
            sender_sign,
            sender_decrypt,
            receiver_sign_public,
            receiver_decrypt_public,
        );
        let receiver_keys = KeyMaterial::new(
            receiver_sign,
            receiver_decrypt,
            sender_sign_public,
            sender_decrypt_public,
        );
        let sender = crate::client_config::test_client_config(
            "sender",
            b"sender-id",
            b"receiver-id",
            mode.clone(),
        );
        let receiver = crate::client_config::test_client_config(
            "receiver",
            b"receiver-id",
            b"sender-id",
            mode,
        );
        (sender, sender_keys, receiver, receiver_keys)
    }

    #[test]
    fn distinct_directional_keys_round_trip() {
        let (sender, sender_keys, receiver, receiver_keys) =
            peers(AuthenticationMode::LegacyPlaintext);
        let context = AuthenticationContext::legacy();
        let envelope = seal(&sender, &sender_keys, b"payload", &context).unwrap();
        let opened = open(&receiver, &receiver_keys, &envelope, &context).unwrap();
        assert_eq!(opened, b"payload");
    }

    #[test]
    fn inbound_crypto_failures_are_opaque() {
        let (sender, sender_keys, receiver, receiver_keys) =
            peers(AuthenticationMode::LegacyPlaintext);
        let context = AuthenticationContext::legacy();
        let original = seal(&sender, &sender_keys, b"payload", &context).unwrap();

        let mut bad_cipher = original.clone();
        let mut cipher = STANDARD.decode(&bad_cipher.cipher).unwrap();
        let last = cipher.len() - 1;
        cipher[last] ^= 1;
        bad_cipher.cipher = STANDARD.encode(cipher);

        let mut bad_key = original.clone();
        bad_key.wrapped_session_key.replace_range(..1, "!");

        let mut bad_signature = original;
        let mut signature = STANDARD.decode(&bad_signature.signature).unwrap();
        signature[0] ^= 1;
        bad_signature.signature = STANDARD.encode(signature);

        for envelope in [bad_cipher, bad_key, bad_signature] {
            assert!(matches!(
                open(&receiver, &receiver_keys, &envelope, &context),
                Err(Error::InvalidEnvelope)
            ));
        }
    }
}
```

Implement a crate-private `test_client_config` under `#[cfg(test)]` in `client_config.rs` with the complete neutral builder fields used above. Add a context-bound unit test that seals with one non-empty context, opens with the same context, and returns `InvalidEnvelope` for different bound context bytes.

- [ ] **Step 2: Run focused tests and verify failure**

Run: `cargo test envelope_crypto::tests`

Expected: FAIL because the neutral envelope crypto path is absent.

- [ ] **Step 3: Implement seal with role-specific keys and authentication input**

In `src/envelope_crypto.rs`:

```rust
pub(crate) fn seal(
    config: &ClientConfig,
    keys: &KeyMaterial,
    plaintext: &[u8],
    context: &AuthenticationContext,
) -> Result<SecureEnvelope> {
    if plaintext.len() > config.max_plaintext_bytes() {
        return Err(Error::MessageTooLarge {
            limit: config.max_plaintext_bytes(),
        });
    }
    let signing_input = config
        .authentication_mode()
        .authentication_input(context, plaintext)?;
    let mut session_key = Zeroizing::new([0_u8; 16]);
    getrandom::fill(&mut *session_key).map_err(|_| Error::Encryption)?;
    let cipher = sm4::mode_cbc::encrypt(&session_key, config.iv(), plaintext);
    let mut rng = SysRng;
    let wrapped = sm2::encrypt(&keys.remote_encryption, &session_key[..], &mut rng)
        .map_err(|_| Error::Encryption)?;
    let signature = sm2::sign_with_id(
        &keys.local_signing,
        config.local_signer_id(),
        &signing_input,
        &mut rng,
    )
    .map_err(|_| Error::Encryption)?;
    Ok(SecureEnvelope {
        cipher: STANDARD.encode(cipher),
        wrapped_session_key: STANDARD.encode(wrapped),
        signature: STANDARD.encode(signature),
    })
}
```

- [ ] **Step 4: Implement fail-closed open with one inbound error**

Perform encoded-length checks before allocation. From Base64 decoding through unwrap, key-length validation, CBC unpadding, context framing, and signature verification, map every failure to `Error::InvalidEnvelope`. Own decrypted-but-unverified plaintext in `Zeroizing<Vec<u8>>`; return it with `Zeroizing::to_vec` only after verification succeeds.

Use `local_decryption`, `remote_verification`, and `expected_remote_signer_id` in the corresponding operations. Preserve the configured plaintext limit both before decode and after decrypt.

- [ ] **Step 5: Run crypto and full tests**

Run: `cargo test envelope_crypto::tests`

Expected: PASS, including exact `InvalidEnvelope` equality across tampering classes.

Run: `cargo test --all-targets`

Expected: PASS.

- [ ] **Step 6: Commit the crypto core**

```bash
git add src/envelope_crypto.rs src/client_config.rs src/lib.rs
git commit -m "feat: add fail-closed secure envelope core"
```

## Task 6: Add `SecureClient` orchestration and collision enforcement

**Files:**
- Create: `src/client.rs`
- Modify: `src/message.rs`
- Modify: `src/lib.rs`
- Create: `tests/secure_client.rs`

- [ ] **Step 1: Write failing end-to-end client tests**

First extend `tests/support/mod.rs` with reusable neutral helpers:

```rust
use secure_envelope_lite::{
    AuthenticationMode, CipherLocation, ClientConfig, HeaderProtocolAdapter, HeaderSchema,
    KeyMaterial, PrivateKey, PublicKey, RequestParts, ResponseParts, SecureClient,
};

pub fn neutral_header_schema() -> HeaderSchema {
    HeaderSchema::builder()
        .static_request_header("Content-Type", "application/octet-stream")
        .unwrap()
        .local_identity_header("X-Demo-Client")
        .operation_header("X-Demo-Operation")
        .request_id_header("X-Demo-Request-Id")
        .request_time_header("X-Demo-Time")
        .api_version_header("X-Demo-Version")
        .local_certificate_header("X-Demo-Local-Certificate")
        .remote_signing_certificate_header("X-Demo-Remote-Signing-Certificate")
        .remote_encryption_certificate_header("X-Demo-Remote-Encryption-Certificate")
        .request_signature_header("X-Demo-Signature")
        .request_wrapped_key_header("X-Demo-Wrapped-Key")
        .request_cipher(CipherLocation::Body)
        .response_signature_header("X-Demo-Signature")
        .response_wrapped_key_header("X-Demo-Wrapped-Key")
        .response_remote_signing_certificate_header("X-Demo-Remote-Certificate")
        .response_cipher(CipherLocation::Body)
        .legacy_authentication()
        .build()
        .unwrap()
}

pub fn client_parts_with_mode(
    seed: u8,
    mode: AuthenticationMode,
) -> (ClientConfig, KeyMaterial, HeaderSchema) {
    let pair = test_key_pair(seed);
    let config = ClientConfig::builder()
        .local_identity_id(format!("demo-client-{seed}"))
        .api_version("1")
        .local_certificate_id(format!("demo-certificate-{seed}"))
        .expected_remote_signing_certificate_id(format!("demo-certificate-{seed}"))
        .remote_encryption_certificate_id(format!("demo-certificate-{seed}"))
        .local_signer_id(b"demo-sm2-id")
        .expected_remote_signer_id(b"demo-sm2-id")
        .iv(*b"example-iv-00001")
        .authentication_mode(mode)
        .build()
        .unwrap();
    let keys = KeyMaterial::shared(
        PrivateKey::from_encrypted_der(&pair.encrypted_private_der, TEST_PASSWORD).unwrap(),
        PublicKey::from_der(&pair.public_der).unwrap(),
    );
    (config, keys, neutral_header_schema())
}

pub fn legacy_client_parts() -> (ClientConfig, KeyMaterial, HeaderSchema) {
    client_parts_with_mode(21, AuthenticationMode::LegacyPlaintext)
}

pub fn secure_client_with_seed(seed: u8) -> SecureClient {
    let (config, keys, schema) =
        client_parts_with_mode(seed, AuthenticationMode::LegacyPlaintext);
    SecureClient::new(config, keys, Arc::new(HeaderProtocolAdapter::new(schema)))
}

pub fn response_from_request(request: &RequestParts, certificate: &str) -> ResponseParts {
    ResponseParts::new(
        [
            ("X-Demo-Signature", request.header("X-Demo-Signature").unwrap()),
            ("X-Demo-Wrapped-Key", request.header("X-Demo-Wrapped-Key").unwrap()),
            ("X-Demo-Remote-Certificate", certificate),
        ],
        request.body(),
    )
}
```

Import `std::sync::Arc` in the support module. Then create `tests/secure_client.rs` with a neutral legacy schema. The test must prove per-request operations and final collision enforcement:

```rust
mod support;

use std::sync::Arc;

use secure_envelope_lite::{
    AdapterError, AdapterErrorKind, AdapterResult, AuthenticationContext, AuthenticationMode,
    ClientIdentity, Error, HeaderProtocolAdapter, ParsedResponse, ProtocolAdapter,
    ProtocolRequestContext, RequestContext, RequestParts, ResponseParts, SecureClient,
    SecureEnvelope,
};

struct ContextAdapter;

impl ProtocolAdapter for ContextAdapter {
    fn request_authentication_context(
        &self,
        _identity: &ClientIdentity,
        context: &ProtocolRequestContext,
    ) -> AdapterResult<AuthenticationContext> {
        AuthenticationContext::context_bound(context.operation().as_bytes())
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidField))
    }

    fn build_request(
        &self,
        _identity: &ClientIdentity,
        _context: &ProtocolRequestContext,
        envelope: &SecureEnvelope,
    ) -> AdapterResult<RequestParts> {
        RequestParts::new(
            [
                ("X-Demo-Signature", envelope.signature.as_str()),
                ("X-Demo-Wrapped-Key", envelope.wrapped_session_key.as_str()),
            ],
            envelope.cipher.as_str(),
        )
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidField))
    }

    fn parse_response(&self, _response: ResponseParts) -> AdapterResult<ParsedResponse> {
        Err(AdapterError::new(AdapterErrorKind::InvalidMapping))
    }
}

#[test]
fn one_client_builds_multiple_operations() {
    let (config, keys, schema) = support::legacy_client_parts();
    let client = SecureClient::new(config, keys, Arc::new(HeaderProtocolAdapter::new(schema)));
    let first = client
        .build_request(b"one", RequestContext::builder("operation-one").build().unwrap())
        .unwrap();
    let second = client
        .build_request(b"two", RequestContext::builder("operation-two").build().unwrap())
        .unwrap();
    assert_eq!(first.header("x-demo-operation"), Some("operation-one"));
    assert_eq!(second.header("x-demo-operation"), Some("operation-two"));
}

#[test]
fn additional_headers_cannot_replace_adapter_output_under_other_casing() {
    let (config, keys, schema) = support::legacy_client_parts();
    let client = SecureClient::new(config, keys, Arc::new(HeaderProtocolAdapter::new(schema)));
    let context = RequestContext::builder("operation")
        .header("x-DEMO-operation", "attacker-value")
        .unwrap()
        .build()
        .unwrap();
    assert!(matches!(
        client.build_request(b"payload", context),
        Err(Error::HeaderConflict)
    ));
}

#[test]
fn secure_client_requests_context_before_context_bound_signing() {
    let mode = AuthenticationMode::context_bound(b"demo-domain").unwrap();
    let (config, keys, _) = support::client_parts_with_mode(22, mode);
    let client = SecureClient::new(config, keys, Arc::new(ContextAdapter));
    let request = client
        .build_request(
            b"payload",
            RequestContext::builder("bound-operation").build().unwrap(),
        )
        .unwrap();
    assert!(!request.body().is_empty());
}
```

Add an end-to-end response test that constructs a valid peer envelope, maps it into the neutral response fields, and asserts `open_response` returns plaintext only when the remote signing-certificate claim matches the configured expected value.

```rust
#[test]
fn response_identity_is_checked_before_verified_plaintext_is_returned() {
    let (config, keys, schema) = support::legacy_client_parts();
    let client = SecureClient::new(config, keys, Arc::new(HeaderProtocolAdapter::new(schema)));
    let request = client
        .build_request(b"verified", RequestContext::builder("operation").build().unwrap())
        .unwrap();
    let response = ResponseParts::new(
        [
            ("X-Demo-Signature", request.header("X-Demo-Signature").unwrap()),
            ("X-Demo-Wrapped-Key", request.header("X-Demo-Wrapped-Key").unwrap()),
            ("X-Demo-Remote-Certificate", "demo-certificate-21"),
        ],
        request.body(),
    );
    assert_eq!(client.open_response(response).unwrap(), b"verified");

    let mismatch = ResponseParts::new(
        [
            ("X-Demo-Signature", request.header("X-Demo-Signature").unwrap()),
            ("X-Demo-Wrapped-Key", request.header("X-Demo-Wrapped-Key").unwrap()),
            ("X-Demo-Remote-Certificate", "different-certificate"),
        ],
        request.body(),
    );
    assert!(matches!(client.open_response(mismatch), Err(Error::ProtocolAdapter)));
}
```

- [ ] **Step 2: Run the client test and verify failure**

Run: `cargo test --test secure_client`

Expected: FAIL because `SecureClient` does not exist.

- [ ] **Step 3: Implement immutable client construction and direct envelope methods**

Add `src/client.rs`:

```rust
pub struct SecureClient {
    config: ClientConfig,
    keys: KeyMaterial,
    adapter: Arc<dyn ProtocolAdapter>,
}

impl SecureClient {
    #[must_use]
    pub fn new(
        config: ClientConfig,
        keys: KeyMaterial,
        adapter: Arc<dyn ProtocolAdapter>,
    ) -> Self {
        Self { config, keys, adapter }
    }

    pub fn seal(
        &self,
        plaintext: &[u8],
        context: &AuthenticationContext,
    ) -> Result<SecureEnvelope> {
        crate::envelope_crypto::seal(&self.config, &self.keys, plaintext, context)
    }

    pub fn open(
        &self,
        envelope: &SecureEnvelope,
        context: &AuthenticationContext,
    ) -> Result<Vec<u8>> {
        crate::envelope_crypto::open(&self.config, &self.keys, envelope, context)
    }
}
```

- [ ] **Step 4: Implement request and response orchestration**

`build_request` must:

1. split `RequestContext` into `ProtocolRequestContext` and additional headers;
2. request and validate authentication context before sealing;
3. call the adapter with semantic context only;
4. revalidate every adapter-emitted header even though `RequestParts` constructors validate;
5. append additional headers with case-insensitive collision checks; and
6. return parts without I/O.

`open_response` must parse through the adapter, compare the remote signing-certificate claim with `expected_remote_signing_certificate_id`, and then call `open` with the parsed authentication context. Map `AdapterError` to `Error::ProtocolAdapter`; never include adapter-owned strings in the public error.

- [ ] **Step 5: Run client and full tests**

Run: `cargo test --test secure_client`

Expected: PASS.

Run: `cargo test --all-targets`

Expected: PASS.

- [ ] **Step 6: Commit the client façade**

```bash
git add src/client.rs src/message.rs src/lib.rs tests/secure_client.rs tests/support/mod.rs
git commit -m "feat: add immutable secure client facade"
```

## Task 7: Add fluent requests, JSON helpers, sharing, and rotation tests

**Files:**
- Create: `src/request.rs`
- Modify: `src/client.rs`
- Modify: `src/lib.rs`
- Create: `tests/client_convenience.rs`

- [ ] **Step 1: Write failing convenience and lifecycle tests**

Create `tests/client_convenience.rs`:

```rust
mod support;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use secure_envelope_lite::{
    AuthenticationContext, Error, HeaderProtocolAdapter, RequestMetadata, SecureClient,
};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct Payload {
    amount: String,
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn secure_client_is_shareable() {
    assert_send_sync::<SecureClient>();
}

#[test]
fn fluent_builder_supports_json_metadata_and_additional_headers() {
    let (config, keys, schema) = support::legacy_client_parts();
    let client = SecureClient::new(config, keys, Arc::new(HeaderProtocolAdapter::new(schema)));
    let request = client
        .request("demo-operation")
        .metadata(RequestMetadata::new("request-1", "2026-07-12T00:00:00Z").unwrap())
        .header("X-Demo-Trace", "trace-1")
        .unwrap()
        .json(&Payload { amount: "10.00".into() })
        .unwrap();
    assert_eq!(request.header("x-demo-trace"), Some("trace-1"));
}

#[test]
fn json_response_is_deserialized_only_after_verification() {
    let client = support::secure_client_with_seed(19);
    let request = client
        .request("demo-operation")
        .json(&Payload { amount: "10.00".into() })
        .unwrap();
    let response = support::response_from_request(&request, "demo-certificate-19");
    let opened: Payload = client.open_json_response(response).unwrap();
    assert_eq!(opened, Payload { amount: "10.00".into() });

    let tampered = secure_envelope_lite::ResponseParts::new(
        [
            ("X-Demo-Signature", "not-valid-base64"),
            ("X-Demo-Wrapped-Key", request.header("X-Demo-Wrapped-Key").unwrap()),
            ("X-Demo-Remote-Certificate", "demo-certificate-19"),
        ],
        request.body(),
    );
    assert!(matches!(
        client.open_json_response::<Payload>(tampered),
        Err(Error::InvalidEnvelope)
    ));
}

#[test]
fn replacement_client_rotation_does_not_mutate_existing_client() {
    let old = Arc::new(support::secure_client_with_seed(20));
    let replacement = Arc::new(support::secure_client_with_seed(40));
    let context = AuthenticationContext::legacy();
    let old_envelope = old.seal(b"old", &context).unwrap();
    let new_envelope = replacement.seal(b"new", &context).unwrap();

    assert_eq!(old.open(&old_envelope, &context).unwrap(), b"old");
    assert_eq!(replacement.open(&new_envelope, &context).unwrap(), b"new");
    assert!(matches!(
        replacement.open(&old_envelope, &context),
        Err(Error::InvalidEnvelope)
    ));
    assert!(matches!(
        old.open(&new_envelope, &context),
        Err(Error::InvalidEnvelope)
    ));
}
```

- [ ] **Step 2: Run the convenience test and verify failure**

Run: `cargo test --test client_convenience`

Expected: FAIL because the fluent builder and neutral JSON helpers are missing.

- [ ] **Step 3: Implement the fluent builder**

Add `src/request.rs` with a builder borrowing `SecureClient`:

```rust
pub struct RequestBuilder<'a> {
    client: &'a SecureClient,
    operation: String,
    metadata: Option<RequestMetadata>,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl RequestBuilder<'_> {
    pub fn bytes(self, plaintext: &[u8]) -> Result<RequestParts> {
        let metadata = match self.metadata {
            Some(value) => value,
            None => RequestMetadata::generate()?,
        };
        let context = RequestContext::from_parts(self.operation, metadata, self.headers)?;
        self.client.build_request(plaintext, context)
    }

    pub fn json<T: serde::Serialize>(self, value: &T) -> Result<RequestParts> {
        let plaintext = serde_json::to_vec(value).map_err(|_| Error::Serialization)?;
        self.bytes(&plaintext)
    }
}
```

Add `SecureClient::request`, `build_json_request`, and `open_json_response`. JSON deserialization must happen only after `open_response` succeeds.

- [ ] **Step 4: Complete runtime-sharing and replacement-client tests**

Add this runtime-sharing test; the rotation test from Step 1 already proves old and replacement key sets remain isolated:

```rust
#[test]
fn shared_client_builds_independent_operations_in_parallel() {
    let client = Arc::new(support::secure_client_with_seed(18));
    let handles = ["operation-one", "operation-two"].map(|operation| {
        let client = Arc::clone(&client);
        std::thread::spawn(move || {
            client
                .request(operation)
                .bytes(operation.as_bytes())
                .unwrap()
        })
    });
    let [first, second] = handles.map(|handle| handle.join().unwrap());
    assert_eq!(first.header("X-Demo-Operation"), Some("operation-one"));
    assert_eq!(second.header("X-Demo-Operation"), Some("operation-two"));
}
```

- [ ] **Step 5: Run convenience and full tests**

Run: `cargo test --test client_convenience`

Expected: PASS.

Run: `cargo test --all-targets`

Expected: PASS.

- [ ] **Step 6: Commit request conveniences**

```bash
git add src/request.rs src/client.rs src/lib.rs tests/client_convenience.rs tests/support/mod.rs
git commit -m "feat: add fluent request and rotation workflows"
```

## Task 8: Replace inherited fixtures with public-only generated fixtures

**Files:**
- Create: `tools/generate-public-test-fixtures.sh`
- Create: `tests/public-fixtures/test-peer-public.pem`
- Create: `tests/public-fixtures/test-peer-certificate.pem`
- Modify: `tests/key_roles.rs`

- [ ] **Step 1: Add a failing public-certificate parsing test**

Append to `tests/key_roles.rs`:

```rust
use secure_envelope_lite::PeerKeySource;

#[test]
fn newly_generated_public_certificate_is_supported() {
    let key = PublicKey::from_pem(include_bytes!(
        "public-fixtures/test-peer-certificate.pem"
    ))
    .unwrap();
    assert_eq!(key.source(), PeerKeySource::Certificate);
}
```

- [ ] **Step 2: Run the focused test and verify fixture absence**

Run: `cargo test --test key_roles newly_generated_public_certificate_is_supported`

Expected: FAIL because the new public fixture does not exist.

- [ ] **Step 3: Add a disposable fixture-generation script**

Create executable `tools/generate-public-test-fixtures.sh`:

```sh
#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output="$root/tests/public-fixtures"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

mkdir -p "$output"
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:SM2 \
  -out "$temporary/private.pem"
openssl pkey \
  -in "$temporary/private.pem" \
  -pubout \
  -out "$output/test-peer-public.pem"
openssl req \
  -new \
  -x509 \
  -sm3 \
  -key "$temporary/private.pem" \
  -subj "/CN=Secure Envelope SDK Public Test Peer" \
  -days 36500 \
  -out "$output/test-peer-certificate.pem"

if grep -Rqs 'PRIVATE KEY' "$output"; then
  echo "private key material escaped into public fixtures" >&2
  exit 1
fi
```

Use `apply_patch` for the script, then run `chmod +x tools/generate-public-test-fixtures.sh` and `./tools/generate-public-test-fixtures.sh`. Only the public SPKI and certificate are retained; the trap destroys the disposable private key.

- [ ] **Step 4: Run public fixture and full key tests**

Run: `cargo test --test key_roles`

Expected: PASS for DER runtime keys plus the committed public certificate.

Run: `grep -RIl 'PRIVATE KEY' tests/public-fixtures`

Expected: no output and exit code 1.

- [ ] **Step 5: Commit public-only fixtures**

```bash
git add tools/generate-public-test-fixtures.sh tests/public-fixtures tests/key_roles.rs
git commit -m "test: add disposable public key fixtures"
```

## Task 9: Cut over the public crate and remove protocol-specific artifacts

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Replace: `src/lib.rs`
- Delete: `src/config.rs`
- Delete: `src/crypto.rs`
- Delete: `src/headers.rs`
- Delete: `src/package.rs`
- Delete: the legacy façade source file
- Delete: `tests/common/`
- Delete: `tests/fixtures/`
- Delete: `tests/config_and_headers.rs`
- Delete: `tests/gmssl_interop.rs`
- Delete: `tests/key_loading.rs`
- Delete: `tests/php_interop.rs`
- Delete: `tests/protocol_vectors.rs`
- Delete: `.github/workflows/gmssl-interop.yml`
- Delete: `docs/superpowers/specs/2026-07-11-rust-lite-sdk-design.md`
- Delete: `docs/superpowers/plans/2026-07-11-rust-lite-sdk.md`
- Replace: `examples/build_request.rs`
- Replace: `examples/open_response.rs`
- Replace: `README.md`

- [ ] **Step 1: Add a public-API smoke test before removing legacy exports**

Create `tests/public_api.rs` that imports only neutral names from `secure_envelope_lite`, constructs a legacy `HeaderSchema`, builds one request, and opens a response through `SecureClient`. Add this compile-time boundary:

```rust
#![forbid(unsafe_code)]

use secure_envelope_lite::{
    AuthenticationMode, ClientConfig, HeaderProtocolAdapter, KeyMaterial, RequestContext,
    SecureClient,
};

#[test]
fn public_surface_contains_only_neutral_workflow_types() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SecureClient>();
    let _ = std::any::TypeId::of::<RequestContext>();
    let _ = std::any::TypeId::of::<HeaderProtocolAdapter>();
    let _ = std::any::TypeId::of::<KeyMaterial>();
    let _ = AuthenticationMode::LegacyPlaintext;
    let _ = ClientConfig::builder();
}
```

- [ ] **Step 2: Rename the package and library**

Set in `Cargo.toml`:

```toml
[package]
name = "secure-envelope-lite"
version = "0.1.0"
edition = "2024"
rust-version = "1.85"
description = "HTTP-neutral SM2/SM3 and SM4 secure-envelope primitives"
license = "Apache-2.0"
readme = "README.md"
keywords = ["sm2", "sm3", "sm4", "cryptography", "envelope"]
categories = ["cryptography", "encoding"]
publish = false
exclude = [".worktrees/**", "tests/**", "tools/**", "docs/superpowers/**"]

[lib]
name = "secure_envelope_lite"
path = "src/lib.rs"
```

Run `cargo check` once to update `Cargo.lock`.

- [ ] **Step 3: Replace the public module surface and remove legacy modules**

Make `src/lib.rs` contain only neutral modules and exports:

```rust
#![forbid(unsafe_code)]

mod adapter;
mod auth;
mod client;
mod client_config;
mod envelope_crypto;
mod error;
mod header;
mod keys;
mod message;
mod request;

pub use adapter::{
    CipherLocation, HeaderProtocolAdapter, HeaderSchema, HeaderSchemaBuilder, ProtocolAdapter,
};
pub use auth::{AuthenticationContext, AuthenticationMode};
pub use client::SecureClient;
pub use client_config::{
    ClientConfig, ClientConfigBuilder, ClientIdentity, DEFAULT_MAX_PLAINTEXT_BYTES,
};
pub use error::{
    AdapterError, AdapterErrorKind, AdapterResult, Error, KeyKind, Result,
};
pub use header::{HeaderName, HeaderValue};
pub use keys::{KeyMaterial, PeerKeySource, PrivateKey, PublicKey};
pub use message::{
    ParsedResponse, ProtocolRequestContext, RequestContext, RequestContextBuilder,
    RequestMetadata, RequestParts, ResponseParts, SecureEnvelope,
};
pub use request::RequestBuilder;
```

Delete the listed legacy source files, tests, fixtures, old design/plan, and interoperability workflow. Remove temporary compatibility constructors/exports that encode the old API. Preserve generic shared-role constructors where their names and docs are neutral.

- [ ] **Step 4: Rewrite examples and README with fictitious mapping names**

`examples/build_request.rs` must load file paths and passwords from arguments/environment, build a fictitious `HeaderSchema`, select operation per request, add a trace header, and print only header names and body length.

`examples/open_response.rs` must read neutral JSON response parts and print only verified byte length or JSON type, never plaintext.

Rewrite `README.md` to cover:

- neutral purpose and non-audited status;
- role-specific keys and explicit shared roles;
- protocol adapter separation;
- `LegacyPlaintext` requiring authenticated TLS and application replay/correlation checks;
- `ContextBound` transcript format;
- custom headers being additive only;
- one identity per immutable client and replacement-client rotation;
- HTTP-client neutrality;
- private mappings living outside the public checkout; and
- clean-export publication requirements.

All example identities and header names use `demo`, `example`, or `x-envelope` vocabulary only.

- [ ] **Step 5: Scan the tree manually before automated policy exists**

Run a self-safe scan whose source does not contain the complete prohibited strings:

```bash
mac_home=$(printf '/%s/' Users)
legacy_runtime=php
legacy_kind=reference
legacy_reference=$(printf '%s %s' "$legacy_runtime" "$legacy_kind")
legacy_compatibility=$(printf '%s-%s' java compatible)
for pattern in "$mac_home" "$legacy_reference" "$legacy_compatibility"; do
  if rg -n -i -F "$pattern" src tests examples README.md Cargo.toml docs .github ci tools; then
    echo "legacy or workstation-specific content remains" >&2
    exit 1
  fi
done
```

Expected: no matches. The private release policy later supplies organization-specific strings without storing them in this repository.

- [ ] **Step 6: Run the new complete test suite**

Run: `cargo fmt --all`

Run: `cargo test --all-targets`

Expected: PASS with only the neutral tests created in Tasks 1–9.

Run: `cargo test --doc`

Expected: PASS.

- [ ] **Step 7: Commit the breaking cutover**

```bash
git add -A
git commit -m "refactor!: publish neutral secure envelope API"
```

## Task 10: Add open-source release checks and complete verification

**Files:**
- Create: `ci/check-open-source-boundary.sh`
- Delete: `ci/check-production-boundary.sh`
- Modify: `.github/workflows/ci.yml`
- Modify: `.gitignore`
- Create: `LICENSE`
- Modify: `deny.toml`

- [ ] **Step 1: Write a shell-level failing boundary-check test**

Create `tests/open_source_boundary.sh`:

```sh
#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

mkdir -p "$temporary/export/src"
printf '%s\n' 'neutral text' > "$temporary/export/src/lib.rs"
"$root/ci/check-open-source-boundary.sh" "$temporary/export"

printf '/%s/%s\n' Users 'example/internal/path' > "$temporary/export/src/lib.rs"
if "$root/ci/check-open-source-boundary.sh" "$temporary/export"; then
  echo "absolute private path was not rejected" >&2
  exit 1
fi

printf '%s\n' 'neutral text' > "$temporary/export/src/lib.rs"
ln -s src/lib.rs "$temporary/export/link"
if "$root/ci/check-open-source-boundary.sh" "$temporary/export"; then
  echo "symbolic link was not rejected" >&2
  exit 1
fi
rm "$temporary/export/link"

printf '%s\n' 'secret-protocol-token' > "$temporary/policy"
printf '%s\n' 'secret-protocol-token' > "$temporary/export/src/lib.rs"
if OPEN_SOURCE_DENYLIST_FILE="$temporary/policy" \
  "$root/ci/check-open-source-boundary.sh" "$temporary/export"; then
  echo "private injected policy was not enforced" >&2
  exit 1
fi
```

- [ ] **Step 2: Run the shell test and verify it fails**

Run: `sh tests/open_source_boundary.sh`

Expected: FAIL because `ci/check-open-source-boundary.sh` is absent.

- [ ] **Step 3: Implement complete-export scanning with private policy injection**

Create executable `ci/check-open-source-boundary.sh` with these behaviors:

```sh
#!/usr/bin/env sh
set -eu

root=${1:?usage: check-open-source-boundary.sh EXPORT_ROOT}
root=$(CDPATH= cd -- "$root" && pwd)
mac_home=$(printf '/%s/' Users)
unix_home=$(printf '/%s/' home)
private_key_prefix=$(printf '%s ' BEGIN)
private_key_pattern="${private_key_prefix}.*PRIVATE KEY"

if find "$root" -type l \
  ! -path '*/.git/*' \
  ! -path '*/target/*' \
  | grep -q .; then
  echo "symbolic links are not permitted in the public export" >&2
  exit 1
fi

contains_fixed() {
  needle=$1
  find "$root" -type f \
    ! -path '*/.git/*' \
    ! -path '*/target/*' \
    -exec grep -IlF -- "$needle" {} + \
    | grep -q .
}

contains_regex() {
  expression=$1
  find "$root" -type f \
    ! -path '*/.git/*' \
    ! -path '*/target/*' \
    -exec grep -IlE -- "$expression" {} + \
    | grep -q .
}

if contains_fixed "$mac_home" \
  || contains_fixed "$unix_home" \
  || contains_regex '[A-Za-z]:\\[U]sers\\'; then
  echo "absolute workstation path found in export" >&2
  exit 1
fi

if contains_regex "$private_key_pattern"; then
  echo "private key material found in export" >&2
  exit 1
fi

if [ -n "${OPEN_SOURCE_DENYLIST_FILE:-}" ]; then
  policy=$(CDPATH= cd -- "$(dirname -- "$OPEN_SOURCE_DENYLIST_FILE")" && pwd)/$(basename -- "$OPEN_SOURCE_DENYLIST_FILE")
  case "$policy" in
    "$root"/*)
      echo "private policy must live outside the public export" >&2
      exit 1
      ;;
  esac
  while IFS= read -r pattern; do
    [ -z "$pattern" ] && continue
    if grep -RIlF --exclude-dir=.git --exclude-dir=target -- "$pattern" "$root" | grep -q .; then
      echo "private policy match found in export" >&2
      exit 1
    fi
  done < "$policy"
fi

echo "open-source boundary check passed"
```

Use an explicit `find` pass rather than `git grep`, so untracked files in the export are scanned. Fix portability issues discovered on macOS and Ubuntu without weakening coverage.

- [ ] **Step 4: Add license and package checks**

Read the canonical `LICENSE-APACHE` from an installed Apache-licensed Rust dependency such as `zeroize`, verify it is the unmodified Apache License 2.0 text, and use `apply_patch` to add that exact text as `LICENSE`. Do not add an organization copyright line without legal approval.

Update `.gitignore` for generated package/export directories. Keep `deny.toml` limited to public dependency and license policy; organization-specific denied terms must never be stored there.

Build and inspect the package:

```bash
cargo package --allow-dirty --list > /tmp/secure-envelope-package-files.txt
if grep -Ei '(^|/)(tests|tools|docs/superpowers|[^/]+\.(pem|der|key|p12|pfx))($|/)' \
  /tmp/secure-envelope-package-files.txt; then
  echo "test, planning, or key material entered the package" >&2
  exit 1
fi

cargo package --allow-dirty
crate=$(find target/package -maxdepth 1 -name 'secure-envelope-lite-*.crate' -print -quit)
rm -rf /tmp/secure-envelope-package
mkdir -p /tmp/secure-envelope-package
tar -xzf "$crate" -C /tmp/secure-envelope-package
./ci/check-open-source-boundary.sh /tmp/secure-envelope-package
```

The private release pipeline repeats package and export scanning with `OPEN_SOURCE_DENYLIST_FILE` pointing to a policy outside the checkout.

- [ ] **Step 5: Update public CI**

Keep stable Linux/macOS/Windows tests, Rust 1.85 MSRV, formatting, Clippy, documentation, `cargo deny`, and package checks. Replace `check-production-boundary.sh` with:

```yaml
- name: Check complete public export
  shell: bash
  run: |
    mkdir -p /tmp/public-export
    git archive HEAD | tar -x -C /tmp/public-export
    ./ci/check-open-source-boundary.sh /tmp/public-export
- name: Verify package contents
  shell: bash
  run: |
    cargo package --allow-dirty --list > /tmp/package-files.txt
    if grep -Ei '(^|/)(tests|tools|docs/superpowers|[^/]+\.(pem|der|key|p12|pfx))($|/)' /tmp/package-files.txt; then
      exit 1
    fi
```

Delete the protocol-specific interoperability workflow. Private compatibility CI remains in the separate private repository.

- [ ] **Step 6: Run every verification gate from fresh output**

Run, in order:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --doc --locked
cargo deny check
sh tests/open_source_boundary.sh
./ci/check-open-source-boundary.sh --worktree .
git add -A
tree=$(git write-tree)
rm -rf /tmp/secure-envelope-public-export
mkdir -p /tmp/secure-envelope-public-export
git archive "$tree" | tar -x -C /tmp/secure-envelope-public-export
./ci/check-open-source-boundary.sh /tmp/secure-envelope-public-export
cargo package --allow-dirty --list
```

Expected: every command passes. Worktree mode covers untracked and ignored files while skipping only root Git metadata and build output; the staged-tree export covers the exact proposed commit. Complete exports and package archives use the default mode, which does not exclude paths by basename. The clean export contains no private policy; the internal release process must separately repeat export and package scanning with its externally stored denylist/fingerprint policy before publication.

- [ ] **Step 7: Commit release hardening**

```bash
git add LICENSE ci .github/workflows/ci.yml .gitignore deny.toml tests/open_source_boundary.sh
git commit -m "ci: enforce open-source release boundary"
```

- [ ] **Step 8: Record the external compatibility gate**

Do not copy the private schema or fixtures into this repository. In the implementation handoff, record these required external results:

```text
Private schema builds the exact deployed request headers and body: PASS required
Private adapter opens deployed-compatible responses: PASS required
Existing remote accepts the refactored legacy profile: PASS required
Private denylist/fingerprint scan of export and package: PASS required
Security and legal publication approval: REQUIRED
```

The SDK implementation may be complete when public checks pass, but it must not be described as deployment-compatible or publication-approved until the owning organization supplies those external results.
