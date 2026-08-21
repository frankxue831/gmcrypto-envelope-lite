# gmcrypto-envelope-lite

`gmcrypto-envelope-lite` is a small, synchronous, HTTP-neutral Rust library for SM2/SM3 signatures and SM4 secure envelopes. It is **not independently audited**. Treat it as security-sensitive software, review it for your threat model, and complete your own cryptographic and integration assessment before deployment.

The versioned [Security model](SECURITY_MODEL.md) is the authoritative list of claims, non-claims, trust boundaries, and required caller controls.

## Position in the ecosystem

`gmcrypto-envelope-lite` is the independently versioned public protocol layer above `gmcrypto-core`; it consumes core cryptography without exposing core types in its public API. Partner-specific wire mappings, identities, and exact-wire fixtures remain in private downstream adapters.

Official membership, layering, versioning, admission rules, and compatibility gates are defined by the [gmcrypto Rust ecosystem charter](https://github.com/frankxue831/gm-crypto-rs/blob/main/docs/ECOSYSTEM.md). This crate's gate suite is compatibility gate #1 for candidate `gmcrypto-core` releases: `ci/check-compatibility-gate.sh` runs it against a candidate core in every feature configuration this crate ships, and the charter requires a passing run before any core release.

The crate turns application bytes into transport-neutral `RequestParts` and opens `ResponseParts` only after authentication. It does not send HTTP, select an async runtime, establish TLS, retry requests, manage endpoints, or impose an HTTP client.

## Model and trust boundaries

A `SecureClient` owns one validated `ClientConfig`, four role-specific keys, and one `ProtocolAdapter`. It is immutable and `Send + Sync`. Create one client per identity; do not use a single instance as a mutable multi-identity registry.

The four key roles are explicit:

- local signing private key;
- local decryption private key;
- remote verification public key;
- remote encryption public key.

`KeyMaterial::new` accepts all four roles. `KeyMaterial::shared` deliberately reuses one local key for signing and decryption and one remote key for verification and encryption; use that convenience only when the protocol explicitly assigns shared roles. The equally explicit `shared_from_pem`, `shared_from_der`, and `shared_from_files` conveniences load that shared-role arrangement. Role-specific protocols should use the loaders on `PrivateKey` and `PublicKey`, then call `KeyMaterial::new`.

A `ProtocolAdapter` maps only identity metadata, per-request protocol context, and opaque envelope fields. It cannot access plaintext, private or public key objects, or caller-supplied custom headers. Custom headers are appended after adapter output, and a case-insensitive collision is rejected rather than overriding an emitted header.

## Authentication modes

`AuthenticationMode::ContextBound` is preferred for new protocols. Its signed transcript is exactly:

```text
0x01 || u64be(domain_len) || domain || u64be(context_len) || context || u64be(plaintext_len) || plaintext
```

Lengths count bytes. The domain is fixed in immutable client configuration, while the adapter derives the per-request context from semantic request data.

`ClientConfig::iv` is a fixed SM4-CBC IV only for compatibility with an existing legacy wire. A fixed CBC IV is deterministic under key reuse and can reveal plaintext-prefix equality; generating a fresh session key for each envelope narrows that exposure but does not turn this construction into a modern authenticated-encryption design. `ContextBound` expands only what the signature authenticates. It does not replace CBC, repair fixed-IV or mode-leakage risks, or provide nonce/IV misuse resistance.

Do not copy this fixed-IV CBC design into a new protocol. New integrations should enable the opt-in `aead` feature and select the SM4-GCM envelope mode described under "Choosing an envelope mode"; without that feature this crate provides no AEAD envelope profile.

`AuthenticationMode::LegacyPlaintext` exists only for legacy compatibility. Its SM2 signature covers plaintext alone; it does not authenticate envelope metadata or transport headers. A deployment using this mode must use authenticated TLS and must implement application-level replay protection and request/response correlation.

Because the legacy wire signature covers plaintext, opening a legacy envelope necessarily decrypts before signature verification. The crate returns the unified `Error::InvalidEnvelope` for malformed or unauthenticated cryptographic input, but that error unification does not eliminate timing differences. Callers must not turn failure categories, response bodies, logging detail, retry behavior, or timing into externally observable distinctions.

## Choosing an envelope mode

The envelope mode and AEAD algorithm are pinned by `ClientConfig` and never inferred from incoming bytes: there is no negotiation and no fallback, and a client rejects envelopes of another mode or algorithm outright. `AuthenticationMode` (what the SM2 signature covers) is an independent axis and composes with every mode.

| | `EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm)` — feature `aead` (recommended AEAD) | `EnvelopeMode::Aead(AeadAlgorithm::Sm4Ccm)` — feature `aead` | `EnvelopeMode::LegacyCbc` — default |
| --- | --- | --- | --- |
| Payload cipher | SM4-GCM with a fresh random 12-byte nonce and a full 16-byte tag per envelope; frame id `0x01` | SM4-CCM with a fresh random 12-byte nonce and a full 16-byte tag per envelope; frame id `0x02`; plaintext limit defaults to `SM4_CCM_DEFAULT_MAX_PLAINTEXT_BYTES` (64 KiB) and may be raised explicitly to the ceiling `SM4_CCM_MAX_PLAINTEXT_BYTES` (`2^24 - 1`) | SM4-CBC with the configured fixed IV |
| Ciphertext integrity | AEAD tag, verified before any plaintext is produced | AEAD tag; CCM decrypts CTR plaintext before verifying CBC-MAC, then wipes its tentative plaintext on tag failure (other primitive-internal copies are not wiped — see `SECURITY_MODEL.md`) | none from the cipher; only the SM2 signature, after decryption |
| Bound metadata | frame header always; domain separator and protocol context under `ContextBound` (empty fields under `LegacyPlaintext`), all in the AAD | same AAD as GCM | signed transcript only |
| Replay protection | none — application concern | none — application concern | none — application concern |
| Intended use | new integrations | peers that require CCM on the wire | existing deployed wires, supported indefinitely |

The SM2 signature remains mandatory under AEAD: the session key is encrypted to a public key, so the tag alone proves nothing about who sealed the envelope. An AEAD configuration must not set `iv`:

```no_run
# #[cfg(feature = "aead")] {
use gmcrypto_envelope_lite::{AeadAlgorithm, AuthenticationMode, ClientConfig, EnvelopeMode};

let mode = AuthenticationMode::context_bound(b"example-app/envelope/v1")
    .expect("nonempty domain separator");
let config = ClientConfig::builder()
    .local_identity_id("demo-client")
    .api_version("example-v1")
    .local_certificate_id("example-local-signing-certificate")
    .expected_remote_signing_certificate_id("example-remote-signing-certificate")
    .remote_encryption_certificate_id("example-remote-encryption-certificate")
    .local_signer_id(b"demo-local-signer")
    .expected_remote_signer_id(b"demo-remote-signer")
    .authentication_mode(mode)
    .envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm))
    .build();
assert!(config.is_ok());
# }
```

## Constructing a client

All protocol mappings are explicit; there are no built-in remote wire names. A new integration enables the `aead` feature and pairs the SM4-GCM envelope mode with context-bound authentication. Its `ProtocolAdapter` defines the wire: which authentication context each signature covers, and how envelope fields travel. The adapter never sees plaintext or key material.

```no_run
# #[cfg(feature = "aead")] {
use std::sync::Arc;

use gmcrypto_envelope_lite::{
    AdapterError, AdapterErrorKind, AdapterResult, AeadAlgorithm, AuthenticationContext,
    AuthenticationMode, ClientConfig, ClientIdentity, EnvelopeMode, KeyMaterial, ParsedResponse,
    PrivateKey, ProtocolAdapter, ProtocolRequestContext, PublicKey, RequestParts, ResponseParts,
    SecureClient, SecureEnvelope,
};

struct ExampleContextAdapter;

impl ProtocolAdapter for ExampleContextAdapter {
    fn request_authentication_context(
        &self,
        _identity: &ClientIdentity,
        context: &ProtocolRequestContext,
    ) -> AdapterResult<AuthenticationContext> {
        // Bind semantic request data the verifying peer re-derives from the
        // received wire fields.
        AuthenticationContext::context_bound(
            format!(
                "operation={}&request-id={}",
                context.operation(),
                context.metadata().request_id()
            )
            .into_bytes(),
        )
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidField))
    }

    fn build_request(
        &self,
        identity: &ClientIdentity,
        context: &ProtocolRequestContext,
        envelope: &SecureEnvelope,
    ) -> AdapterResult<RequestParts> {
        RequestParts::new(
            [
                ("X-Envelope-Local-Identity", identity.local_identity_id()),
                ("X-Envelope-Operation", context.operation()),
                ("X-Envelope-Request-Id", context.metadata().request_id()),
                ("X-Envelope-Request-Signature", envelope.signature.as_str()),
                (
                    "X-Envelope-Request-Wrapped-Key",
                    envelope.wrapped_session_key.as_str(),
                ),
            ],
            envelope.cipher.as_str(),
        )
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidField))
    }

    fn parse_response(&self, response: ResponseParts) -> AdapterResult<ParsedResponse> {
        let header = |name: &str| {
            response
                .headers()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.to_owned())
                .ok_or_else(|| AdapterError::new(AdapterErrorKind::MissingField))
        };
        let envelope = SecureEnvelope {
            cipher: response.body().to_owned(),
            wrapped_session_key: header("X-Envelope-Response-Wrapped-Key")?,
            signature: header("X-Envelope-Response-Signature")?,
        };
        let certificate = header("X-Envelope-Response-Remote-Signing-Certificate")?;
        // The remote binds the request id it answers into its signed
        // transcript; the application still correlates the verified response
        // with its originating request.
        let request_id = header("X-Envelope-Request-Id")?;
        let context = AuthenticationContext::context_bound(
            format!("request-id={request_id}").into_bytes(),
        )
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidField))?;
        ParsedResponse::new(envelope, certificate, context)
    }
}

fn client(key_password: &[u8]) -> Result<SecureClient, Box<dyn std::error::Error>> {
    let keys = KeyMaterial::new(
        PrivateKey::from_encrypted_file("example-local-signing.pem", key_password)?,
        PrivateKey::from_encrypted_file("example-local-decryption.pem", key_password)?,
        PublicKey::from_file("example-remote-verification.pem")?,
        PublicKey::from_file("example-remote-encryption.pem")?,
    );
    let config = ClientConfig::builder()
        .local_identity_id("demo-client")
        .api_version("example-v1")
        .local_certificate_id("example-local-signing-certificate")
        .expected_remote_signing_certificate_id("example-remote-signing-certificate")
        .remote_encryption_certificate_id("example-remote-encryption-certificate")
        .local_signer_id(b"demo-local-signer")
        .expected_remote_signer_id(b"demo-remote-signer")
        .authentication_mode(AuthenticationMode::context_bound(
            b"example-app/envelope/v1",
        )?)
        .envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm))
        .build()?;
    Ok(SecureClient::new(
        config,
        keys,
        Arc::new(ExampleContextAdapter),
    ))
}
# let key_password = std::env::var("SECURE_ENVELOPE_KEY_PASSWORD").expect("example password");
# let _client = client(key_password.as_bytes()).expect("example client");
# }
```

The domain separator is fixed in configuration and versioned like a wire format; the per-request context is derived from semantic request data that the verifying peer can re-derive. `examples/build_request.rs` and `examples/open_response.rs` are complete runnable versions of this integration.

### Compatibility mode: an existing CBC wire

An already-deployed fixed-IV CBC wire remains supported indefinitely; configure it explicitly as the compatibility mode it is. For header-mapped wires, `.context_bound_authentication()` with `AuthenticationMode::ContextBound` is the convenience when both ends use the crate-owned version-1 binary context. The schema below uses the explicit `.legacy_authentication()` acknowledgement because the compatibility mode signs plaintext only.

```no_run
use std::sync::Arc;

use gmcrypto_envelope_lite::{
    AuthenticationMode, CipherLocation, ClientConfig, HeaderProtocolAdapter, HeaderSchema,
    KeyMaterial, PrivateKey, PublicKey, SecureClient,
};

fn client(key_password: &[u8]) -> Result<SecureClient, Box<dyn std::error::Error>> {
    let keys = KeyMaterial::new(
        PrivateKey::from_encrypted_file("example-local-signing.pem", key_password)?,
        PrivateKey::from_encrypted_file("example-local-decryption.pem", key_password)?,
        PublicKey::from_file("example-remote-verification.pem")?,
        PublicKey::from_file("example-remote-encryption.pem")?,
    );
    let config = ClientConfig::builder()
        .local_identity_id("demo-client")
        .api_version("example-v1")
        .local_certificate_id("example-local-signing-certificate")
        .expected_remote_signing_certificate_id("example-remote-signing-certificate")
        .remote_encryption_certificate_id("example-remote-encryption-certificate")
        .local_signer_id(b"demo-local-signer")
        .expected_remote_signer_id(b"demo-remote-signer")
        .authentication_mode(AuthenticationMode::LegacyPlaintext)
        // A fixed IV is shown only for legacy wire compatibility.
        .iv(*b"example-iv-00001")
        .build()?;
    let schema = HeaderSchema::builder()
        .static_request_header("Content-Type", "application/example-envelope")
        .local_identity_header("X-Envelope-Local-Identity")
        .operation_header("X-Envelope-Operation")
        .request_id_header("X-Envelope-Request-Id")
        .request_time_header("X-Envelope-Request-Time")
        .api_version_header("X-Envelope-Api-Version")
        .local_certificate_header("X-Envelope-Local-Certificate")
        .remote_signing_certificate_header("X-Envelope-Remote-Signing-Certificate")
        .remote_encryption_certificate_header("X-Envelope-Remote-Encryption-Certificate")
        .request_signature_header("X-Envelope-Request-Signature")
        .request_wrapped_key_header("X-Envelope-Request-Wrapped-Key")
        .request_cipher(CipherLocation::Body)
        .response_signature_header("X-Envelope-Response-Signature")
        .response_wrapped_key_header("X-Envelope-Response-Wrapped-Key")
        .response_remote_signing_certificate_header(
            "X-Envelope-Response-Remote-Signing-Certificate",
        )
        .response_cipher(CipherLocation::Body)
        .legacy_authentication()
        .build()?;

    Ok(SecureClient::new(
        config,
        keys,
        Arc::new(HeaderProtocolAdapter::new(schema)),
    ))
}
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let key_password = std::env::var("SECURE_ENVELOPE_KEY_PASSWORD")?;
# let _client = client(key_password.as_bytes())?;
# Ok(())
# }
```

## Migrating an existing wire

The envelope mode and the authentication mode are pinned by configuration with no negotiation and no fallback, so each migration step is a coordinated wire change on both ends, not a rolling client-side upgrade.

**CBC → AEAD.** Enable the `aead` feature, select `EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm)` (the recommended AEAD) or `AeadAlgorithm::Sm4Ccm`, and remove the `iv` setting — an AEAD configuration rejects a configured IV. GCM, CCM, and CBC envelopes are not wire-compatible with each other, and a client pinned to one rejects the others outright, so both peers must switch in the same coordinated change. The SM2 signature, the key roles, and the wrapped-session-key construction are unchanged.

**LegacyPlaintext → ContextBound.** Choose a fixed domain separator and version it like a wire format, select `AuthenticationMode::context_bound(domain)`, and derive request and response contexts the verifying peer can re-derive from data on the wire. Header-mapped wires may use `HeaderProtocolAdapter` when they adopt the crate-owned version-1 binary encoding via `.context_bound_authentication()`. ASCII `operation={op}&request-id={id}` is not this crate's header-adapter encoding; custom `ProtocolAdapter` implementations may still use it if both ends agree. The signed transcript changes shape, so signatures made in one mode never verify in the other and peers must agree on the mode, the domain, and the exact context derivation. This expands signature coverage only — it does not modernize the underlying CBC construction or repair fixed-IV and mode-leakage risks.

The two axes are independent: an existing deployment can adopt `ContextBound` while still on the CBC wire, and the end state for a migrated integration is the same as for a new one — AEAD with `ContextBound`.

## HTTP integration

Build each operation independently and copy the returned parts into the HTTP stack selected by the application:

```no_run
# fn use_client(client: &gmcrypto_envelope_lite::SecureClient) -> gmcrypto_envelope_lite::Result<()> {
let request = client
    .request("demo-operation")
    .header("X-Envelope-Trace", "demo-trace")?
    .bytes(b"application payload")?;

for (name, value) in request.headers() {
    let (_http_name, _http_value) = (name.as_str(), value.as_str());
    // Set this pair on the chosen HTTP client.
}
let body = request.body();
# let _ = body;
# Ok(())
# }
```

Capture an HTTP response as an ordered sequence of header pairs plus its body, then pass it to `open_response` or `open_json_response`:

```no_run
# fn use_response(client: &gmcrypto_envelope_lite::SecureClient) -> gmcrypto_envelope_lite::Result<()> {
use gmcrypto_envelope_lite::ResponseParts;

# let received_headers = Vec::<(String, String)>::new();
# let received_body = String::new();
let response = ResponseParts::new(received_headers, received_body);
let verified_bytes = client.open_response(response)?;
# let _ = verified_bytes;
# Ok(())
# }
```

The application remains responsible for HTTP method and URI selection, TLS validation, timeouts, retry safety, replay defense, and correlating the verified response with the originating request.

## Rotation and memory handling

Key or identity rotation means constructing a complete replacement client whose configuration, schema, and all four keys have already been validated. Publish it with an application-owned atomic `Arc` swap; do not mutate a live client in place. In-flight operations may finish on the old immutable instance while new operations use the replacement.

The crate zeroizes SDK-owned session-key buffers, unverified plaintext buffers, and temporary plaintext JSON-helper buffers. It cannot guarantee zeroization of allocations, padding, or intermediate values owned internally by cryptographic and serialization dependencies. It makes no claim of independent audit, universal constant-time behavior, or protection from a compromised process.

## Private mappings, compatibility, and publication

Real remote mappings, identifiers, fixtures, and the exact-wire compatibility suite must live outside the public checkout, such as in a separately access-controlled repository, configuration system, or adapter crate. Untracked files inside a public checkout are not a secrecy boundary. Before an internal deployment, the private compatibility suite must prove exact compatibility with the existing remote wire.

Removing sensitive material from the current tree does not remove it from Git history. Publication uses either this repository made public after a recorded history scan and an explicit owner decision, or a fresh, reviewed export. Before publication, scan the complete export and package contents and record the review disposition.

## Release status

Version 0.4.0 is unreleased and in development on `main`. Version 0.3.0 is the current tagged line (`v0.3.0`). Version 0.2.0 remains the tagged first crates.io candidate (`v0.2.0`). Repository checks produce an immutable `rc-built` artifact set for a named commit. Publication to crates.io has not occurred; when 0.2.0 is published it is from `git checkout v0.2.0`, not from a later `main`. When 0.3.0 is published it is from `git checkout v0.3.0`. When 0.4.0 is published it is from `git checkout v0.4.0`.

`rc-built` is evidence of repository gate completion, not of the later external states. Publication requires the external gates in the [release checklist](RELEASE_CHECKLIST.md), which is deliberately excluded from the Cargo package.

## Examples

Both examples demonstrate the configuration recommended for new integrations — the SM4-GCM envelope mode with context-bound authentication and a caller-implemented `ProtocolAdapter` — and therefore declare `required-features = ["aead"]`; build them with `--features aead`. The fixed-IV CBC compatibility configuration appears only in the section above, labeled as such.

`examples/build_request.rs` reads payload and role-specific key paths from command-line arguments and reads the key secret from `SECURE_ENVELOPE_KEY_PASSWORD`. It prints only header names and the encrypted body length. `examples/open_response.rs` reads a JSON response document containing header pairs and a body, then prints only the verified byte length. Neither example sends HTTP or prints header values, envelope bodies, verified plaintext, keys, or secrets.
