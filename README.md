# gmcrypto-envelope-lite

`gmcrypto-envelope-lite` is a small, synchronous, HTTP-neutral Rust library for SM2/SM3 signatures and SM4 secure envelopes. It is **not independently audited**. Treat it as security-sensitive software, review it for your threat model, and complete your own cryptographic and integration assessment before deployment.

The versioned [Security model](SECURITY_MODEL.md) is the authoritative list of claims, non-claims, trust boundaries, and required caller controls.

## Position in the ecosystem

`gmcrypto-envelope-lite` is the independently versioned public protocol layer above `gmcrypto-core`; it consumes core cryptography without exposing core types in its public API. Partner-specific wire mappings, identities, and exact-wire fixtures remain in private downstream adapters.

Official membership, layering, versioning, admission rules, and compatibility gates are defined by the [gmcrypto Rust ecosystem charter](https://github.com/frankxue831/gm-crypto-rs/blob/main/docs/ECOSYSTEM.md). This crate's 0.1.0 RC suite is compatibility gate #1 for candidate `gmcrypto-core` releases.

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

The envelope mode is pinned by `ClientConfig` and never inferred from incoming bytes: there is no negotiation and no fallback, and a client rejects envelopes of the other mode outright. `AuthenticationMode` (what the SM2 signature covers) is an independent axis and composes with both modes.

| | `EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm)` — feature `aead` | `EnvelopeMode::LegacyCbc` — default |
| --- | --- | --- |
| Payload cipher | SM4-GCM with a fresh random 12-byte nonce per envelope | SM4-CBC with the configured fixed IV |
| Ciphertext integrity | AEAD tag, verified before any plaintext is produced | none from the cipher; only the SM2 signature, after decryption |
| Bound metadata | frame header always; domain separator and protocol context under `ContextBound` (empty fields under `LegacyPlaintext`), all in the AAD | signed transcript only |
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

## Constructing a client

All protocol mappings are explicit; there are no built-in remote wire names.

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

Where an existing envelope wire can expand its signature coverage, select `AuthenticationMode::context_bound(domain)` and implement a `ProtocolAdapter` that returns the matching context-bound authentication context. This does not modernize the underlying CBC construction. `HeaderProtocolAdapter` is the explicit legacy-compatibility convenience.

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

Removing sensitive material from the current tree does not remove it from Git history. Publication must use a fresh, reviewed export or repository, unless a separately approved history rewrite is performed. Before publication, scan the complete export and package contents, then obtain security and legal approval.

## Release status

Version 0.2.0 is unreleased and in development; the 0.1.0 release-candidate artifact set remains recorded at promotion state rc-built. Publishing is enabled in the manifest, and publication happens only after the external gates in the release checklist pass. Repository checks can produce an immutable `rc-built` artifact set containing the source export, Cargo package, manifest, and checksums for one exact commit.

`rc-built` is evidence of repository gate completion, not approval for private exact-wire compatibility, independent security review, legal approval, production deployment, or publication. The blank [release checklist](RELEASE_CHECKLIST.md) defines those external states and is deliberately excluded from the Cargo package.

## Examples

`examples/build_request.rs` reads payload and role-specific key paths from command-line arguments and reads the key secret from `SECURE_ENVELOPE_KEY_PASSWORD`. It prints only header names and the encrypted body length. `examples/open_response.rs` reads a JSON response document containing header pairs and a body, then prints only the verified byte length. Neither example sends HTTP or prints header values, envelope bodies, verified plaintext, keys, or secrets.
