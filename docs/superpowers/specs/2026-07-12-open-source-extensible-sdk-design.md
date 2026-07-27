# Open-Source Extensible Secure Envelope SDK Design

**Status:** Approved design
**Date:** 2026-07-12  
**Working package name:** `secure-envelope-lite`

## 1. Purpose

Refactor the current single-protocol SDK into an open-source-safe, HTTP-neutral secure-envelope SDK. The open-source repository must contain no company identity, private repository references, proprietary header names, production-like identifiers, inherited internal test keys, or private protocol fixtures.

The refactored SDK must still support the existing remote system without requiring any remote change. Compatibility is supplied by a private protocol configuration or adapter maintained outside the open-source repository.

## 2. Goals

- Keep the SM2/SM3 signing and verification, SM2 session-key wrapping, and SM4-CBC payload protection in a small, auditable core.
- Separate generic cryptographic envelope handling from organization-specific HTTP field mapping.
- Let one immutable client instance serve one identity and call multiple operations by selecting the operation code per request.
- Allow additive custom request headers while preventing case-insensitive collisions with protocol-reserved headers.
- Keep HTTP transport outside the SDK.
- Support key and certificate rotation by constructing a new client and atomically switching the application to it.
- Preserve fail-closed behavior: plaintext is returned only after successful decryption, size validation, peer-key validation, and signature verification.
- Make authentication coverage explicit: legacy plaintext-only signatures require authenticated TLS, while new profiles can bind protocol context into the signature.
- Make the tracked source tree suitable for a clean public export.

## 3. Non-goals

- The SDK will not manage multiple identities or tenants in a registry.
- The SDK will not send HTTP requests, select an async runtime, implement retries, or configure TLS.
- The first refactor will not introduce pluggable cryptographic algorithms or HSM/KMS traits. Authentication coverage is selectable, but the SM2/SM3 and SM4 primitive suite remains fixed.
- The SDK will not embed a proprietary protocol adapter, proprietary field names, or organization-specific fixtures.
- The SDK will not rewrite the current Git history automatically. Public release must use a reviewed clean export or a separately approved history-rewrite process.
- The SDK does not provide legal approval to disclose a protocol. Company security and legal review remain required before publication.

## 4. Architecture

Use a ports-and-adapters design with four layers:

```text
Application
    |
    v
SecureClient ---- RequestContext
    |                    |
    |                    v
    |              ProtocolAdapter
    |                    |
    v                    v
EnvelopeCrypto      RequestParts / ResponseParts
    |
    v
SM2 / SM3 / SM4 implementation
```

### 4.1 `EnvelopeCrypto`

This private module owns all `gmcrypto-core` integration. It:

- generates a fresh 16-byte session key for every message;
- encrypts and decrypts payload bytes with SM4-CBC and PKCS#7;
- wraps and unwraps session keys with SM2;
- signs and verifies the authentication input selected by the configured mode with SM2/SM3;
- enforces encoded and decoded message-size limits;
- owns session keys and decrypted-but-unverified plaintext in zeroizing guards, guaranteeing cleanup on every failure and early-return path; and
- maps dependency errors into SDK-owned, redacted errors.

No `gmcrypto-core` type appears in the public API.

### 4.2 `SecureClient`

`SecureClient` is the public façade. It owns:

- immutable `ClientConfig`;
- parsed, role-specific `KeyMaterial`; and
- an immutable `Arc<dyn ProtocolAdapter>`.

One client represents one local identity and one expected remote identity. `KeyMaterial` has explicit slots for the local signing private key, local decryption private key, remote verification public key, and remote encryption public key. A convenience constructor may deliberately reuse one local key and one remote key across both roles, but the reuse is explicit rather than implied. It is safe to share a validated client between requests. Rotation creates a fully validated replacement client; no key or configuration mutates during an in-flight operation.

The client performs cryptographic operations, protocol-consistency checks, and verification against the configured remote public key. An adapter can map fields, but it cannot bypass signature verification or obtain unverified plaintext.

### 4.3 `ProtocolAdapter`

`ProtocolAdapter` is the organization-neutral extension point:

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
```

`ProtocolRequestContext` contains only the operation and request metadata. Caller-supplied additional headers remain private to `SecureClient`, so an adapter cannot consume them as protocol values. Before encryption, the client asks the adapter for an SDK-owned `AuthenticationContext`; this contains context bytes only and never plaintext. After request mapping, the client validates every emitted header name and value, rejects case-insensitive duplicates, and compares caller headers against the actual emitted names before appending them. A self-reported reserved-name list is not trusted as the enforcement boundary.

The adapter sees public identifiers, protocol request metadata, and encrypted envelope values. It never receives caller extension headers, key material, session keys, private-key passwords, or plaintext.

`AdapterResult<T>` uses a public, constructible, redacted `AdapterError` so implementations in other crates can report mapping failures without depending on private SDK error internals. `SecureClient` converts it to the public SDK error category at the boundary.

`ParsedResponse` contains a `SecureEnvelope`, the semantic remote signing-certificate identifier extracted from the response, and the SDK-owned `AuthenticationContext` required by the selected authentication mode. `SecureClient` compares that identifier with `ClientConfig::expected_remote_signing_certificate_id` before returning plaintext. The configured remote verification key, not the unauthenticated certificate-name field, is the cryptographic peer identity.

### 4.4 `HeaderProtocolAdapter`

The open-source crate includes a data-driven `HeaderProtocolAdapter`. Callers construct it from a validated `HeaderSchema` containing semantic mappings for:

- content type;
- local identity;
- operation code;
- request ID and timestamp;
- API version;
- local and remote certificate identifiers;
- signature;
- wrapped session key; and
- encrypted body placement.

The schema contains no built-in proprietary names or organization-specific defaults. A private application or private companion crate supplies the real mapping. This is sufficient for the existing remote protocol without requiring a custom Rust type.

Construction validates all required mappings, rejects empty or syntactically invalid names and values, and rejects case-insensitive duplicate names. `SecureClient` independently validates adapter output and merges additional headers after mapping, so a custom adapter cannot weaken collision enforcement accidentally.

### 4.5 Authentication modes

The fixed primitive suite supports two explicit authentication modes:

- `LegacyPlaintext` signs and verifies the exact plaintext bytes. It exists only for deployed compatibility. Operation, request metadata, API version, and mapped certificate-name fields are not authenticated by the envelope in this mode. Applications must use authenticated TLS, must not treat a mapped certificate ID as cryptographic proof, and must perform any required replay or business-response correlation checks outside the envelope API.
- `ContextBound` signs a domain-separated, length-delimited transcript containing canonical protocol context followed by the exact plaintext. Before encryption, the adapter maps semantic fields into `AuthenticationContext`; the SDK, not the adapter, applies versioned transcript framing and appends plaintext. This mode is intended for new protocols whose remote endpoint implements the same transcript.

Transcript version 1 is `0x01 || domain_length || domain || context_length || context || plaintext_length || plaintext`, using unsigned 64-bit big-endian lengths. The domain separator is non-empty and client-configured. No implicit fallback or trial verification is permitted. Both peers must agree on the authentication mode, domain separator, context bytes, and transcript version when the client is constructed.

## 5. Public API

### 5.1 Static client configuration

`ClientConfig` contains only values fixed for a client lifetime:

- `local_identity_id`;
- `api_version`;
- `local_certificate_id`;
- `expected_remote_signing_certificate_id`;
- `remote_encryption_certificate_id`;
- `local_signer_id`;
- `expected_remote_signer_id`;
- `authentication_mode`;
- protocol IV; and
- maximum plaintext size.

The signer IDs are separate because SM2 identity input is directional and may differ between peers. The IV is explicit because the open-source core must not embed a private protocol value. Documentation warns that a static IV exists only for legacy protocol compatibility and is not a recommended design for a new protocol.

All string values used in transport mappings reject empty values and CR/LF. Both signer IDs and the IV length are validated at construction. Client construction also requires every directional key role, unless the caller uses the explicit shared-role convenience constructor.

### 5.2 Per-request context

`RequestContext` contains:

- required `operation`;
- `RequestMetadata`; and
- additional request headers.

Metadata can be supplied explicitly for deterministic operation or generated by the SDK. The convenience request builder generates metadata if the caller does not provide it.

Additional headers are additive only. Names are compared case-insensitively. A duplicate custom name or collision with an adapter-emitted name returns an error; values are never silently overwritten.

Before invoking the adapter, `SecureClient` derives a `ProtocolRequestContext` that omits additional headers. After mapping, the client validates that adapter output is syntactically valid and case-insensitively unique, then rejects additional-header names that collide with the actual adapter output.

### 5.3 Message types

- `SecureEnvelope` contains Base64 ciphertext, wrapped session key, and signature.
- `RequestParts` contains an ordered sequence of unique header pairs and a body.
- `ResponseParts` preserves the original sequence of response header pairs and body so duplicate required fields can be detected.
- `ParsedResponse` contains the encrypted envelope, semantic remote signing-certificate claim, and authentication context required for verification.
- `AuthenticationContext` is an SDK-owned byte wrapper used only as input to versioned transcript framing; it contains no plaintext or key material.

Header collections remain SDK-owned and HTTP-library-neutral. Convenience iterators make copying into any HTTP client straightforward.

### 5.4 Client operations

The byte-oriented core API is:

```rust
client.seal(plaintext: &[u8], context: &AuthenticationContext) -> Result<SecureEnvelope>
client.open(
    envelope: &SecureEnvelope,
    context: &AuthenticationContext,
) -> Result<Vec<u8>>
```

`LegacyPlaintext` requires `AuthenticationContext::legacy()`, which is an explicit empty context marker. `ContextBound` rejects the legacy marker. This keeps direct envelope calls as explicit as the request/response helpers and prevents silent mode fallback.

The transport-neutral API is:

```rust
client.build_request(plaintext: &[u8], context: RequestContext) -> Result<RequestParts>
client.open_response(response: ResponseParts) -> Result<Vec<u8>>
```

JSON convenience methods serialize once before sealing and deserialize only after verification. A fluent `client.request(operation)` builder can set metadata and additive headers before accepting bytes or a serializable value.

## 6. Data flow

### 6.1 Build

1. Validate the request context and additional headers, then derive a semantic-only `ProtocolRequestContext`.
2. Ask the adapter for the outbound `AuthenticationContext` and validate it against the configured authentication mode.
3. Reject plaintext exceeding the configured limit.
4. Generate a fresh session key.
5. Encrypt the exact plaintext.
6. Wrap the session key for the remote key.
7. Sign either the exact plaintext (`LegacyPlaintext`) or the SDK-framed context and plaintext transcript (`ContextBound`).
8. Construct `SecureEnvelope` with standard padded Base64 values.
9. Ask the protocol adapter to map semantic identity, semantic-only context, and envelope fields into request parts.
10. Validate all adapter-emitted headers for syntax and case-insensitive uniqueness.
11. Add caller headers only after checking them against the actual adapter-emitted names.
12. Return request parts without performing I/O.

### 6.2 Open

1. Preserve all received response header pairs.
2. Ask the adapter to parse required fields and reject missing or duplicate mapped fields.
3. Compare the parsed remote signing-certificate identifier with the configured expected identifier as a protocol-consistency check; use the pinned remote verification key as cryptographic identity.
4. Enforce encoded size bounds before Base64 allocation.
5. Strictly decode the envelope values.
6. Unwrap the session key and require exactly 16 bytes.
7. Decrypt the payload.
8. Enforce the plaintext size limit.
9. Validate the parsed `AuthenticationContext` against the selected mode, frame the verification input, and verify with the expected remote signer ID.
10. Return plaintext only after every check succeeds.

From strict envelope decoding onward, unwrap, padding, decryption, and signature failures are indistinguishable at the public boundary and map to one opaque `InvalidEnvelope` error. This prevents callers from accidentally exposing a CBC padding oracle. More detailed classifications may exist only in tests or private, non-observable instrumentation and must never cross the public API.

## 7. Error handling

The public, non-exhaustive error model remains SDK-owned and redacted. It distinguishes:

- invalid client configuration;
- invalid request context;
- invalid header name or value;
- duplicate or reserved-header conflict;
- invalid protocol mapping;
- missing, duplicate, or invalid response field;
- key-material failure;
- malformed protocol parts before cryptographic processing;
- message-size failure;
- serialization failure;
- outbound encryption failure;
- opaque invalid-envelope failure for all inbound decode, unwrap, padding, decryption, and signature failures; and
- safe file I/O context.

Errors never contain plaintext, passwords, private keys, session keys, complete encrypted bodies, or dependency-internal cryptographic diagnostics. Invalid header values are not echoed.

## 8. Open-source boundary

The refactor removes from the tracked public source tree:

- organization and counterparty names except standards attribution required by licenses;
- proprietary request and response header names;
- actual or production-like identity, certificate, operation, and signer identifiers;
- local absolute paths and private repository references;
- inherited private keys, certificates, encrypted test keys, passwords, and protocol captures;
- PHP or other internal reference implementations; and
- documentation that describes private deployment or integration details.

The project replaces them with:

- neutral names and fictitious values;
- newly generated, clearly labeled test-only key material;
- a fictitious header schema;
- public-standard interoperability tests;
- a generic public release-boundary scanner for absolute workspace paths, private-key packaging, unsafe file classes, and caller-supplied prohibited patterns; and
- a privately maintained release policy containing organization-specific denylist entries and private fixture fingerprints, injected only in the private release pipeline.

Because deleted files remain in Git history, the existing repository must not be published directly. Publication uses a fresh repository initialized from a reviewed export, or a separately authorized history rewrite followed by a fresh-clone verification. Both the generic public scanner and privately injected release policy scan the complete exported tree and built package archive, not merely Git-tracked files. The public package contents and source archive are reviewed independently of the working tree.

The real mapping needed by the existing remote system must live outside the public checkout, preferably in a separate private repository or private adapter crate. Untracked files inside the public checkout are explicitly prohibited as a secrecy boundary. A private integration suite must prove that the refactored client still emits and accepts the exact deployed wire format.

## 9. Testing strategy

### 9.1 Open-source tests

- Configuration, directional signer-ID, directional key-role, IV, and size validation.
- Newly generated PEM/DER encrypted private keys, public keys, and certificates.
- Envelope round trips, randomized output, boundaries, Unicode, and empty input.
- Tampered ciphertext, signature, wrapped key, peer identity, padding, and Base64 rejection.
- Multiple operation codes from one immutable client.
- Generated and caller-supplied request metadata.
- Additive custom headers and case-insensitive collision rejection.
- Header-schema construction, missing mappings, duplicate mappings, response duplicates, and unknown response headers.
- Adapter-output validation when a deliberately faulty adapter emits duplicate or conflicting names.
- Legacy authentication documentation/behavior and context-bound transcript vectors.
- A single opaque public error for malformed inbound cryptographic envelopes regardless of whether unwrap, padding, decryption, or signature verification failed.
- Immutable-client sharing and replacement-client key rotation.
- Public-standard interoperability checks that contain no private protocol mapping.
- Formatting, Clippy, documentation, MSRV, platform, dependency, license, package-content, and open-source-boundary checks.

### 9.2 Private compatibility tests

Maintained outside the open-source repository:

- configure the real header schema;
- compare every emitted header name, value source, casing, and body placement with deployed fixtures;
- open deployed-compatible responses;
- verify bidirectional compatibility with the existing remote or approved reference environment; and
- confirm that rotating to a replacement client does not change the wire contract.

## 10. Migration

This is an intentional breaking Rust API refactor. The remote wire contract remains unchanged when the private schema is supplied.

Migration steps for an application are:

1. Move proprietary header mappings into a separate private repository, private configuration system, or private adapter crate outside the public checkout.
2. Replace static operation configuration with per-request `operation`.
3. Construct `SecureClient` with immutable client config, role-specific keys, explicit authentication mode, and adapter.
4. Move request metadata and custom headers into `RequestContext` or the fluent request builder.
5. Copy `RequestParts` into the application's existing HTTP client.
6. Replace the active client instance when rotating keys or certificates.

No compatibility aliases for the old public types are required because those types encode the private protocol boundary the refactor is intended to remove.

## 11. Acceptance criteria

1. No open-source export, documentation, example, test, fixture, workflow, package file, or archive contains proprietary protocol names, organization identifiers, internal paths, inherited internal key material, or private release-policy data.
2. The public API uses only organization-neutral semantic names.
3. One immutable client can issue requests for multiple operation codes.
4. Custom headers are supported but cannot replace any adapter-emitted protocol header under any casing, including when the adapter implementation is faulty.
5. A validated private header schema reproduces the existing wire protocol without remote changes.
6. Key rotation occurs through a replacement client and cannot mutate an in-flight request.
7. `open_response` never returns plaintext before protocol-consistency checks and signature verification with the configured remote verification key succeed; direct `open` trusts the caller's envelope source but still verifies it with that configured key before returning plaintext.
8. Public inbound cryptographic failures expose only the opaque `InvalidEnvelope` category.
9. Legacy plaintext-only authentication is documented as requiring authenticated TLS; context-bound profiles authenticate a deterministic, domain-separated transcript.
10. Directional key roles and local/remote signer IDs are independently configurable, with explicit shared-role convenience only.
11. Both generic and privately injected release-boundary checks pass against the complete export and package archive.
12. The private compatibility suite passes before any internal deployment.
13. Publication occurs only from a reviewed clean history/export after company security and legal approval.
