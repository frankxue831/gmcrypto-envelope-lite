# Security Model

**Model version:** 2

This document defines the security claims and non-claims for `gmcrypto-envelope-lite` 0.3.x. It is not an independent audit, certification, warranty, or proof of cryptographic security.

## Protected assets and attacker-controlled inputs

The SDK handles local signing and decryption private keys, remote verification and encryption public keys, per-envelope SM4 session keys, application plaintext, authentication context, encoded envelope fields, and protocol metadata.

Inbound header names, header values, bodies, Base64 text, wrapped keys, signatures, ciphertext, request metadata supplied by callers, key files, key passwords, and custom `ProtocolAdapter` results must be treated as untrusted until the documented validation or verification step succeeds.

## Trust boundaries

- The embedding process is trusted to protect key passwords, loaded keys, verified plaintext, and the selected client instance.
- `SecureClient` owns immutable configuration and four directional key roles. One instance represents one local and one expected remote identity.
- A `ProtocolAdapter` may map public identity metadata, semantic request context, and opaque envelope values. It does not receive keys, session keys, plaintext, or caller extension headers.
- The embedding application owns HTTP method and URI selection, endpoint authentication, TLS validation, timeouts, retry safety, replay defense, and request/response correlation.
- The configured remote verification key is the cryptographic peer identity. A mapped certificate identifier is a checked protocol claim, not a replacement for key verification.
- Private exact-wire mappings, captures, identities, denylist data, and compatibility evidence remain outside the public repository.

## Security claims

### Directional key use

`KeyMaterial::new` assigns independent local signing, local decryption, remote verification, and remote encryption roles. Shared-role constructors reuse keys only when the caller selects an explicitly named `shared` API.

### Outbound envelopes

Every seal operation generates a fresh 16-byte session key from the operating-system random source, encrypts plaintext with the configured compatibility SM4-CBC construction, wraps the session key for the configured remote encryption key, and signs the authentication input with the local signing key and signer ID.

Under the opt-in `aead` feature and a configured AEAD envelope mode, sealing instead encrypts with SM4-GCM under a fresh random 12-byte nonce. Its length-prefixed AAD always binds a fixed domain label and the cipher frame header; under `ContextBound` it also binds the configured domain separator and protocol context, while `LegacyPlaintext` encodes both as empty fields. Session-key freshness — not the nonce — is the primary defense against `(key, nonce)` reuse; the random nonce is defense in depth. The SM2 signature over the authentication input remains mandatory, because an AEAD tag under a session key encrypted to a public key proves nothing about the sender.

### Inbound envelopes

Plaintext is returned only after encoded-size checks, strict Base64 decoding, session-key unwrapping with the local decryption key, block decryption and padding validation, decoded-size validation, authentication-input construction, and signature verification with the configured remote verification key and expected signer ID.

Under an AEAD envelope mode, plaintext is returned only after encoded-size checks, strict Base64 decoding, frame version and algorithm-identifier pinning against the configuration, ciphertext-length validation, session-key unwrapping, AAD reconstruction, GCM tag verification (which precedes any plaintext materialization), and signature verification. The envelope mode is never inferred from inbound bytes: an AEAD client rejects CBC envelopes outright and a CBC client rejects AEAD frames.

Malformed Base64, key-wrap, unwrapped-key length, padding, ciphertext, and signature failures after strict decoding are reported as `Error::InvalidEnvelope`. This public error unification does not claim identical timing.

In the compatibility SM4-CBC mode, every envelope whose session key unwraps runs exactly one SM2 signature verification regardless of whether padding, the decoded-size bound, or authentication-input construction failed; on decrypt failure the transcript is rebuilt from the raw ciphertext so the verification still runs, and its result can never on its own accept an envelope. This equalizes the dominant asymmetric operation across the CBC failure paths as defense in depth for the required authenticated-TLS transport. It is request-level equalization, not a constant-time claim, and it does not cover the fast paths reached before key unwrap: the encoded-size and Base64 checks, and key-unwrap failure itself.

### Authentication modes

`AuthenticationMode::LegacyPlaintext` signs only the exact plaintext and exists solely for deployed compatibility. It does not authenticate envelope metadata or transport headers.

`AuthenticationMode::ContextBound` signs a versioned, length-delimited transcript containing the configured domain, adapter-provided canonical context bytes, and exact plaintext. It expands signature coverage but does not replace CBC, create AEAD, or supply replay protection.

### Input and output validation

Configured message limits bound encoded and decoded envelope inputs. Typed headers reject invalid syntax, control-byte injection, and case-insensitive collisions. Caller headers are additive and cannot override actual adapter output.

### SDK-owned memory and diagnostics

SDK-owned session-key buffers, unverified plaintext buffers, and temporary JSON plaintext buffers use zeroizing guards. SDK-owned errors and `Debug` implementations are designed not to echo passwords, private keys, session keys, plaintext, complete encrypted bodies, header values, or dependency-internal cryptographic errors.

## Required caller controls

- Use authenticated TLS and validate the intended endpoint.
- Implement application-level replay defense and request/response correlation.
- Treat retries as unsafe unless the application protocol proves them idempotent.
- Keep private key passwords and verified plaintext out of logs and diagnostics.
- Use role-specific keys unless the protocol explicitly defines shared roles.
- Construct and validate a complete replacement client before rotating identity or key material.
- Run the private exact-wire compatibility suite before deployment.
- Complete an independent cryptographic and integration assessment for the deployment threat model.

## Explicit non-claims

- The library is not independently audited and provides no formal verification, FIPS validation, GM certification, or security warranty.
- Without the opt-in `aead` feature it provides no AEAD envelope profile; the fixed-IV SM4-CBC construction exists only for legacy wire compatibility and can reveal plaintext-prefix equality under key reuse. The `aead` feature's SM4-GCM mode does not add replay protection or freshness, and it compiles `gmcrypto-simd` and `cpufeatures`, which contain unsafe code reviewed only as recorded in the cryptographic dependency inventory.
- It does not claim universal constant-time behavior or resistance to timing, cache, power, electromagnetic, fault-injection, or other side channels.
- Public error unification does not guarantee identical failure timing.
- It does not guarantee zeroization of allocations, padding, copies, or intermediate values owned by cryptographic, serialization, allocator, operating-system, or other third-party code.
- It does not protect a compromised process, exposed key password, malicious trusted adapter implementation, incorrect private protocol mapping, or application that releases unverified data through another path.
- Passing unit tests, fuzzing, Clippy, dependency policy, or release-boundary checks is engineering evidence, not proof that the cryptographic construction is secure.

## Change control

Any change to this claim set, cryptographic backend, authentication transcript, envelope order, key-role semantics, public failure categories, or supported input boundary requires review of the engineering evidence map and a new release-candidate artifact identity.
