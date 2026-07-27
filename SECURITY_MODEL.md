# Security Model

**Model version:** 1

This document defines the security claims and non-claims for `gmcrypto-envelope-lite` 0.1.x. It is not an independent audit, certification, warranty, or proof of cryptographic security.

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

### Inbound envelopes

Plaintext is returned only after encoded-size checks, strict Base64 decoding, session-key unwrapping with the local decryption key, block decryption and padding validation, decoded-size validation, authentication-input construction, and signature verification with the configured remote verification key and expected signer ID.

Malformed Base64, key-wrap, unwrapped-key length, padding, ciphertext, and signature failures after strict decoding are reported as `Error::InvalidEnvelope`. This public error unification does not claim identical timing.

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
- It does not provide an AEAD envelope profile. The fixed-IV SM4-CBC construction exists only for legacy wire compatibility and can reveal plaintext-prefix equality under key reuse.
- It does not claim universal constant-time behavior or resistance to timing, cache, power, electromagnetic, fault-injection, or other side channels.
- Public error unification does not guarantee identical failure timing.
- It does not guarantee zeroization of allocations, padding, copies, or intermediate values owned by cryptographic, serialization, allocator, operating-system, or other third-party code.
- It does not protect a compromised process, exposed key password, malicious trusted adapter implementation, incorrect private protocol mapping, or application that releases unverified data through another path.
- Passing unit tests, fuzzing, Clippy, dependency policy, or release-boundary checks is engineering evidence, not proof that the cryptographic construction is secure.

## Change control

Any change to this claim set, cryptographic backend, authentication transcript, envelope order, key-role semantics, public failure categories, or supported input boundary requires review of the engineering evidence map and a new release-candidate artifact identity.
