#![forbid(unsafe_code)]

//! The SDK's [`Error`] is documented as redacted, yet nothing formatted the
//! error type itself with a sentinel to prove it. `tests/redacted_debug.rs`
//! covers the value types (envelopes, headers, contexts); this file covers the
//! error path, which is the text most likely to be logged across a trust
//! boundary. Each case drives a real failure with a caller secret planted in
//! the secret-bearing input — an envelope field, a header value, key bytes, or
//! oversized plaintext — and asserts the secret survives in neither `Display`
//! nor `Debug`. `Error` is `#[non_exhaustive]`, so these variants can only be
//! obtained through the public API, never constructed here.

use std::sync::Arc;

use gmcrypto_envelope_lite::{
    AuthenticationContext, AuthenticationMode, ClientConfig, Error, HeaderProtocolAdapter,
    KeyMaterial, PrivateKey, PublicKey, RequestParts, SecureClient, SecureEnvelope,
};

#[path = "support/mod.rs"]
mod support;

/// A caller secret that must never surface in a formatted error: it stands in
/// for plaintext, key bytes, a signature, or a header value. The `-` bytes also
/// make it invalid Base64, so it drives the envelope decode path to rejection.
const SECRET: &str = "sentinel-caller-secret-2f7a-do-not-log";

/// Asserts an error keeps the caller secret out of both formatted forms.
fn assert_redacted(context: &str, error: &Error) {
    let display = format!("{error}");
    let debug = format!("{error:?}");
    assert!(
        !display.contains(SECRET),
        "{context}: Display surfaced the caller secret: {display}"
    );
    assert!(
        !debug.contains(SECRET),
        "{context}: Debug surfaced the caller secret: {debug}"
    );
}

#[test]
fn invalid_envelope_error_redacts_the_envelope_fields() {
    let client = support::secure_client_with_seed(1);
    let envelope = SecureEnvelope {
        cipher: SECRET.to_owned(),
        wrapped_session_key: SECRET.to_owned(),
        signature: SECRET.to_owned(),
    };

    let error = client
        .open(&envelope, &AuthenticationContext::legacy())
        .expect_err("a sentinel-bearing envelope must not open");

    assert!(matches!(error, Error::InvalidEnvelope));
    assert_eq!(format!("{error}"), "invalid secure envelope");
    assert_redacted("open", &error);
}

#[test]
fn invalid_header_error_redacts_the_offending_value() {
    // A CRLF in the value is rejected as header injection; the sentinel rides
    // along in the value and must not surface in the error.
    let injected = format!("{SECRET}\r\nX-Injected: 1");
    let error = RequestParts::new([("X-Demo-Trace", injected.as_str())], "body")
        .expect_err("a CRLF-bearing header value must be rejected");

    assert!(matches!(error, Error::InvalidHeader));
    assert_redacted("RequestParts::new invalid value", &error);
}

#[test]
fn header_conflict_error_redacts_the_conflicting_values() {
    let error = RequestParts::new([("X-Demo-Trace", SECRET), ("x-demo-trace", SECRET)], "body")
        .expect_err("case-insensitive duplicate header names must conflict");

    assert!(matches!(error, Error::HeaderConflict));
    assert_redacted("RequestParts::new duplicate", &error);
}

#[test]
fn key_material_error_redacts_the_rejected_key_bytes() {
    let error = PublicKey::from_der(SECRET.as_bytes())
        .expect_err("sentinel bytes are not a valid SPKI public key");

    assert!(matches!(error, Error::KeyMaterial { .. }));
    assert_redacted("PublicKey::from_der", &error);
}

#[test]
fn message_too_large_error_redacts_the_oversized_plaintext() {
    // A tiny plaintext limit so a sentinel-bearing payload overflows it. The
    // error names the public limit but never the plaintext.
    let pair = support::test_key_pair(9);
    let config = ClientConfig::builder()
        .local_identity_id("identity")
        .api_version("v1")
        .local_certificate_id("certificate")
        .expected_remote_signing_certificate_id("certificate")
        .remote_encryption_certificate_id("encryption-certificate")
        .local_signer_id(b"signer")
        .expected_remote_signer_id(b"signer")
        .authentication_mode(AuthenticationMode::LegacyPlaintext)
        .iv(*b"0123456789abcdef")
        .max_plaintext_bytes(8)
        .build()
        .expect("small-limit configuration");
    let keys = KeyMaterial::new(
        PrivateKey::from_encrypted_der(&pair.encrypted_private_der, support::TEST_PASSWORD)
            .expect("local signing key"),
        PrivateKey::from_encrypted_der(&pair.encrypted_private_der, support::TEST_PASSWORD)
            .expect("local decryption key"),
        PublicKey::from_der(&pair.public_der).expect("remote verification key"),
        PublicKey::from_der(&pair.public_der).expect("remote encryption key"),
    );
    let client = SecureClient::new(
        config,
        keys,
        Arc::new(HeaderProtocolAdapter::new(support::neutral_header_schema())),
    );

    let oversized = format!("{SECRET}{SECRET}");
    let error = client
        .seal(oversized.as_bytes(), &AuthenticationContext::legacy())
        .expect_err("plaintext over the configured limit must be rejected");

    assert!(matches!(error, Error::MessageTooLarge { limit: 8 }));
    assert!(
        format!("{error}").contains("8-byte"),
        "the public limit is intended to appear"
    );
    assert_redacted("seal oversized", &error);
}
