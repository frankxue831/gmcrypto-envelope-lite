#![cfg(feature = "aead")]

use std::sync::Arc;

use gmcrypto_core::sm2::Sm2PrivateKey;
use gmcrypto_core::{pkcs8, spki};
use gmcrypto_envelope_lite::{
    AeadAlgorithm, AuthenticationContext, AuthenticationMode, CipherLocation, ClientConfig,
    ClientConfigBuilder, EnvelopeMode, Error, HeaderProtocolAdapter, HeaderSchema, KeyMaterial,
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
        .static_request_header("Content-Type", "application/integration+octets")
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
    aead_client_with(AeadAlgorithm::Sm4Gcm)
}

fn ccm_client() -> SecureClient {
    aead_client_with(AeadAlgorithm::Sm4Ccm)
}

fn aead_client_with(algorithm: AeadAlgorithm) -> SecureClient {
    let config = base_builder()
        .envelope_mode(EnvelopeMode::Aead(algorithm))
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
    let ccm = ccm_client();
    let cbc = cbc_client();
    let context = AuthenticationContext::legacy();

    let aead_envelope = aead.seal(b"aead payload", &context).expect("GCM seal");
    assert!(matches!(
        cbc.open(&aead_envelope, &context),
        Err(Error::InvalidEnvelope)
    ));
    assert!(matches!(
        ccm.open(&aead_envelope, &context),
        Err(Error::InvalidEnvelope)
    ));

    let cbc_envelope = cbc.seal(b"cbc payload", &context).expect("CBC seal");
    assert!(matches!(
        aead.open(&cbc_envelope, &context),
        Err(Error::InvalidEnvelope)
    ));
    assert!(matches!(
        ccm.open(&cbc_envelope, &context),
        Err(Error::InvalidEnvelope)
    ));

    let ccm_envelope = ccm.seal(b"ccm payload", &context).expect("CCM seal");
    assert!(matches!(
        aead.open(&ccm_envelope, &context),
        Err(Error::InvalidEnvelope)
    ));
    assert!(matches!(
        cbc.open(&ccm_envelope, &context),
        Err(Error::InvalidEnvelope)
    ));
}

#[test]
fn secure_client_round_trips_ccm_envelopes_through_a_header_adapter() {
    let client = ccm_client();
    let plaintext = b"adapter-mapped ccm payload";
    let envelope = client
        .seal(plaintext, &AuthenticationContext::legacy())
        .expect("seal");
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
