#![allow(dead_code)] // Shared integration-test helpers are compiled separately by each test target.

use std::sync::Arc;

use gmcrypto_core::sm2::Sm2PrivateKey;
use gmcrypto_core::{pkcs8, spki};
use gmcrypto_envelope_lite::{
    AuthenticationMode, CipherLocation, ClientConfig, HeaderProtocolAdapter, HeaderSchema,
    KeyMaterial, PrivateKey, PublicKey, RequestParts, ResponseParts, SecureClient,
};

pub const TEST_PASSWORD: &[u8] = b"public-test-password";

pub struct TestKeyPair {
    pub encrypted_private_der: Vec<u8>,
    pub public_der: Vec<u8>,
}

pub fn test_key_pair(discriminator: u8) -> TestKeyPair {
    assert_ne!(discriminator, 0, "zero is not a valid SM2 private scalar");

    let mut scalar = [0_u8; 32];
    scalar[31] = discriminator;
    let private = Sm2PrivateKey::from_bytes_be(&scalar).expect("valid test-only SM2 scalar");

    // Deterministic salt/IV values and a single PBKDF2 iteration keep tests fast and
    // reproducible. They are intentionally unsafe for production key encryption.
    let salt = [discriminator; 16];
    let iv = [discriminator.wrapping_add(1); 16];
    let encrypted_private_der = pkcs8::encrypt(&private, TEST_PASSWORD, &salt, 1, &iv)
        .expect("encrypt test-only private key");
    let public_der = spki::encode(&private.public_key());

    TestKeyPair {
        encrypted_private_der,
        public_der,
    }
}

pub fn neutral_header_schema() -> HeaderSchema {
    HeaderSchema::builder()
        .static_request_header("Content-Type", "application/demo+octets")
        .local_identity_header("X-Demo-Local-Identity")
        .operation_header("X-Demo-Operation")
        .request_id_header("X-Demo-Request-Id")
        .request_time_header("X-Demo-Request-Time")
        .api_version_header("X-Demo-Api-Version")
        .local_certificate_header("X-Demo-Local-Certificate")
        .remote_signing_certificate_header("X-Demo-Remote-Signing-Certificate")
        .remote_encryption_certificate_header("X-Demo-Remote-Encryption-Certificate")
        .request_signature_header("X-Demo-Request-Signature")
        .request_wrapped_key_header("X-Demo-Request-Wrapped-Key")
        .request_cipher(CipherLocation::Body)
        .response_signature_header("X-Demo-Response-Signature")
        .response_wrapped_key_header("X-Demo-Response-Wrapped-Key")
        .response_remote_signing_certificate_header("X-Demo-Response-Remote-Signing-Certificate")
        .response_cipher(CipherLocation::Body)
        .legacy_authentication()
        .build()
        .expect("complete neutral test schema")
}

pub fn client_parts_with_mode(
    seed: u8,
    authentication_mode: AuthenticationMode,
) -> (ClientConfig, KeyMaterial, HeaderSchema) {
    let pair = runtime_key_pair(seed.max(1));
    let local_signer_id = format!("signer-{seed}").into_bytes();
    let certificate_id = format!("certificate-{seed}");
    let config = ClientConfig::builder()
        .local_identity_id(format!("identity-{seed}"))
        .api_version(format!("version-{seed}"))
        .local_certificate_id(certificate_id.clone())
        .expected_remote_signing_certificate_id(certificate_id)
        .remote_encryption_certificate_id(format!("encryption-certificate-{seed}"))
        .local_signer_id(local_signer_id.clone())
        .expected_remote_signer_id(local_signer_id)
        .authentication_mode(authentication_mode)
        .iv(*b"0123456789abcdef")
        .build()
        .expect("valid neutral client configuration");
    let keys = KeyMaterial::new(
        PrivateKey::from_encrypted_der(&pair.encrypted_private_der, TEST_PASSWORD)
            .expect("runtime local signing key"),
        PrivateKey::from_encrypted_der(&pair.encrypted_private_der, TEST_PASSWORD)
            .expect("runtime local decryption key"),
        PublicKey::from_der(&pair.public_der).expect("runtime remote verification key"),
        PublicKey::from_der(&pair.public_der).expect("runtime remote encryption key"),
    );

    (config, keys, neutral_header_schema())
}

pub fn legacy_client_parts() -> (ClientConfig, KeyMaterial, HeaderSchema) {
    client_parts_with_mode(1, AuthenticationMode::LegacyPlaintext)
}

pub fn secure_client_with_seed(seed: u8) -> SecureClient {
    let (config, keys, schema) = client_parts_with_mode(seed, AuthenticationMode::LegacyPlaintext);
    SecureClient::new(config, keys, Arc::new(HeaderProtocolAdapter::new(schema)))
}

pub fn response_from_request(request: &RequestParts, certificate: &str) -> ResponseParts {
    ResponseParts::new(
        [
            (
                "X-Demo-Response-Signature",
                request
                    .header("X-Demo-Request-Signature")
                    .expect("request signature"),
            ),
            (
                "X-Demo-Response-Wrapped-Key",
                request
                    .header("X-Demo-Request-Wrapped-Key")
                    .expect("request wrapped key"),
            ),
            ("X-Demo-Response-Remote-Signing-Certificate", certificate),
        ],
        request.body(),
    )
}

fn runtime_key_pair(discriminator: u8) -> TestKeyPair {
    let private = loop {
        let mut scalar = [0_u8; 32];
        getrandom::fill(&mut scalar).expect("runtime test-key randomness");
        if let Some(private) = Option::<Sm2PrivateKey>::from(Sm2PrivateKey::from_bytes_be(&scalar))
        {
            break private;
        }
    };
    let salt = [discriminator; 16];
    let iv = [discriminator.wrapping_add(1); 16];
    let encrypted_private_der = pkcs8::encrypt(&private, TEST_PASSWORD, &salt, 1, &iv)
        .expect("encrypt runtime test-only private key");
    let public_der = spki::encode(&private.public_key());

    TestKeyPair {
        encrypted_private_der,
        public_der,
    }
}
