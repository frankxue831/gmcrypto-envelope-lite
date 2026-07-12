use std::env;
use std::fs;
use std::sync::Arc;

use secure_envelope_lite::{
    AuthenticationMode, CipherLocation, ClientConfig, HeaderProtocolAdapter, HeaderSchema,
    KeyMaterial, PrivateKey, PublicKey, ResponseParts, SecureClient,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct ResponseDocument {
    headers: Vec<(String, String)>,
    body: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let response_path = args.next().ok_or("missing response JSON argument")?;
    let local_signing_path = args.next().ok_or("missing local signing key argument")?;
    let local_decryption_path = args.next().ok_or("missing local decryption key argument")?;
    let remote_verification_path = args
        .next()
        .ok_or("missing remote verification key argument")?;
    let remote_encryption_path = args
        .next()
        .ok_or("missing remote encryption key argument")?;
    if args.next().is_some() {
        return Err("too many arguments".into());
    }

    let password = env::var("SECURE_ENVELOPE_KEY_PASSWORD")
        .map_err(|_| "SECURE_ENVELOPE_KEY_PASSWORD is not set or is not valid UTF-8")?;
    let keys = KeyMaterial::new(
        PrivateKey::from_encrypted_file(local_signing_path, password.as_bytes())?,
        PrivateKey::from_encrypted_file(local_decryption_path, password.as_bytes())?,
        PublicKey::from_file(remote_verification_path)?,
        PublicKey::from_file(remote_encryption_path)?,
    );
    let client = example_client(keys)?;
    let document: ResponseDocument = serde_json::from_slice(&fs::read(response_path)?)?;
    let verified = client.open_response(ResponseParts::new(document.headers, document.body))?;

    println!("verified bytes: {}", verified.len());
    Ok(())
}

fn example_client(keys: KeyMaterial) -> secure_envelope_lite::Result<SecureClient> {
    let config = ClientConfig::builder()
        .local_identity_id("demo-client")
        .api_version("example-v1")
        .local_certificate_id("example-local-signing-certificate")
        .expected_remote_signing_certificate_id("example-remote-signing-certificate")
        .remote_encryption_certificate_id("example-remote-encryption-certificate")
        .local_signer_id(b"demo-local-signer")
        .expected_remote_signer_id(b"demo-remote-signer")
        .authentication_mode(AuthenticationMode::LegacyPlaintext)
        .iv(*b"example-iv-00001")
        .build()?;
    Ok(SecureClient::new(
        config,
        keys,
        Arc::new(HeaderProtocolAdapter::new(
            example_schema().map_err(|_| secure_envelope_lite::Error::ProtocolAdapter)?,
        )),
    ))
}

fn example_schema() -> Result<HeaderSchema, secure_envelope_lite::AdapterError> {
    HeaderSchema::builder()
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
        .build()
}
