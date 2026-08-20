use std::env;
use std::fs;
use std::sync::Arc;

use gmcrypto_envelope_lite::{
    AdapterError, AdapterErrorKind, AdapterResult, AeadAlgorithm, AuthenticationContext,
    AuthenticationMode, ClientConfig, ClientIdentity, EnvelopeMode, KeyMaterial, ParsedResponse,
    PrivateKey, ProtocolAdapter, ProtocolRequestContext, PublicKey, RequestParts, ResponseParts,
    SecureClient, SecureEnvelope,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let payload_path = args.next().ok_or("missing payload file argument")?;
    let operation = args
        .next()
        .ok_or("missing operation argument")?
        .into_string()
        .map_err(|_| "operation must be valid UTF-8")?;
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
    let payload = fs::read(payload_path)?;
    let request = client
        .request(operation)
        .header("X-Envelope-Trace", "demo-trace")?
        .bytes(&payload)?;

    for (name, _) in request.headers() {
        println!("header: {}", name.as_str());
    }
    println!("body bytes: {}", request.body().len());
    Ok(())
}

/// A new integration selects the SM4-GCM envelope mode and context-bound
/// authentication. The fixed-IV SM4-CBC construction and `LegacyPlaintext`
/// exist only for compatibility with already-deployed wires.
fn example_client(keys: KeyMaterial) -> gmcrypto_envelope_lite::Result<SecureClient> {
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

/// This example implements [`ProtocolAdapter`] so callers can see custom
/// context derivation. `HeaderProtocolAdapter` can emit ContextBound
/// authentication with the crate-owned version-1 binary layout when the
/// schema calls `.context_bound_authentication()`.
struct ExampleContextAdapter;

impl ProtocolAdapter for ExampleContextAdapter {
    fn request_authentication_context(
        &self,
        _identity: &ClientIdentity,
        context: &ProtocolRequestContext,
    ) -> AdapterResult<AuthenticationContext> {
        // Bind the semantic request data the remote re-derives from the wire:
        // a verifying peer commits to the operation and request id, not just
        // the plaintext bytes.
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
                ("Content-Type", "application/example-envelope"),
                ("X-Envelope-Local-Identity", identity.local_identity_id()),
                ("X-Envelope-Api-Version", identity.api_version()),
                (
                    "X-Envelope-Local-Certificate",
                    identity.local_certificate_id(),
                ),
                ("X-Envelope-Operation", context.operation()),
                ("X-Envelope-Request-Id", context.metadata().request_id()),
                ("X-Envelope-Request-Time", context.metadata().request_time()),
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
        // The remote binds the request id it is answering into its signed
        // transcript. A verified open therefore authenticates that claim; the
        // application still correlates it with the originating request itself.
        let request_id = header("X-Envelope-Request-Id")?;
        let context =
            AuthenticationContext::context_bound(format!("request-id={request_id}").into_bytes())
                .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidField))?;
        ParsedResponse::new(envelope, certificate, context)
    }
}
