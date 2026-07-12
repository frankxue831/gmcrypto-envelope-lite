use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::message::{RequestContext, RequestParts, ResponseParts, SecureEnvelope};
use crate::request::serialize_json;
use crate::{
    AuthenticationContext, ClientConfig, Error, KeyMaterial, ProtocolAdapter, RequestBuilder,
    Result, envelope_crypto,
};

/// Immutable orchestration facade for transport-neutral secure envelopes.
pub struct SecureClient {
    config: ClientConfig,
    keys: KeyMaterial,
    adapter: Arc<dyn ProtocolAdapter>,
}

impl SecureClient {
    /// Creates a client from validated configuration, owned keys, and a protocol adapter.
    #[must_use]
    pub fn new(config: ClientConfig, keys: KeyMaterial, adapter: Arc<dyn ProtocolAdapter>) -> Self {
        Self {
            config,
            keys,
            adapter,
        }
    }

    /// Returns the immutable client-lifetime configuration.
    #[must_use]
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Starts a fluent builder for one operation using this immutable client.
    #[must_use]
    pub fn request(&self, operation: impl Into<String>) -> RequestBuilder<'_> {
        RequestBuilder::new(self, operation.into())
    }

    /// Encrypts and signs plaintext using an explicit authentication context.
    pub fn seal(
        &self,
        plaintext: &[u8],
        context: &AuthenticationContext,
    ) -> Result<SecureEnvelope> {
        envelope_crypto::seal(&self.config, &self.keys, plaintext, context)
    }

    /// Verifies and decrypts an envelope using an explicit authentication context.
    pub fn open(
        &self,
        envelope: &SecureEnvelope,
        context: &AuthenticationContext,
    ) -> Result<Vec<u8>> {
        envelope_crypto::open(&self.config, &self.keys, envelope, context)
    }

    /// Builds a complete outbound request without performing transport I/O.
    pub fn build_request(
        &self,
        plaintext: &[u8],
        request_context: RequestContext,
    ) -> Result<RequestParts> {
        let (protocol_context, additional_headers) = request_context.into_parts();
        let authentication_context = self
            .adapter
            .request_authentication_context(self.config.identity(), &protocol_context)
            .map_err(|_| Error::ProtocolAdapter)?;
        let envelope = self.seal(plaintext, &authentication_context)?;
        let mut request = self
            .adapter
            .build_request(self.config.identity(), &protocol_context, &envelope)
            .map_err(|_| Error::ProtocolAdapter)?;
        request.validate()?;
        request.append_checked(&additional_headers)?;
        Ok(request)
    }

    /// Serializes a value once and builds a complete outbound JSON request.
    pub fn build_json_request<T: Serialize>(
        &self,
        value: &T,
        request_context: RequestContext,
    ) -> Result<RequestParts> {
        let plaintext = serialize_json(value)?;
        self.build_request(&plaintext, request_context)
    }

    /// Parses, validates, verifies, and decrypts inbound response parts.
    pub fn open_response(&self, response: ResponseParts) -> Result<Vec<u8>> {
        let parsed = self
            .adapter
            .parse_response(response)
            .map_err(|_| Error::ProtocolAdapter)?;
        if parsed.remote_signing_certificate_id()
            != self
                .config
                .identity()
                .expected_remote_signing_certificate_id()
        {
            return Err(Error::ProtocolAdapter);
        }
        self.open(parsed.envelope(), parsed.authentication_context())
    }

    /// Opens and verifies a response before deserializing its plaintext as JSON.
    pub fn open_json_response<T: DeserializeOwned>(&self, response: ResponseParts) -> Result<T> {
        let plaintext = Zeroizing::new(self.open_response(response)?);
        serde_json::from_slice(&plaintext).map_err(|_| Error::Serialization)
    }
}

#[cfg(test)]
mod tests {
    use gmcrypto_core::sm2::Sm2PrivateKey;
    use gmcrypto_core::{pkcs8, spki};

    use super::*;
    use crate::message::{ParsedResponse, ProtocolRequestContext, RequestMetadata};
    use crate::{AdapterError, AdapterErrorKind, AdapterResult, ClientIdentity};

    struct FaultyAdapter;

    impl ProtocolAdapter for FaultyAdapter {
        fn request_authentication_context(
            &self,
            _identity: &ClientIdentity,
            _context: &ProtocolRequestContext,
        ) -> AdapterResult<AuthenticationContext> {
            Ok(AuthenticationContext::legacy())
        }

        fn build_request(
            &self,
            _identity: &ClientIdentity,
            _context: &ProtocolRequestContext,
            _envelope: &SecureEnvelope,
        ) -> AdapterResult<RequestParts> {
            Ok(RequestParts::malformed_for_test(
                [("X-Faulty", "first"), ("x-faulty", "second")],
                "body",
            ))
        }

        fn parse_response(&self, _response: ResponseParts) -> AdapterResult<ParsedResponse> {
            Err(AdapterError::new(AdapterErrorKind::InvalidMapping))
        }
    }

    #[test]
    fn build_request_rejects_duplicate_headers_returned_by_a_faulty_adapter() {
        let config = ClientConfig::builder()
            .local_identity_id("identity")
            .api_version("version")
            .local_certificate_id("certificate")
            .expected_remote_signing_certificate_id("certificate")
            .remote_encryption_certificate_id("certificate")
            .local_signer_id(b"signer".to_vec())
            .expected_remote_signer_id(b"signer".to_vec())
            .authentication_mode(crate::AuthenticationMode::LegacyPlaintext)
            .iv(*b"0123456789abcdef")
            .build()
            .expect("configuration");
        let keys = test_key_material();
        let client = SecureClient::new(config, keys, Arc::new(FaultyAdapter));
        let context = RequestContext::builder("operation")
            .metadata(RequestMetadata::new("request", "time").expect("metadata"))
            .build()
            .expect("context");

        let result = client.build_request(b"plaintext", context);

        assert!(matches!(result, Err(Error::HeaderConflict)));
    }

    fn test_key_material() -> KeyMaterial {
        let mut scalar = [0_u8; 32];
        scalar[31] = 42;
        let private = Sm2PrivateKey::from_bytes_be(&scalar).expect("test private key");
        let password = b"test password";
        let encrypted = pkcs8::encrypt(&private, password, &[1_u8; 16], 1, &[2_u8; 16])
            .expect("encrypted test key");
        let public = spki::encode(&private.public_key());
        KeyMaterial::new(
            crate::PrivateKey::from_encrypted_der(&encrypted, password).expect("signing key"),
            crate::PrivateKey::from_encrypted_der(&encrypted, password).expect("decryption key"),
            crate::PublicKey::from_der(&public).expect("verification key"),
            crate::PublicKey::from_der(&public).expect("encryption key"),
        )
    }
}
