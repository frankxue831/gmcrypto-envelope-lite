use crate::{AuthenticationMode, Error, Result};

/// Default maximum accepted plaintext size: 16 MiB.
pub const DEFAULT_MAX_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SIGNER_ID_BYTES: usize = u16::MAX as usize / 8;

/// Stable, non-secret identifiers exposed to protocol adapters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIdentity {
    local_identity_id: String,
    api_version: String,
    local_certificate_id: String,
    expected_remote_signing_certificate_id: String,
    remote_encryption_certificate_id: String,
}

impl ClientIdentity {
    /// Creates a validated identity from values that may be placed in transport headers.
    pub fn new(
        local_identity_id: impl Into<String>,
        api_version: impl Into<String>,
        local_certificate_id: impl Into<String>,
        expected_remote_signing_certificate_id: impl Into<String>,
        remote_encryption_certificate_id: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            local_identity_id: validate_header_value(
                local_identity_id.into(),
                "local_identity_id",
            )?,
            api_version: validate_header_value(api_version.into(), "api_version")?,
            local_certificate_id: validate_header_value(
                local_certificate_id.into(),
                "local_certificate_id",
            )?,
            expected_remote_signing_certificate_id: validate_header_value(
                expected_remote_signing_certificate_id.into(),
                "expected_remote_signing_certificate_id",
            )?,
            remote_encryption_certificate_id: validate_header_value(
                remote_encryption_certificate_id.into(),
                "remote_encryption_certificate_id",
            )?,
        })
    }

    /// Returns the local application or account identity.
    #[must_use]
    pub fn local_identity_id(&self) -> &str {
        &self.local_identity_id
    }

    /// Returns the protocol API version.
    #[must_use]
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// Returns the identifier advertised for the local signing certificate.
    #[must_use]
    pub fn local_certificate_id(&self) -> &str {
        &self.local_certificate_id
    }

    /// Returns the required remote signing-certificate identifier.
    #[must_use]
    pub fn expected_remote_signing_certificate_id(&self) -> &str {
        &self.expected_remote_signing_certificate_id
    }

    /// Returns the remote encryption-certificate identifier.
    #[must_use]
    pub fn remote_encryption_certificate_id(&self) -> &str {
        &self.remote_encryption_certificate_id
    }
}

/// Immutable client-lifetime configuration for secure-envelope operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfig {
    identity: ClientIdentity,
    local_signer_id: Vec<u8>,
    expected_remote_signer_id: Vec<u8>,
    authentication_mode: AuthenticationMode,
    iv: [u8; 16],
    max_plaintext_bytes: usize,
}

impl ClientConfig {
    /// Starts a builder with no protocol-specific defaults.
    #[must_use]
    pub fn builder() -> ClientConfigBuilder {
        ClientConfigBuilder::default()
    }

    /// Returns the validated identifiers exposed to protocol adapters.
    #[must_use]
    pub fn identity(&self) -> &ClientIdentity {
        &self.identity
    }

    /// Returns the SM2 signer ID used for local signatures.
    #[must_use]
    pub fn local_signer_id(&self) -> &[u8] {
        &self.local_signer_id
    }

    /// Returns the SM2 signer ID expected for remote signatures.
    #[must_use]
    pub fn expected_remote_signer_id(&self) -> &[u8] {
        &self.expected_remote_signer_id
    }

    /// Returns the configured authentication mode.
    #[must_use]
    pub fn authentication_mode(&self) -> &AuthenticationMode {
        &self.authentication_mode
    }

    /// Returns the explicit protocol IV.
    #[must_use]
    pub fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    /// Returns the maximum accepted plaintext size in bytes.
    #[must_use]
    pub fn max_plaintext_bytes(&self) -> usize {
        self.max_plaintext_bytes
    }
}

/// Consuming builder for [`ClientConfig`].
#[derive(Clone, Debug, Default)]
pub struct ClientConfigBuilder {
    local_identity_id: Option<String>,
    api_version: Option<String>,
    local_certificate_id: Option<String>,
    expected_remote_signing_certificate_id: Option<String>,
    remote_encryption_certificate_id: Option<String>,
    local_signer_id: Option<Vec<u8>>,
    expected_remote_signer_id: Option<Vec<u8>>,
    authentication_mode: Option<AuthenticationMode>,
    iv: Option<[u8; 16]>,
    max_plaintext_bytes: Option<usize>,
}

impl ClientConfigBuilder {
    /// Sets the local application or account identity.
    #[must_use]
    pub fn local_identity_id(mut self, value: impl Into<String>) -> Self {
        self.local_identity_id = Some(value.into());
        self
    }

    /// Sets the protocol API version.
    #[must_use]
    pub fn api_version(mut self, value: impl Into<String>) -> Self {
        self.api_version = Some(value.into());
        self
    }

    /// Sets the identifier advertised for the local signing certificate.
    #[must_use]
    pub fn local_certificate_id(mut self, value: impl Into<String>) -> Self {
        self.local_certificate_id = Some(value.into());
        self
    }

    /// Sets the signing-certificate identifier required from the remote peer.
    #[must_use]
    pub fn expected_remote_signing_certificate_id(mut self, value: impl Into<String>) -> Self {
        self.expected_remote_signing_certificate_id = Some(value.into());
        self
    }

    /// Sets the remote encryption-certificate identifier.
    #[must_use]
    pub fn remote_encryption_certificate_id(mut self, value: impl Into<String>) -> Self {
        self.remote_encryption_certificate_id = Some(value.into());
        self
    }

    /// Sets the SM2 signer ID used for local signatures.
    #[must_use]
    pub fn local_signer_id(mut self, value: impl Into<Vec<u8>>) -> Self {
        self.local_signer_id = Some(value.into());
        self
    }

    /// Sets the SM2 signer ID required for remote signatures.
    #[must_use]
    pub fn expected_remote_signer_id(mut self, value: impl Into<Vec<u8>>) -> Self {
        self.expected_remote_signer_id = Some(value.into());
        self
    }

    /// Sets the explicit authentication mode.
    #[must_use]
    pub fn authentication_mode(mut self, value: AuthenticationMode) -> Self {
        self.authentication_mode = Some(value);
        self
    }

    /// Sets the explicit 16-byte protocol IV.
    #[must_use]
    pub fn iv(mut self, value: [u8; 16]) -> Self {
        self.iv = Some(value);
        self
    }

    /// Overrides the default maximum plaintext size.
    #[must_use]
    pub fn max_plaintext_bytes(mut self, value: usize) -> Self {
        self.max_plaintext_bytes = Some(value);
        self
    }

    /// Validates all required fields and creates an immutable configuration.
    pub fn build(self) -> Result<ClientConfig> {
        let identity = ClientIdentity {
            local_identity_id: required_header_value(self.local_identity_id, "local_identity_id")?,
            api_version: required_header_value(self.api_version, "api_version")?,
            local_certificate_id: required_header_value(
                self.local_certificate_id,
                "local_certificate_id",
            )?,
            expected_remote_signing_certificate_id: required_header_value(
                self.expected_remote_signing_certificate_id,
                "expected_remote_signing_certificate_id",
            )?,
            remote_encryption_certificate_id: required_header_value(
                self.remote_encryption_certificate_id,
                "remote_encryption_certificate_id",
            )?,
        };
        let local_signer_id = required_signer_id(self.local_signer_id, "local_signer_id")?;
        let expected_remote_signer_id =
            required_signer_id(self.expected_remote_signer_id, "expected_remote_signer_id")?;
        let iv = self.iv.ok_or(Error::Configuration { field: "iv" })?;
        let authentication_mode = self.authentication_mode.ok_or(Error::Configuration {
            field: "authentication_mode",
        })?;
        authentication_mode.validate()?;
        let max_plaintext_bytes = self
            .max_plaintext_bytes
            .unwrap_or(DEFAULT_MAX_PLAINTEXT_BYTES);
        if max_plaintext_bytes == 0 {
            return Err(Error::Configuration {
                field: "max_plaintext_bytes",
            });
        }

        Ok(ClientConfig {
            identity,
            local_signer_id,
            expected_remote_signer_id,
            authentication_mode,
            iv,
            max_plaintext_bytes,
        })
    }
}

fn required_header_value(value: Option<String>, field: &'static str) -> Result<String> {
    validate_header_value(value.ok_or(Error::Configuration { field })?, field)
}

fn validate_header_value(value: String, field: &'static str) -> Result<String> {
    if value.trim().is_empty() || value.contains(['\r', '\n']) {
        return Err(Error::Configuration { field });
    }
    Ok(value)
}

fn required_signer_id(value: Option<Vec<u8>>, field: &'static str) -> Result<Vec<u8>> {
    let value = value.ok_or(Error::Configuration { field })?;
    if value.is_empty() || value.len() > MAX_SIGNER_ID_BYTES {
        return Err(Error::Configuration { field });
    }
    Ok(value)
}
