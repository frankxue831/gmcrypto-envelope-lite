use crate::{AuthenticationMode, Error, Result};

/// Default maximum accepted plaintext size: 16 MiB.
pub const DEFAULT_MAX_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum plaintext SM4-CCM accepts under this crate's pinned 12-byte nonce.
///
/// NIST SP 800-38C encodes the payload length in `q = 15 - nonce_len` bytes.
/// A 12-byte nonce therefore caps plaintext at `2^24 - 1` bytes, one byte
/// below [`DEFAULT_MAX_PLAINTEXT_BYTES`].
#[cfg(feature = "aead")]
pub const SM4_CCM_MAX_PLAINTEXT_BYTES: usize = (1 << 24) - 1;
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

/// Selects how the envelope payload is encrypted.
///
/// The mode is pinned by immutable client configuration and never
/// inferred from incoming bytes: a client seals and opens only its
/// configured mode, with no negotiation and no fallback.
#[cfg(feature = "aead")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvelopeMode {
    /// The compatibility SM4-CBC payload with the configured fixed IV.
    LegacyCbc,
    /// An authenticated-encryption payload using the selected algorithm.
    Aead(AeadAlgorithm),
}

/// Authenticated-encryption algorithms available to [`EnvelopeMode::Aead`].
#[cfg(feature = "aead")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadAlgorithm {
    /// SM4-GCM with a 12-byte random nonce and a full 16-byte tag.
    Sm4Gcm,
    /// SM4-CCM with a 12-byte random nonce and a full 16-byte tag.
    ///
    /// Frame algorithm id `0x02`. Not a negotiation field: a client
    /// accepts only the identifier its configuration pins. CCM decrypts
    /// before verifying (the primitive wipes tentative plaintext on tag
    /// failure). The pinned 12-byte nonce caps plaintext at
    /// [`SM4_CCM_MAX_PLAINTEXT_BYTES`], which is also the default limit
    /// under this algorithm; a larger explicit
    /// [`ClientConfigBuilder::max_plaintext_bytes`] is rejected by
    /// [`ClientConfigBuilder::build`]. New integrations should prefer
    /// [`AeadAlgorithm::Sm4Gcm`].
    Sm4Ccm,
}

/// Immutable client-lifetime configuration for secure-envelope operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfig {
    identity: ClientIdentity,
    local_signer_id: Vec<u8>,
    expected_remote_signer_id: Vec<u8>,
    authentication_mode: AuthenticationMode,
    iv: [u8; 16],
    #[cfg(feature = "aead")]
    envelope_mode: EnvelopeMode,
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
    /// Under an AEAD envelope mode (feature `aead`) the stored value is all zeroes and is not used
    /// by sealing or opening.
    #[must_use]
    pub fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    /// Returns the configured envelope mode.
    #[cfg(feature = "aead")]
    #[must_use]
    pub fn envelope_mode(&self) -> EnvelopeMode {
        self.envelope_mode
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
    #[cfg(feature = "aead")]
    envelope_mode: Option<EnvelopeMode>,
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
    ///
    /// # Security
    ///
    /// The fixed IV exists only for legacy wire compatibility. Reusing a session key with this
    /// fixed IV causes equal plaintext prefixes to produce equal ciphertext prefixes, revealing
    /// plaintext-prefix equality. Sealing relies on a fresh random session key for every envelope
    /// to prevent this cross-envelope leakage. CBC provides no ciphertext authentication, AEAD,
    /// or nonce-misuse resistance.
    /// Setting an IV together with an AEAD envelope mode is a configuration error.
    #[must_use]
    pub fn iv(mut self, value: [u8; 16]) -> Self {
        self.iv = Some(value);
        self
    }

    /// Sets the envelope mode; the default is the compatibility SM4-CBC mode.
    #[cfg(feature = "aead")]
    #[must_use]
    pub fn envelope_mode(mut self, value: EnvelopeMode) -> Self {
        self.envelope_mode = Some(value);
        self
    }

    /// Overrides the default maximum plaintext size.
    ///
    /// The default is `DEFAULT_MAX_PLAINTEXT_BYTES`, except under
    /// `EnvelopeMode::Aead(AeadAlgorithm::Sm4Ccm)`, where the pinned
    /// 12-byte nonce lowers both the default and the accepted maximum to
    /// `SM4_CCM_MAX_PLAINTEXT_BYTES` (`2^24 - 1`). A larger explicit value
    /// makes [`ClientConfigBuilder::build`] fail with
    /// `Error::Configuration`, so a configuration ported from SM4-GCM that
    /// sets 16 MiB explicitly must be lowered.
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
        #[cfg(feature = "aead")]
        let envelope_mode = self.envelope_mode.unwrap_or(EnvelopeMode::LegacyCbc);
        #[cfg(feature = "aead")]
        let iv = match envelope_mode {
            EnvelopeMode::LegacyCbc => self.iv.ok_or(Error::Configuration { field: "iv" })?,
            EnvelopeMode::Aead(_) => {
                if self.iv.is_some() {
                    return Err(Error::Configuration { field: "iv" });
                }
                // Inert filler: the AEAD payload path never reads the IV.
                [0_u8; 16]
            }
        };
        #[cfg(not(feature = "aead"))]
        let iv = self.iv.ok_or(Error::Configuration { field: "iv" })?;
        let authentication_mode = self.authentication_mode.ok_or(Error::Configuration {
            field: "authentication_mode",
        })?;
        authentication_mode.validate()?;
        #[cfg(feature = "aead")]
        let max_plaintext_bytes = {
            let max = self.max_plaintext_bytes.unwrap_or(
                if matches!(envelope_mode, EnvelopeMode::Aead(AeadAlgorithm::Sm4Ccm)) {
                    SM4_CCM_MAX_PLAINTEXT_BYTES
                } else {
                    DEFAULT_MAX_PLAINTEXT_BYTES
                },
            );
            if max == 0
                || (matches!(envelope_mode, EnvelopeMode::Aead(AeadAlgorithm::Sm4Ccm))
                    && max > SM4_CCM_MAX_PLAINTEXT_BYTES)
            {
                return Err(Error::Configuration {
                    field: "max_plaintext_bytes",
                });
            }
            max
        };
        #[cfg(not(feature = "aead"))]
        let max_plaintext_bytes = {
            let max = self
                .max_plaintext_bytes
                .unwrap_or(DEFAULT_MAX_PLAINTEXT_BYTES);
            if max == 0 {
                return Err(Error::Configuration {
                    field: "max_plaintext_bytes",
                });
            }
            max
        };

        Ok(ClientConfig {
            identity,
            local_signer_id,
            expected_remote_signer_id,
            authentication_mode,
            iv,
            #[cfg(feature = "aead")]
            envelope_mode,
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

#[cfg(all(test, feature = "aead"))]
mod tests {
    use super::{
        AeadAlgorithm, ClientConfig, ClientConfigBuilder, DEFAULT_MAX_PLAINTEXT_BYTES, EnvelopeMode,
    };
    use crate::{AuthenticationMode, Error};

    fn base_builder() -> ClientConfigBuilder {
        ClientConfig::builder()
            .local_identity_id("identity")
            .api_version("version")
            .local_certificate_id("certificate")
            .expected_remote_signing_certificate_id("certificate")
            .remote_encryption_certificate_id("certificate")
            .local_signer_id(b"signer".to_vec())
            .expected_remote_signer_id(b"signer".to_vec())
            .authentication_mode(AuthenticationMode::LegacyPlaintext)
    }

    #[test]
    fn envelope_mode_defaults_to_legacy_cbc_and_still_requires_an_iv() {
        let config = base_builder()
            .iv(*b"0123456789abcdef")
            .build()
            .expect("legacy configuration");
        assert_eq!(config.envelope_mode(), EnvelopeMode::LegacyCbc);

        let missing_iv = base_builder().build().expect_err("legacy mode without IV");
        assert!(matches!(missing_iv, Error::Configuration { field: "iv" }));
    }

    #[test]
    fn aead_mode_builds_without_an_iv_and_rejects_a_configured_iv() {
        let config = base_builder()
            .envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm))
            .build()
            .expect("AEAD configuration");
        assert_eq!(
            config.envelope_mode(),
            EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm)
        );

        let with_iv = base_builder()
            .envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Gcm))
            .iv(*b"0123456789abcdef")
            .build()
            .expect_err("AEAD mode with a configured IV");
        assert!(matches!(with_iv, Error::Configuration { field: "iv" }));
    }

    #[test]
    fn ccm_mode_builds_without_an_iv_and_rejects_a_configured_iv() {
        let config = base_builder()
            .envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Ccm))
            .build()
            .expect("CCM configuration");
        assert_eq!(
            config.envelope_mode(),
            EnvelopeMode::Aead(AeadAlgorithm::Sm4Ccm)
        );
        assert_eq!(
            config.max_plaintext_bytes(),
            super::SM4_CCM_MAX_PLAINTEXT_BYTES
        );

        let with_iv = base_builder()
            .envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Ccm))
            .iv(*b"0123456789abcdef")
            .build()
            .expect_err("CCM mode with a configured IV");
        assert!(matches!(with_iv, Error::Configuration { field: "iv" }));
    }

    #[test]
    fn ccm_rejects_a_plaintext_limit_above_the_12_byte_nonce_ceiling() {
        let over = base_builder()
            .envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Ccm))
            .max_plaintext_bytes(DEFAULT_MAX_PLAINTEXT_BYTES)
            .build()
            .expect_err("16 MiB exceeds CCM q=3 ceiling");
        assert!(matches!(
            over,
            Error::Configuration {
                field: "max_plaintext_bytes"
            }
        ));

        let at_ceiling = base_builder()
            .envelope_mode(EnvelopeMode::Aead(AeadAlgorithm::Sm4Ccm))
            .max_plaintext_bytes(super::SM4_CCM_MAX_PLAINTEXT_BYTES)
            .build()
            .expect("ceiling is legal");
        assert_eq!(
            at_ceiling.max_plaintext_bytes(),
            super::SM4_CCM_MAX_PLAINTEXT_BYTES
        );
    }
}
