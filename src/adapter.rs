use std::collections::HashSet;
use std::fmt;

use crate::message::{
    ParsedResponse, ProtocolRequestContext, RequestParts, ResponseParts, SecureEnvelope,
};
use crate::{
    AdapterError, AdapterErrorKind, AdapterResult, AuthenticationContext, ClientIdentity,
    HeaderName, HeaderValue,
};
#[cfg(doc)]
use crate::{AuthenticationMode, ClientConfig};

/// Converts between protocol-neutral secure envelopes and a wire representation.
pub trait ProtocolAdapter: Send + Sync {
    /// Selects the authentication context for an outbound request.
    fn request_authentication_context(
        &self,
        identity: &ClientIdentity,
        context: &ProtocolRequestContext,
    ) -> AdapterResult<AuthenticationContext>;

    /// Maps a protocol-neutral request into transport parts.
    fn build_request(
        &self,
        identity: &ClientIdentity,
        context: &ProtocolRequestContext,
        envelope: &SecureEnvelope,
    ) -> AdapterResult<RequestParts>;

    /// Parses raw transport parts into a protocol-neutral response.
    fn parse_response(&self, response: ResponseParts) -> AdapterResult<ParsedResponse>;
}

/// Selects whether encrypted content is carried in the body or in a header.
/// The two variants intentionally exhaust the transport-neutral locations supported by
/// `HeaderProtocolAdapter`; new wire models belong in a custom [`ProtocolAdapter`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CipherLocation {
    /// Carry encrypted content in the transport body.
    Body,
    /// Carry encrypted content in the named header.
    Header(HeaderName),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderAuthentication {
    Legacy,
    ContextBound,
}

/// A complete, validated header mapping for [`HeaderProtocolAdapter`].
#[derive(Clone, Debug)]
pub struct HeaderSchema {
    static_request_headers: Vec<(HeaderName, HeaderValue)>,
    local_identity_header: HeaderName,
    operation_header: HeaderName,
    request_id_header: HeaderName,
    request_time_header: HeaderName,
    api_version_header: HeaderName,
    local_certificate_header: HeaderName,
    remote_signing_certificate_header: HeaderName,
    remote_encryption_certificate_header: HeaderName,
    request_signature_header: HeaderName,
    request_wrapped_key_header: HeaderName,
    request_cipher: CipherLocation,
    response_signature_header: HeaderName,
    response_wrapped_key_header: HeaderName,
    response_remote_signing_certificate_header: HeaderName,
    response_cipher: CipherLocation,
    authentication: HeaderAuthentication,
}

impl HeaderSchema {
    /// Starts an empty schema builder with no protocol-specific defaults.
    #[must_use]
    pub fn builder() -> HeaderSchemaBuilder {
        HeaderSchemaBuilder::default()
    }
}

/// Consuming builder for [`HeaderSchema`].
#[derive(Clone, Default)]
pub struct HeaderSchemaBuilder {
    static_request_headers: Vec<(String, String)>,
    local_identity_header: Option<String>,
    operation_header: Option<String>,
    request_id_header: Option<String>,
    request_time_header: Option<String>,
    api_version_header: Option<String>,
    local_certificate_header: Option<String>,
    remote_signing_certificate_header: Option<String>,
    remote_encryption_certificate_header: Option<String>,
    request_signature_header: Option<String>,
    request_wrapped_key_header: Option<String>,
    request_cipher: Option<CipherLocation>,
    response_signature_header: Option<String>,
    response_wrapped_key_header: Option<String>,
    response_remote_signing_certificate_header: Option<String>,
    response_cipher: Option<CipherLocation>,
    legacy_authentication: bool,
    context_bound_authentication: bool,
}

impl fmt::Debug for HeaderSchemaBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderSchemaBuilder")
            .field(
                "static_request_header_count",
                &self.static_request_headers.len(),
            )
            .field(
                "local_identity_header_set",
                &self.local_identity_header.is_some(),
            )
            .field("operation_header_set", &self.operation_header.is_some())
            .field("request_id_header_set", &self.request_id_header.is_some())
            .field(
                "request_time_header_set",
                &self.request_time_header.is_some(),
            )
            .field("api_version_header_set", &self.api_version_header.is_some())
            .field(
                "local_certificate_header_set",
                &self.local_certificate_header.is_some(),
            )
            .field(
                "remote_signing_certificate_header_set",
                &self.remote_signing_certificate_header.is_some(),
            )
            .field(
                "remote_encryption_certificate_header_set",
                &self.remote_encryption_certificate_header.is_some(),
            )
            .field(
                "request_signature_header_set",
                &self.request_signature_header.is_some(),
            )
            .field(
                "request_wrapped_key_header_set",
                &self.request_wrapped_key_header.is_some(),
            )
            .field("request_cipher", &self.request_cipher)
            .field(
                "response_signature_header_set",
                &self.response_signature_header.is_some(),
            )
            .field(
                "response_wrapped_key_header_set",
                &self.response_wrapped_key_header.is_some(),
            )
            .field(
                "response_remote_signing_certificate_header_set",
                &self.response_remote_signing_certificate_header.is_some(),
            )
            .field("response_cipher", &self.response_cipher)
            .field("legacy_authentication", &self.legacy_authentication)
            .field(
                "context_bound_authentication",
                &self.context_bound_authentication,
            )
            .finish()
    }
}

impl HeaderSchemaBuilder {
    /// Adds a request header whose value is fixed for every request.
    #[must_use]
    pub fn static_request_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.static_request_headers
            .push((name.into(), value.into()));
        self
    }

    /// Maps the local application or account identity.
    #[must_use]
    pub fn local_identity_header(mut self, name: impl Into<String>) -> Self {
        self.local_identity_header = Some(name.into());
        self
    }

    /// Maps the request operation.
    #[must_use]
    pub fn operation_header(mut self, name: impl Into<String>) -> Self {
        self.operation_header = Some(name.into());
        self
    }

    /// Maps the request identifier.
    #[must_use]
    pub fn request_id_header(mut self, name: impl Into<String>) -> Self {
        self.request_id_header = Some(name.into());
        self
    }

    /// Maps the request timestamp.
    #[must_use]
    pub fn request_time_header(mut self, name: impl Into<String>) -> Self {
        self.request_time_header = Some(name.into());
        self
    }

    /// Maps the API version.
    #[must_use]
    pub fn api_version_header(mut self, name: impl Into<String>) -> Self {
        self.api_version_header = Some(name.into());
        self
    }

    /// Maps the local signing-certificate identifier.
    #[must_use]
    pub fn local_certificate_header(mut self, name: impl Into<String>) -> Self {
        self.local_certificate_header = Some(name.into());
        self
    }

    /// Maps the expected remote signing-certificate identifier on requests.
    #[must_use]
    pub fn remote_signing_certificate_header(mut self, name: impl Into<String>) -> Self {
        self.remote_signing_certificate_header = Some(name.into());
        self
    }

    /// Maps the remote encryption-certificate identifier.
    #[must_use]
    pub fn remote_encryption_certificate_header(mut self, name: impl Into<String>) -> Self {
        self.remote_encryption_certificate_header = Some(name.into());
        self
    }

    /// Maps the outbound signature.
    #[must_use]
    pub fn request_signature_header(mut self, name: impl Into<String>) -> Self {
        self.request_signature_header = Some(name.into());
        self
    }

    /// Maps the outbound wrapped session key.
    #[must_use]
    pub fn request_wrapped_key_header(mut self, name: impl Into<String>) -> Self {
        self.request_wrapped_key_header = Some(name.into());
        self
    }

    /// Selects the outbound cipher location.
    #[must_use]
    pub fn request_cipher(mut self, location: CipherLocation) -> Self {
        self.request_cipher = Some(location);
        self
    }

    /// Maps the inbound signature.
    #[must_use]
    pub fn response_signature_header(mut self, name: impl Into<String>) -> Self {
        self.response_signature_header = Some(name.into());
        self
    }

    /// Maps the inbound wrapped session key.
    #[must_use]
    pub fn response_wrapped_key_header(mut self, name: impl Into<String>) -> Self {
        self.response_wrapped_key_header = Some(name.into());
        self
    }

    /// Maps the remote signing-certificate claim on responses.
    #[must_use]
    pub fn response_remote_signing_certificate_header(mut self, name: impl Into<String>) -> Self {
        self.response_remote_signing_certificate_header = Some(name.into());
        self
    }

    /// Selects the inbound cipher location.
    #[must_use]
    pub fn response_cipher(mut self, location: CipherLocation) -> Self {
        self.response_cipher = Some(location);
        self
    }

    /// Selects legacy plaintext authentication explicitly.
    ///
    /// This schema signs plaintext only. Use authenticated TLS, replay defense,
    /// and request/response correlation.
    ///
    /// # Security
    ///
    /// Both peers must reconstruct the same typed fields. There is no
    /// negotiation or fallback.
    #[must_use]
    pub fn legacy_authentication(mut self) -> Self {
        self.legacy_authentication = true;
        self
    }

    /// Selects context-bound authentication for this header mapping.
    ///
    /// Request and response context bytes use the crate-owned version-1
    /// layout documented on [`HeaderProtocolAdapter`]. This is not AEAD,
    /// replay protection, or request/response correlation.
    /// [`ClientConfig`] must pin [`AuthenticationMode::ContextBound`]
    /// separately.
    ///
    /// # Security
    ///
    /// Both peers must reconstruct the same typed fields. There is no
    /// negotiation or fallback.
    #[must_use]
    pub fn context_bound_authentication(mut self) -> Self {
        self.context_bound_authentication = true;
        self
    }

    /// Validates every mapping and creates an immutable schema.
    pub fn build(self) -> AdapterResult<HeaderSchema> {
        if self.static_request_headers.is_empty()
            || self.request_cipher.is_none()
            || self.response_cipher.is_none()
        {
            return Err(adapter_error(AdapterErrorKind::MissingField));
        }
        if self.legacy_authentication && self.context_bound_authentication {
            return Err(adapter_error(AdapterErrorKind::InvalidMapping));
        }
        if !self.legacy_authentication && !self.context_bound_authentication {
            return Err(adapter_error(AdapterErrorKind::MissingField));
        }
        let authentication = if self.context_bound_authentication {
            HeaderAuthentication::ContextBound
        } else {
            HeaderAuthentication::Legacy
        };

        let static_request_headers = self
            .static_request_headers
            .into_iter()
            .map(|(name, value)| {
                if value.trim().is_empty() {
                    return Err(adapter_error(AdapterErrorKind::InvalidMapping));
                }
                let name = HeaderName::new(name)
                    .map_err(|_| adapter_error(AdapterErrorKind::InvalidMapping))?;
                let value = HeaderValue::new(value)
                    .map_err(|_| adapter_error(AdapterErrorKind::InvalidMapping))?;
                Ok((name, value))
            })
            .collect::<AdapterResult<Vec<_>>>()?;

        let schema = HeaderSchema {
            static_request_headers,
            local_identity_header: required_header(self.local_identity_header)?,
            operation_header: required_header(self.operation_header)?,
            request_id_header: required_header(self.request_id_header)?,
            request_time_header: required_header(self.request_time_header)?,
            api_version_header: required_header(self.api_version_header)?,
            local_certificate_header: required_header(self.local_certificate_header)?,
            remote_signing_certificate_header: required_header(
                self.remote_signing_certificate_header,
            )?,
            remote_encryption_certificate_header: required_header(
                self.remote_encryption_certificate_header,
            )?,
            request_signature_header: required_header(self.request_signature_header)?,
            request_wrapped_key_header: required_header(self.request_wrapped_key_header)?,
            request_cipher: self
                .request_cipher
                .ok_or_else(|| adapter_error(AdapterErrorKind::MissingField))?,
            response_signature_header: required_header(self.response_signature_header)?,
            response_wrapped_key_header: required_header(self.response_wrapped_key_header)?,
            response_remote_signing_certificate_header: required_header(
                self.response_remote_signing_certificate_header,
            )?,
            response_cipher: self
                .response_cipher
                .ok_or_else(|| adapter_error(AdapterErrorKind::MissingField))?,
            authentication,
        };
        schema.validate_collisions()?;
        Ok(schema)
    }
}

impl HeaderSchema {
    fn validate_collisions(&self) -> AdapterResult<()> {
        let mut request_names = HashSet::new();
        for (name, _) in &self.static_request_headers {
            insert_mapping(&mut request_names, name)?;
        }
        for name in [
            &self.local_identity_header,
            &self.operation_header,
            &self.request_id_header,
            &self.request_time_header,
            &self.api_version_header,
            &self.local_certificate_header,
            &self.remote_signing_certificate_header,
            &self.remote_encryption_certificate_header,
            &self.request_signature_header,
            &self.request_wrapped_key_header,
        ] {
            insert_mapping(&mut request_names, name)?;
        }
        if let CipherLocation::Header(name) = &self.request_cipher {
            insert_mapping(&mut request_names, name)?;
        }

        let mut response_names = HashSet::new();
        for name in [
            &self.response_signature_header,
            &self.response_wrapped_key_header,
            &self.response_remote_signing_certificate_header,
        ] {
            insert_mapping(&mut response_names, name)?;
        }
        if let CipherLocation::Header(name) = &self.response_cipher {
            insert_mapping(&mut response_names, name)?;
        }
        Ok(())
    }
}

/// A schema-driven adapter for protocols represented by headers and a body.
#[derive(Clone, Debug)]
pub struct HeaderProtocolAdapter {
    schema: HeaderSchema,
}

impl HeaderProtocolAdapter {
    /// Creates an adapter from a validated schema.
    #[must_use]
    pub fn new(schema: HeaderSchema) -> Self {
        Self { schema }
    }
}

impl ProtocolAdapter for HeaderProtocolAdapter {
    fn request_authentication_context(
        &self,
        _identity: &ClientIdentity,
        context: &ProtocolRequestContext,
    ) -> AdapterResult<AuthenticationContext> {
        match self.schema.authentication {
            HeaderAuthentication::Legacy => Ok(AuthenticationContext::legacy()),
            HeaderAuthentication::ContextBound => {
                encode_request_context(context.operation(), context.metadata().request_id())
            }
        }
    }

    fn build_request(
        &self,
        identity: &ClientIdentity,
        context: &ProtocolRequestContext,
        envelope: &SecureEnvelope,
    ) -> AdapterResult<RequestParts> {
        validate_nonempty(&envelope.signature)?;
        validate_nonempty(&envelope.wrapped_session_key)?;
        validate_nonempty(&envelope.cipher)?;

        let mut headers = self
            .schema
            .static_request_headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_str().to_owned()))
            .collect::<Vec<_>>();
        headers.extend([
            pair(
                &self.schema.local_identity_header,
                identity.local_identity_id(),
            ),
            pair(&self.schema.operation_header, context.operation()),
            pair(
                &self.schema.request_id_header,
                context.metadata().request_id(),
            ),
            pair(
                &self.schema.request_time_header,
                context.metadata().request_time(),
            ),
            pair(&self.schema.api_version_header, identity.api_version()),
            pair(
                &self.schema.local_certificate_header,
                identity.local_certificate_id(),
            ),
            pair(
                &self.schema.remote_signing_certificate_header,
                identity.expected_remote_signing_certificate_id(),
            ),
            pair(
                &self.schema.remote_encryption_certificate_header,
                identity.remote_encryption_certificate_id(),
            ),
            pair(&self.schema.request_signature_header, &envelope.signature),
            pair(
                &self.schema.request_wrapped_key_header,
                &envelope.wrapped_session_key,
            ),
        ]);

        let body = match &self.schema.request_cipher {
            CipherLocation::Body => envelope.cipher.clone(),
            CipherLocation::Header(name) => {
                headers.push(pair(name, &envelope.cipher));
                String::new()
            }
        };

        RequestParts::new(headers, body).map_err(|_| adapter_error(AdapterErrorKind::InvalidField))
    }

    fn parse_response(&self, response: ResponseParts) -> AdapterResult<ParsedResponse> {
        let (headers, body) = response.into_parts();
        let mut signature = None;
        let mut wrapped_session_key = None;
        let mut remote_signing_certificate_id = None;
        let mut cipher = None;
        let mut request_id = None;

        for (name, value) in headers {
            let target = if name
                .eq_ignore_ascii_case(self.schema.response_signature_header.as_str())
            {
                Some(&mut signature)
            } else if name.eq_ignore_ascii_case(self.schema.response_wrapped_key_header.as_str()) {
                Some(&mut wrapped_session_key)
            } else if name.eq_ignore_ascii_case(
                self.schema
                    .response_remote_signing_certificate_header
                    .as_str(),
            ) {
                Some(&mut remote_signing_certificate_id)
            } else if matches!(
                self.schema.authentication,
                HeaderAuthentication::ContextBound
            ) && name.eq_ignore_ascii_case(self.schema.request_id_header.as_str())
            {
                Some(&mut request_id)
            } else if let CipherLocation::Header(cipher_header) = &self.schema.response_cipher {
                name.eq_ignore_ascii_case(cipher_header.as_str())
                    .then_some(&mut cipher)
            } else {
                None
            };

            if let Some(target) = target {
                if target.replace(value).is_some() {
                    return Err(adapter_error(AdapterErrorKind::DuplicateField));
                }
            }
        }

        let signature = required_response_header(signature)?;
        let wrapped_session_key = required_response_header(wrapped_session_key)?;
        let remote_signing_certificate_id =
            required_response_header(remote_signing_certificate_id)?;
        let cipher = match &self.schema.response_cipher {
            CipherLocation::Body => trimmed_nonempty(body)?,
            CipherLocation::Header(_) => required_response_header(cipher)?,
        };

        let authentication_context = match self.schema.authentication {
            HeaderAuthentication::Legacy => AuthenticationContext::legacy(),
            HeaderAuthentication::ContextBound => {
                let value =
                    request_id.ok_or_else(|| adapter_error(AdapterErrorKind::MissingField))?;
                HeaderValue::new(&value)
                    .map_err(|_| adapter_error(AdapterErrorKind::InvalidField))?;
                encode_response_context(&value)?
            }
        };

        ParsedResponse::new(
            SecureEnvelope {
                cipher,
                wrapped_session_key,
                signature,
            },
            remote_signing_certificate_id,
            authentication_context,
        )
    }
}

fn required_header(value: Option<String>) -> AdapterResult<HeaderName> {
    let value = value.ok_or_else(|| adapter_error(AdapterErrorKind::MissingField))?;
    HeaderName::new(value).map_err(|_| adapter_error(AdapterErrorKind::InvalidMapping))
}

fn insert_mapping(names: &mut HashSet<HeaderName>, name: &HeaderName) -> AdapterResult<()> {
    if !names.insert(name.clone()) {
        return Err(adapter_error(AdapterErrorKind::InvalidMapping));
    }
    Ok(())
}

fn pair(name: &HeaderName, value: &str) -> (String, String) {
    (name.as_str().to_owned(), value.to_owned())
}

fn validate_nonempty(value: &str) -> AdapterResult<()> {
    if value.trim().is_empty() {
        return Err(adapter_error(AdapterErrorKind::InvalidField));
    }
    Ok(())
}

fn required_response_header(value: Option<String>) -> AdapterResult<String> {
    let value = value.ok_or_else(|| adapter_error(AdapterErrorKind::MissingField))?;
    HeaderValue::new(&value).map_err(|_| adapter_error(AdapterErrorKind::InvalidField))?;
    trimmed_nonempty(value)
}

fn trimmed_nonempty(value: String) -> AdapterResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(adapter_error(AdapterErrorKind::InvalidField));
    }
    Ok(value.to_owned())
}

const HEADER_CONTEXT_VERSION: u8 = 0x01;
const HEADER_CONTEXT_REQUEST: u8 = 0x01;
const HEADER_CONTEXT_RESPONSE: u8 = 0x02;

fn require_exact_trim(value: &str) -> AdapterResult<&str> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(adapter_error(AdapterErrorKind::InvalidField));
    }
    Ok(value)
}

fn push_length_prefixed(buffer: &mut Vec<u8>, value: &str) -> AdapterResult<()> {
    let length =
        u64::try_from(value.len()).map_err(|_| adapter_error(AdapterErrorKind::InvalidField))?;
    buffer.extend_from_slice(&length.to_be_bytes());
    buffer.extend_from_slice(value.as_bytes());
    Ok(())
}

fn bound_context(bytes: Vec<u8>) -> AdapterResult<AuthenticationContext> {
    AuthenticationContext::context_bound(bytes)
        .map_err(|_| adapter_error(AdapterErrorKind::InvalidField))
}

fn encode_request_context(
    operation: &str,
    request_id: &str,
) -> AdapterResult<AuthenticationContext> {
    let operation = require_exact_trim(operation)?;
    let request_id = require_exact_trim(request_id)?;
    let mut bytes = Vec::new();
    bytes.push(HEADER_CONTEXT_VERSION);
    bytes.push(HEADER_CONTEXT_REQUEST);
    push_length_prefixed(&mut bytes, operation)?;
    push_length_prefixed(&mut bytes, request_id)?;
    bound_context(bytes)
}

fn encode_response_context(request_id: &str) -> AdapterResult<AuthenticationContext> {
    let request_id = require_exact_trim(request_id)?;
    let mut bytes = Vec::new();
    bytes.push(HEADER_CONTEXT_VERSION);
    bytes.push(HEADER_CONTEXT_RESPONSE);
    push_length_prefixed(&mut bytes, request_id)?;
    bound_context(bytes)
}

const fn adapter_error(kind: AdapterErrorKind) -> AdapterError {
    AdapterError::new(kind)
}
