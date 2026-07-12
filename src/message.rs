use std::fmt::{self, Write as _};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::header::HeaderCollection;
use crate::{
    AdapterError, AdapterErrorKind, AdapterResult, AuthenticationContext, Error, HeaderName,
    HeaderValue, Result,
};

/// A transport-neutral encrypted and signed message.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureEnvelope {
    pub cipher: String,
    pub wrapped_session_key: String,
    pub signature: String,
}

impl fmt::Debug for SecureEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecureEnvelope")
            .field("cipher_len", &self.cipher.len())
            .field("wrapped_session_key_len", &self.wrapped_session_key.len())
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

/// Caller-supplied or generated request correlation metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestMetadata {
    request_id: String,
    request_time: String,
}

impl RequestMetadata {
    /// Creates validated request metadata.
    pub fn new(request_id: impl Into<String>, request_time: impl Into<String>) -> Result<Self> {
        Ok(Self {
            request_id: validate_context_value(request_id.into())?,
            request_time: validate_context_value(request_time.into())?,
        })
    }

    /// Generates a random request identifier and a UTC request timestamp.
    pub fn generate() -> Result<Self> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| Error::Encryption)?;
        let mut request_id = String::with_capacity(32);
        for byte in random {
            write!(&mut request_id, "{byte:02x}").expect("writing to String cannot fail");
        }

        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Serialization)?;
        let request_time = format_utc_timestamp(since_epoch)?;

        Self::new(request_id, request_time)
    }

    /// Returns the request identifier.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the UTC request timestamp.
    #[must_use]
    pub fn request_time(&self) -> &str {
        &self.request_time
    }
}

/// The semantic request context visible to a protocol adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolRequestContext {
    operation: String,
    metadata: RequestMetadata,
}

impl ProtocolRequestContext {
    /// Creates a context containing only protocol-semantic fields.
    pub fn new(operation: impl Into<String>, metadata: RequestMetadata) -> Result<Self> {
        Ok(Self {
            operation: validate_context_value(operation.into())?,
            metadata,
        })
    }

    /// Returns the per-request operation.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Returns the request metadata.
    #[must_use]
    pub fn metadata(&self) -> &RequestMetadata {
        &self.metadata
    }
}

/// A complete request context, including caller-owned additive headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestContext {
    protocol: ProtocolRequestContext,
    additional_headers: HeaderCollection,
}

impl RequestContext {
    /// Starts a consuming request-context builder.
    pub fn builder(operation: impl Into<String>) -> RequestContextBuilder {
        RequestContextBuilder::new(operation)
    }

    /// Returns the semantic-only context intended for a protocol adapter.
    #[must_use]
    pub fn protocol(&self) -> &ProtocolRequestContext {
        &self.protocol
    }

    /// Iterates over caller-supplied additional headers in insertion order.
    pub fn additional_headers(&self) -> impl ExactSizeIterator<Item = (&HeaderName, &HeaderValue)> {
        self.additional_header_collection().iter()
    }

    /// Looks up an additional header case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.additional_headers.get(name).map(HeaderValue::as_str)
    }

    /// Returns the number of additional headers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.additional_headers.len()
    }

    /// Returns whether there are no additional headers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.additional_headers.is_empty()
    }

    pub(crate) fn from_parts(
        operation: String,
        metadata: RequestMetadata,
        additional_headers: Vec<(HeaderName, HeaderValue)>,
    ) -> Result<Self> {
        let additional_headers = HeaderCollection::from_typed_pairs(additional_headers)?;
        additional_headers.revalidate()?;
        let protocol = ProtocolRequestContext::new(operation, metadata)?;
        Ok(Self {
            protocol,
            additional_headers,
        })
    }

    pub(crate) fn additional_header_collection(&self) -> &HeaderCollection {
        &self.additional_headers
    }

    pub(crate) fn into_parts(self) -> (ProtocolRequestContext, HeaderCollection) {
        (self.protocol, self.additional_headers)
    }
}

/// A consuming builder for [`RequestContext`].
#[derive(Clone, Debug)]
pub struct RequestContextBuilder {
    operation: String,
    metadata: Option<RequestMetadata>,
    additional_headers: HeaderCollection,
}

impl RequestContextBuilder {
    /// Starts a builder for an operation.
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            metadata: None,
            additional_headers: HeaderCollection::default(),
        }
    }

    /// Uses explicit request metadata instead of generating it at build time.
    #[must_use]
    pub fn metadata(mut self, metadata: RequestMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Adds a validated caller header, rejecting duplicates under any casing.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Result<Self> {
        self.additional_headers.insert(name, value)?;
        Ok(self)
    }

    /// Validates and creates the request context.
    pub fn build(self) -> Result<RequestContext> {
        let metadata = match self.metadata {
            Some(metadata) => metadata,
            None => RequestMetadata::generate()?,
        };
        RequestContext::from_parts(
            self.operation,
            metadata,
            self.additional_headers.into_pairs(),
        )
    }
}

/// An ordered, validated outbound request and body.
#[derive(Clone, PartialEq, Eq)]
pub struct RequestParts {
    headers: HeaderCollection,
    body: String,
}

impl fmt::Debug for RequestParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names = self
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        formatter
            .debug_struct("RequestParts")
            .field("header_count", &header_names.len())
            .field("header_names", &header_names)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl RequestParts {
    #[cfg(test)]
    pub(crate) fn malformed_for_test<I, K, V, B>(headers: I, body: B) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
        B: Into<String>,
    {
        let entries = headers
            .into_iter()
            .map(|(name, value)| {
                (
                    HeaderName::new(name).expect("malformed test header name remains syntactic"),
                    HeaderValue::new(value).expect("malformed test header value remains syntactic"),
                )
            })
            .collect();
        Self {
            headers: HeaderCollection::from_unchecked_for_test(entries),
            body: body.into(),
        }
    }

    /// Creates request parts with syntactically valid, case-insensitively unique headers.
    pub fn new<I, K, V, B>(headers: I, body: B) -> Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
        B: Into<String>,
    {
        let incoming = HeaderCollection::from_pairs(headers)?;
        let mut parts = Self {
            headers: HeaderCollection::default(),
            body: body.into(),
        };
        parts.append_checked(&incoming)?;
        parts.validate()?;
        Ok(parts)
    }

    /// Iterates over headers in insertion order.
    pub fn headers(&self) -> impl ExactSizeIterator<Item = (&HeaderName, &HeaderValue)> {
        self.headers.iter()
    }

    /// Looks up a header case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(HeaderValue::as_str)
    }

    /// Returns the number of request headers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Returns whether the request contains no headers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Returns the request body.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    pub(crate) fn append_checked(&mut self, headers: &HeaderCollection) -> Result<()> {
        self.headers.append_checked(headers)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.headers.revalidate()
    }
}

/// Raw inbound response parts whose header order and duplicates are preserved.
#[derive(Clone, PartialEq, Eq)]
pub struct ResponseParts {
    headers: Vec<(String, String)>,
    body: String,
}

impl fmt::Debug for ResponseParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names = self
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        formatter
            .debug_struct("ResponseParts")
            .field("header_count", &header_names.len())
            .field("header_names", &header_names)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl ResponseParts {
    /// Captures response data without normalizing or deduplicating headers.
    #[must_use]
    pub fn new<I, K, V, B>(headers: I, body: B) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
        B: Into<String>,
    {
        Self {
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
            body: body.into(),
        }
    }

    /// Iterates over the unmodified response header sequence.
    pub fn headers(&self) -> impl ExactSizeIterator<Item = (&str, &str)> {
        self.headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// Returns the unmodified response body.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    /// Returns the owned raw response data.
    #[must_use]
    pub fn into_parts(self) -> (Vec<(String, String)>, String) {
        (self.headers, self.body)
    }
}

/// A protocol adapter's validated semantic response.
#[derive(Clone, PartialEq, Eq)]
pub struct ParsedResponse {
    envelope: SecureEnvelope,
    remote_signing_certificate_id: String,
    authentication_context: AuthenticationContext,
}

impl fmt::Debug for ParsedResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedResponse")
            .field("envelope", &self.envelope)
            .field(
                "remote_signing_certificate_id_len",
                &self.remote_signing_certificate_id.len(),
            )
            .field("authentication_context", &self.authentication_context)
            .finish()
    }
}

impl ParsedResponse {
    /// Creates a parsed response with a nonempty, injection-safe certificate claim.
    pub fn new(
        envelope: SecureEnvelope,
        remote_signing_certificate_id: impl Into<String>,
        authentication_context: AuthenticationContext,
    ) -> AdapterResult<Self> {
        let remote_signing_certificate_id = remote_signing_certificate_id.into();
        if remote_signing_certificate_id.trim().is_empty()
            || remote_signing_certificate_id.contains(['\r', '\n'])
        {
            return Err(AdapterError::new(AdapterErrorKind::InvalidField));
        }

        Ok(Self {
            envelope,
            remote_signing_certificate_id,
            authentication_context,
        })
    }

    /// Returns the secure envelope extracted from the response.
    #[must_use]
    pub fn envelope(&self) -> &SecureEnvelope {
        &self.envelope
    }

    /// Returns the remote signing-certificate claim carried by the response.
    #[must_use]
    pub fn remote_signing_certificate_id(&self) -> &str {
        &self.remote_signing_certificate_id
    }

    /// Returns the authentication context required to verify the response.
    #[must_use]
    pub fn authentication_context(&self) -> &AuthenticationContext {
        &self.authentication_context
    }

    /// Returns the owned semantic response components.
    #[must_use]
    pub fn into_parts(self) -> (SecureEnvelope, String, AuthenticationContext) {
        (
            self.envelope,
            self.remote_signing_certificate_id,
            self.authentication_context,
        )
    }
}

fn validate_context_value(value: String) -> Result<String> {
    if value.trim().is_empty() || value.contains(['\r', '\n']) {
        return Err(Error::InvalidHeader);
    }
    Ok(value)
}

fn format_utc_timestamp(since_epoch: Duration) -> Result<String> {
    let seconds = since_epoch.as_secs();
    let days = i64::try_from(seconds / 86_400).map_err(|_| Error::Serialization)?;
    let seconds_of_day = seconds % 86_400;
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    let (year, month, day) = civil_date_from_days(days);

    Ok(format!(
        "{year:04}-{month:02}-{day:02}-{hour:02}.{minute:02}.{second:02}.{:06}",
        since_epoch.subsec_micros()
    ))
}

fn civil_date_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let shifted = days_since_epoch + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::format_utc_timestamp;
    use super::{HeaderName, HeaderValue, RequestContext, RequestMetadata};

    #[test]
    fn context_from_parts_accepts_typed_builder_output() {
        let metadata =
            RequestMetadata::new("request-1", "2026-07-12-01.02.03.123456").expect("metadata");
        let headers = vec![(
            HeaderName::new("X-Demo-Trace").expect("header name"),
            HeaderValue::new("trace-1").expect("header value"),
        )];

        let context =
            RequestContext::from_parts("demo-operation".to_owned(), metadata.clone(), headers)
                .expect("request context");

        assert_eq!(context.protocol().metadata(), &metadata);
        assert_eq!(context.header("x-demo-trace"), Some("trace-1"));
    }

    #[test]
    fn utc_timestamp_formatter_covers_epoch_and_leap_day() {
        assert_eq!(
            format_utc_timestamp(Duration::ZERO).expect("Unix epoch"),
            "1970-01-01-00.00.00.000000"
        );
        assert_eq!(
            format_utc_timestamp(
                Duration::from_secs(1_709_210_096) + Duration::from_micros(123_456)
            )
            .expect("leap-day timestamp"),
            "2024-02-29-12.34.56.123456"
        );
    }
}
