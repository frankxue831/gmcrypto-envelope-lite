use serde::Serialize;
use zeroize::Zeroizing;

use crate::header::HeaderCollection;
use crate::message::{RequestContext, RequestMetadata, RequestParts};
use crate::{Error, Result, SecureClient};

/// A consuming fluent builder for one transport-neutral secure request.
pub struct RequestBuilder<'a> {
    client: &'a SecureClient,
    operation: String,
    metadata: Option<RequestMetadata>,
    headers: HeaderCollection,
}

impl<'a> RequestBuilder<'a> {
    pub(crate) fn new(client: &'a SecureClient, operation: String) -> Self {
        Self {
            client,
            operation,
            metadata: None,
            headers: HeaderCollection::default(),
        }
    }

    /// Uses explicit correlation metadata instead of generating it when the request is built.
    #[must_use]
    pub fn metadata(mut self, metadata: RequestMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Adds a validated caller-owned header without allowing protocol-header replacement.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Result<Self> {
        self.headers.insert(name, value)?;
        Ok(self)
    }

    /// Encrypts and signs an exact byte payload, generating metadata when necessary.
    pub fn bytes(self, plaintext: &[u8]) -> Result<RequestParts> {
        let (client, context) = self.into_context()?;
        client.build_request(plaintext, context)
    }

    /// Serializes a value once, then encrypts and signs the resulting compact JSON bytes.
    pub fn json<T: Serialize>(self, value: &T) -> Result<RequestParts> {
        let (client, context) = self.into_context()?;
        let plaintext = serialize_json(value)?;
        client.build_request(&plaintext, context)
    }

    fn into_context(self) -> Result<(&'a SecureClient, RequestContext)> {
        let metadata = match self.metadata {
            Some(metadata) => metadata,
            None => RequestMetadata::generate()?,
        };
        let context =
            RequestContext::from_parts(self.operation, metadata, self.headers.into_pairs())?;
        Ok((self.client, context))
    }
}

pub(crate) fn serialize_json<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let mut plaintext = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *plaintext, value).map_err(|_| Error::Serialization)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::serialize_json;

    #[test]
    fn serialized_json_plaintext_is_owned_by_a_zeroizing_guard() {
        let plaintext: Zeroizing<Vec<u8>> =
            serialize_json(&serde_json::json!({"message": "secret"})).expect("JSON plaintext");

        assert_eq!(&*plaintext, br#"{"message":"secret"}"#);
    }
}
