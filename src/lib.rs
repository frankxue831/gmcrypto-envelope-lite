#![forbid(unsafe_code)]
//! HTTP-neutral SM2/SM3 and SM4 secure-envelope primitives.
//!
//! [`SecureClient`] seals application bytes into [`RequestParts`] and opens
//! [`ResponseParts`] only after authentication. Transport I/O and protocol-specific
//! wire mappings remain caller concerns behind [`ProtocolAdapter`].

mod adapter;
mod auth;
mod client;
mod client_config;
mod envelope_crypto;
mod error;
mod header;
mod keys;
mod message;
mod request;

pub use adapter::{
    CipherLocation, HeaderProtocolAdapter, HeaderSchema, HeaderSchemaBuilder, ProtocolAdapter,
};
pub use auth::{AuthenticationContext, AuthenticationMode};
pub use client::SecureClient;
pub use client_config::{
    ClientConfig, ClientConfigBuilder, ClientIdentity, DEFAULT_MAX_PLAINTEXT_BYTES,
};
pub use error::{AdapterError, AdapterErrorKind, AdapterResult, Error, KeyKind, Result};
pub use header::{HeaderName, HeaderValue};
pub use keys::{KeyMaterial, PeerKeySource, PrivateKey, PublicKey};
pub use message::{
    ParsedResponse, ProtocolRequestContext, RequestContext, RequestContextBuilder, RequestMetadata,
    RequestParts, ResponseParts, SecureEnvelope,
};
pub use request::RequestBuilder;
