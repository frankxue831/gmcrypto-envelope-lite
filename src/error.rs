use std::path::PathBuf;

use thiserror::Error;

/// Stable categories that an external protocol adapter can report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterErrorKind {
    /// Protocol values could not be mapped to the neutral model.
    InvalidMapping,
    /// A required protocol field was absent.
    MissingField,
    /// A protocol field occurred more than once.
    DuplicateField,
    /// A protocol field failed validation.
    InvalidField,
}

/// Redacted error returned by an external protocol adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("protocol adapter failed: {kind:?}")]
pub struct AdapterError {
    kind: AdapterErrorKind,
}

impl AdapterError {
    /// Creates an adapter error without retaining caller-owned values.
    #[must_use]
    pub const fn new(kind: AdapterErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable adapter-error category.
    #[must_use]
    pub const fn kind(self) -> AdapterErrorKind {
        self.kind
    }
}

/// Result type implemented by protocol adapters.
pub type AdapterResult<T> = std::result::Result<T, AdapterError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    LocalPrivate,
    PeerPublic,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid configuration field: {field}")]
    Configuration { field: &'static str },

    #[error("invalid {kind:?} key material")]
    KeyMaterial { kind: KeyKind },

    #[error("message exceeds the configured {limit}-byte limit")]
    MessageTooLarge { limit: usize },

    #[error("serialization failed")]
    Serialization,

    #[error("encryption failed")]
    Encryption,

    #[error("authentication context is invalid for the configured mode")]
    AuthenticationContext,

    #[error("invalid header")]
    InvalidHeader,

    #[error("header conflict")]
    HeaderConflict,

    #[error("protocol adapter failed")]
    ProtocolAdapter,

    #[error("invalid secure envelope")]
    InvalidEnvelope,

    #[error("I/O operation {operation} failed for {path}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;
