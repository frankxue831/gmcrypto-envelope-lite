use std::path::PathBuf;

use thiserror::Error as ThisError;

/// Stable categories that an external protocol adapter can report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, ThisError)]
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

/// Identifies the broad key-material class without retaining key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyKind {
    /// A local encrypted private key used for signing or decryption.
    LocalPrivate,
    /// A remote public key or certificate used for verification or encryption.
    PeerPublic,
}

/// Redacted failures returned by the secure-envelope SDK.
#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    /// A required configuration field is absent or invalid.
    #[error("invalid configuration field: {field}")]
    Configuration {
        /// Stable field name; never the rejected value.
        field: &'static str,
    },

    /// Private or peer key material could not be decoded or validated.
    #[error("invalid {kind:?} key material")]
    KeyMaterial {
        /// Redacted key-material class.
        kind: KeyKind,
    },

    /// Outbound plaintext or encoded inbound ciphertext exceeds the configured plaintext limit;
    /// decoded or decrypted oversize is reported as [`Error::InvalidEnvelope`].
    #[error("message exceeds the configured {limit}-byte limit")]
    MessageTooLarge {
        /// Configured maximum plaintext byte length.
        limit: usize,
    },

    /// JSON serialization, verified-plaintext deserialization, or request timestamp generation
    /// or formatting failed.
    #[error("serialization failed")]
    Serialization,

    /// Outbound randomness, wrapping, encryption, or signing failed.
    #[error("encryption failed")]
    Encryption,

    /// An authentication context is empty, does not match the configured mode, or cannot form a
    /// versioned transcript because of size.
    #[error("authentication context is invalid for the configured mode")]
    AuthenticationContext,

    /// A header name or value, operation, or request metadata value is syntactically invalid.
    #[error("invalid header")]
    InvalidHeader,

    /// A header duplicates or overrides another name case-insensitively.
    #[error("header conflict")]
    HeaderConflict,

    /// A protocol adapter rejected or could not map neutral data, or the SDK detected a remote
    /// signing-certificate claim mismatch.
    #[error("protocol adapter failed")]
    ProtocolAdapter,

    /// An inbound cryptographic envelope is malformed or unauthenticated.
    #[error("invalid secure envelope")]
    InvalidEnvelope,

    /// A key file could not be read.
    #[error("I/O operation {operation} failed for {path}")]
    Io {
        /// Stable read operation description.
        operation: &'static str,
        /// Caller-supplied key path; key-file contents are never retained here.
        path: PathBuf,
        /// Underlying operating-system I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// SDK result type using the redacted [`Error`] categories.
pub type Result<T> = std::result::Result<T, Error>;
