use std::fmt;

use zeroize::Zeroizing;

use crate::{Error, Result};

const TRANSCRIPT_VERSION: u8 = 1;
const TRANSCRIPT_LENGTH_BYTES: usize = 3 * size_of::<u64>();

/// Selects how plaintext is authenticated by the secure envelope.
#[derive(Clone, PartialEq, Eq)]
pub enum AuthenticationMode {
    /// Authenticates the exact plaintext for compatibility with deployed protocols.
    LegacyPlaintext,
    /// Authenticates a versioned transcript containing a domain and protocol context.
    ContextBound {
        /// Non-empty separation between otherwise independent protocol transcripts.
        domain_separator: Vec<u8>,
    },
}

/// Protocol context supplied for one authentication operation.
///
/// Constructors keep the legacy marker distinct from context-bound bytes, so an
/// authentication mode cannot silently fall back to another mode.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticationContext {
    kind: ContextKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ContextKind {
    Legacy,
    Bound(Vec<u8>),
}

impl fmt::Debug for AuthenticationMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("AuthenticationMode");
        match self {
            Self::LegacyPlaintext => {
                debug.field("kind", &"LegacyPlaintext");
            }
            Self::ContextBound { domain_separator } => {
                debug
                    .field("kind", &"ContextBound")
                    .field("domain_separator_len", &domain_separator.len());
            }
        }
        debug.finish()
    }
}

impl fmt::Debug for AuthenticationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("AuthenticationContext");
        match &self.kind {
            ContextKind::Legacy => {
                debug.field("kind", &"Legacy");
            }
            ContextKind::Bound(context) => {
                debug
                    .field("kind", &"ContextBound")
                    .field("context_len", &context.len());
            }
        }
        debug.finish()
    }
}

impl AuthenticationMode {
    /// Creates a context-bound mode with a non-empty domain separator.
    pub fn context_bound(domain_separator: impl Into<Vec<u8>>) -> Result<Self> {
        let domain_separator = domain_separator.into();
        if domain_separator.is_empty() {
            return Err(Error::Configuration {
                field: "domain_separator",
            });
        }
        Ok(Self::ContextBound { domain_separator })
    }

    /// Builds the exact owned bytes that must be signed or verified.
    ///
    /// Context-bound transcripts use version 1 and unsigned 64-bit big-endian
    /// lengths for the domain separator, protocol context, and plaintext.
    pub fn authentication_input(
        &self,
        context: &AuthenticationContext,
        plaintext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;

        match (self, &context.kind) {
            (Self::LegacyPlaintext, ContextKind::Legacy) => Ok(Zeroizing::new(plaintext.to_vec())),
            (Self::ContextBound { domain_separator }, ContextKind::Bound(context)) => {
                let capacity = 1_usize
                    .checked_add(TRANSCRIPT_LENGTH_BYTES)
                    .and_then(|length| length.checked_add(domain_separator.len()))
                    .and_then(|length| length.checked_add(context.len()))
                    .and_then(|length| length.checked_add(plaintext.len()))
                    .ok_or(Error::AuthenticationContext)?;
                let mut input = Zeroizing::new(Vec::with_capacity(capacity));
                input.push(TRANSCRIPT_VERSION);
                push_field(&mut input, domain_separator)?;
                push_field(&mut input, context)?;
                push_field(&mut input, plaintext)?;
                Ok(input)
            }
            _ => Err(Error::AuthenticationContext),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::ContextBound { domain_separator } if domain_separator.is_empty() => {
                Err(Error::Configuration {
                    field: "domain_separator",
                })
            }
            Self::LegacyPlaintext | Self::ContextBound { .. } => Ok(()),
        }
    }
}

impl AuthenticationContext {
    /// Creates the marker required by [`AuthenticationMode::LegacyPlaintext`].
    #[must_use]
    pub fn legacy() -> Self {
        Self {
            kind: ContextKind::Legacy,
        }
    }

    /// Creates a context-bound value from non-empty canonical protocol bytes.
    pub fn context_bound(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(Error::AuthenticationContext);
        }
        Ok(Self {
            kind: ContextKind::Bound(bytes),
        })
    }
}

fn push_field(target: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length = u64::try_from(value.len()).map_err(|_| Error::AuthenticationContext)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}
