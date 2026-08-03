use std::fmt;

use zeroize::Zeroizing;

use crate::{Error, Result};

const TRANSCRIPT_VERSION: u8 = 1;
const TRANSCRIPT_LENGTH_BYTES: usize = 3 * size_of::<u64>();
#[cfg(feature = "aead")]
const AEAD_AAD_LABEL: &[u8] = b"gmcrypto-envelope-lite/aead-aad/v1";

/// Selects how plaintext is authenticated by the secure envelope.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthenticationMode {
    /// Authenticates the exact plaintext for compatibility with deployed protocols.
    ///
    /// # Security
    ///
    /// This mode does not authenticate envelope metadata or transport headers. Use
    /// authenticated TLS plus application replay defense and request/response correlation.
    LegacyPlaintext,
    /// Authenticates a versioned transcript containing a domain and protocol context.
    ///
    /// This expands signature coverage only. It does not turn the fixed-IV SM4-CBC
    /// envelope into AEAD or provide replay protection.
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
    ///
    /// # Errors
    ///
    /// Returns [`Error::Configuration`] when the domain separator is empty.
    ///
    /// # Security
    ///
    /// Domain separators must be stable and distinct for independent transcript meanings.
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

    /// Builds the additional authenticated data for one AEAD envelope.
    ///
    /// The layout is four fields, each preceded by its unsigned 64-bit
    /// big-endian byte length: a fixed domain label, the 14-byte cipher
    /// frame header, the configured domain separator, and the protocol
    /// context. Under [`AuthenticationMode::LegacyPlaintext`] the last
    /// two fields are empty.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AuthenticationContext`] when the context kind
    /// does not match this mode, mirroring
    /// [`AuthenticationMode::authentication_input`].
    #[cfg(feature = "aead")]
    pub fn aead_aad(
        &self,
        context: &AuthenticationContext,
        frame_header: &[u8; 14],
    ) -> Result<Vec<u8>> {
        self.validate()?;

        let (domain_separator, protocol_context): (&[u8], &[u8]) = match (self, &context.kind) {
            (Self::LegacyPlaintext, ContextKind::Legacy) => (&[], &[]),
            (Self::ContextBound { domain_separator }, ContextKind::Bound(bound)) => {
                (domain_separator.as_slice(), bound.as_slice())
            }
            _ => return Err(Error::AuthenticationContext),
        };

        let capacity = (4 * size_of::<u64>())
            .checked_add(AEAD_AAD_LABEL.len())
            .and_then(|length| length.checked_add(frame_header.len()))
            .and_then(|length| length.checked_add(domain_separator.len()))
            .and_then(|length| length.checked_add(protocol_context.len()))
            .ok_or(Error::AuthenticationContext)?;
        let mut aad = Vec::with_capacity(capacity);
        push_field(&mut aad, AEAD_AAD_LABEL)?;
        push_field(&mut aad, frame_header)?;
        push_field(&mut aad, domain_separator)?;
        push_field(&mut aad, protocol_context)?;
        Ok(aad)
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

#[cfg(all(test, feature = "aead"))]
mod tests {
    use super::{AuthenticationContext, AuthenticationMode};
    use crate::Error;

    fn expected_aad(fields: [&[u8]; 4]) -> Vec<u8> {
        let mut aad = Vec::new();
        for field in fields {
            let length = u64::try_from(field.len()).expect("test field length");
            aad.extend_from_slice(&length.to_be_bytes());
            aad.extend_from_slice(field);
        }
        aad
    }

    #[test]
    fn aead_aad_is_length_prefixed_label_header_domain_and_context() {
        let header = [7_u8; 14];

        let legacy = AuthenticationMode::LegacyPlaintext
            .aead_aad(&AuthenticationContext::legacy(), &header)
            .expect("legacy AAD");
        assert_eq!(
            legacy,
            expected_aad([
                &b"gmcrypto-envelope-lite/aead-aad/v1"[..],
                &header[..],
                &b""[..],
                &b""[..],
            ])
        );
        assert_eq!(
            legacy[0], 0x00,
            "an AAD must never begin with the transcript version byte"
        );

        let mode = AuthenticationMode::context_bound(b"domain/v1").expect("domain");
        let context = AuthenticationContext::context_bound(b"operation=aad").expect("context");
        assert_eq!(
            mode.aead_aad(&context, &header).expect("bound AAD"),
            expected_aad([
                &b"gmcrypto-envelope-lite/aead-aad/v1"[..],
                &header[..],
                &b"domain/v1"[..],
                &b"operation=aad"[..],
            ])
        );
    }

    #[test]
    fn aead_aad_rejects_context_kinds_that_do_not_match_the_mode() {
        let header = [0_u8; 14];
        let bound = AuthenticationContext::context_bound(b"operation=aad").expect("context");
        assert!(matches!(
            AuthenticationMode::LegacyPlaintext.aead_aad(&bound, &header),
            Err(Error::AuthenticationContext)
        ));

        let mode = AuthenticationMode::context_bound(b"domain/v1").expect("domain");
        assert!(matches!(
            mode.aead_aad(&AuthenticationContext::legacy(), &header),
            Err(Error::AuthenticationContext)
        ));
    }
}
