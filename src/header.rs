use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::{Error, Result};

/// An SDK-owned, case-insensitive transport header name.
#[derive(Clone)]
pub struct HeaderName {
    original: String,
    canonical: String,
}

impl HeaderName {
    /// Creates a header name from a nonempty ASCII RFC token.
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let original = name.into();
        if original.is_empty() || !original.bytes().all(is_token_byte) {
            return Err(Error::InvalidHeader);
        }

        let canonical = original.to_ascii_lowercase();
        Ok(Self {
            original,
            canonical,
        })
    }

    /// Returns the header name with its original wire casing.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.original
    }
}

impl fmt::Debug for HeaderName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HeaderName")
            .field(&self.original)
            .finish()
    }
}

impl PartialEq for HeaderName {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for HeaderName {}

impl PartialOrd for HeaderName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeaderName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical.cmp(&other.canonical)
    }
}

impl Hash for HeaderName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

/// An SDK-owned transport header value that is safe to place on one wire line.
#[derive(Clone, PartialEq, Eq)]
pub struct HeaderValue(String);

impl HeaderValue {
    /// Creates a value without CR, LF, NUL, DEL, or disallowed C0 controls.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.chars().any(is_disallowed_value_character) {
            return Err(Error::InvalidHeader);
        }
        Ok(Self(value))
    }

    /// Returns the validated header value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HeaderValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HeaderValue")
            .field(&"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct HeaderCollection {
    entries: Vec<(HeaderName, HeaderValue)>,
}

impl HeaderCollection {
    #[cfg(test)]
    pub(crate) fn from_unchecked_for_test(entries: Vec<(HeaderName, HeaderValue)>) -> Self {
        Self { entries }
    }

    pub(crate) fn from_pairs<I, K, V>(headers: I) -> Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut collection = Self::default();
        for (name, value) in headers {
            collection.insert(name, value)?;
        }
        Ok(collection)
    }

    pub(crate) fn from_typed_pairs<I>(headers: I) -> Result<Self>
    where
        I: IntoIterator<Item = (HeaderName, HeaderValue)>,
    {
        let mut collection = Self::default();
        for (name, value) in headers {
            collection.insert_typed(name, value)?;
        }
        collection.revalidate()?;
        Ok(collection)
    }

    pub(crate) fn insert(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<()> {
        let name = HeaderName::new(name)?;
        let value = HeaderValue::new(value)?;
        self.insert_typed(name, value)
    }

    pub(crate) fn append_checked(&mut self, other: &Self) -> Result<()> {
        self.revalidate()?;
        other.revalidate()?;

        if other
            .entries
            .iter()
            .any(|(candidate, _)| self.entries.iter().any(|(name, _)| name == candidate))
        {
            return Err(Error::HeaderConflict);
        }

        self.entries.extend(other.entries.iter().cloned());
        Ok(())
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        let mut validated = Self::default();
        for (name, value) in &self.entries {
            validated.insert(name.as_str(), value.as_str())?;
        }
        Ok(())
    }

    pub(crate) fn get(&self, name: &str) -> Option<&HeaderValue> {
        self.entries
            .iter()
            .find(|(candidate, _)| candidate.as_str().eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = (&HeaderName, &HeaderValue)> {
        self.entries.iter().map(|(name, value)| (name, value))
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn into_pairs(self) -> Vec<(HeaderName, HeaderValue)> {
        self.entries
    }

    fn insert_typed(&mut self, name: HeaderName, value: HeaderValue) -> Result<()> {
        if self.entries.iter().any(|(candidate, _)| candidate == &name) {
            return Err(Error::HeaderConflict);
        }
        self.entries.push((name, value));
        Ok(())
    }
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_disallowed_value_character(character: char) -> bool {
    (character <= '\u{1f}' && character != '\t') || character == '\u{7f}'
}

#[cfg(test)]
mod tests {
    use super::HeaderCollection;
    use crate::Error;

    #[test]
    fn checked_append_rejects_cross_collection_collision_atomically() {
        let mut emitted =
            HeaderCollection::from_pairs([("X-Demo", "protocol")]).expect("emitted headers");
        let additional =
            HeaderCollection::from_pairs([("x-demo", "caller")]).expect("additional headers");
        let before = emitted.clone();

        assert!(matches!(
            emitted.append_checked(&additional),
            Err(Error::HeaderConflict)
        ));
        assert_eq!(emitted, before);
    }
}
