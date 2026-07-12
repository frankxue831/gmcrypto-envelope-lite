use std::fmt;
use std::fs;
use std::path::Path;

use gmcrypto_core::sm2::{Sm2PrivateKey, Sm2PublicKey};
use gmcrypto_core::{pem, pkcs8, spki, x509};

use crate::{Error, KeyKind, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerKeySource {
    Spki,
    Certificate,
}

/// An SDK-owned local private key loaded from encrypted PKCS#8 material.
///
/// The wrapped key is zeroized when dropped. This type deliberately does not
/// implement `Debug` or serialization traits.
pub struct PrivateKey {
    pub(crate) inner: Sm2PrivateKey,
}

impl PrivateKey {
    pub fn from_encrypted_pem(private_pem: &[u8], password: &[u8]) -> Result<Self> {
        let private_text = std::str::from_utf8(private_pem).map_err(|_| private_key_error())?;
        let private_der =
            pem::decode(private_text, "ENCRYPTED PRIVATE KEY").map_err(|_| private_key_error())?;
        Self::from_encrypted_der(&private_der, password)
    }

    pub fn from_encrypted_der(private_der: &[u8], password: &[u8]) -> Result<Self> {
        let inner = pkcs8::decrypt(private_der, password).map_err(|_| private_key_error())?;
        Ok(Self { inner })
    }

    pub fn from_encrypted_file(path: impl AsRef<Path>, password: &[u8]) -> Result<Self> {
        let path = path.as_ref();
        let private = fs::read(path).map_err(|source| Error::Io {
            operation: "read private key",
            path: path.to_path_buf(),
            source,
        })?;

        if is_pem(&private) {
            Self::from_encrypted_pem(&private, password)
        } else {
            Self::from_encrypted_der(&private, password)
        }
    }
}

/// An SDK-owned remote public key and the container it was loaded from.
#[derive(Clone, Copy)]
pub struct PublicKey {
    pub(crate) inner: Sm2PublicKey,
    source: PeerKeySource,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicKey")
            .field("source", &self.source)
            .finish()
    }
}

impl PublicKey {
    pub fn from_pem(public_pem: &[u8]) -> Result<Self> {
        let public_text = std::str::from_utf8(public_pem).map_err(|_| public_key_error())?;

        if public_text.contains("-----BEGIN PUBLIC KEY-----") {
            let public_der =
                pem::decode(public_text, "PUBLIC KEY").map_err(|_| public_key_error())?;
            return Self::from_spki_der(&public_der);
        }
        if public_text.contains("-----BEGIN CERTIFICATE-----") {
            let certificate_der =
                pem::decode(public_text, "CERTIFICATE").map_err(|_| public_key_error())?;
            return Self::from_certificate_der(&certificate_der);
        }

        Err(public_key_error())
    }

    pub fn from_der(public_der: &[u8]) -> Result<Self> {
        if let Some(inner) = spki::decode(public_der) {
            return Ok(Self {
                inner,
                source: PeerKeySource::Spki,
            });
        }
        if let Some(certificate) = x509::Certificate::from_der(public_der) {
            return Ok(Self {
                inner: certificate.subject_public_key(),
                source: PeerKeySource::Certificate,
            });
        }

        Err(public_key_error())
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let public = fs::read(path).map_err(|source| Error::Io {
            operation: "read peer key",
            path: path.to_path_buf(),
            source,
        })?;

        if is_pem(&public) {
            Self::from_pem(&public)
        } else {
            Self::from_der(&public)
        }
    }

    #[must_use]
    pub const fn source(&self) -> PeerKeySource {
        self.source
    }

    fn from_spki_der(public_der: &[u8]) -> Result<Self> {
        let inner = spki::decode(public_der).ok_or_else(public_key_error)?;
        Ok(Self {
            inner,
            source: PeerKeySource::Spki,
        })
    }

    fn from_certificate_der(certificate_der: &[u8]) -> Result<Self> {
        let certificate =
            x509::Certificate::from_der(certificate_der).ok_or_else(public_key_error)?;
        Ok(Self {
            inner: certificate.subject_public_key(),
            source: PeerKeySource::Certificate,
        })
    }
}

/// Validated local and remote keys assigned to four directional envelope roles.
pub struct KeyMaterial {
    pub(crate) local_signing: Sm2PrivateKey,
    pub(crate) local_decryption: Sm2PrivateKey,
    pub(crate) remote_verification: Sm2PublicKey,
    pub(crate) remote_encryption: Sm2PublicKey,
    remote_verification_source: PeerKeySource,
    remote_encryption_source: PeerKeySource,
    shared_roles: bool,
}

impl KeyMaterial {
    /// Assigns independent keys to local signing, local decryption, remote verification, and
    /// remote encryption roles, in that order.
    #[must_use]
    pub fn new(
        local_signing: PrivateKey,
        local_decryption: PrivateKey,
        remote_verification: PublicKey,
        remote_encryption: PublicKey,
    ) -> Self {
        Self {
            local_signing: local_signing.inner,
            local_decryption: local_decryption.inner,
            remote_verification: remote_verification.inner,
            remote_encryption: remote_encryption.inner,
            remote_verification_source: remote_verification.source,
            remote_encryption_source: remote_encryption.source,
            shared_roles: false,
        }
    }

    /// Reuses one local private key for signing and decryption and one remote public key for
    /// verification and encryption.
    ///
    /// Use this only when the protocol explicitly assigns the same key to both local roles and
    /// the same key to both remote roles. Otherwise load each key separately and call [`Self::new`].
    #[must_use]
    pub fn shared(local: PrivateKey, remote: PublicKey) -> Self {
        Self {
            local_signing: local.inner.clone(),
            local_decryption: local.inner,
            remote_verification: remote.inner,
            remote_encryption: remote.inner,
            remote_verification_source: remote.source,
            remote_encryption_source: remote.source,
            shared_roles: true,
        }
    }

    /// Loads PEM material and explicitly reuses the local key for signing and decryption and the
    /// remote key for verification and encryption.
    ///
    /// Use this only when the protocol defines shared roles. Role-specific protocols should use
    /// [`PrivateKey`] and [`PublicKey`] loaders followed by [`Self::new`].
    pub fn shared_from_pem(private_pem: &[u8], password: &[u8], peer_pem: &[u8]) -> Result<Self> {
        let local = PrivateKey::from_encrypted_pem(private_pem, password)?;
        let remote = PublicKey::from_pem(peer_pem)?;
        Ok(Self::shared(local, remote))
    }

    /// Loads DER material and explicitly reuses the local key for signing and decryption and the
    /// remote key for verification and encryption.
    ///
    /// Use this only when the protocol defines shared roles. Role-specific protocols should use
    /// [`PrivateKey`] and [`PublicKey`] loaders followed by [`Self::new`].
    pub fn shared_from_der(private_der: &[u8], password: &[u8], peer_der: &[u8]) -> Result<Self> {
        let local = PrivateKey::from_encrypted_der(private_der, password)?;
        let remote = PublicKey::from_der(peer_der)?;
        Ok(Self::shared(local, remote))
    }

    /// Reads both key files before parsing either one, then explicitly reuses the local key for
    /// signing and decryption and the remote key for verification and encryption.
    ///
    /// Use this only when the protocol defines shared roles. Role-specific protocols should use
    /// [`PrivateKey::from_encrypted_file`] and [`PublicKey::from_file`] followed by [`Self::new`].
    pub fn shared_from_files(
        private_path: impl AsRef<Path>,
        password: &[u8],
        peer_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let private_path = private_path.as_ref();
        let peer_path = peer_path.as_ref();
        let private = fs::read(private_path).map_err(|source| Error::Io {
            operation: "read private key",
            path: private_path.to_path_buf(),
            source,
        })?;
        let peer = fs::read(peer_path).map_err(|source| Error::Io {
            operation: "read peer key",
            path: peer_path.to_path_buf(),
            source,
        })?;

        let local = if is_pem(&private) {
            PrivateKey::from_encrypted_pem(&private, password)?
        } else {
            PrivateKey::from_encrypted_der(&private, password)?
        };
        let remote = if is_pem(&peer) {
            PublicKey::from_pem(&peer)?
        } else {
            PublicKey::from_der(&peer)?
        };
        Ok(Self::shared(local, remote))
    }

    /// Returns whether this value was created with explicit shared local and remote roles.
    #[must_use]
    pub const fn uses_shared_roles(&self) -> bool {
        self.shared_roles
    }

    /// Returns the container type from which the remote verification key was loaded.
    #[must_use]
    pub const fn remote_verification_source(&self) -> PeerKeySource {
        self.remote_verification_source
    }

    /// Returns the container type from which the remote encryption key was loaded.
    #[must_use]
    pub const fn remote_encryption_source(&self) -> PeerKeySource {
        self.remote_encryption_source
    }
}

fn private_key_error() -> Error {
    Error::KeyMaterial {
        kind: KeyKind::LocalPrivate,
    }
}

fn public_key_error() -> Error {
    Error::KeyMaterial {
        kind: KeyKind::PeerPublic,
    }
}

fn is_pem(input: &[u8]) -> bool {
    input.starts_with(b"-----BEGIN ")
}
