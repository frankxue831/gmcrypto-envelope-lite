//! Envelope-mode dispatch plus the helpers every payload mode shares.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use gmcrypto_core::sm2;
use zeroize::Zeroizing;

#[cfg(feature = "aead")]
use crate::client_config::EnvelopeMode;
use crate::message::SecureEnvelope;
use crate::{AuthenticationContext, ClientConfig, Error, KeyMaterial, Result};

#[cfg(feature = "aead")]
mod aead;
mod cbc;

const SESSION_KEY_BYTES: usize = 16;
const MAX_AUXILIARY_BASE64_BYTES: usize = 16 * 1024;

pub(crate) fn seal(
    config: &ClientConfig,
    keys: &KeyMaterial,
    plaintext: &[u8],
    context: &AuthenticationContext,
) -> Result<SecureEnvelope> {
    let plaintext_limit = config.max_plaintext_bytes();
    if plaintext.len() > plaintext_limit {
        return Err(Error::MessageTooLarge {
            limit: plaintext_limit,
        });
    }

    #[cfg(feature = "aead")]
    if let EnvelopeMode::Aead(algorithm) = config.envelope_mode() {
        return aead::seal(config, keys, plaintext, context, algorithm);
    }

    cbc::seal(config, keys, plaintext, context)
}

pub(crate) fn open(
    config: &ClientConfig,
    keys: &KeyMaterial,
    envelope: &SecureEnvelope,
    context: &AuthenticationContext,
) -> Result<Vec<u8>> {
    #[cfg(feature = "aead")]
    if let EnvelopeMode::Aead(algorithm) = config.envelope_mode() {
        return aead::open(config, keys, envelope, context, algorithm);
    }

    cbc::open(config, keys, envelope, context)
}

fn generate_session_key() -> Result<Zeroizing<[u8; SESSION_KEY_BYTES]>> {
    let mut session_key = Zeroizing::new([0_u8; SESSION_KEY_BYTES]);
    getrandom::fill(&mut *session_key).map_err(|_| Error::Encryption)?;
    Ok(session_key)
}

fn unwrap_session_key(
    keys: &KeyMaterial,
    wrapped_session_key: &[u8],
) -> Result<Zeroizing<[u8; SESSION_KEY_BYTES]>> {
    let unwrapped = Zeroizing::new(
        sm2::decrypt(&keys.local_decryption, wrapped_session_key)
            .map_err(|_| Error::InvalidEnvelope)?,
    );
    if unwrapped.len() != SESSION_KEY_BYTES {
        return Err(Error::InvalidEnvelope);
    }

    let mut session_key = Zeroizing::new([0_u8; SESSION_KEY_BYTES]);
    session_key.copy_from_slice(unwrapped.as_slice());
    Ok(session_key)
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    STANDARD.decode(value).map_err(|_| Error::InvalidEnvelope)
}

fn base64_len(binary_len: usize) -> usize {
    binary_len
        .checked_add(2)
        .map(|bytes| bytes / 3)
        .and_then(|groups| groups.checked_mul(4))
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
pub(crate) mod test_support {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use getrandom::SysRng;
    use gmcrypto_core::sm2::{self, Sm2PrivateKey};
    use gmcrypto_core::spki;

    use crate::{
        AuthenticationContext, AuthenticationMode, ClientConfig, Error, KeyMaterial, PrivateKey,
        PublicKey,
    };

    pub(crate) const IV: [u8; 16] = *b"0123456789abcdef";
    pub(crate) const SENDER_SIGNER_ID: &[u8] = b"sender-directional-id";
    pub(crate) const RECEIVER_SIGNER_ID: &[u8] = b"receiver-directional-id";

    pub(crate) const SENDER_SIGNING: u8 = 1;
    pub(crate) const SENDER_DECRYPTION: u8 = 2;
    pub(crate) const RECEIVER_SIGNING: u8 = 3;
    pub(crate) const RECEIVER_DECRYPTION: u8 = 4;
    pub(crate) const UNRELATED_KEY: u8 = 5;

    pub(crate) struct Peers {
        pub(crate) sender_config: ClientConfig,
        pub(crate) sender_keys: KeyMaterial,
        pub(crate) receiver_config: ClientConfig,
        pub(crate) receiver_keys: KeyMaterial,
    }

    pub(crate) fn peers(mode: AuthenticationMode, max_plaintext_bytes: usize) -> Peers {
        Peers {
            sender_config: config(
                "sender",
                SENDER_SIGNER_ID,
                RECEIVER_SIGNER_ID,
                mode.clone(),
                max_plaintext_bytes,
            ),
            sender_keys: key_material(
                SENDER_SIGNING,
                SENDER_DECRYPTION,
                RECEIVER_SIGNING,
                RECEIVER_DECRYPTION,
            ),
            receiver_config: config(
                "receiver",
                RECEIVER_SIGNER_ID,
                SENDER_SIGNER_ID,
                mode,
                max_plaintext_bytes,
            ),
            receiver_keys: key_material(
                RECEIVER_SIGNING,
                RECEIVER_DECRYPTION,
                SENDER_SIGNING,
                SENDER_DECRYPTION,
            ),
        }
    }

    pub(crate) fn config(
        name: &str,
        local_signer_id: &[u8],
        expected_remote_signer_id: &[u8],
        mode: AuthenticationMode,
        max_plaintext_bytes: usize,
    ) -> ClientConfig {
        ClientConfig::builder()
            .local_identity_id(format!("{name}-identity"))
            .api_version("test-v1")
            .local_certificate_id(format!("{name}-signing-certificate"))
            .expected_remote_signing_certificate_id(format!("{name}-remote-signing-certificate"))
            .remote_encryption_certificate_id(format!("{name}-remote-encryption-certificate"))
            .local_signer_id(local_signer_id)
            .expected_remote_signer_id(expected_remote_signer_id)
            .authentication_mode(mode)
            .iv(IV)
            .max_plaintext_bytes(max_plaintext_bytes)
            .build()
            .expect("valid test configuration")
    }

    pub(crate) fn key_material(
        local_signing: u8,
        local_decryption: u8,
        remote_verification: u8,
        remote_encryption: u8,
    ) -> KeyMaterial {
        KeyMaterial::new(
            private_key(local_signing),
            private_key(local_decryption),
            public_key(remote_verification),
            public_key(remote_encryption),
        )
    }

    fn private_key(scalar: u8) -> PrivateKey {
        PrivateKey {
            inner: raw_private_key(scalar),
        }
    }

    fn public_key(scalar: u8) -> PublicKey {
        let der = spki::encode(&raw_private_key(scalar).public_key());
        PublicKey::from_der(&der).expect("runtime SPKI public key")
    }

    pub(crate) fn raw_private_key(scalar: u8) -> Sm2PrivateKey {
        let mut bytes = [0_u8; 32];
        bytes[31] = scalar;
        Sm2PrivateKey::from_bytes_be(&bytes).expect("small nonzero SM2 scalar")
    }

    pub(crate) fn legacy_context() -> AuthenticationContext {
        AuthenticationContext::legacy()
    }

    pub(crate) fn assert_invalid_envelope(result: crate::Result<Vec<u8>>) {
        assert!(matches!(result, Err(Error::InvalidEnvelope)));
    }

    pub(crate) fn wrapped_plaintext_for_receiver(bytes: &[u8]) -> String {
        let receiver_public = raw_private_key(RECEIVER_DECRYPTION).public_key();
        let mut rng = SysRng;
        STANDARD.encode(
            sm2::encrypt(&receiver_public, bytes, &mut rng).expect("wrap test bytes for receiver"),
        )
    }

    #[cfg(feature = "aead")]
    pub(crate) fn aead_peers(mode: AuthenticationMode, max_plaintext_bytes: usize) -> Peers {
        Peers {
            sender_config: aead_config(
                "sender",
                SENDER_SIGNER_ID,
                RECEIVER_SIGNER_ID,
                mode.clone(),
                max_plaintext_bytes,
            ),
            sender_keys: key_material(
                SENDER_SIGNING,
                SENDER_DECRYPTION,
                RECEIVER_SIGNING,
                RECEIVER_DECRYPTION,
            ),
            receiver_config: aead_config(
                "receiver",
                RECEIVER_SIGNER_ID,
                SENDER_SIGNER_ID,
                mode,
                max_plaintext_bytes,
            ),
            receiver_keys: key_material(
                RECEIVER_SIGNING,
                RECEIVER_DECRYPTION,
                SENDER_SIGNING,
                SENDER_DECRYPTION,
            ),
        }
    }

    #[cfg(feature = "aead")]
    pub(crate) fn aead_config(
        name: &str,
        local_signer_id: &[u8],
        expected_remote_signer_id: &[u8],
        mode: AuthenticationMode,
        max_plaintext_bytes: usize,
    ) -> ClientConfig {
        ClientConfig::builder()
            .local_identity_id(format!("{name}-identity"))
            .api_version("test-v1")
            .local_certificate_id(format!("{name}-signing-certificate"))
            .expected_remote_signing_certificate_id(format!("{name}-remote-signing-certificate"))
            .remote_encryption_certificate_id(format!("{name}-remote-encryption-certificate"))
            .local_signer_id(local_signer_id)
            .expected_remote_signer_id(expected_remote_signer_id)
            .authentication_mode(mode)
            .envelope_mode(crate::EnvelopeMode::Aead(crate::AeadAlgorithm::Sm4Gcm))
            .max_plaintext_bytes(max_plaintext_bytes)
            .build()
            .expect("valid AEAD test configuration")
    }
}
