use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use getrandom::SysRng;
use gmcrypto_core::{sm2, sm4};
use zeroize::Zeroizing;

use crate::message::SecureEnvelope;
use crate::{AuthenticationContext, ClientConfig, Error, KeyMaterial, Result};

const SM4_BLOCK_BYTES: usize = 16;
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

    let authentication_input = config
        .authentication_mode()
        .authentication_input(context, plaintext)?;

    let mut session_key = Zeroizing::new([0_u8; SM4_BLOCK_BYTES]);
    getrandom::fill(&mut *session_key).map_err(|_| Error::Encryption)?;

    let cipher = sm4::mode_cbc::encrypt(&session_key, config.iv(), plaintext);
    let mut rng = SysRng;
    let wrapped_session_key = sm2::encrypt(&keys.remote_encryption, &session_key[..], &mut rng)
        .map_err(|_| Error::Encryption)?;
    let signature = sm2::sign_with_id(
        &keys.local_signing,
        config.local_signer_id(),
        authentication_input.as_slice(),
        &mut rng,
    )
    .map_err(|_| Error::Encryption)?;

    Ok(SecureEnvelope {
        cipher: STANDARD.encode(cipher),
        wrapped_session_key: STANDARD.encode(wrapped_session_key),
        signature: STANDARD.encode(signature),
    })
}

pub(crate) fn open(
    config: &ClientConfig,
    keys: &KeyMaterial,
    envelope: &SecureEnvelope,
    context: &AuthenticationContext,
) -> Result<Vec<u8>> {
    let plaintext_limit = config.max_plaintext_bytes();
    let max_cipher_bytes = padded_cipher_len(plaintext_limit);
    let max_cipher_base64_bytes = base64_len(max_cipher_bytes);

    if envelope.cipher.len() > max_cipher_base64_bytes {
        return Err(Error::MessageTooLarge {
            limit: plaintext_limit,
        });
    }
    if envelope.wrapped_session_key.len() > MAX_AUXILIARY_BASE64_BYTES
        || envelope.signature.len() > MAX_AUXILIARY_BASE64_BYTES
    {
        return Err(Error::InvalidEnvelope);
    }

    let cipher = decode_base64(&envelope.cipher)?;
    if cipher.len() > max_cipher_bytes {
        return Err(Error::InvalidEnvelope);
    }
    let wrapped_session_key = decode_base64(&envelope.wrapped_session_key)?;
    let signature = decode_base64(&envelope.signature)?;

    let unwrapped_session_key = Zeroizing::new(
        sm2::decrypt(&keys.local_decryption, &wrapped_session_key)
            .map_err(|_| Error::InvalidEnvelope)?,
    );
    if unwrapped_session_key.len() != SM4_BLOCK_BYTES {
        return Err(Error::InvalidEnvelope);
    }

    let mut session_key = Zeroizing::new([0_u8; SM4_BLOCK_BYTES]);
    session_key.copy_from_slice(unwrapped_session_key.as_slice());

    let plaintext = Zeroizing::new(
        sm4::mode_cbc::decrypt(&session_key, config.iv(), &cipher).ok_or(Error::InvalidEnvelope)?,
    );
    if plaintext.len() > plaintext_limit {
        return Err(Error::InvalidEnvelope);
    }

    let authentication_input = config
        .authentication_mode()
        .authentication_input(context, plaintext.as_slice())
        .map_err(|_| Error::InvalidEnvelope)?;
    if !sm2::verify_with_id(
        &keys.remote_verification,
        config.expected_remote_signer_id(),
        authentication_input.as_slice(),
        &signature,
    ) {
        return Err(Error::InvalidEnvelope);
    }

    Ok(plaintext.to_vec())
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    STANDARD.decode(value).map_err(|_| Error::InvalidEnvelope)
}

fn padded_cipher_len(plaintext_limit: usize) -> usize {
    plaintext_limit
        .checked_div(SM4_BLOCK_BYTES)
        .and_then(|blocks| blocks.checked_add(1))
        .and_then(|blocks| blocks.checked_mul(SM4_BLOCK_BYTES))
        .unwrap_or(usize::MAX)
}

fn base64_len(binary_len: usize) -> usize {
    binary_len
        .checked_add(2)
        .map(|bytes| bytes / 3)
        .and_then(|groups| groups.checked_mul(4))
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use getrandom::SysRng;
    use gmcrypto_core::sm2::{self, Sm2PrivateKey};
    use gmcrypto_core::spki;
    use zeroize::Zeroizing;

    use super::{open, seal};
    use crate::message::SecureEnvelope;
    use crate::{
        AuthenticationContext, AuthenticationMode, ClientConfig, Error, KeyMaterial, PrivateKey,
        PublicKey,
    };

    const IV: [u8; 16] = *b"0123456789abcdef";
    const SENDER_SIGNER_ID: &[u8] = b"sender-directional-id";
    const RECEIVER_SIGNER_ID: &[u8] = b"receiver-directional-id";

    const SENDER_SIGNING: u8 = 1;
    const SENDER_DECRYPTION: u8 = 2;
    const RECEIVER_SIGNING: u8 = 3;
    const RECEIVER_DECRYPTION: u8 = 4;
    const UNRELATED_KEY: u8 = 5;

    struct Peers {
        sender_config: ClientConfig,
        sender_keys: KeyMaterial,
        receiver_config: ClientConfig,
        receiver_keys: KeyMaterial,
    }

    fn peers(mode: AuthenticationMode, max_plaintext_bytes: usize) -> Peers {
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

    fn config(
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

    fn key_material(
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

    fn raw_private_key(scalar: u8) -> Sm2PrivateKey {
        let mut bytes = [0_u8; 32];
        bytes[31] = scalar;
        Sm2PrivateKey::from_bytes_be(&bytes).expect("small nonzero SM2 scalar")
    }

    fn legacy_context() -> AuthenticationContext {
        AuthenticationContext::legacy()
    }

    fn assert_invalid_envelope(result: crate::Result<Vec<u8>>) {
        assert!(matches!(result, Err(Error::InvalidEnvelope)));
    }

    fn wrapped_plaintext_for_receiver(bytes: &[u8]) -> String {
        let receiver_public = raw_private_key(RECEIVER_DECRYPTION).public_key();
        let mut rng = SysRng;
        STANDARD.encode(
            sm2::encrypt(&receiver_public, bytes, &mut rng).expect("wrap test bytes for receiver"),
        )
    }

    #[test]
    fn legacy_exact_plaintext_round_trips_in_both_directions_with_distinct_roles() {
        let peers = peers(AuthenticationMode::LegacyPlaintext, 256);
        let context = legacy_context();
        let sender_plaintext = b"sender signs exactly these bytes\0with no framing";

        let sender_envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            sender_plaintext,
            &context,
        )
        .expect("sender seals");
        let sender_signature = STANDARD
            .decode(&sender_envelope.signature)
            .expect("signature Base64");
        assert!(sm2::verify_with_id(
            &raw_private_key(SENDER_SIGNING).public_key(),
            SENDER_SIGNER_ID,
            sender_plaintext,
            &sender_signature,
        ));
        assert_eq!(
            open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &sender_envelope,
                &context,
            )
            .expect("receiver opens"),
            sender_plaintext
        );

        let receiver_plaintext = b"receiver response uses inverse directional roles";
        let receiver_envelope = seal(
            &peers.receiver_config,
            &peers.receiver_keys,
            receiver_plaintext,
            &context,
        )
        .expect("receiver seals");
        assert_eq!(
            open(
                &peers.sender_config,
                &peers.sender_keys,
                &receiver_envelope,
                &context,
            )
            .expect("sender opens"),
            receiver_plaintext
        );
    }

    #[test]
    fn context_bound_round_trip_rejects_different_or_wrong_context_kinds() {
        let mode = AuthenticationMode::context_bound(b"example/request/v1")
            .expect("nonempty domain separator");
        let peers = peers(mode, 256);
        let context =
            AuthenticationContext::context_bound(b"operation=pay&id=17").expect("bound context");
        let envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"context-bound payload",
            &context,
        )
        .expect("seal context-bound payload");

        assert_eq!(
            open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &envelope,
                &context,
            )
            .expect("matching context opens"),
            b"context-bound payload"
        );

        let different = AuthenticationContext::context_bound(b"operation=pay&id=18")
            .expect("different bound context");
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &envelope,
            &different,
        ));
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &envelope,
            &legacy_context(),
        ));

        let seal_error = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"wrong context kind",
            &legacy_context(),
        )
        .expect_err("outbound context mismatch must be specific");
        assert!(matches!(seal_error, Error::AuthenticationContext));
    }

    #[test]
    fn context_bound_round_trip_preserves_exact_unicode_utf8_bytes() {
        let mode = AuthenticationMode::context_bound(b"example/unicode/v1")
            .expect("nonempty domain separator");
        let peers = peers(mode, 256);
        let context =
            AuthenticationContext::context_bound(b"operation=unicode").expect("bound context");
        let plaintext = "你好，secure envelope 🔐 — café".as_bytes();
        let envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            plaintext,
            &context,
        )
        .expect("seal Unicode UTF-8 bytes");

        assert_eq!(
            open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &envelope,
                &context,
            )
            .expect("open Unicode UTF-8 bytes"),
            plaintext
        );
    }

    #[test]
    fn context_bound_domain_separator_is_part_of_the_verified_transcript() {
        let sender_mode =
            AuthenticationMode::context_bound(b"example/request/v1").expect("sender domain");
        let receiver_mode =
            AuthenticationMode::context_bound(b"example/response/v1").expect("receiver domain");
        let peers = peers(sender_mode, 256);
        let mismatched_receiver_config = config(
            "receiver",
            RECEIVER_SIGNER_ID,
            SENDER_SIGNER_ID,
            receiver_mode,
            256,
        );
        let context =
            AuthenticationContext::context_bound(b"operation=pay&id=17").expect("bound context");
        let envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"domain-separated payload",
            &context,
        )
        .expect("seal with sender domain");

        assert_invalid_envelope(open(
            &mismatched_receiver_config,
            &peers.receiver_keys,
            &envelope,
            &context,
        ));
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let peers = peers(AuthenticationMode::LegacyPlaintext, 32);
        let envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"",
            &legacy_context(),
        )
        .expect("seal empty plaintext");

        assert_eq!(
            open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &envelope,
                &legacy_context(),
            )
            .expect("open empty plaintext"),
            b""
        );
    }

    #[test]
    fn every_seal_uses_a_fresh_random_session_key() {
        let peers = peers(AuthenticationMode::LegacyPlaintext, 128);
        let plaintext = b"same payload";
        let first = seal(
            &peers.sender_config,
            &peers.sender_keys,
            plaintext,
            &legacy_context(),
        )
        .expect("first seal");
        let second = seal(
            &peers.sender_config,
            &peers.sender_keys,
            plaintext,
            &legacy_context(),
        )
        .expect("second seal");

        assert_ne!(first.cipher, second.cipher);
        let receiver_private = raw_private_key(RECEIVER_DECRYPTION);
        let first_wrapped = STANDARD
            .decode(first.wrapped_session_key)
            .expect("first wrapped key Base64");
        let second_wrapped = STANDARD
            .decode(second.wrapped_session_key)
            .expect("second wrapped key Base64");
        let first_key = Zeroizing::new(
            sm2::decrypt(&receiver_private, &first_wrapped).expect("unwrap first session key"),
        );
        let second_key = Zeroizing::new(
            sm2::decrypt(&receiver_private, &second_wrapped).expect("unwrap second session key"),
        );
        assert_ne!(*first_key, *second_key);
    }

    #[test]
    fn seal_rejects_plaintext_over_the_configured_limit() {
        let peers = peers(AuthenticationMode::LegacyPlaintext, 8);
        let error = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"123456789",
            &legacy_context(),
        )
        .expect_err("oversized outbound plaintext");

        assert!(matches!(error, Error::MessageTooLarge { limit: 8 }));
    }

    #[test]
    fn oversized_encoded_or_decoded_cipher_is_rejected_before_key_operations() {
        // A 17-byte maximum pads to 32 bytes, whose padded Base64 length is 44.
        let peers = peers(AuthenticationMode::LegacyPlaintext, 17);
        let encoded_too_large = SecureEnvelope {
            cipher: "!".repeat(45),
            wrapped_session_key: "not Base64".to_owned(),
            signature: "not Base64".to_owned(),
        };
        let encoded_error = open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &encoded_too_large,
            &legacy_context(),
        )
        .expect_err("encoded cipher is over its public bound");
        assert!(matches!(
            encoded_error,
            Error::MessageTooLarge { limit: 17 }
        ));

        // 33 bytes still encode to 44 Base64 characters, so the decoded bound is separate
        // and opaque like every failure after strict decoding begins.
        let decoded_too_large = SecureEnvelope {
            cipher: STANDARD.encode([0_u8; 33]),
            wrapped_session_key: "not Base64".to_owned(),
            signature: "not Base64".to_owned(),
        };
        let decoded_error = open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &decoded_too_large,
            &legacy_context(),
        )
        .expect_err("decoded cipher is over its public bound");
        assert!(matches!(decoded_error, Error::InvalidEnvelope));
    }

    #[test]
    fn invalid_base64_in_any_envelope_field_is_indistinguishable() {
        let peers = peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"valid envelope",
            &legacy_context(),
        )
        .expect("seal valid envelope");

        for invalid in [
            SecureEnvelope {
                cipher: "!!!!".to_owned(),
                ..valid.clone()
            },
            SecureEnvelope {
                wrapped_session_key: "!!!!".to_owned(),
                ..valid.clone()
            },
            SecureEnvelope {
                signature: "!!!!".to_owned(),
                ..valid.clone()
            },
        ] {
            assert_invalid_envelope(open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &invalid,
                &legacy_context(),
            ));
        }
    }

    #[test]
    fn base64_requires_canonical_trailing_bits_and_standard_padding() {
        let peers = peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"canonical Base64 envelope",
            &legacy_context(),
        )
        .expect("seal valid envelope");

        for invalid in [
            SecureEnvelope {
                cipher: "AA".to_owned(),
                ..valid.clone()
            },
            SecureEnvelope {
                wrapped_session_key: "AB==".to_owned(),
                ..valid.clone()
            },
            SecureEnvelope {
                signature: "AA".to_owned(),
                ..valid.clone()
            },
        ] {
            assert_invalid_envelope(open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &invalid,
                &legacy_context(),
            ));
        }
    }

    #[test]
    fn malformed_wrapped_keys_and_wrong_length_unwrapped_keys_are_indistinguishable() {
        let peers = peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"wrapped key failures",
            &legacy_context(),
        )
        .expect("seal valid envelope");

        let malformed = SecureEnvelope {
            wrapped_session_key: STANDARD.encode(b"not SM2 DER"),
            ..valid.clone()
        };
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &malformed,
            &legacy_context(),
        ));

        let wrong_length = SecureEnvelope {
            wrapped_session_key: wrapped_plaintext_for_receiver(b"not-16-bytes"),
            ..valid
        };
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &wrong_length,
            &legacy_context(),
        ));
    }

    #[test]
    fn wrong_decryption_key_is_an_invalid_envelope() {
        let peers = peers(AuthenticationMode::LegacyPlaintext, 128);
        let envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"encrypted for receiver decryption role",
            &legacy_context(),
        )
        .expect("seal valid envelope");
        let wrong_keys = key_material(
            RECEIVER_SIGNING,
            UNRELATED_KEY,
            SENDER_SIGNING,
            SENDER_DECRYPTION,
        );

        assert_invalid_envelope(open(
            &peers.receiver_config,
            &wrong_keys,
            &envelope,
            &legacy_context(),
        ));
    }

    #[test]
    fn cbc_padding_and_cipher_tampering_is_an_invalid_envelope() {
        let peers = peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = seal(
            &peers.sender_config,
            &peers.sender_keys,
            &[b'x'; 17],
            &legacy_context(),
        )
        .expect("seal two-block cipher");

        let mut bad_padding = STANDARD.decode(&valid.cipher).expect("cipher Base64");
        // The original final padding byte is 0x0f. Changing the preceding CBC block's
        // corresponding byte by 0x0f makes that final plaintext byte zero deterministically.
        let previous_block_last_byte = bad_padding.len() - 17;
        bad_padding[previous_block_last_byte] ^= 0x0f;
        let bad_padding = SecureEnvelope {
            cipher: STANDARD.encode(bad_padding),
            ..valid.clone()
        };
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &bad_padding,
            &legacy_context(),
        ));

        let mut changed_cipher = STANDARD.decode(&valid.cipher).expect("cipher Base64");
        changed_cipher[0] ^= 1;
        let changed_cipher = SecureEnvelope {
            cipher: STANDARD.encode(changed_cipher),
            ..valid
        };
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &changed_cipher,
            &legacy_context(),
        ));
    }

    #[test]
    fn signature_tampering_and_wrong_verification_key_are_indistinguishable() {
        let peers = peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"decrypted plaintext must remain unverified",
            &legacy_context(),
        )
        .expect("seal valid envelope");

        let mut signature = STANDARD.decode(&valid.signature).expect("signature Base64");
        let final_byte = signature.len() - 1;
        signature[final_byte] ^= 1;
        let tampered = SecureEnvelope {
            signature: STANDARD.encode(signature),
            ..valid.clone()
        };
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &tampered,
            &legacy_context(),
        ));

        let wrong_keys = key_material(
            RECEIVER_SIGNING,
            RECEIVER_DECRYPTION,
            UNRELATED_KEY,
            SENDER_DECRYPTION,
        );
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &wrong_keys,
            &valid,
            &legacy_context(),
        ));
    }

    #[test]
    fn oversized_wrapped_key_and_signature_inputs_are_bounded() {
        let peers = peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"bounded auxiliary fields",
            &legacy_context(),
        )
        .expect("seal valid envelope");
        let oversized = "A".repeat(16 * 1024 + 1);

        let wrapped = SecureEnvelope {
            wrapped_session_key: oversized.clone(),
            ..valid.clone()
        };
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &wrapped,
            &legacy_context(),
        ));

        let signature = SecureEnvelope {
            signature: oversized,
            ..valid
        };
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &signature,
            &legacy_context(),
        ));
    }

    #[test]
    fn configured_plaintext_boundary_round_trips() {
        let peers = peers(AuthenticationMode::LegacyPlaintext, 64);
        let plaintext = [0xa5_u8; 64];
        let envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            &plaintext,
            &legacy_context(),
        )
        .expect("seal boundary-size plaintext");

        assert_eq!(
            open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &envelope,
                &legacy_context(),
            )
            .expect("open boundary-size plaintext"),
            plaintext
        );
    }

    #[test]
    fn post_decrypt_oversize_and_unverified_plaintext_are_never_returned() {
        let sealing_peers = peers(AuthenticationMode::LegacyPlaintext, 18);
        let opening_peers = peers(AuthenticationMode::LegacyPlaintext, 17);
        let envelope = seal(
            &sealing_peers.sender_config,
            &sealing_peers.sender_keys,
            &[b'z'; 18],
            &legacy_context(),
        )
        .expect("seal payload within the sender's limit");

        assert_invalid_envelope(open(
            &opening_peers.receiver_config,
            &opening_peers.receiver_keys,
            &envelope,
            &legacy_context(),
        ));

        let mut unverified = envelope;
        unverified.signature = STANDARD.encode(b"malformed signature");
        assert_invalid_envelope(open(
            &sealing_peers.receiver_config,
            &sealing_peers.receiver_keys,
            &unverified,
            &legacy_context(),
        ));
    }
}
