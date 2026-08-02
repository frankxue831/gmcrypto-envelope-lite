//! The SM4-GCM authenticated-encryption payload mode.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use getrandom::SysRng;
use gmcrypto_core::{sm2, sm4};
use zeroize::Zeroizing;

use super::{
    MAX_AUXILIARY_BASE64_BYTES, base64_len, decode_base64, generate_session_key, unwrap_session_key,
};
use crate::client_config::AeadAlgorithm;
use crate::message::SecureEnvelope;
use crate::{AuthenticationContext, ClientConfig, Error, KeyMaterial, Result};

const FRAME_VERSION: u8 = 0x01;
const ALGORITHM_SM4_GCM: u8 = 0x01;
const FRAME_HEADER_BYTES: usize = 14;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const FRAME_OVERHEAD_BYTES: usize = FRAME_HEADER_BYTES + TAG_BYTES;

fn algorithm_byte(algorithm: AeadAlgorithm) -> u8 {
    match algorithm {
        AeadAlgorithm::Sm4Gcm => ALGORITHM_SM4_GCM,
    }
}

pub(super) fn seal(
    config: &ClientConfig,
    keys: &KeyMaterial,
    plaintext: &[u8],
    context: &AuthenticationContext,
    algorithm: AeadAlgorithm,
) -> Result<SecureEnvelope> {
    let authentication_input = config
        .authentication_mode()
        .authentication_input(context, plaintext)?;

    let session_key = generate_session_key()?;
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| Error::Encryption)?;

    let mut frame_header = [0_u8; FRAME_HEADER_BYTES];
    frame_header[0] = FRAME_VERSION;
    frame_header[1] = algorithm_byte(algorithm);
    frame_header[2..].copy_from_slice(&nonce);
    let aad = config
        .authentication_mode()
        .aead_aad(context, &frame_header)?;

    let (ciphertext, tag) =
        sm4::mode_gcm::encrypt(&session_key, &nonce, &aad, plaintext).ok_or(Error::Encryption)?;

    let frame_len = FRAME_OVERHEAD_BYTES
        .checked_add(ciphertext.len())
        .ok_or(Error::Encryption)?;
    let mut frame = Vec::with_capacity(frame_len);
    frame.extend_from_slice(&frame_header);
    frame.extend_from_slice(&ciphertext);
    frame.extend_from_slice(&tag);

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
        cipher: STANDARD.encode(frame),
        wrapped_session_key: STANDARD.encode(wrapped_session_key),
        signature: STANDARD.encode(signature),
    })
}

pub(super) fn open(
    config: &ClientConfig,
    keys: &KeyMaterial,
    envelope: &SecureEnvelope,
    context: &AuthenticationContext,
    algorithm: AeadAlgorithm,
) -> Result<Vec<u8>> {
    let plaintext_limit = config.max_plaintext_bytes();
    let max_frame_bytes = plaintext_limit.saturating_add(FRAME_OVERHEAD_BYTES);

    if envelope.cipher.len() > base64_len(max_frame_bytes) {
        return Err(Error::MessageTooLarge {
            limit: plaintext_limit,
        });
    }
    if envelope.wrapped_session_key.len() > MAX_AUXILIARY_BASE64_BYTES
        || envelope.signature.len() > MAX_AUXILIARY_BASE64_BYTES
    {
        return Err(Error::InvalidEnvelope);
    }

    let frame = decode_base64(&envelope.cipher)?;
    let wrapped_session_key = decode_base64(&envelope.wrapped_session_key)?;
    let signature = decode_base64(&envelope.signature)?;

    if frame.len() < FRAME_OVERHEAD_BYTES {
        return Err(Error::InvalidEnvelope);
    }
    if frame[0] != FRAME_VERSION || frame[1] != algorithm_byte(algorithm) {
        return Err(Error::InvalidEnvelope);
    }
    let (header_bytes, body) = frame.split_at(FRAME_HEADER_BYTES);
    let ciphertext_len = body.len() - TAG_BYTES;
    if ciphertext_len > plaintext_limit {
        return Err(Error::InvalidEnvelope);
    }
    let (ciphertext, tag_bytes) = body.split_at(ciphertext_len);
    let mut frame_header = [0_u8; FRAME_HEADER_BYTES];
    frame_header.copy_from_slice(header_bytes);
    let mut tag = [0_u8; TAG_BYTES];
    tag.copy_from_slice(tag_bytes);
    let nonce = &frame_header[2..];

    let session_key = unwrap_session_key(keys, &wrapped_session_key)?;
    let aad = config
        .authentication_mode()
        .aead_aad(context, &frame_header)
        .map_err(|_| Error::InvalidEnvelope)?;
    let plaintext = Zeroizing::new(
        sm4::mode_gcm::decrypt(&session_key, nonce, &aad, ciphertext, &tag)
            .ok_or(Error::InvalidEnvelope)?,
    );

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

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use gmcrypto_core::sm2;
    use zeroize::Zeroizing;

    use crate::envelope_crypto::test_support::{
        RECEIVER_DECRYPTION, RECEIVER_SIGNING, SENDER_DECRYPTION, SENDER_SIGNING, UNRELATED_KEY,
        aead_peers, assert_invalid_envelope, key_material, legacy_context, raw_private_key,
        wrapped_plaintext_for_receiver,
    };
    use crate::envelope_crypto::{open, seal};
    use crate::message::SecureEnvelope;
    use crate::{AuthenticationContext, AuthenticationMode, Error};

    const FRAME_HEADER_BYTES: usize = 14;
    const FRAME_OVERHEAD_BYTES: usize = 30;
    const TAG_BYTES: usize = 16;

    #[test]
    fn aead_round_trips_in_both_directions_with_distinct_roles() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 256);
        let context = legacy_context();
        let request = b"aead request payload \x00 with binary bytes";

        let envelope = seal(&peers.sender_config, &peers.sender_keys, request, &context)
            .expect("sender seals");
        let frame = STANDARD.decode(&envelope.cipher).expect("cipher Base64");
        assert_eq!(frame.len(), request.len() + FRAME_OVERHEAD_BYTES);
        assert_eq!(frame[0], 0x01, "frame version");
        assert_eq!(frame[1], 0x01, "SM4-GCM algorithm id");
        assert_eq!(
            open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &envelope,
                &context,
            )
            .expect("receiver opens"),
            request
        );

        let response = b"aead response uses inverse directional roles";
        let reply = seal(
            &peers.receiver_config,
            &peers.receiver_keys,
            response,
            &context,
        )
        .expect("receiver seals");
        assert_eq!(
            open(&peers.sender_config, &peers.sender_keys, &reply, &context).expect("sender opens"),
            response
        );
    }

    #[test]
    fn aead_context_bound_round_trip_rejects_wrong_or_mismatched_contexts() {
        let mode = AuthenticationMode::context_bound(b"example/aead/v1").expect("domain");
        let peers = aead_peers(mode, 256);
        let context =
            AuthenticationContext::context_bound(b"operation=pay&id=17").expect("bound context");
        let envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"context-bound aead payload",
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
            b"context-bound aead payload"
        );

        let different =
            AuthenticationContext::context_bound(b"operation=pay&id=18").expect("other context");
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
    fn aead_round_trips_empty_boundary_and_unicode_plaintext() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 64);
        for plaintext in [
            &b""[..],
            &[0xa5_u8; 64][..],
            "你好，secure envelope 🔐 — café".as_bytes(),
        ] {
            let envelope = seal(
                &peers.sender_config,
                &peers.sender_keys,
                plaintext,
                &legacy_context(),
            )
            .expect("seal boundary payload");
            assert_eq!(
                open(
                    &peers.receiver_config,
                    &peers.receiver_keys,
                    &envelope,
                    &legacy_context(),
                )
                .expect("open boundary payload"),
                plaintext
            );
        }
    }

    #[test]
    fn every_aead_seal_uses_a_fresh_session_key_and_nonce() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 128);
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

        let first_frame = STANDARD.decode(&first.cipher).expect("first frame");
        let second_frame = STANDARD.decode(&second.cipher).expect("second frame");
        assert_ne!(
            first_frame[2..FRAME_HEADER_BYTES],
            second_frame[2..FRAME_HEADER_BYTES],
            "nonces must differ"
        );
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
    fn aead_seal_rejects_plaintext_over_the_configured_limit() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 8);
        let error = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"123456789",
            &legacy_context(),
        )
        .expect_err("oversized outbound plaintext");
        assert!(matches!(error, Error::MessageTooLarge { limit: 8 }));
    }

    fn valid_envelope(peers: &crate::envelope_crypto::test_support::Peers) -> SecureEnvelope {
        seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"aead negative-matrix payload",
            &legacy_context(),
        )
        .expect("seal valid AEAD envelope")
    }

    fn with_mutated_frame(
        valid: &SecureEnvelope,
        mutate: impl FnOnce(&mut Vec<u8>),
    ) -> SecureEnvelope {
        let mut frame = STANDARD.decode(&valid.cipher).expect("cipher Base64");
        mutate(&mut frame);
        SecureEnvelope {
            cipher: STANDARD.encode(frame),
            ..valid.clone()
        }
    }

    #[test]
    fn aead_frame_version_algorithm_and_reserved_ccm_ids_are_rejected() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = valid_envelope(&peers);

        for mutated in [
            with_mutated_frame(&valid, |frame| frame[0] ^= 0x01),
            with_mutated_frame(&valid, |frame| frame[0] = 0x02),
            with_mutated_frame(&valid, |frame| frame[1] = 0x02),
            with_mutated_frame(&valid, |frame| frame[1] = 0x7f),
        ] {
            assert_invalid_envelope(open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &mutated,
                &legacy_context(),
            ));
        }
    }

    #[test]
    fn aead_short_and_truncated_frames_are_rejected() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = valid_envelope(&peers);

        let mut floor_minus_one = vec![0_u8; 29];
        floor_minus_one[0] = 0x01;
        floor_minus_one[1] = 0x01;
        for mutated in [
            SecureEnvelope {
                cipher: STANDARD.encode(floor_minus_one),
                ..valid.clone()
            },
            SecureEnvelope {
                cipher: String::new(),
                ..valid.clone()
            },
            with_mutated_frame(&valid, |frame| {
                frame.pop();
            }),
            with_mutated_frame(&valid, |frame| frame.truncate(FRAME_HEADER_BYTES)),
        ] {
            assert_invalid_envelope(open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &mutated,
                &legacy_context(),
            ));
        }
    }

    #[test]
    fn aead_nonce_ciphertext_and_tag_tampering_are_indistinguishable() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = valid_envelope(&peers);

        for mutated in [
            with_mutated_frame(&valid, |frame| frame[2] ^= 0x01),
            // Cover first, middle, and last ciphertext bytes independently.
            with_mutated_frame(&valid, |frame| frame[FRAME_HEADER_BYTES] ^= 0x01),
            with_mutated_frame(&valid, |frame| {
                let ciphertext_len = frame.len() - FRAME_OVERHEAD_BYTES;
                let middle = FRAME_HEADER_BYTES + ciphertext_len / 2;
                frame[middle] ^= 0x01;
            }),
            with_mutated_frame(&valid, |frame| {
                let tag_start = frame.len() - TAG_BYTES;
                let last_ciphertext = tag_start - 1;
                frame[last_ciphertext] ^= 0x01;
            }),
            with_mutated_frame(&valid, |frame| {
                let last = frame.len() - 1;
                frame[last] ^= 0x01;
            }),
            with_mutated_frame(&valid, |frame| {
                let tag_start = frame.len() - 16;
                frame[tag_start..].fill(0);
            }),
        ] {
            assert_invalid_envelope(open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &mutated,
                &legacy_context(),
            ));
        }
    }

    #[test]
    fn aead_domain_separator_and_context_are_covered_by_the_aad() {
        let sender_mode =
            AuthenticationMode::context_bound(b"example/request/v1").expect("sender domain");
        let receiver_mode =
            AuthenticationMode::context_bound(b"example/response/v1").expect("receiver domain");
        let peers = aead_peers(sender_mode, 256);
        let mismatched_receiver_config = crate::envelope_crypto::test_support::aead_config(
            "receiver",
            crate::envelope_crypto::test_support::RECEIVER_SIGNER_ID,
            crate::envelope_crypto::test_support::SENDER_SIGNER_ID,
            receiver_mode,
            256,
        );
        let context =
            AuthenticationContext::context_bound(b"operation=pay&id=17").expect("bound context");
        let envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"domain-separated aead payload",
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
    fn aead_oversized_encoded_and_decoded_ciphers_split_the_public_bounds() {
        // Limit 17: max frame is 47 bytes, whose Base64 length is 64.
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 17);
        let encoded_too_large = SecureEnvelope {
            cipher: "!".repeat(65),
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

        // An authentic 48-byte frame for an 18-byte plaintext still encodes
        // within the opening client's 64-character public Base64 bound, but
        // its ciphertext body exceeds that client's 17-byte decoded limit.
        let sealing_peers = aead_peers(AuthenticationMode::LegacyPlaintext, 18);
        let valid = seal(
            &sealing_peers.sender_config,
            &sealing_peers.sender_keys,
            &[b'z'; 18],
            &legacy_context(),
        )
        .expect("seal valid 18-byte payload");
        let decoded_frame = STANDARD.decode(&valid.cipher).expect("cipher Base64");
        assert_eq!(decoded_frame.len(), 48);
        assert_eq!(valid.cipher.len(), 64);
        let decoded_too_large = SecureEnvelope {
            cipher: STANDARD.encode(decoded_frame),
            ..valid
        };
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &decoded_too_large,
            &legacy_context(),
        ));
    }

    #[test]
    fn aead_wrapped_key_signature_and_wrong_key_failures_match_cbc_semantics() {
        let peers = aead_peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = valid_envelope(&peers);

        let malformed_wrapped = SecureEnvelope {
            wrapped_session_key: STANDARD.encode(b"not SM2 DER"),
            ..valid.clone()
        };
        let wrong_length_wrapped = SecureEnvelope {
            wrapped_session_key: wrapped_plaintext_for_receiver(b"not-16-bytes"),
            ..valid.clone()
        };
        let mut tampered_signature_bytes =
            STANDARD.decode(&valid.signature).expect("signature Base64");
        let final_byte = tampered_signature_bytes.len() - 1;
        tampered_signature_bytes[final_byte] ^= 1;
        let tampered_signature = SecureEnvelope {
            signature: STANDARD.encode(tampered_signature_bytes),
            ..valid.clone()
        };
        let non_canonical = SecureEnvelope {
            cipher: "AA".to_owned(),
            ..valid.clone()
        };
        let invalid_base64_wrapped = SecureEnvelope {
            wrapped_session_key: "!!!!".to_owned(),
            ..valid.clone()
        };
        let invalid_base64_signature = SecureEnvelope {
            signature: "!!!!".to_owned(),
            ..valid.clone()
        };
        for mutated in [
            malformed_wrapped,
            wrong_length_wrapped,
            tampered_signature,
            non_canonical,
            invalid_base64_wrapped,
            invalid_base64_signature,
        ] {
            assert_invalid_envelope(open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &mutated,
                &legacy_context(),
            ));
        }

        let wrong_decryption = key_material(
            RECEIVER_SIGNING,
            UNRELATED_KEY,
            SENDER_SIGNING,
            SENDER_DECRYPTION,
        );
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &wrong_decryption,
            &valid,
            &legacy_context(),
        ));
        let wrong_verification = key_material(
            RECEIVER_SIGNING,
            RECEIVER_DECRYPTION,
            UNRELATED_KEY,
            SENDER_DECRYPTION,
        );
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &wrong_verification,
            &valid,
            &legacy_context(),
        ));
    }

    #[test]
    fn aead_and_cbc_clients_reject_each_other_s_envelopes() {
        let cbc =
            crate::envelope_crypto::test_support::peers(AuthenticationMode::LegacyPlaintext, 128);
        let aead = aead_peers(AuthenticationMode::LegacyPlaintext, 128);

        let cbc_envelope = seal(
            &cbc.sender_config,
            &cbc.sender_keys,
            b"cbc payload",
            &legacy_context(),
        )
        .expect("CBC seal");
        assert_invalid_envelope(open(
            &aead.receiver_config,
            &aead.receiver_keys,
            &cbc_envelope,
            &legacy_context(),
        ));

        let aead_envelope = seal(
            &aead.sender_config,
            &aead.sender_keys,
            b"aead payload",
            &legacy_context(),
        )
        .expect("AEAD seal");
        assert_invalid_envelope(open(
            &cbc.receiver_config,
            &cbc.receiver_keys,
            &aead_envelope,
            &legacy_context(),
        ));
    }
}
