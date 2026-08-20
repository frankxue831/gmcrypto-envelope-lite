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
const ALGORITHM_SM4_CCM: u8 = 0x02;
const FRAME_HEADER_BYTES: usize = 14;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const FRAME_OVERHEAD_BYTES: usize = FRAME_HEADER_BYTES + TAG_BYTES;

fn algorithm_byte(algorithm: AeadAlgorithm) -> u8 {
    match algorithm {
        AeadAlgorithm::Sm4Gcm => ALGORITHM_SM4_GCM,
        AeadAlgorithm::Sm4Ccm => ALGORITHM_SM4_CCM,
    }
}

fn split_ciphertext_and_tag(mut joined: Vec<u8>) -> Option<(Vec<u8>, [u8; TAG_BYTES])> {
    if joined.len() < TAG_BYTES {
        return None;
    }
    let tag_bytes = joined.split_off(joined.len() - TAG_BYTES);
    let tag = <[u8; TAG_BYTES]>::try_from(tag_bytes).ok()?;
    Some((joined, tag))
}

fn aead_encrypt(
    algorithm: AeadAlgorithm,
    session_key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_BYTES])> {
    match algorithm {
        AeadAlgorithm::Sm4Gcm => {
            sm4::mode_gcm::encrypt(session_key, nonce, aad, plaintext).ok_or(Error::Encryption)
        }
        AeadAlgorithm::Sm4Ccm => {
            let joined = sm4::mode_ccm::encrypt(session_key, nonce, aad, plaintext, TAG_BYTES)
                .ok_or(Error::Encryption)?;
            split_ciphertext_and_tag(joined).ok_or(Error::Encryption)
        }
    }
}

fn aead_decrypt(
    algorithm: AeadAlgorithm,
    session_key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_BYTES],
) -> Result<Vec<u8>> {
    match algorithm {
        AeadAlgorithm::Sm4Gcm => sm4::mode_gcm::decrypt(session_key, nonce, aad, ciphertext, tag)
            .ok_or(Error::InvalidEnvelope),
        AeadAlgorithm::Sm4Ccm => {
            let mut joined = Vec::with_capacity(ciphertext.len() + TAG_BYTES);
            joined.extend_from_slice(ciphertext);
            joined.extend_from_slice(tag);
            sm4::mode_ccm::decrypt(session_key, nonce, aad, &joined, TAG_BYTES)
                .ok_or(Error::InvalidEnvelope)
        }
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

    let (ciphertext, tag) = aead_encrypt(algorithm, &session_key, &nonce, &aad, plaintext)?;

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
    let plaintext = Zeroizing::new(aead_decrypt(
        algorithm,
        &session_key,
        nonce,
        &aad,
        ciphertext,
        &tag,
    )?);

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
        aead_peers, assert_invalid_envelope, ccm_peers, key_material, legacy_context,
        raw_private_key, wrapped_plaintext_for_receiver,
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
    fn aead_plaintext_length_sweep_round_trips_across_frame_and_base64_boundaries() {
        // GCM does not pad, so the CBC block boundaries do not apply here --
        // what does is the frame's fixed overhead around a variable-length
        // ciphertext, and Base64 alignment of the framed result. The sweep
        // covers both, plus the same lengths the CBC sweep uses so a core
        // regression that hits one mode and not the other is visible.
        const LENGTHS: &[usize] = &[
            0, 1, 2, 3, 4, 5, // empty, and each Base64 group alignment
            15, 16, 17, 31, 32, 33, // where CBC would change padding
            63, 64, 65, 255, 256, 257, 1023, 1024, 1025,
        ];

        let cases = [
            (AuthenticationMode::LegacyPlaintext, legacy_context()),
            (
                AuthenticationMode::context_bound(b"example/aead-sweep/v1")
                    .expect("nonempty domain separator"),
                AuthenticationContext::context_bound(b"operation=sweep").expect("bound context"),
            ),
        ];

        for (mode, context) in cases {
            let peers = aead_peers(mode, 2048);
            for &length in LENGTHS {
                // Position-dependent bytes: a truncation or off-by-one in the
                // frame arithmetic that a constant payload would hide changes
                // the compared value here.
                let plaintext: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();

                let envelope = seal(
                    &peers.sender_config,
                    &peers.sender_keys,
                    &plaintext,
                    &context,
                )
                .unwrap_or_else(|error| panic!("seal {length} bytes: {error}"));

                // The frame carries a fixed header and tag around the
                // ciphertext, and GCM ciphertext is the plaintext length.
                let framed = STANDARD
                    .decode(&envelope.cipher)
                    .expect("framed cipher is Base64");
                assert_eq!(
                    framed.len(),
                    length + FRAME_OVERHEAD_BYTES,
                    "frame overhead must stay constant at {length} bytes"
                );

                let opened = open(
                    &peers.receiver_config,
                    &peers.receiver_keys,
                    &envelope,
                    &context,
                )
                .unwrap_or_else(|error| panic!("open {length} bytes: {error}"));

                assert_eq!(
                    opened.as_slice(),
                    plaintext.as_slice(),
                    "round trip must be exact at {length} bytes"
                );
            }
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

    fn literal_aad(
        label: &[u8],
        frame_header: &[u8],
        domain_separator: &[u8],
        protocol_context: &[u8],
    ) -> Vec<u8> {
        let mut aad = Vec::new();

        let label_len = u64::try_from(label.len()).expect("label length fits u64");
        aad.extend_from_slice(&label_len.to_be_bytes());
        aad.extend_from_slice(label);

        let header_len = u64::try_from(frame_header.len()).expect("header length fits u64");
        aad.extend_from_slice(&header_len.to_be_bytes());
        aad.extend_from_slice(frame_header);

        let domain_len = u64::try_from(domain_separator.len()).expect("domain length fits u64");
        aad.extend_from_slice(&domain_len.to_be_bytes());
        aad.extend_from_slice(domain_separator);

        let context_len = u64::try_from(protocol_context.len()).expect("context length fits u64");
        aad.extend_from_slice(&context_len.to_be_bytes());
        aad.extend_from_slice(protocol_context);

        aad
    }

    #[test]
    fn aead_gcm_rejects_wrong_version_and_non_gcm_algorithm_ids() {
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
            crate::AeadAlgorithm::Sm4Gcm,
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
    fn aead_seal_gcm_tag_binds_literal_label_header_domain_and_context() {
        const LABEL: &[u8] = b"gmcrypto-envelope-lite/aead-aad/v1";
        const DOMAIN: &[u8] = b"example/request/v1";
        const CONTEXT: &[u8] = b"operation=pay&id=17";
        const PLAINTEXT: &[u8] = b"independently verified GCM AAD";

        let mode = AuthenticationMode::context_bound(DOMAIN).expect("sender domain");
        let peers = aead_peers(mode, 256);
        let context = AuthenticationContext::context_bound(CONTEXT).expect("bound context");
        let envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            PLAINTEXT,
            &context,
        )
        .expect("seal context-bound envelope");
        let untouched_envelope = envelope.clone();

        let wrapped_session_key = STANDARD
            .decode(&envelope.wrapped_session_key)
            .expect("wrapped key Base64");
        let receiver_private = raw_private_key(RECEIVER_DECRYPTION);
        let unwrapped_session_key = Zeroizing::new(
            sm2::decrypt(&receiver_private, &wrapped_session_key).expect("unwrap session key"),
        );
        let session_key: &[u8; 16] = unwrapped_session_key
            .as_slice()
            .try_into()
            .expect("16-byte session key");

        let frame = STANDARD.decode(&envelope.cipher).expect("cipher Base64");
        assert_eq!(frame.len(), FRAME_OVERHEAD_BYTES + PLAINTEXT.len());
        let frame_header: &[u8; FRAME_HEADER_BYTES] = frame[..FRAME_HEADER_BYTES]
            .try_into()
            .expect("14-byte frame header");
        assert_eq!(frame_header[0], 0x01, "frame version");
        assert_eq!(frame_header[1], 0x01, "SM4-GCM algorithm id");
        let ciphertext_end = frame.len() - TAG_BYTES;
        let ciphertext = &frame[FRAME_HEADER_BYTES..ciphertext_end];
        let tag: &[u8; TAG_BYTES] = frame[ciphertext_end..].try_into().expect("16-byte GCM tag");
        let nonce = &frame_header[2..];

        let expected_aad = literal_aad(LABEL, frame_header, DOMAIN, CONTEXT);
        assert_eq!(
            gmcrypto_core::sm4::mode_gcm::decrypt(
                session_key,
                nonce,
                &expected_aad,
                ciphertext,
                tag,
            )
            .expect("literal four-field AAD verifies the sealed GCM tag"),
            PLAINTEXT
        );

        let mut different_header = *frame_header;
        different_header[0] ^= 0x01;
        for (field, different_aad) in [
            (
                "domain label",
                literal_aad(
                    b"gmcrypto-envelope-lite/aead-aad/v2",
                    frame_header,
                    DOMAIN,
                    CONTEXT,
                ),
            ),
            (
                "frame header",
                literal_aad(LABEL, &different_header, DOMAIN, CONTEXT),
            ),
            (
                "domain separator",
                literal_aad(LABEL, frame_header, b"example/response/v1", CONTEXT),
            ),
            (
                "protocol context",
                literal_aad(LABEL, frame_header, DOMAIN, b"operation=pay&id=18"),
            ),
        ] {
            assert!(
                gmcrypto_core::sm4::mode_gcm::decrypt(
                    session_key,
                    nonce,
                    &different_aad,
                    ciphertext,
                    tag,
                )
                .is_none(),
                "changing the {field} must fail primitive GCM tag verification"
            );
        }

        assert_eq!(
            envelope, untouched_envelope,
            "AAD-only mutations must not alter the sealed envelope or its signature"
        );
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

    #[test]
    fn ccm_round_trips_in_both_directions_with_distinct_roles() {
        let peers = ccm_peers(AuthenticationMode::LegacyPlaintext, 256);
        let context = legacy_context();
        let request = b"ccm request payload \x00 with binary bytes";

        let envelope = seal(&peers.sender_config, &peers.sender_keys, request, &context)
            .expect("sender seals");
        let frame = STANDARD.decode(&envelope.cipher).expect("cipher Base64");
        assert_eq!(frame.len(), request.len() + FRAME_OVERHEAD_BYTES);
        assert_eq!(frame[0], 0x01, "frame version");
        assert_eq!(frame[1], 0x02, "SM4-CCM algorithm id");
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

        let response = b"ccm response uses inverse directional roles";
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
    fn ccm_context_bound_round_trip_rejects_wrong_or_mismatched_contexts() {
        let mode = AuthenticationMode::context_bound(b"example/ccm/v1").expect("domain");
        let peers = ccm_peers(mode, 256);
        let context =
            AuthenticationContext::context_bound(b"operation=pay&id=17").expect("bound context");
        let envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"context-bound ccm payload",
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
            b"context-bound ccm payload"
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
    fn ccm_round_trips_empty_boundary_and_unicode_plaintext() {
        let peers = ccm_peers(AuthenticationMode::LegacyPlaintext, 64);
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
    fn ccm_plaintext_length_sweep_round_trips_across_frame_and_base64_boundaries() {
        const LENGTHS: &[usize] = &[
            0, 1, 2, 3, 4, 5, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 257, 1023, 1024, 1025,
        ];

        let cases = [
            (AuthenticationMode::LegacyPlaintext, legacy_context()),
            (
                AuthenticationMode::context_bound(b"example/ccm-sweep/v1")
                    .expect("nonempty domain separator"),
                AuthenticationContext::context_bound(b"operation=sweep").expect("bound context"),
            ),
        ];

        for (mode, context) in cases {
            let peers = ccm_peers(mode, 2048);
            for &length in LENGTHS {
                let plaintext: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
                let envelope = seal(
                    &peers.sender_config,
                    &peers.sender_keys,
                    &plaintext,
                    &context,
                )
                .unwrap_or_else(|error| panic!("seal {length} bytes: {error}"));
                let framed = STANDARD
                    .decode(&envelope.cipher)
                    .expect("framed cipher is Base64");
                assert_eq!(
                    framed.len(),
                    length + FRAME_OVERHEAD_BYTES,
                    "frame overhead must stay constant at {length} bytes"
                );
                let opened = open(
                    &peers.receiver_config,
                    &peers.receiver_keys,
                    &envelope,
                    &context,
                )
                .unwrap_or_else(|error| panic!("open {length} bytes: {error}"));
                assert_eq!(
                    opened.as_slice(),
                    plaintext.as_slice(),
                    "round trip must be exact at {length} bytes"
                );
            }
        }
    }

    #[test]
    fn every_ccm_seal_uses_a_fresh_session_key_and_nonce() {
        let peers = ccm_peers(AuthenticationMode::LegacyPlaintext, 128);
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
    fn ccm_seal_rejects_plaintext_over_the_configured_limit() {
        let peers = ccm_peers(AuthenticationMode::LegacyPlaintext, 8);
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
    fn ccm_client_at_the_nonce_ceiling_still_round_trips_a_small_payload() {
        let peers = ccm_peers(
            AuthenticationMode::LegacyPlaintext,
            crate::SM4_CCM_MAX_PLAINTEXT_BYTES,
        );
        assert_eq!(
            peers.sender_config.max_plaintext_bytes(),
            crate::SM4_CCM_MAX_PLAINTEXT_BYTES
        );
        let plaintext = b"under the q=3 ceiling";
        let envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            plaintext,
            &legacy_context(),
        )
        .expect("ceiling-configured client seals");
        assert_eq!(
            open(
                &peers.receiver_config,
                &peers.receiver_keys,
                &envelope,
                &legacy_context(),
            )
            .expect("ceiling-configured client opens"),
            plaintext
        );
    }

    #[test]
    fn ccm_primitive_rejects_plaintext_above_the_12_byte_nonce_ceiling() {
        let key = [0x42_u8; 16];
        let nonce = [0_u8; 12];
        let over = vec![0_u8; crate::SM4_CCM_MAX_PLAINTEXT_BYTES + 1];
        assert!(
            gmcrypto_core::sm4::mode_ccm::encrypt(&key, &nonce, &[], &over, 16).is_none(),
            "q=3 must reject 16 MiB plaintext before encrypting"
        );
    }

    fn valid_ccm_envelope(peers: &crate::envelope_crypto::test_support::Peers) -> SecureEnvelope {
        seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"ccm negative-matrix payload",
            &legacy_context(),
        )
        .expect("seal valid CCM envelope")
    }

    #[test]
    fn ccm_rejects_wrong_version_and_non_ccm_algorithm_ids() {
        let peers = ccm_peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = valid_ccm_envelope(&peers);

        for mutated in [
            with_mutated_frame(&valid, |frame| frame[0] ^= 0x01),
            with_mutated_frame(&valid, |frame| frame[0] = 0x02),
            with_mutated_frame(&valid, |frame| frame[1] = 0x01),
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
    fn ccm_short_and_truncated_frames_are_rejected() {
        let peers = ccm_peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = valid_ccm_envelope(&peers);

        let mut floor_minus_one = vec![0_u8; 29];
        floor_minus_one[0] = 0x01;
        floor_minus_one[1] = 0x02;
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
    fn ccm_nonce_ciphertext_and_tag_tampering_are_indistinguishable() {
        let peers = ccm_peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = valid_ccm_envelope(&peers);

        for mutated in [
            with_mutated_frame(&valid, |frame| frame[2] ^= 0x01),
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
    fn ccm_domain_separator_and_context_are_covered_by_the_aad() {
        let sender_mode =
            AuthenticationMode::context_bound(b"example/request/v1").expect("sender domain");
        let receiver_mode =
            AuthenticationMode::context_bound(b"example/response/v1").expect("receiver domain");
        let peers = ccm_peers(sender_mode, 256);
        let mismatched_receiver_config = crate::envelope_crypto::test_support::aead_config(
            "receiver",
            crate::envelope_crypto::test_support::RECEIVER_SIGNER_ID,
            crate::envelope_crypto::test_support::SENDER_SIGNER_ID,
            receiver_mode,
            256,
            crate::AeadAlgorithm::Sm4Ccm,
        );
        let context =
            AuthenticationContext::context_bound(b"operation=pay&id=17").expect("bound context");
        let envelope = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"domain-separated ccm payload",
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
    fn ccm_oversized_encoded_and_decoded_ciphers_split_the_public_bounds() {
        let peers = ccm_peers(AuthenticationMode::LegacyPlaintext, 17);
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

        let sealing_peers = ccm_peers(AuthenticationMode::LegacyPlaintext, 18);
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
    fn ccm_wrapped_key_signature_and_wrong_key_failures_match_cbc_semantics() {
        let peers = ccm_peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = valid_ccm_envelope(&peers);

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
    fn ccm_and_gcm_clients_reject_each_other_s_envelopes() {
        let gcm = aead_peers(AuthenticationMode::LegacyPlaintext, 128);
        let ccm = ccm_peers(AuthenticationMode::LegacyPlaintext, 128);

        let gcm_envelope = seal(
            &gcm.sender_config,
            &gcm.sender_keys,
            b"gcm payload",
            &legacy_context(),
        )
        .expect("GCM seal");
        assert_invalid_envelope(open(
            &ccm.receiver_config,
            &ccm.receiver_keys,
            &gcm_envelope,
            &legacy_context(),
        ));

        let ccm_envelope = seal(
            &ccm.sender_config,
            &ccm.sender_keys,
            b"ccm payload",
            &legacy_context(),
        )
        .expect("CCM seal");
        assert_invalid_envelope(open(
            &gcm.receiver_config,
            &gcm.receiver_keys,
            &ccm_envelope,
            &legacy_context(),
        ));
    }

    #[test]
    fn ccm_and_cbc_clients_reject_each_other_s_envelopes() {
        let cbc =
            crate::envelope_crypto::test_support::peers(AuthenticationMode::LegacyPlaintext, 128);
        let ccm = ccm_peers(AuthenticationMode::LegacyPlaintext, 128);

        let cbc_envelope = seal(
            &cbc.sender_config,
            &cbc.sender_keys,
            b"cbc payload",
            &legacy_context(),
        )
        .expect("CBC seal");
        assert_invalid_envelope(open(
            &ccm.receiver_config,
            &ccm.receiver_keys,
            &cbc_envelope,
            &legacy_context(),
        ));

        let ccm_envelope = seal(
            &ccm.sender_config,
            &ccm.sender_keys,
            b"ccm payload",
            &legacy_context(),
        )
        .expect("CCM seal");
        assert_invalid_envelope(open(
            &cbc.receiver_config,
            &cbc.receiver_keys,
            &ccm_envelope,
            &legacy_context(),
        ));
    }
}
