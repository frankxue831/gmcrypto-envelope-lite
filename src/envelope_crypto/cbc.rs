//! The compatibility SM4-CBC payload mode.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use getrandom::SysRng;
use gmcrypto_core::{sm2, sm4};
use zeroize::Zeroizing;

use super::{
    MAX_AUXILIARY_BASE64_BYTES, base64_len, decode_base64, generate_session_key, unwrap_session_key,
};
use crate::message::SecureEnvelope;
use crate::{AuthenticationContext, ClientConfig, Error, KeyMaterial, Result};

const SM4_BLOCK_BYTES: usize = 16;

/// The single place `open` performs SM2 verification.
///
/// Every verification is routed through this one function so the tests can pin
/// the F1 invariant that `open` runs *exactly one* SM2 verification per call,
/// regardless of which validation step failed. That invariant is what keeps the
/// CBC failure paths from leaking a padding-oracle timing signal (see the
/// `open` comment and the module tests).
fn verify_transcript(
    keys: &KeyMaterial,
    config: &ClientConfig,
    transcript: &[u8],
    signature: &[u8],
) -> bool {
    #[cfg(test)]
    {
        record_verify_call();
    }
    sm2::verify_with_id(
        &keys.remote_verification,
        config.expected_remote_signer_id(),
        transcript,
        signature,
    )
}

#[cfg(test)]
thread_local! {
    /// Per-thread tally of `verify_transcript` calls, so a test can assert the
    /// exact number of SM2 verifications a single `open` performed.
    static VERIFY_CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn record_verify_call() {
    VERIFY_CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));
}

/// Returns the verifications performed since the last call, resetting the tally.
#[cfg(test)]
fn take_verify_calls() -> u32 {
    VERIFY_CALLS.with(|calls| calls.replace(0))
}

pub(super) fn seal(
    config: &ClientConfig,
    keys: &KeyMaterial,
    plaintext: &[u8],
    context: &AuthenticationContext,
) -> Result<SecureEnvelope> {
    let authentication_input = config
        .authentication_mode()
        .authentication_input(context, plaintext)?;

    let session_key = generate_session_key()?;

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

pub(super) fn open(
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

    let session_key = unwrap_session_key(keys, &wrapped_session_key)?;

    // F1 — CBC failure-path cost equalization.
    //
    // The SM2 signature covers the *plaintext* transcript, so verification
    // cannot run before decryption. That used to make padding failure return
    // here, before the SM2 verify below — and since that verify (two EC scalar
    // multiplications) dominates this function's cost, the early return was a
    // network-observable Vaudenay padding oracle in this default CBC mode.
    //
    // Now every envelope that unwraps its session key runs *exactly one*
    // verification. When CBC decryption fails we build the transcript from the
    // raw ciphertext bytes (same code path; the hashed length differs by at most
    // one padding block) so the verify still runs with the same shape and cost.
    //
    // CRITICAL invariant: the outcome flags are ANDed and `verified` is only
    // ever one conjunct — it can never alone authorize success. An attacker who
    // copies the bytes of a legitimately signed plaintext into `cipher` makes
    // the fallback transcript equal the signed one, so `verified` is true, but
    // `padding_ok` is false and the envelope is still rejected. Dropping any
    // conjunct reopens either the oracle or a signature-replay bypass;
    // `a_signed_cleartext_placed_in_cipher_reaches_verify_yet_is_rejected` and
    // `open_runs_exactly_one_verification_on_every_post_unwrap_path` pin this.
    //
    // Residuals (request-level equalization of the dominant asymmetric op, not a
    // constant-time claim — see the engineering-evidence map): the wrapped-key
    // unwrap above still fast-fails, since the core exposes no constant-time
    // unwrap and probe traffic reuses a valid wrapped key; the key-independent
    // Base64/length checks fast-fail before it; and the core's internal PKCS#7
    // check is its own. The AEAD mode is not an oracle — its GCM tag is a real
    // MAC verified before any plaintext exists.
    let decrypted = sm4::mode_cbc::decrypt(&session_key, config.iv(), &cipher);
    let padding_ok = decrypted.is_some();
    let plaintext = Zeroizing::new(decrypted.unwrap_or_else(|| cipher.clone()));
    let length_ok = plaintext.len() <= plaintext_limit;

    let authentication_input = config
        .authentication_mode()
        .authentication_input(context, plaintext.as_slice());
    let input_ok = authentication_input.is_ok();
    let transcript = authentication_input.unwrap_or_else(|_| Zeroizing::new(Vec::new()));

    let verified = verify_transcript(keys, config, transcript.as_slice(), &signature);

    if padding_ok && length_ok && input_ok && verified {
        Ok(plaintext.to_vec())
    } else {
        Err(Error::InvalidEnvelope)
    }
}

fn padded_cipher_len(plaintext_limit: usize) -> usize {
    plaintext_limit
        .checked_div(SM4_BLOCK_BYTES)
        .and_then(|blocks| blocks.checked_add(1))
        .and_then(|blocks| blocks.checked_mul(SM4_BLOCK_BYTES))
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use gmcrypto_core::sm2;
    use zeroize::Zeroizing;

    use crate::envelope_crypto::test_support::{
        RECEIVER_DECRYPTION, RECEIVER_SIGNER_ID, RECEIVER_SIGNING, SENDER_DECRYPTION,
        SENDER_SIGNER_ID, SENDER_SIGNING, UNRELATED_KEY, assert_invalid_envelope, config,
        key_material, legacy_context, peers, raw_private_key, wrapped_plaintext_for_receiver,
    };
    use crate::envelope_crypto::{open, seal};
    use crate::message::SecureEnvelope;
    use crate::{AuthenticationContext, AuthenticationMode, Error};

    use super::take_verify_calls;

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
    fn plaintext_length_sweep_round_trips_across_block_and_base64_boundaries() {
        // Every other round-trip test picks one arbitrary length, which leaves
        // the boundaries where this construction actually changes behaviour
        // untested: PKCS#7 appends a whole extra block at an exact multiple of
        // 16, and Base64 pads differently for each length mod 3. Gate #1 runs
        // this suite against candidate `gmcrypto-core` releases, so a padding
        // or encoding regression that only appears at a boundary has to fail
        // here rather than reach a release.
        const LENGTHS: &[usize] = &[
            0, 1, 2, 3, 4, 5, // empty, and each Base64 group alignment
            15, 16, 17, // one SM4 block; 16 is the full-pad-block case
            31, 32, 33, // two blocks
            47, 48, 49, // three blocks
            63, 64, 65, 255, 256, 257, 1023, 1024, 1025,
        ];

        let cases = [
            (AuthenticationMode::LegacyPlaintext, legacy_context()),
            (
                AuthenticationMode::context_bound(b"example/sweep/v1")
                    .expect("nonempty domain separator"),
                AuthenticationContext::context_bound(b"operation=sweep").expect("bound context"),
            ),
        ];

        for (mode, context) in cases {
            let peers = peers(mode, 2048);
            for &length in LENGTHS {
                // Position-dependent bytes: a truncation, block reorder, or
                // off-by-one that a constant payload would hide changes the
                // compared value here.
                let plaintext: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();

                let envelope = seal(
                    &peers.sender_config,
                    &peers.sender_keys,
                    &plaintext,
                    &context,
                )
                .unwrap_or_else(|error| panic!("seal {length} bytes: {error}"));

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
    fn truncated_cipher_and_malformed_signature_encoding_are_invalid_envelopes() {
        let peers = peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = seal(
            &peers.sender_config,
            &peers.sender_keys,
            b"truncation and signature encoding",
            &legacy_context(),
        )
        .expect("seal valid envelope");

        let mut truncated_cipher = STANDARD.decode(&valid.cipher).expect("cipher Base64");
        truncated_cipher.pop().expect("nonempty padded ciphertext");
        let truncated = SecureEnvelope {
            cipher: STANDARD.encode(truncated_cipher),
            ..valid.clone()
        };
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &truncated,
            &legacy_context(),
        ));

        let malformed_signature = SecureEnvelope {
            signature: STANDARD.encode([0x30, 0x01, 0x00]),
            ..valid
        };
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &malformed_signature,
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

    #[test]
    fn open_runs_exactly_one_verification_on_every_post_unwrap_path() {
        // F1: from a successful key-unwrap onward, `open` must run exactly one
        // SM2 verification no matter which later step fails. That verification
        // is this function's dominant cost, so any path returning *before* it
        // leaks a padding-oracle timing signal in this default CBC mode. This
        // test pins the call count on the happy path and on each failure that
        // can occur after key-unwrap.
        let peers = peers(AuthenticationMode::LegacyPlaintext, 128);
        let valid = seal(
            &peers.sender_config,
            &peers.sender_keys,
            &[b'x'; 17],
            &legacy_context(),
        )
        .expect("seal two-block cipher");

        // Happy path: one verification.
        take_verify_calls();
        open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &valid,
            &legacy_context(),
        )
        .expect("valid envelope opens");
        assert_eq!(take_verify_calls(), 1, "a valid open verifies exactly once");

        // Invalid CBC padding: flipping the padding-controlling byte of the
        // preceding block makes PKCS#7 unpad fail.
        let mut bad_padding = STANDARD.decode(&valid.cipher).expect("cipher Base64");
        let previous_block_last_byte = bad_padding.len() - 17;
        bad_padding[previous_block_last_byte] ^= 0x0f;
        let bad_padding = SecureEnvelope {
            cipher: STANDARD.encode(bad_padding),
            ..valid.clone()
        };
        take_verify_calls();
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &bad_padding,
            &legacy_context(),
        ));
        assert_eq!(
            take_verify_calls(),
            1,
            "invalid padding must still reach the one verification (F1)"
        );

        // Valid padding but the plaintext exceeds the opening client's limit: a
        // 17-byte payload opened by a 16-byte-limit client, which shares the
        // same directional keys and IV so it decrypts before the length check.
        let smaller =
            crate::envelope_crypto::test_support::peers(AuthenticationMode::LegacyPlaintext, 16);
        take_verify_calls();
        assert_invalid_envelope(open(
            &smaller.receiver_config,
            &smaller.receiver_keys,
            &valid,
            &legacy_context(),
        ));
        assert_eq!(
            take_verify_calls(),
            1,
            "post-decrypt oversize must still reach the one verification (F1)"
        );

        // Valid padding and length, tampered signature: this is the one
        // verification returning false.
        let mut signature = STANDARD.decode(&valid.signature).expect("signature Base64");
        let final_byte = signature.len() - 1;
        signature[final_byte] ^= 1;
        let bad_signature = SecureEnvelope {
            signature: STANDARD.encode(signature),
            ..valid.clone()
        };
        take_verify_calls();
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &bad_signature,
            &legacy_context(),
        ));
        assert_eq!(
            take_verify_calls(),
            1,
            "a bad signature is the one verification returning false"
        );

        // Documented residual: a wrapped key that fails to unwrap returns on the
        // out-of-scope fast path *before* any verification. Equalizing it would
        // need a constant-time key-unwrap the core does not expose, and the
        // security model treats probe traffic here as reusing a valid wrapped
        // key. Pinned so this residual stays a deliberate, visible choice.
        let unwrappable = SecureEnvelope {
            wrapped_session_key: STANDARD.encode(b"not an SM2 ciphertext"),
            ..valid.clone()
        };
        take_verify_calls();
        assert_invalid_envelope(open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &unwrappable,
            &legacy_context(),
        ));
        assert_eq!(
            take_verify_calls(),
            0,
            "unwrap failure is the accepted fast-path residual"
        );
    }

    #[test]
    fn a_signed_cleartext_placed_in_cipher_reaches_verify_yet_is_rejected() {
        // The F1 fix runs one verification even when CBC decryption fails, using
        // the raw ciphertext bytes as the transcript. This pins the invariant
        // that the fallback verification's *result can never authorize success*:
        // an attacker who copies the bytes of a legitimately signed plaintext
        // into `cipher` (keeping the matching wrapped key and signature) makes
        // that fallback verification return true — and must still be rejected,
        // because the real CBC padding never validated. Dropping the padding
        // gate would turn this into a signature-replay acceptance.
        let peers = peers(AuthenticationMode::LegacyPlaintext, 128);

        // Block-misaligned length, so decrypting these bytes as ciphertext fails
        // deterministically (CBC requires block alignment) and forces the
        // raw-ciphertext fallback transcript.
        let signed_plaintext: &[u8] = b"a legitimately signed plaintext, replayed as cleartext";
        assert_ne!(
            signed_plaintext.len() % 16,
            0,
            "must be block-misaligned for a deterministic decrypt failure"
        );

        let legitimate = seal(
            &peers.sender_config,
            &peers.sender_keys,
            signed_plaintext,
            &legacy_context(),
        )
        .expect("seal a legitimate envelope");

        // Forge: cipher = the cleartext signed bytes; keep the real wrapped key
        // (so unwrap yields the true session key) and the real signature.
        let forged = SecureEnvelope {
            cipher: STANDARD.encode(signed_plaintext),
            ..legitimate
        };

        take_verify_calls();
        let result = open(
            &peers.receiver_config,
            &peers.receiver_keys,
            &forged,
            &legacy_context(),
        );

        // It reached verification (not a pre-verify padding bail) ...
        assert_eq!(
            take_verify_calls(),
            1,
            "the forged envelope must still reach exactly one verification"
        );
        // ... and although the fallback transcript equals the signed plaintext
        // so that verification returns true, the envelope is rejected because
        // CBC padding failed.
        assert_invalid_envelope(result);
    }
}
