# Engineering Evidence Map

**Evidence version:** 2

This engineering evidence map is not an independent audit, certification, warranty, or proof of cryptographic security. Claims are defined only by `SECURITY_MODEL.md`; a test name does not create a stronger claim.

| Claim or boundary | Repository evidence | Gate |
| --- | --- | --- |
| Four directional key roles drive signing, decryption, verification, and encryption | `tests/key_roles.rs::directional_roles_drive_two_party_cryptography`; `src/envelope_crypto/cbc.rs::tests::legacy_exact_plaintext_round_trips_in_both_directions_with_distinct_roles` | Required test |
| Shared roles are explicit | `tests/key_roles.rs::shared_constructor_is_explicit`; `tests/key_roles.rs::shared_pem_and_der_loaders_make_role_reuse_explicit` | Required test and rustdoc |
| ContextBound framing is versioned and length-delimited | `tests/auth_and_config.rs::context_bound_transcript_is_versioned_and_length_delimited` | Required test |
| Empty or wrong authentication contexts fail | `tests/auth_and_config.rs::authentication_constructors_reject_empty_bound_values`; `src/envelope_crypto/cbc.rs::tests::context_bound_round_trip_rejects_different_or_wrong_context_kinds` | Required test |
| Context domain changes invalidate verification | `src/envelope_crypto/cbc.rs::tests::context_bound_domain_separator_is_part_of_the_verified_transcript` | Required test |
| Fresh per-envelope session keys produce independent wrapped keys and ciphertext | `src/envelope_crypto/cbc.rs::tests::every_seal_uses_a_fresh_random_session_key` | Required test |
| SM2 verification, SM3, and SM4 match public standard vectors | `tests/standard_vectors.rs` | Non-removable KAT gate |
| Invalid Base64 is canonical, bounded, and opaque | `invalid_base64_in_any_envelope_field_is_indistinguishable`; `base64_requires_canonical_trailing_bits_and_standard_padding`; `oversized_encoded_or_decoded_cipher_is_rejected_before_key_operations` | Required test |
| Key unwrap and role failures fail closed | `malformed_wrapped_keys_and_wrong_length_unwrapped_keys_are_indistinguishable`; `wrong_decryption_key_is_an_invalid_envelope`; `tests/key_roles.rs` | Required test |
| CBC padding, ciphertext truncation/mutation, malformed signatures, signature changes, and wrong verification keys return only InvalidEnvelope | `cbc_padding_and_cipher_tampering_is_an_invalid_envelope`; `truncated_cipher_and_malformed_signature_encoding_are_invalid_envelopes`; `signature_tampering_and_wrong_verification_key_are_indistinguishable` | Required semantic-negative gate |
| Unverified or oversized plaintext is not returned | `post_decrypt_oversize_and_unverified_plaintext_are_never_returned` | Required test |
| Header injection, duplicates, and adapter-output collisions fail closed | `tests/transport_types.rs`; `tests/protocol_adapter.rs`; `tests/secure_client.rs` | Required test |
| Errors and Debug output do not echo protected values | `tests/redacted_debug.rs`; redaction assertions across integration tests | Required test |
| SDK-owned plaintext and session-key buffers use zeroizing guards | `src/envelope_crypto/mod.rs`; `src/envelope_crypto/cbc.rs`; `src/envelope_crypto/aead.rs`; `src/request.rs::tests::serialized_json_plaintext_is_owned_by_a_zeroizing_guard` | Code review plus required unit test |
| Public source export and Cargo package exclude prohibited material | `tests/open_source_boundary.sh`; `ci/check-open-source-boundary.sh`; `ci/check-cargo-package.sh` | Required open-source boundary gate |
| Crypto dependency resolution matches the reviewed inventory | `docs/security/cryptographic-dependencies.md`; `ci/crypto-inventory.snapshot`; `ci/check-crypto-inventory.sh`; Cargo.lock hash in the dependency inventory | Required dependency gate |
| AEAD envelopes round-trip under both authentication modes with fresh keys and nonces | `src/envelope_crypto/aead.rs::tests::aead_round_trips_in_both_directions_with_distinct_roles`; `src/envelope_crypto/aead.rs::tests::aead_context_bound_round_trip_rejects_wrong_or_mismatched_contexts`; `src/envelope_crypto/aead.rs::tests::every_aead_seal_uses_a_fresh_session_key_and_nonce` | Required test |
| AEAD frame pinning, tampering, decoded bounds, and wrong keys return only InvalidEnvelope; an encoded `cipher` above the public bound returns MessageTooLarge | `src/envelope_crypto/aead.rs::tests::aead_frame_version_algorithm_and_reserved_ccm_ids_are_rejected`; `src/envelope_crypto/aead.rs::tests::aead_nonce_ciphertext_and_tag_tampering_are_indistinguishable`; `src/envelope_crypto/aead.rs::tests::aead_oversized_encoded_and_decoded_ciphers_split_the_public_bounds`; `src/envelope_crypto/aead.rs::tests::aead_wrapped_key_signature_and_wrong_key_failures_match_cbc_semantics` | Required semantic-negative gate |
| The envelope mode is config-pinned with no downgrade path | `src/envelope_crypto/aead.rs::tests::aead_and_cbc_clients_reject_each_other_s_envelopes`; `tests/aead_envelope.rs::aead_and_cbc_secure_clients_reject_each_other_s_envelopes` | Required test |
| The AAD binds the frame header, domain separator, and protocol context | `src/auth.rs::tests::aead_aad_is_length_prefixed_label_header_domain_and_context`; `src/envelope_crypto/aead.rs::tests::aead_seal_gcm_tag_binds_literal_label_header_domain_and_context` | Required discriminating test |
| SM4-GCM matches the public standard vector | `tests/standard_vectors.rs::sm4_gcm_matches_rfc_8998_appendix_a_1` | Non-removable KAT gate |
| A `gmcrypto-core` candidate is exercised against this crate in every shipped feature configuration before that core release ships | `ci/check-compatibility-gate.sh`; `tests/compatibility_gate.sh`; `.github/workflows/compatibility-gate.yml`; `gm-crypto-rs/docs/ECOSYSTEM.md` section 8 | Required compatibility gate, manually triggered |

## External evidence

The following remain External and cannot be marked passed by repository tooling: deployed exact-wire compatibility, organization-specific denylist and fixture-fingerprint scanning, independent security review, legal/open-source approval, and release authorization.
