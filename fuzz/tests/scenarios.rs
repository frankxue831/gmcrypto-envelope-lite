#[path = "../fuzz_targets/support.rs"]
mod support;

use std::fs;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use gmcrypto_envelope_lite::{Error, ProtocolAdapter, RequestParts, ResponseParts};

use support::ScenarioOutcome::{Accepted, Rejected};

const FULL_VALID_OPEN: &[u8] = include_bytes!("../corpus/encoded_envelope/full_valid_open");
const AEAD_FULL_VALID: &[u8] = include_bytes!("../corpus/aead_envelope/full_valid_open");
const RAW_MALFORMED: &[u8] = include_bytes!("../corpus/encoded_envelope/raw_malformed");
const TRANSPORT_SUCCESS: &[u8] = include_bytes!("../corpus/transport_parts/success");
const TYPED_VALID: &[u8] = include_bytes!("../corpus/typed_headers/valid_request");
const TRANSPORT_CRLF: &[u8] =
    include_bytes!("../corpus/transport_parts/generic_value_crlf_injection");
const HEADER_CIPHER_CRLF: &[u8] =
    include_bytes!("../corpus/transport_parts/header_cipher_generic_value_crlf_injection");
const TYPED_CRLF: &[u8] = include_bytes!("../corpus/typed_headers/generic_value_crlf_injection");

const ENCODED_CASES: &[(&str, &[u8])] = &[
    (
        "cipher_limit",
        include_bytes!("../corpus/encoded_envelope/cipher_limit"),
    ),
    (
        "cipher_limit_minus_one",
        include_bytes!("../corpus/encoded_envelope/cipher_limit_minus_one"),
    ),
    (
        "cipher_limit_plus_one",
        include_bytes!("../corpus/encoded_envelope/cipher_limit_plus_one"),
    ),
    (
        "cryptographic_mutation_cipher",
        include_bytes!("../corpus/encoded_envelope/cryptographic_mutation_cipher"),
    ),
    (
        "cryptographic_mutation_signature",
        include_bytes!("../corpus/encoded_envelope/cryptographic_mutation_signature"),
    ),
    (
        "cryptographic_mutation_wrapped_key",
        include_bytes!("../corpus/encoded_envelope/cryptographic_mutation_wrapped_key"),
    ),
    ("full_valid_open", FULL_VALID_OPEN),
    ("raw_malformed", RAW_MALFORMED),
    (
        "signature_limit",
        include_bytes!("../corpus/encoded_envelope/signature_limit"),
    ),
    (
        "signature_limit_minus_one",
        include_bytes!("../corpus/encoded_envelope/signature_limit_minus_one"),
    ),
    (
        "signature_limit_plus_one",
        include_bytes!("../corpus/encoded_envelope/signature_limit_plus_one"),
    ),
    (
        "wrapped_key_limit",
        include_bytes!("../corpus/encoded_envelope/wrapped_key_limit"),
    ),
    (
        "wrapped_key_limit_minus_one",
        include_bytes!("../corpus/encoded_envelope/wrapped_key_limit_minus_one"),
    ),
    (
        "wrapped_key_limit_plus_one",
        include_bytes!("../corpus/encoded_envelope/wrapped_key_limit_plus_one"),
    ),
];

const AEAD_CASES: &[(&str, &[u8])] = &[
    (
        "cipher_limit",
        include_bytes!("../corpus/aead_envelope/cipher_limit"),
    ),
    (
        "cipher_limit_minus_one",
        include_bytes!("../corpus/aead_envelope/cipher_limit_minus_one"),
    ),
    (
        "cipher_limit_plus_one",
        include_bytes!("../corpus/aead_envelope/cipher_limit_plus_one"),
    ),
    (
        "cryptographic_mutation_cipher",
        include_bytes!("../corpus/aead_envelope/cryptographic_mutation_cipher"),
    ),
    (
        "cryptographic_mutation_nonce",
        include_bytes!("../corpus/aead_envelope/cryptographic_mutation_nonce"),
    ),
    (
        "cryptographic_mutation_signature",
        include_bytes!("../corpus/aead_envelope/cryptographic_mutation_signature"),
    ),
    (
        "cryptographic_mutation_tag",
        include_bytes!("../corpus/aead_envelope/cryptographic_mutation_tag"),
    ),
    (
        "cryptographic_mutation_wrapped_key",
        include_bytes!("../corpus/aead_envelope/cryptographic_mutation_wrapped_key"),
    ),
    (
        "frame_floor",
        include_bytes!("../corpus/aead_envelope/frame_floor"),
    ),
    (
        "frame_floor_minus_one",
        include_bytes!("../corpus/aead_envelope/frame_floor_minus_one"),
    ),
    ("full_valid_open", AEAD_FULL_VALID),
    (
        "raw_malformed",
        include_bytes!("../corpus/aead_envelope/raw_malformed"),
    ),
    (
        "reserved_ccm_algorithm",
        include_bytes!("../corpus/aead_envelope/reserved_ccm_algorithm"),
    ),
    (
        "signature_limit",
        include_bytes!("../corpus/aead_envelope/signature_limit"),
    ),
    (
        "signature_limit_minus_one",
        include_bytes!("../corpus/aead_envelope/signature_limit_minus_one"),
    ),
    (
        "signature_limit_plus_one",
        include_bytes!("../corpus/aead_envelope/signature_limit_plus_one"),
    ),
    (
        "wrapped_key_limit",
        include_bytes!("../corpus/aead_envelope/wrapped_key_limit"),
    ),
    (
        "wrapped_key_limit_minus_one",
        include_bytes!("../corpus/aead_envelope/wrapped_key_limit_minus_one"),
    ),
    (
        "wrapped_key_limit_plus_one",
        include_bytes!("../corpus/aead_envelope/wrapped_key_limit_plus_one"),
    ),
];

const TRANSPORT_CASES: &[(
    &str,
    &[u8],
    support::TransportScenario,
    support::ScenarioOutcome,
)] = &[
    (
        "case_insensitive_duplicate",
        include_bytes!("../corpus/transport_parts/case_insensitive_duplicate"),
        support::TransportScenario::Duplicate,
        support::ScenarioOutcome::Rejected,
    ),
    (
        "missing_required",
        include_bytes!("../corpus/transport_parts/missing_required"),
        support::TransportScenario::Missing,
        support::ScenarioOutcome::Rejected,
    ),
    (
        "success",
        TRANSPORT_SUCCESS,
        support::TransportScenario::Success,
        support::ScenarioOutcome::Accepted,
    ),
    (
        "unknown_header",
        include_bytes!("../corpus/transport_parts/unknown_header"),
        support::TransportScenario::Unknown,
        support::ScenarioOutcome::Accepted,
    ),
    (
        "header_cipher_duplicate",
        include_bytes!("../corpus/transport_parts/header_cipher_duplicate"),
        support::TransportScenario::HeaderCipherDuplicate,
        support::ScenarioOutcome::Rejected,
    ),
    (
        "header_cipher_empty",
        include_bytes!("../corpus/transport_parts/header_cipher_empty"),
        support::TransportScenario::HeaderCipherEmpty,
        support::ScenarioOutcome::Rejected,
    ),
    (
        "header_cipher_missing",
        include_bytes!("../corpus/transport_parts/header_cipher_missing"),
        support::TransportScenario::HeaderCipherMissing,
        support::ScenarioOutcome::Rejected,
    ),
    (
        "header_cipher_success",
        include_bytes!("../corpus/transport_parts/header_cipher_success"),
        support::TransportScenario::HeaderCipherSuccess,
        support::ScenarioOutcome::Accepted,
    ),
];

const TYPED_CASES: &[(
    &str,
    &[u8],
    support::TypedScenario,
    support::ScenarioOutcome,
)] = &[
    (
        "case_insensitive_duplicate",
        include_bytes!("../corpus/typed_headers/case_insensitive_duplicate"),
        support::TypedScenario::Duplicate,
        support::ScenarioOutcome::Rejected,
    ),
    (
        "valid_request",
        TYPED_VALID,
        support::TypedScenario::Valid,
        support::ScenarioOutcome::Accepted,
    ),
];

// Seeds for the `Generic` arm, which the tables above cannot express: its
// `expected_outcome` is `None` by construction, because the shape is built from
// the seed rather than fixed in `support`. Each seed instead declares the
// outcome the adapter must reach for the headers that seed builds.
const TRANSPORT_GENERIC_CASES: &[(&str, &[u8], support::ScenarioOutcome)] = &[
    (
        "generic_canonical",
        include_bytes!("../corpus/transport_parts/generic_canonical"),
        Accepted,
    ),
    (
        "generic_empty_names",
        include_bytes!("../corpus/transport_parts/generic_empty_names"),
        Rejected,
    ),
    // Rejected, unlike the typed side: a schema-required response header runs
    // through `trimmed_nonempty`, so an empty value is a missing field. Nothing
    // requires a particular header when building `RequestParts`, so the typed
    // seed of the same name is accepted.
    (
        "generic_empty_values",
        include_bytes!("../corpus/transport_parts/generic_empty_values"),
        Rejected,
    ),
    (
        "generic_exact_duplicate",
        include_bytes!("../corpus/transport_parts/generic_exact_duplicate"),
        Rejected,
    ),
    (
        "generic_lowercase_names",
        include_bytes!("../corpus/transport_parts/generic_lowercase_names"),
        Accepted,
    ),
    (
        "generic_lowercased_duplicate",
        include_bytes!("../corpus/transport_parts/generic_lowercased_duplicate"),
        Rejected,
    ),
    (
        "generic_mixed_case_names",
        include_bytes!("../corpus/transport_parts/generic_mixed_case_names"),
        Accepted,
    ),
    (
        "generic_name_collision_signature",
        include_bytes!("../corpus/transport_parts/generic_name_collision_signature"),
        Rejected,
    ),
    (
        "generic_raw_name_empty",
        include_bytes!("../corpus/transport_parts/generic_raw_name_empty"),
        Rejected,
    ),
    (
        "generic_raw_name_non_ascii",
        include_bytes!("../corpus/transport_parts/generic_raw_name_non_ascii"),
        Rejected,
    ),
    (
        "generic_raw_name_token_punctuation",
        include_bytes!("../corpus/transport_parts/generic_raw_name_token_punctuation"),
        Rejected,
    ),
    (
        "generic_raw_name_with_colon",
        include_bytes!("../corpus/transport_parts/generic_raw_name_with_colon"),
        Rejected,
    ),
    (
        "generic_raw_name_with_space",
        include_bytes!("../corpus/transport_parts/generic_raw_name_with_space"),
        Rejected,
    ),
    (
        "generic_reversed_order",
        include_bytes!("../corpus/transport_parts/generic_reversed_order"),
        Accepted,
    ),
    (
        "generic_unknown_names",
        include_bytes!("../corpus/transport_parts/generic_unknown_names"),
        Rejected,
    ),
    ("generic_value_crlf_injection", TRANSPORT_CRLF, Rejected),
    (
        "generic_value_delete",
        include_bytes!("../corpus/transport_parts/generic_value_delete"),
        Rejected,
    ),
    (
        "generic_value_nul",
        include_bytes!("../corpus/transport_parts/generic_value_nul"),
        Rejected,
    ),
    (
        "generic_value_tab",
        include_bytes!("../corpus/transport_parts/generic_value_tab"),
        Accepted,
    ),
    (
        "generic_value_unit_separator",
        include_bytes!("../corpus/transport_parts/generic_value_unit_separator"),
        Rejected,
    ),
];

// Seeds for the header-carried cipher Generic arm. The Body-schema tables
// above cannot reach `CipherLocation::Header`: `support::schema()` hardcodes
// Body, so these seeds use a separate 9-field frame and adapter.
const HEADER_CIPHER_GENERIC_CASES: &[(&str, &[u8], support::ScenarioOutcome)] = &[
    (
        "header_cipher_generic_body_ignored",
        include_bytes!("../corpus/transport_parts/header_cipher_generic_body_ignored"),
        Accepted,
    ),
    (
        "header_cipher_generic_canonical",
        include_bytes!("../corpus/transport_parts/header_cipher_generic_canonical"),
        Accepted,
    ),
    (
        "header_cipher_generic_duplicate_cipher",
        include_bytes!("../corpus/transport_parts/header_cipher_generic_duplicate_cipher"),
        Rejected,
    ),
    (
        "header_cipher_generic_empty_cipher_value",
        include_bytes!("../corpus/transport_parts/header_cipher_generic_empty_cipher_value"),
        Rejected,
    ),
    (
        "header_cipher_generic_missing_cipher",
        include_bytes!("../corpus/transport_parts/header_cipher_generic_missing_cipher"),
        Rejected,
    ),
    (
        "header_cipher_generic_value_crlf_injection",
        HEADER_CIPHER_CRLF,
        Rejected,
    ),
    (
        "header_cipher_generic_value_delete",
        include_bytes!("../corpus/transport_parts/header_cipher_generic_value_delete"),
        Rejected,
    ),
    (
        "header_cipher_generic_value_nul",
        include_bytes!("../corpus/transport_parts/header_cipher_generic_value_nul"),
        Rejected,
    ),
    (
        "header_cipher_generic_value_tab",
        include_bytes!("../corpus/transport_parts/header_cipher_generic_value_tab"),
        Accepted,
    ),
    (
        "header_cipher_generic_value_unit_separator",
        include_bytes!("../corpus/transport_parts/header_cipher_generic_value_unit_separator"),
        Rejected,
    ),
    (
        "header_cipher_generic_whitespace_cipher_value",
        include_bytes!("../corpus/transport_parts/header_cipher_generic_whitespace_cipher_value"),
        Rejected,
    ),
];

const TYPED_GENERIC_CASES: &[(&str, &[u8], support::ScenarioOutcome)] = &[
    (
        "generic_canonical",
        include_bytes!("../corpus/typed_headers/generic_canonical"),
        Accepted,
    ),
    (
        "generic_case_collision",
        include_bytes!("../corpus/typed_headers/generic_case_collision"),
        Rejected,
    ),
    (
        "generic_empty_names",
        include_bytes!("../corpus/typed_headers/generic_empty_names"),
        Rejected,
    ),
    (
        "generic_empty_values",
        include_bytes!("../corpus/typed_headers/generic_empty_values"),
        Accepted,
    ),
    (
        "generic_exact_duplicate",
        include_bytes!("../corpus/typed_headers/generic_exact_duplicate"),
        Rejected,
    ),
    (
        "generic_lowercase_names",
        include_bytes!("../corpus/typed_headers/generic_lowercase_names"),
        Accepted,
    ),
    (
        "generic_lowercased_duplicate",
        include_bytes!("../corpus/typed_headers/generic_lowercased_duplicate"),
        Rejected,
    ),
    (
        "generic_mixed_case_names",
        include_bytes!("../corpus/typed_headers/generic_mixed_case_names"),
        Accepted,
    ),
    (
        "generic_raw_name_non_ascii",
        include_bytes!("../corpus/typed_headers/generic_raw_name_non_ascii"),
        Rejected,
    ),
    (
        "generic_raw_name_token_punctuation",
        include_bytes!("../corpus/typed_headers/generic_raw_name_token_punctuation"),
        Accepted,
    ),
    (
        "generic_raw_name_with_colon",
        include_bytes!("../corpus/typed_headers/generic_raw_name_with_colon"),
        Rejected,
    ),
    (
        "generic_raw_name_with_space",
        include_bytes!("../corpus/typed_headers/generic_raw_name_with_space"),
        Rejected,
    ),
    (
        "generic_swapped_names_and_values",
        include_bytes!("../corpus/typed_headers/generic_swapped_names_and_values"),
        Accepted,
    ),
    ("generic_value_crlf_injection", TYPED_CRLF, Rejected),
    (
        "generic_value_delete",
        include_bytes!("../corpus/typed_headers/generic_value_delete"),
        Rejected,
    ),
    (
        "generic_value_nul",
        include_bytes!("../corpus/typed_headers/generic_value_nul"),
        Rejected,
    ),
    (
        "generic_value_tab",
        include_bytes!("../corpus/typed_headers/generic_value_tab"),
        Accepted,
    ),
    (
        "generic_value_unit_separator",
        include_bytes!("../corpus/typed_headers/generic_value_unit_separator"),
        Rejected,
    ),
];

#[test]
fn every_tracked_seed_has_a_contract_case() {
    assert_corpus_names("aead_envelope", AEAD_CASES.iter().map(|(name, _)| *name));
    assert_corpus_names(
        "encoded_envelope",
        ENCODED_CASES.iter().map(|(name, _)| *name),
    );
    assert_corpus_names(
        "transport_parts",
        TRANSPORT_CASES
            .iter()
            .map(|(name, ..)| *name)
            .chain(TRANSPORT_GENERIC_CASES.iter().map(|(name, ..)| *name))
            .chain(HEADER_CIPHER_GENERIC_CASES.iter().map(|(name, ..)| *name)),
    );
    assert_corpus_names(
        "typed_headers",
        TYPED_CASES
            .iter()
            .map(|(name, ..)| *name)
            .chain(TYPED_GENERIC_CASES.iter().map(|(name, ..)| *name)),
    );
}

#[test]
fn crlf_injection_seeds_still_carry_a_carriage_return() {
    // Git rewrites CRLF to LF on commit unless the path is marked `-text`, which
    // `.gitattributes` does for the corpus. Nothing else here would notice: the
    // seeds keep their names and their declared outcomes, because a lone LF is
    // rejected exactly like CRLF. The length prefix is checked too, since a
    // stripped CR leaves it describing one more byte than the value holds.
    for (target, seed, prefix, length) in [
        ("transport_parts", TRANSPORT_CRLF, &b"|21:"[..], 21),
        (
            "transport_parts_header_cipher",
            HEADER_CIPHER_CRLF,
            &b"|21:"[..],
            21,
        ),
        ("typed_headers", TYPED_CRLF, &b"|24:"[..], 24),
    ] {
        assert!(
            seed.windows(2).any(|pair| pair == b"\r\n"),
            "{target}: CRLF seed carries no carriage return; check .gitattributes"
        );
        let start = seed
            .windows(prefix.len())
            .position(|window| window == prefix)
            .unwrap_or_else(|| panic!("{target}: declared CRLF field is missing"))
            + prefix.len();
        assert!(
            seed[start..start + length]
                .windows(2)
                .any(|pair| pair == b"\r\n"),
            "{target}: the declared field length no longer spans the carriage return"
        );
    }
}

#[test]
fn curated_generic_header_cipher_seeds_reach_named_adapter_outcomes() {
    for (name, seed, expected) in HEADER_CIPHER_GENERIC_CASES {
        assert_eq!(
            support::transport_scenario(seed),
            support::TransportScenario::HeaderCipherGeneric,
            "{name}"
        );
        let outcome = match support::header_cipher_adapter()
            .parse_response(support::generic_header_cipher_parts(seed))
        {
            Ok(_) => Accepted,
            Err(_) => Rejected,
        };
        assert_eq!(outcome, *expected, "{name}");
    }
}

#[test]
fn curated_generic_transport_seeds_reach_named_adapter_outcomes() {
    for (name, seed, expected) in TRANSPORT_GENERIC_CASES {
        assert_eq!(
            support::transport_scenario(seed),
            support::TransportScenario::Generic,
            "{name}"
        );
        let outcome =
            match support::adapter().parse_response(support::generic_transport_parts(seed)) {
                Ok(_) => Accepted,
                Err(_) => Rejected,
            };
        assert_eq!(outcome, *expected, "{name}");
    }
}

#[test]
fn curated_generic_typed_seeds_reach_named_construction_outcomes() {
    for (name, seed, expected) in TYPED_GENERIC_CASES {
        assert_eq!(
            support::typed_scenario(seed),
            support::TypedScenario::Generic,
            "{name}"
        );
        let outcome = match support::generic_typed_parts(seed) {
            Ok(_) => Accepted,
            Err(_) => Rejected,
        };
        assert_eq!(outcome, *expected, "{name}");
    }
}

#[test]
fn curated_aead_seeds_open_or_reject_as_their_contract_requires() {
    let open_with = |seed: &[u8]| {
        let (signature, wrapped_key, cipher) = support::aead_encoded_values(seed);
        support::aead_client().open_response(ResponseParts::new(
            [
                ("X-Fuzz-Response-Signature", signature),
                ("X-Fuzz-Response-Wrapped-Key", wrapped_key),
                (
                    "X-Fuzz-Response-Remote-Signing-Certificate",
                    "fuzz-certificate".to_owned(),
                ),
            ],
            cipher,
        ))
    };

    assert_eq!(
        open_with(AEAD_FULL_VALID).expect("full valid AEAD seed opens"),
        support::VALID_PLAINTEXT
    );
    for (name, seed) in AEAD_CASES {
        if *name == "full_valid_open" {
            continue;
        }
        assert!(open_with(seed).is_err(), "{name} must be rejected");
    }
}

#[test]
fn curated_aead_mutation_seeds_change_their_named_frame_regions() {
    let valid_cipher = &support::aead_valid_envelope().cipher;
    let valid = STANDARD
        .decode(valid_cipher)
        .expect("valid AEAD cipher is Base64");
    assert_eq!(valid.len(), 43, "fixture frame length");

    for (name, seed, selector, expected_changed_bytes) in [
        (
            "cryptographic_mutation_nonce",
            include_bytes!("../corpus/aead_envelope/cryptographic_mutation_nonce").as_slice(),
            8,
            &[6][..],
        ),
        (
            "cryptographic_mutation_cipher",
            include_bytes!("../corpus/aead_envelope/cryptographic_mutation_cipher").as_slice(),
            20,
            &[15][..],
        ),
        (
            "cryptographic_mutation_tag",
            include_bytes!("../corpus/aead_envelope/cryptographic_mutation_tag").as_slice(),
            40,
            &[30][..],
        ),
    ] {
        let (_, _, cipher) = support::aead_encoded_values(seed);
        let changed_base64_positions = valid_cipher
            .bytes()
            .zip(cipher.bytes())
            .enumerate()
            .filter_map(|(offset, (before, after))| (before != after).then_some(offset))
            .collect::<Vec<_>>();
        assert_eq!(changed_base64_positions, [selector], "{name}");
        let mutated = STANDARD.decode(cipher).expect("mutated cipher is Base64");
        let changed = valid
            .iter()
            .zip(mutated)
            .enumerate()
            .filter_map(|(offset, (before, after))| (before != &after).then_some(offset))
            .collect::<Vec<_>>();
        assert_eq!(changed, expected_changed_bytes, "{name}");
    }
}

#[test]
fn curated_aead_boundary_seeds_reach_literal_auxiliary_and_cipher_limits() {
    assert_eq!(support::AEAD_FRAME_OVERHEAD_BYTES, 30);
    assert_eq!(support::AEAD_CIPHER_LIMIT, 128);

    let valid = support::aead_valid_envelope();
    for (name, seed, field, expected_len) in [
        (
            "signature_limit_minus_one",
            include_bytes!("../corpus/aead_envelope/signature_limit_minus_one").as_slice(),
            0,
            16_383,
        ),
        (
            "signature_limit",
            include_bytes!("../corpus/aead_envelope/signature_limit").as_slice(),
            0,
            16_384,
        ),
        (
            "signature_limit_plus_one",
            include_bytes!("../corpus/aead_envelope/signature_limit_plus_one").as_slice(),
            0,
            16_385,
        ),
        (
            "wrapped_key_limit_minus_one",
            include_bytes!("../corpus/aead_envelope/wrapped_key_limit_minus_one").as_slice(),
            1,
            16_383,
        ),
        (
            "wrapped_key_limit",
            include_bytes!("../corpus/aead_envelope/wrapped_key_limit").as_slice(),
            1,
            16_384,
        ),
        (
            "wrapped_key_limit_plus_one",
            include_bytes!("../corpus/aead_envelope/wrapped_key_limit_plus_one").as_slice(),
            1,
            16_385,
        ),
        (
            "cipher_limit_minus_one",
            include_bytes!("../corpus/aead_envelope/cipher_limit_minus_one").as_slice(),
            2,
            127,
        ),
        (
            "cipher_limit",
            include_bytes!("../corpus/aead_envelope/cipher_limit").as_slice(),
            2,
            128,
        ),
        (
            "cipher_limit_plus_one",
            include_bytes!("../corpus/aead_envelope/cipher_limit_plus_one").as_slice(),
            2,
            129,
        ),
    ] {
        let values = support::aead_encoded_values(seed);
        let actual = [&values.0, &values.1, &values.2];
        assert_eq!(actual[field].len(), expected_len, "{name}");
        for unchanged in 0..3 {
            if unchanged != field {
                let expected = [&valid.signature, &valid.wrapped_session_key, &valid.cipher];
                assert_eq!(actual[unchanged], expected[unchanged], "{name}");
            }
        }
    }
}

#[test]
fn curated_transport_scenarios_reach_named_adapter_outcomes() {
    for (name, seed, scenario, expected) in TRANSPORT_CASES {
        assert_eq!(support::transport_scenario(seed), *scenario, "{name}");
        assert_eq!(
            support::transport_outcome(*scenario),
            Some(*expected),
            "{name}"
        );
    }
}

#[test]
fn curated_typed_scenarios_reach_valid_and_conflicting_requests() {
    for (name, seed, scenario, expected) in TYPED_CASES {
        assert_eq!(support::typed_scenario(seed), *scenario, "{name}");
        assert_eq!(support::typed_outcome(*scenario), Some(*expected), "{name}");
    }
}

#[test]
fn transport_success_suffix_drives_generic_name_order_and_duplicate_paths() {
    let generic = with_byte(TRANSPORT_SUCCESS, 0, b'G');
    assert_eq!(
        support::transport_scenario(&generic),
        support::TransportScenario::Generic
    );
    let generic_parts = support::generic_transport_parts(&generic);
    assert_eq!(
        generic_parts.headers().collect::<Vec<_>>(),
        [
            ("X-Fuzz-Response-Signature", "signature"),
            ("X-Fuzz-Response-Wrapped-Key", "wrapped"),
            (
                "X-Fuzz-Response-Remote-Signing-Certificate",
                "fuzz-certificate",
            ),
        ]
    );
    assert_eq!(generic_parts.body(), "cipher");
    assert!(support::adapter().parse_response(generic_parts).is_ok());
    assert_eq!(
        response_names(&generic),
        [
            "X-Fuzz-Response-Signature",
            "X-Fuzz-Response-Wrapped-Key",
            "X-Fuzz-Response-Remote-Signing-Certificate",
        ]
    );

    let lowercase = with_byte(&generic, 1, b'l');
    assert_eq!(response_names(&lowercase)[0], "x-fuzz-response-signature");
    assert!(
        support::adapter()
            .parse_response(support::generic_transport_parts(&lowercase))
            .is_ok()
    );

    let mixed_case = with_byte(&generic, 1, b'm');
    assert_eq!(response_names(&mixed_case)[0], "X-fUzZ-ReSpOnSe-SiGnAtUrE");
    assert!(
        support::adapter()
            .parse_response(support::generic_transport_parts(&mixed_case))
            .is_ok()
    );

    let unknown = with_byte(&generic, 1, b'u');
    assert_eq!(response_names(&unknown)[0], "X-Fuzz-Unknown");
    assert!(
        support::adapter()
            .parse_response(support::generic_transport_parts(&unknown))
            .is_err()
    );

    let empty = with_byte(&generic, 1, b'e');
    assert_eq!(response_names(&empty)[0], "");
    assert!(
        support::adapter()
            .parse_response(support::generic_transport_parts(&empty))
            .is_err()
    );

    let raw = with_byte(&generic, 1, b'r');
    assert_eq!(response_names(&raw)[0], "X-Raw-Name");
    assert!(
        support::adapter()
            .parse_response(support::generic_transport_parts(&raw))
            .is_err()
    );

    let duplicate_name = with_byte(&generic, 2, b's');
    assert_eq!(
        response_names(&duplicate_name)[0],
        response_names(&duplicate_name)[1]
    );
    assert!(
        support::adapter()
            .parse_response(support::generic_transport_parts(&duplicate_name))
            .is_err()
    );

    let reordered = with_byte(&generic, 4, b'1');
    assert_eq!(response_names(&reordered)[0], "X-Fuzz-Response-Wrapped-Key");

    let appended_duplicate = with_byte(&generic, 5, b'2');
    assert_eq!(response_names(&appended_duplicate).len(), 4);
    assert!(
        support::adapter()
            .parse_response(support::generic_transport_parts(&appended_duplicate))
            .is_err()
    );
}

#[test]
fn typed_valid_suffix_drives_generic_success_and_case_insensitive_conflict() {
    let generic = with_byte(TYPED_VALID, 0, b'G');
    assert_eq!(
        support::typed_scenario(&generic),
        support::TypedScenario::Generic
    );
    let valid = support::generic_typed_parts(&generic).expect("generic typed seed is valid");
    assert_eq!(request_names(&valid), ["X-Fuzz-Header", "X-Fuzz-Other"]);
    assert_eq!(valid.header("X-Fuzz-Header"), Some("header-value"));

    let lowercase = with_byte(&generic, 1, b'l');
    assert_eq!(
        request_names(&support::generic_typed_parts(&lowercase).expect("lowercase is valid"))[0],
        "x-fuzz-header"
    );

    let mixed_case = with_byte(&generic, 1, b'm');
    assert_eq!(
        request_names(&support::generic_typed_parts(&mixed_case).expect("mixed case is valid"))[0],
        "X-fUzZ-HeAdEr"
    );

    let raw = with_byte(&generic, 1, b'r');
    assert_eq!(
        request_names(&support::generic_typed_parts(&raw).expect("raw name is valid"))[0],
        "X-Raw-One"
    );

    let empty = with_byte(&generic, 1, b'e');
    assert!(support::generic_typed_parts(&empty).is_err());

    let conflict = with_byte(&generic, 2, b'h');
    assert!(support::generic_typed_parts(&conflict).is_err());

    let reordered = with_byte(&generic, 3, b'1');
    assert_eq!(
        request_names(&support::generic_typed_parts(&reordered).expect("reordered is valid"))[0],
        "X-Fuzz-Other"
    );

    let appended_conflict = with_byte(&generic, 4, b'2');
    assert!(support::generic_typed_parts(&appended_conflict).is_err());
}

#[test]
fn length_delimited_fields_are_independent() {
    assert_eq!(
        support::fields(b"vvv000|1:a|3:two|2:zz"),
        [b"a".as_slice(), b"two", b"zz"]
    );
}

#[test]
fn fixed_transport_schema_is_cached() {
    assert!(std::ptr::eq(support::schema(), support::schema()));
}

#[test]
fn full_valid_encoded_seed_opens_through_crypto() {
    let (signature, wrapped_key, cipher) = support::encoded_values(FULL_VALID_OPEN);
    let envelope = support::valid_envelope();
    assert_eq!(signature, envelope.signature);
    assert_eq!(wrapped_key, envelope.wrapped_session_key);
    assert_eq!(cipher, envelope.cipher);

    let opened = support::client().open_response(ResponseParts::new(
        [
            ("X-Fuzz-Response-Signature", signature),
            ("X-Fuzz-Response-Wrapped-Key", wrapped_key),
            (
                "X-Fuzz-Response-Remote-Signing-Certificate",
                "fuzz-certificate".to_owned(),
            ),
        ],
        cipher,
    ));
    assert_eq!(
        opened.expect("full valid envelope opens"),
        support::VALID_PLAINTEXT
    );
}

#[test]
fn raw_malformed_seed_controls_all_three_fields() {
    let values = support::encoded_values(RAW_MALFORMED);
    assert_eq!(values, ("!".to_owned(), "!".to_owned(), "!".to_owned()));
}

#[test]
fn curated_boundary_seeds_reach_exact_auxiliary_and_cipher_limits() {
    const CIPHER_BASE64_LIMIT: usize = support::CIPHER_LIMIT;
    assert_eq!(support::PADDED_CIPHER_BYTES, 80);
    assert_eq!(
        CIPHER_BASE64_LIMIT,
        support::PADDED_CIPHER_BYTES.div_ceil(3) * 4
    );
    assert_eq!(CIPHER_BASE64_LIMIT, 108);
    let valid = support::valid_envelope();
    for (name, seed, field, expected_len) in [
        (
            "signature_limit_minus_one",
            include_bytes!("../corpus/encoded_envelope/signature_limit_minus_one").as_slice(),
            0,
            support::AUXILIARY_LIMIT - 1,
        ),
        (
            "signature_limit",
            include_bytes!("../corpus/encoded_envelope/signature_limit").as_slice(),
            0,
            support::AUXILIARY_LIMIT,
        ),
        (
            "signature_limit_plus_one",
            include_bytes!("../corpus/encoded_envelope/signature_limit_plus_one").as_slice(),
            0,
            support::AUXILIARY_LIMIT + 1,
        ),
        (
            "wrapped_key_limit_minus_one",
            include_bytes!("../corpus/encoded_envelope/wrapped_key_limit_minus_one").as_slice(),
            1,
            support::AUXILIARY_LIMIT - 1,
        ),
        (
            "wrapped_key_limit",
            include_bytes!("../corpus/encoded_envelope/wrapped_key_limit").as_slice(),
            1,
            support::AUXILIARY_LIMIT,
        ),
        (
            "wrapped_key_limit_plus_one",
            include_bytes!("../corpus/encoded_envelope/wrapped_key_limit_plus_one").as_slice(),
            1,
            support::AUXILIARY_LIMIT + 1,
        ),
        (
            "cipher_limit_minus_one",
            include_bytes!("../corpus/encoded_envelope/cipher_limit_minus_one").as_slice(),
            2,
            support::CIPHER_LIMIT - 1,
        ),
        (
            "cipher_limit",
            include_bytes!("../corpus/encoded_envelope/cipher_limit").as_slice(),
            2,
            support::CIPHER_LIMIT,
        ),
        (
            "cipher_limit_plus_one",
            include_bytes!("../corpus/encoded_envelope/cipher_limit_plus_one").as_slice(),
            2,
            support::CIPHER_LIMIT + 1,
        ),
    ] {
        let values = support::encoded_values(seed);
        let actual = [&values.0, &values.1, &values.2];
        assert_eq!(actual[field].len(), expected_len, "{name}");
        for unchanged in 0..3 {
            if unchanged != field {
                let expected = [&valid.signature, &valid.wrapped_session_key, &valid.cipher];
                assert_eq!(actual[unchanged], expected[unchanged], "{name}");
            }
        }
    }
}

#[test]
fn encoded_boundaries_return_public_safe_error_categories() {
    for (name, seed) in [
        (
            "signature_limit_minus_one",
            include_bytes!("../corpus/encoded_envelope/signature_limit_minus_one").as_slice(),
        ),
        (
            "signature_limit",
            include_bytes!("../corpus/encoded_envelope/signature_limit").as_slice(),
        ),
        (
            "signature_limit_plus_one",
            include_bytes!("../corpus/encoded_envelope/signature_limit_plus_one").as_slice(),
        ),
        (
            "wrapped_key_limit_minus_one",
            include_bytes!("../corpus/encoded_envelope/wrapped_key_limit_minus_one").as_slice(),
        ),
        (
            "wrapped_key_limit",
            include_bytes!("../corpus/encoded_envelope/wrapped_key_limit").as_slice(),
        ),
        (
            "wrapped_key_limit_plus_one",
            include_bytes!("../corpus/encoded_envelope/wrapped_key_limit_plus_one").as_slice(),
        ),
        (
            "cipher_limit_minus_one",
            include_bytes!("../corpus/encoded_envelope/cipher_limit_minus_one").as_slice(),
        ),
        (
            "cipher_limit",
            include_bytes!("../corpus/encoded_envelope/cipher_limit").as_slice(),
        ),
    ] {
        assert!(
            matches!(open_encoded(seed), Err(Error::InvalidEnvelope)),
            "{name}"
        );
    }

    assert!(matches!(
        open_encoded(include_bytes!(
            "../corpus/encoded_envelope/cipher_limit_plus_one"
        )),
        Err(Error::MessageTooLarge { limit: 64 })
    ));
}

#[test]
fn curated_mutation_seeds_change_only_the_named_cryptographic_field() {
    let valid = support::valid_envelope();
    let expected = [&valid.signature, &valid.wrapped_session_key, &valid.cipher];
    for (name, seed, mutated) in [
        (
            "cryptographic_mutation_signature",
            include_bytes!("../corpus/encoded_envelope/cryptographic_mutation_signature")
                .as_slice(),
            0,
        ),
        (
            "cryptographic_mutation_wrapped_key",
            include_bytes!("../corpus/encoded_envelope/cryptographic_mutation_wrapped_key")
                .as_slice(),
            1,
        ),
        (
            "cryptographic_mutation_cipher",
            include_bytes!("../corpus/encoded_envelope/cryptographic_mutation_cipher").as_slice(),
            2,
        ),
    ] {
        let values = support::encoded_values(seed);
        let actual = [&values.0, &values.1, &values.2];
        for field in 0..3 {
            if field == mutated {
                assert_ne!(actual[field], expected[field], "{name}");
            } else {
                assert_eq!(actual[field], expected[field], "{name}");
            }
        }
    }
}

fn assert_corpus_names<'a>(target: &str, names: impl IntoIterator<Item = &'a str>) {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(target);
    let mut actual = fs::read_dir(corpus)
        .expect("tracked corpus is readable")
        .map(|entry| {
            entry
                .expect("tracked corpus entry is readable")
                .file_name()
                .into_string()
                .expect("tracked corpus names are UTF-8")
        })
        .collect::<Vec<_>>();
    actual.sort();
    let mut expected = names.into_iter().map(str::to_owned).collect::<Vec<_>>();
    expected.sort();
    assert_eq!(actual, expected, "{target}");
}

fn with_byte(seed: &[u8], index: usize, value: u8) -> Vec<u8> {
    let mut mutated = seed.to_vec();
    mutated[index] = value;
    mutated
}

fn response_names(data: &[u8]) -> Vec<String> {
    support::generic_transport_parts(data)
        .headers()
        .map(|(name, _)| name.to_owned())
        .collect()
}

fn request_names(parts: &RequestParts) -> Vec<String> {
    parts
        .headers()
        .map(|(name, _)| name.as_str().to_owned())
        .collect()
}

fn open_encoded(seed: &[u8]) -> gmcrypto_envelope_lite::Result<Vec<u8>> {
    let (signature, wrapped_key, cipher) = support::encoded_values(seed);
    support::client().open_response(ResponseParts::new(
        [
            ("X-Fuzz-Response-Signature", signature),
            ("X-Fuzz-Response-Wrapped-Key", wrapped_key),
            (
                "X-Fuzz-Response-Remote-Signing-Certificate",
                "fuzz-certificate".to_owned(),
            ),
        ],
        cipher,
    ))
}
