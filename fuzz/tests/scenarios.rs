#[path = "../fuzz_targets/support.rs"]
mod support;

use std::fs;
use std::path::Path;

use gmcrypto_envelope_lite::{Error, ProtocolAdapter, RequestParts, ResponseParts};

const FULL_VALID_OPEN: &[u8] = include_bytes!("../corpus/encoded_envelope/full_valid_open");
const RAW_MALFORMED: &[u8] = include_bytes!("../corpus/encoded_envelope/raw_malformed");
const TRANSPORT_SUCCESS: &[u8] = include_bytes!("../corpus/transport_parts/success");
const TYPED_VALID: &[u8] = include_bytes!("../corpus/typed_headers/valid_request");

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

#[test]
fn every_tracked_seed_has_a_contract_case() {
    assert_corpus_names(
        "encoded_envelope",
        ENCODED_CASES.iter().map(|(name, _)| *name),
    );
    assert_corpus_names(
        "transport_parts",
        TRANSPORT_CASES.iter().map(|(name, ..)| *name),
    );
    assert_corpus_names("typed_headers", TYPED_CASES.iter().map(|(name, ..)| *name));
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
