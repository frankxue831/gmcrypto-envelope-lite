#![allow(dead_code)]

use std::sync::{Arc, OnceLock};

use gmcrypto_core::sm2::Sm2PrivateKey;
use gmcrypto_core::{pkcs8, spki};
use gmcrypto_envelope_lite::{
    AuthenticationContext, AuthenticationMode, CipherLocation, ClientConfig, HeaderName,
    HeaderProtocolAdapter, HeaderSchema, HeaderValue, KeyMaterial, PrivateKey, ProtocolAdapter,
    PublicKey, RequestParts, ResponseParts, SecureClient, SecureEnvelope,
};

const TEST_PASSWORD: &[u8] = b"public-fuzz-password";
pub const AUXILIARY_LIMIT: usize = 16 * 1024;
pub const MAX_PLAINTEXT_BYTES: usize = 64;
pub const AEAD_FRAME_OVERHEAD_BYTES: usize = 30;
// An AEAD frame at the 64-byte plaintext limit is 94 bytes; Base64 rounds up by triples.
pub const AEAD_CIPHER_LIMIT: usize =
    (MAX_PLAINTEXT_BYTES + AEAD_FRAME_OVERHEAD_BYTES).div_ceil(3) * 4;
// PKCS#7 adds a full SM4 block at the exact 64-byte limit, then Base64 rounds up by triples.
pub const PADDED_CIPHER_BYTES: usize = (MAX_PLAINTEXT_BYTES / 16 + 1) * 16;
pub const CIPHER_LIMIT: usize = PADDED_CIPHER_BYTES.div_ceil(3) * 4;
pub const VALID_PLAINTEXT: &[u8] = b"fuzz envelope";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportScenario {
    Success,
    Duplicate,
    Unknown,
    Missing,
    HeaderCipherSuccess,
    HeaderCipherMissing,
    HeaderCipherEmpty,
    HeaderCipherDuplicate,
    HeaderCipherGeneric,
    Generic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypedScenario {
    Valid,
    Duplicate,
    Generic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioOutcome {
    Accepted,
    Rejected,
}

impl TransportScenario {
    pub fn expected_outcome(self) -> Option<ScenarioOutcome> {
        match self {
            Self::Success | Self::Unknown | Self::HeaderCipherSuccess => {
                Some(ScenarioOutcome::Accepted)
            }
            Self::Duplicate
            | Self::Missing
            | Self::HeaderCipherMissing
            | Self::HeaderCipherEmpty
            | Self::HeaderCipherDuplicate => Some(ScenarioOutcome::Rejected),
            Self::Generic | Self::HeaderCipherGeneric => None,
        }
    }
}

impl TypedScenario {
    pub fn expected_outcome(self) -> Option<ScenarioOutcome> {
        match self {
            Self::Valid => Some(ScenarioOutcome::Accepted),
            Self::Duplicate => Some(ScenarioOutcome::Rejected),
            Self::Generic => None,
        }
    }
}

/// Parses three independently sized fields encoded as `mmmBBB|len:value|len:value|len:value`.
/// The first three bytes select valid/raw/boundary/mutated values, and the next three
/// independently select limit-1/limit/limit+1 for boundary values.
/// Invalid frame syntax yields empty fields; truncated bodies yield all available bytes.
pub fn fields(data: &[u8]) -> [&[u8]; 3] {
    framed(data)
}

fn framed<const N: usize>(data: &[u8]) -> [&[u8]; N] {
    let Some(payload) = data.get(6..).and_then(|data| data.strip_prefix(b"|")) else {
        return [&[]; N];
    };
    let mut remainder = payload;
    std::array::from_fn(|_| {
        let (field, next) = frame(remainder);
        remainder = next;
        field
    })
}

fn frame(data: &[u8]) -> (&[u8], &[u8]) {
    let Some(colon) = data.iter().position(|byte| *byte == b':') else {
        return (&[], &[]);
    };
    let Ok(length) = std::str::from_utf8(&data[..colon])
        .unwrap_or_default()
        .parse::<usize>()
    else {
        return (&[], &[]);
    };
    let body = &data[colon + 1..];
    let length = length.min(body.len());
    let (field, remainder) = body.split_at(length);
    let remainder = remainder.strip_prefix(b"|").unwrap_or(remainder);
    (field, remainder)
}

pub fn text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}

pub fn transport_scenario(data: &[u8]) -> TransportScenario {
    match data.first().copied() {
        Some(b'S') => TransportScenario::Success,
        Some(b'D') => TransportScenario::Duplicate,
        Some(b'U') => TransportScenario::Unknown,
        Some(b'M') => TransportScenario::Missing,
        Some(b'H') => TransportScenario::HeaderCipherSuccess,
        Some(b'I') => TransportScenario::HeaderCipherMissing,
        Some(b'E') => TransportScenario::HeaderCipherEmpty,
        Some(b'J') => TransportScenario::HeaderCipherDuplicate,
        Some(b'C') => TransportScenario::HeaderCipherGeneric,
        _ => TransportScenario::Generic,
    }
}

pub fn typed_scenario(data: &[u8]) -> TypedScenario {
    match data.first().copied() {
        Some(b'V') => TypedScenario::Valid,
        Some(b'D') => TypedScenario::Duplicate,
        _ => TypedScenario::Generic,
    }
}

pub fn generic_transport_parts(data: &[u8]) -> ResponseParts {
    let framed = framed::<7>(data);
    let selectors = data.get(..6).unwrap_or_default();
    let mut headers = (0..3)
        .map(|slot| {
            (
                transport_name(selectors.get(slot + 1), slot, framed[slot]),
                text(framed[slot + 3]),
            )
        })
        .collect::<Vec<_>>();

    let order = match selectors.get(4).copied().unwrap_or_default() % 6 {
        0 => [0, 1, 2],
        1 => [1, 0, 2],
        2 => [0, 2, 1],
        3 => [2, 1, 0],
        4 => [1, 2, 0],
        _ => [2, 0, 1],
    };
    headers = order
        .map(|index| headers[index].clone())
        .into_iter()
        .collect();

    match selectors.get(5).copied().unwrap_or_default() % 3 {
        0 => {}
        1 => headers.push(headers[0].clone()),
        _ => headers.push((headers[0].0.to_ascii_lowercase(), headers[0].1.clone())),
    }

    ResponseParts::new(headers, text(framed[6]))
}

pub fn generic_header_cipher_parts(data: &[u8]) -> ResponseParts {
    let framed = framed::<9>(data);
    let selectors = data.get(..6).unwrap_or_default();
    let mut headers = (0..4)
        .map(|slot| {
            (
                header_cipher_name(selectors.get(slot + 1), slot, framed[slot]),
                text(framed[slot + 4]),
            )
        })
        .collect::<Vec<_>>();

    let packed = selectors.get(5).copied().unwrap_or_default();
    let order = match packed % 6 {
        0 => [0, 1, 2, 3],
        1 => [3, 0, 1, 2],
        2 => [0, 1, 3, 2],
        3 => [3, 2, 1, 0],
        4 => [0, 3, 1, 2],
        _ => [1, 0, 2, 3],
    };
    headers = order
        .map(|index| headers[index].clone())
        .into_iter()
        .collect();

    match packed % 3 {
        0 => {}
        1 => headers.push(headers[0].clone()),
        _ => headers.push((headers[0].0.to_ascii_lowercase(), headers[0].1.clone())),
    }

    ResponseParts::new(headers, text(framed[8]))
}

pub fn generic_typed_parts(data: &[u8]) -> gmcrypto_envelope_lite::Result<RequestParts> {
    let framed = framed::<5>(data);
    let selectors = data.get(..6).unwrap_or_default();
    let mut names = [
        typed_name(selectors.get(1), 0, framed[0]),
        typed_name(selectors.get(2), 1, framed[1]),
    ];
    if selectors.get(3).copied().unwrap_or_default() % 2 == 1 {
        names.swap(0, 1);
    }
    let mut values = [text(framed[2]), text(framed[3])];
    if selectors.get(5).copied().unwrap_or_default() % 2 == 1 {
        values.swap(0, 1);
    }
    let mut headers = vec![
        (names[0].clone(), values[0].clone()),
        (names[1].clone(), values[1].clone()),
    ];
    match selectors.get(4).copied().unwrap_or_default() % 3 {
        0 => {}
        1 => headers.push(headers[0].clone()),
        _ => headers.push((headers[0].0.to_ascii_lowercase(), headers[0].1.clone())),
    }
    RequestParts::new(headers, text(framed[4]))
}

fn transport_name(selector: Option<&u8>, slot: usize, raw: &[u8]) -> String {
    const CANONICAL: [&str; 3] = [
        "X-Fuzz-Response-Signature",
        "X-Fuzz-Response-Wrapped-Key",
        "X-Fuzz-Response-Remote-Signing-Certificate",
    ];
    const MIXED: [&str; 3] = [
        "X-fUzZ-ReSpOnSe-SiGnAtUrE",
        "X-fUzZ-ReSpOnSe-WrApPeD-KeY",
        "X-fUzZ-ReSpOnSe-ReMoTe-SiGnInG-CeRtIfIcAtE",
    ];
    let selector = selector.copied().unwrap_or(b'c');
    match selector {
        b'c' => CANONICAL[slot].to_owned(),
        b'l' => CANONICAL[slot].to_ascii_lowercase(),
        b'm' => MIXED[slot].to_owned(),
        b'u' => "X-Fuzz-Unknown".to_owned(),
        b'e' => String::new(),
        b'r' => text(raw),
        b's' => CANONICAL[0].to_owned(),
        b'w' => CANONICAL[1].to_owned(),
        b'k' => CANONICAL[2].to_owned(),
        other => match other % 9 {
            0 => CANONICAL[slot].to_owned(),
            1 => CANONICAL[slot].to_ascii_lowercase(),
            2 => MIXED[slot].to_owned(),
            3 => "X-Fuzz-Unknown".to_owned(),
            4 => String::new(),
            5 => text(raw),
            6 => CANONICAL[0].to_owned(),
            7 => CANONICAL[1].to_owned(),
            _ => CANONICAL[2].to_owned(),
        },
    }
}

fn header_cipher_name(selector: Option<&u8>, slot: usize, raw: &[u8]) -> String {
    const CANONICAL: [&str; 4] = [
        "X-Fuzz-Response-Signature",
        "X-Fuzz-Response-Wrapped-Key",
        "X-Fuzz-Response-Remote-Signing-Certificate",
        "X-Fuzz-Response-Cipher",
    ];
    const MIXED: [&str; 4] = [
        "X-fUzZ-ReSpOnSe-SiGnAtUrE",
        "X-fUzZ-ReSpOnSe-WrApPeD-KeY",
        "X-fUzZ-ReSpOnSe-ReMoTe-SiGnInG-CeRtIfIcAtE",
        "X-fUzZ-ReSpOnSe-CiPhEr",
    ];
    let selector = selector.copied().unwrap_or(b'c');
    match selector {
        b'c' => CANONICAL[slot].to_owned(),
        b'l' => CANONICAL[slot].to_ascii_lowercase(),
        b'm' => MIXED[slot].to_owned(),
        b'u' => "X-Fuzz-Unknown".to_owned(),
        b'e' => String::new(),
        b'r' => text(raw),
        b's' => CANONICAL[0].to_owned(),
        b'w' => CANONICAL[1].to_owned(),
        b'k' => CANONICAL[2].to_owned(),
        b'p' => CANONICAL[3].to_owned(),
        other => match other % 10 {
            0 => CANONICAL[slot].to_owned(),
            1 => CANONICAL[slot].to_ascii_lowercase(),
            2 => MIXED[slot].to_owned(),
            3 => "X-Fuzz-Unknown".to_owned(),
            4 => String::new(),
            5 => text(raw),
            6 => CANONICAL[0].to_owned(),
            7 => CANONICAL[1].to_owned(),
            8 => CANONICAL[2].to_owned(),
            _ => CANONICAL[3].to_owned(),
        },
    }
}

fn typed_name(selector: Option<&u8>, slot: usize, raw: &[u8]) -> String {
    const CANONICAL: [&str; 2] = ["X-Fuzz-Header", "X-Fuzz-Other"];
    const MIXED: [&str; 2] = ["X-fUzZ-HeAdEr", "X-fUzZ-OtHeR"];
    let selector = selector.copied().unwrap_or(b'c');
    match selector {
        b'c' => CANONICAL[slot].to_owned(),
        b'l' => CANONICAL[slot].to_ascii_lowercase(),
        b'm' => MIXED[slot].to_owned(),
        b'h' => CANONICAL[0].to_ascii_lowercase(),
        b'o' => CANONICAL[1].to_owned(),
        b'e' => String::new(),
        b'r' => text(raw),
        other => match other % 7 {
            0 => CANONICAL[slot].to_owned(),
            1 => CANONICAL[slot].to_ascii_lowercase(),
            2 => MIXED[slot].to_owned(),
            3 => CANONICAL[0].to_ascii_lowercase(),
            4 => CANONICAL[1].to_owned(),
            5 => String::new(),
            _ => text(raw),
        },
    }
}

fn fuzz_schema_builder() -> gmcrypto_envelope_lite::HeaderSchemaBuilder {
    HeaderSchema::builder()
        .static_request_header("Content-Type", "application/fuzz+octets")
        .local_identity_header("X-Fuzz-Local-Identity")
        .operation_header("X-Fuzz-Operation")
        .request_id_header("X-Fuzz-Request-Id")
        .request_time_header("X-Fuzz-Request-Time")
        .api_version_header("X-Fuzz-Api-Version")
        .local_certificate_header("X-Fuzz-Local-Certificate")
        .remote_signing_certificate_header("X-Fuzz-Remote-Signing-Certificate")
        .remote_encryption_certificate_header("X-Fuzz-Remote-Encryption-Certificate")
        .request_signature_header("X-Fuzz-Request-Signature")
        .request_wrapped_key_header("X-Fuzz-Request-Wrapped-Key")
        .request_cipher(CipherLocation::Body)
        .response_signature_header("X-Fuzz-Response-Signature")
        .response_wrapped_key_header("X-Fuzz-Response-Wrapped-Key")
        .response_remote_signing_certificate_header("X-Fuzz-Response-Remote-Signing-Certificate")
}

pub fn schema() -> &'static HeaderSchema {
    static SCHEMA: OnceLock<HeaderSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        fuzz_schema_builder()
            .response_cipher(CipherLocation::Body)
            .legacy_authentication()
            .build()
            .expect("fixed complete fuzz schema")
    })
}

pub fn header_cipher_schema() -> &'static HeaderSchema {
    static SCHEMA: OnceLock<HeaderSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        fuzz_schema_builder()
            .response_cipher(CipherLocation::Header(
                HeaderName::new("X-Fuzz-Response-Cipher").expect("token header name"),
            ))
            .legacy_authentication()
            .build()
            .expect("fixed complete header-cipher fuzz schema")
    })
}

pub fn adapter() -> &'static HeaderProtocolAdapter {
    static ADAPTER: OnceLock<HeaderProtocolAdapter> = OnceLock::new();
    ADAPTER.get_or_init(|| HeaderProtocolAdapter::new(schema().clone()))
}

pub fn header_cipher_adapter() -> &'static HeaderProtocolAdapter {
    static ADAPTER: OnceLock<HeaderProtocolAdapter> = OnceLock::new();
    ADAPTER.get_or_init(|| HeaderProtocolAdapter::new(header_cipher_schema().clone()))
}

pub fn transport_outcome(scenario: TransportScenario) -> Option<ScenarioOutcome> {
    let result = match scenario {
        TransportScenario::Success => adapter().parse_response(ResponseParts::new(
            [
                ("X-Fuzz-Response-Signature", "signature"),
                ("X-Fuzz-Response-Wrapped-Key", "wrapped"),
                (
                    "X-Fuzz-Response-Remote-Signing-Certificate",
                    "fuzz-certificate",
                ),
            ],
            "cipher",
        )),
        TransportScenario::Duplicate => adapter().parse_response(ResponseParts::new(
            [
                ("X-Fuzz-Response-Signature", "first"),
                ("x-fuzz-response-signature", "second"),
                ("X-Fuzz-Response-Wrapped-Key", "wrapped"),
                (
                    "X-Fuzz-Response-Remote-Signing-Certificate",
                    "fuzz-certificate",
                ),
            ],
            "cipher",
        )),
        TransportScenario::Unknown => adapter().parse_response(ResponseParts::new(
            [
                ("X-Fuzz-Unknown", "ignored"),
                ("X-Fuzz-Response-Signature", "signature"),
                ("X-Fuzz-Response-Wrapped-Key", "wrapped"),
                (
                    "X-Fuzz-Response-Remote-Signing-Certificate",
                    "fuzz-certificate",
                ),
            ],
            "cipher",
        )),
        TransportScenario::Missing => adapter().parse_response(ResponseParts::new(
            [("X-Fuzz-Response-Signature", "signature")],
            "cipher",
        )),
        TransportScenario::HeaderCipherSuccess => {
            header_cipher_adapter().parse_response(ResponseParts::new(
                [
                    ("X-Fuzz-Response-Signature", "signature"),
                    ("X-Fuzz-Response-Wrapped-Key", "wrapped"),
                    (
                        "X-Fuzz-Response-Remote-Signing-Certificate",
                        "fuzz-certificate",
                    ),
                    ("X-Fuzz-Response-Cipher", "cipher"),
                ],
                "ignored-body",
            ))
        }
        TransportScenario::HeaderCipherMissing => {
            header_cipher_adapter().parse_response(ResponseParts::new(
                [
                    ("X-Fuzz-Response-Signature", "signature"),
                    ("X-Fuzz-Response-Wrapped-Key", "wrapped"),
                    (
                        "X-Fuzz-Response-Remote-Signing-Certificate",
                        "fuzz-certificate",
                    ),
                ],
                "ignored-body",
            ))
        }
        TransportScenario::HeaderCipherEmpty => {
            header_cipher_adapter().parse_response(ResponseParts::new(
                [
                    ("X-Fuzz-Response-Signature", "signature"),
                    ("X-Fuzz-Response-Wrapped-Key", "wrapped"),
                    (
                        "X-Fuzz-Response-Remote-Signing-Certificate",
                        "fuzz-certificate",
                    ),
                    ("X-Fuzz-Response-Cipher", ""),
                ],
                "ignored-body",
            ))
        }
        TransportScenario::HeaderCipherDuplicate => {
            header_cipher_adapter().parse_response(ResponseParts::new(
                [
                    ("X-Fuzz-Response-Signature", "signature"),
                    ("X-Fuzz-Response-Wrapped-Key", "wrapped"),
                    (
                        "X-Fuzz-Response-Remote-Signing-Certificate",
                        "fuzz-certificate",
                    ),
                    ("X-Fuzz-Response-Cipher", "first"),
                    ("x-fuzz-response-cipher", "second"),
                ],
                "ignored-body",
            ))
        }
        TransportScenario::Generic | TransportScenario::HeaderCipherGeneric => return None,
    };
    Some(if result.is_ok() {
        ScenarioOutcome::Accepted
    } else {
        ScenarioOutcome::Rejected
    })
}

pub fn typed_outcome(scenario: TypedScenario) -> Option<ScenarioOutcome> {
    let accepted = match scenario {
        TypedScenario::Valid => {
            HeaderName::new("X-Fuzz-Header").is_ok()
                && HeaderValue::new("header-value").is_ok()
                && RequestParts::new(
                    [
                        ("X-Fuzz-Header", "header-value"),
                        ("X-Fuzz-Other", "second"),
                    ],
                    "body",
                )
                .is_ok()
        }
        TypedScenario::Duplicate => RequestParts::new(
            [("X-Fuzz-Header", "first"), ("x-fuzz-header", "second")],
            "body",
        )
        .is_ok(),
        TypedScenario::Generic => return None,
    };
    Some(if accepted {
        ScenarioOutcome::Accepted
    } else {
        ScenarioOutcome::Rejected
    })
}

pub fn client() -> &'static SecureClient {
    static CLIENT: OnceLock<SecureClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let mut scalar = [0_u8; 32];
        scalar[31] = 7;
        let private = Sm2PrivateKey::from_bytes_be(&scalar).expect("valid public test scalar");
        let encrypted = pkcs8::encrypt(&private, TEST_PASSWORD, &[7_u8; 16], 1, &[8_u8; 16])
            .expect("runtime-only encrypted fuzz key");
        let public = spki::encode(&private.public_key());
        let config = ClientConfig::builder()
            .local_identity_id("fuzz-identity")
            .api_version("fuzz-v1")
            .local_certificate_id("fuzz-certificate")
            .expected_remote_signing_certificate_id("fuzz-certificate")
            .remote_encryption_certificate_id("fuzz-encryption-certificate")
            .local_signer_id(b"fuzz-signer")
            .expected_remote_signer_id(b"fuzz-signer")
            .authentication_mode(AuthenticationMode::LegacyPlaintext)
            .iv(*b"0123456789abcdef")
            .max_plaintext_bytes(MAX_PLAINTEXT_BYTES)
            .build()
            .expect("fixed fuzz configuration");
        let keys = KeyMaterial::shared(
            PrivateKey::from_encrypted_der(&encrypted, TEST_PASSWORD)
                .expect("runtime-only fuzz private key"),
            PublicKey::from_der(&public).expect("runtime-only fuzz public key"),
        );
        SecureClient::new(
            config,
            keys,
            Arc::new(HeaderProtocolAdapter::new(schema().clone())),
        )
    })
}

pub fn valid_envelope() -> &'static SecureEnvelope {
    static ENVELOPE: OnceLock<SecureEnvelope> = OnceLock::new();
    ENVELOPE.get_or_init(|| {
        client()
            .seal(VALID_PLAINTEXT, &AuthenticationContext::legacy())
            .expect("runtime-generated valid fuzz envelope")
    })
}

pub fn encoded_values(data: &[u8]) -> (String, String, String) {
    let [signature_raw, wrapped_raw, cipher_raw] = fields(data);
    let selectors = data.get(..6).unwrap_or_default();
    let envelope = valid_envelope();
    (
        select_value(
            selectors.first(),
            selectors.get(3),
            signature_raw,
            &envelope.signature,
            AUXILIARY_LIMIT,
        ),
        select_value(
            selectors.get(1),
            selectors.get(4),
            wrapped_raw,
            &envelope.wrapped_session_key,
            AUXILIARY_LIMIT,
        ),
        select_value(
            selectors.get(2),
            selectors.get(5),
            cipher_raw,
            &envelope.cipher,
            CIPHER_LIMIT,
        ),
    )
}

fn select_value(
    mode: Option<&u8>,
    boundary: Option<&u8>,
    raw: &[u8],
    valid: &str,
    limit: usize,
) -> String {
    let mode = match mode.copied() {
        Some(b'v') => 0,
        Some(b'r') => 1,
        Some(b'b') => 2,
        Some(b'm') => 3,
        Some(other) => other % 4,
        None => 0,
    };
    match mode {
        0 => valid.to_owned(),
        1 => text(raw),
        2 => {
            "A".repeat(limit.saturating_sub(1) + usize::from(boundary.copied().unwrap_or(b'0') % 3))
        }
        _ => mutate(valid, raw),
    }
}

fn mutate(valid: &str, raw: &[u8]) -> String {
    let mut value = valid.as_bytes().to_vec();
    if !value.is_empty() {
        let index = usize::from(raw.first().copied().unwrap_or_default()) % value.len();
        value[index] = if value[index] == b'A' { b'B' } else { b'A' };
    }
    String::from_utf8(value).expect("base64 is UTF-8")
}

pub fn aead_client() -> &'static SecureClient {
    static CLIENT: OnceLock<SecureClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let mut scalar = [0_u8; 32];
        scalar[31] = 7;
        let private = Sm2PrivateKey::from_bytes_be(&scalar).expect("valid public test scalar");
        let encrypted = pkcs8::encrypt(&private, TEST_PASSWORD, &[7_u8; 16], 1, &[8_u8; 16])
            .expect("runtime-only encrypted fuzz key");
        let public = spki::encode(&private.public_key());
        let config = ClientConfig::builder()
            .local_identity_id("fuzz-identity")
            .api_version("fuzz-v1")
            .local_certificate_id("fuzz-certificate")
            .expected_remote_signing_certificate_id("fuzz-certificate")
            .remote_encryption_certificate_id("fuzz-encryption-certificate")
            .local_signer_id(b"fuzz-signer")
            .expected_remote_signer_id(b"fuzz-signer")
            .authentication_mode(AuthenticationMode::LegacyPlaintext)
            .envelope_mode(gmcrypto_envelope_lite::EnvelopeMode::Aead(
                gmcrypto_envelope_lite::AeadAlgorithm::Sm4Gcm,
            ))
            .max_plaintext_bytes(MAX_PLAINTEXT_BYTES)
            .build()
            .expect("fixed AEAD fuzz configuration");
        let keys = KeyMaterial::shared(
            PrivateKey::from_encrypted_der(&encrypted, TEST_PASSWORD)
                .expect("runtime-only fuzz private key"),
            PublicKey::from_der(&public).expect("runtime-only fuzz public key"),
        );
        SecureClient::new(
            config,
            keys,
            Arc::new(HeaderProtocolAdapter::new(schema().clone())),
        )
    })
}

pub fn aead_valid_envelope() -> &'static SecureEnvelope {
    static ENVELOPE: OnceLock<SecureEnvelope> = OnceLock::new();
    ENVELOPE.get_or_init(|| {
        aead_client()
            .seal(VALID_PLAINTEXT, &AuthenticationContext::legacy())
            .expect("runtime-generated valid AEAD fuzz envelope")
    })
}

pub fn aead_encoded_values(data: &[u8]) -> (String, String, String) {
    let [signature_raw, wrapped_raw, cipher_raw] = fields(data);
    let selectors = data.get(..6).unwrap_or_default();
    let envelope = aead_valid_envelope();
    (
        select_value(
            selectors.first(),
            selectors.get(3),
            signature_raw,
            &envelope.signature,
            AUXILIARY_LIMIT,
        ),
        select_value(
            selectors.get(1),
            selectors.get(4),
            wrapped_raw,
            &envelope.wrapped_session_key,
            AUXILIARY_LIMIT,
        ),
        select_value(
            selectors.get(2),
            selectors.get(5),
            cipher_raw,
            &envelope.cipher,
            AEAD_CIPHER_LIMIT,
        ),
    )
}
