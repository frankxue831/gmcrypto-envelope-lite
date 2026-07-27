use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use gmcrypto_envelope_lite::{
    Error, HeaderName, HeaderValue, ProtocolRequestContext, RequestContext, RequestMetadata,
    RequestParts, ResponseParts, SecureEnvelope,
};

#[test]
fn header_names_compare_and_hash_case_insensitively() {
    let original = HeaderName::new("X-Demo-Trace").expect("valid header name");
    let lowercase = HeaderName::new("x-demo-trace").expect("valid header name");

    assert_eq!(original, lowercase);
    assert_eq!(original.cmp(&lowercase), std::cmp::Ordering::Equal);
    assert_eq!(header_hash(&original), header_hash(&lowercase));
    assert_eq!(original.as_str(), "X-Demo-Trace");
    assert!(format!("{original:?}").contains("X-Demo-Trace"));
}

#[test]
fn header_names_reject_non_token_input() {
    for invalid in [
        "",
        " ",
        "Bad Header",
        "Bad:Header",
        "café",
        "Bad(Header)",
        "Bad/Header",
    ] {
        assert!(matches!(
            HeaderName::new(invalid),
            Err(Error::InvalidHeader)
        ));
    }
}

#[test]
fn header_values_accept_utf8_and_horizontal_tabs() {
    let value = HeaderValue::new("你好\ttrace-1").expect("valid header value");

    assert_eq!(value.as_str(), "你好\ttrace-1");
}

#[test]
fn header_values_reject_injection_and_control_bytes_without_echoing_them() {
    for invalid in [
        "secret\rvalue",
        "secret\nvalue",
        "secret\0value",
        "secret\u{7f}value",
        "secret\u{1}value",
        "secret\u{b}value",
        "secret\u{1f}value",
    ] {
        let error = HeaderValue::new(invalid).expect_err("control byte must be rejected");
        assert!(matches!(error, Error::InvalidHeader));
        assert_eq!(error.to_string(), "invalid header");
        assert!(!format!("{error:?}").contains("secret"));
    }
}

#[test]
fn request_parts_validate_headers_and_offer_typed_access() {
    let request = RequestParts::new(
        [("X-Demo-Trace", "trace-1"), ("Content-Type", "text/plain")],
        "payload",
    )
    .expect("valid request parts");

    assert_eq!(request.len(), 2);
    assert_eq!(request.header("x-demo-trace"), Some("trace-1"));
    assert_eq!(request.header("CONTENT-TYPE"), Some("text/plain"));
    assert_eq!(request.header("missing"), None);
    assert_eq!(request.body(), "payload");

    let headers = request
        .headers()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        headers,
        vec![("X-Demo-Trace", "trace-1"), ("Content-Type", "text/plain")]
    );
}

#[test]
fn request_parts_reject_invalid_or_case_insensitively_duplicate_headers() {
    assert!(matches!(
        RequestParts::new([("X-Demo", "one"), ("x-demo", "two")], "payload"),
        Err(Error::HeaderConflict)
    ));
    assert!(matches!(
        RequestParts::new([("Bad Header", "value")], "payload"),
        Err(Error::InvalidHeader)
    ));
    assert!(matches!(
        RequestParts::new([("X-Demo", "bad\rvalue")], "payload"),
        Err(Error::InvalidHeader)
    ));
}

#[test]
fn response_parts_preserve_duplicate_raw_headers_and_order() {
    let response = ResponseParts::new(
        [("X-Demo", "one"), ("x-demo", "two"), ("X-Last", "three")],
        "payload",
    );

    let headers = response.headers().collect::<Vec<_>>();
    assert_eq!(
        headers,
        vec![("X-Demo", "one"), ("x-demo", "two"), ("X-Last", "three")]
    );
    assert_eq!(response.body(), "payload");

    let (headers, body) = response.into_parts();
    assert_eq!(
        headers,
        vec![
            ("X-Demo".to_owned(), "one".to_owned()),
            ("x-demo".to_owned(), "two".to_owned()),
            ("X-Last".to_owned(), "three".to_owned())
        ]
    );
    assert_eq!(body, "payload");
}

#[test]
fn request_metadata_validates_values_and_generate_is_fresh() {
    for (request_id, request_time) in [
        ("", "2026-07-12-01.02.03.123456"),
        ("request-1", ""),
        ("request\rid", "2026-07-12-01.02.03.123456"),
        ("request-1", "2026-07-12\n01.02.03.123456"),
    ] {
        assert!(matches!(
            RequestMetadata::new(request_id, request_time),
            Err(Error::InvalidHeader)
        ));
    }

    let first = RequestMetadata::generate().expect("generated metadata");
    let second = RequestMetadata::generate().expect("generated metadata");
    assert!(!first.request_id().is_empty());
    assert_ne!(first.request_id(), second.request_id());
    assert!(is_generated_timestamp(first.request_time()));
    assert!(is_generated_timestamp(second.request_time()));
}

#[test]
fn request_context_separates_protocol_fields_from_additional_headers() {
    let metadata =
        RequestMetadata::new("request-1", "2026-07-12-01.02.03.123456").expect("metadata");
    let context = RequestContext::builder("demo-operation")
        .metadata(metadata.clone())
        .header("X-Demo-Trace", "trace-1")
        .expect("valid additional header")
        .build()
        .expect("request context");

    let protocol = context.protocol();
    assert_eq!(protocol.operation(), "demo-operation");
    assert_eq!(protocol.metadata(), &metadata);
    assert_eq!(context.len(), 1);
    assert_eq!(context.header("x-demo-trace"), Some("trace-1"));
    assert_eq!(
        context
            .additional_headers()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<Vec<_>>(),
        vec![("X-Demo-Trace", "trace-1")]
    );
}

#[test]
fn request_context_rejects_invalid_operations_and_duplicate_headers() {
    let metadata =
        RequestMetadata::new("request-1", "2026-07-12-01.02.03.123456").expect("metadata");

    for operation in ["", "   ", "bad\roperation", "bad\noperation"] {
        assert!(matches!(
            ProtocolRequestContext::new(operation, metadata.clone()),
            Err(Error::InvalidHeader)
        ));
    }

    let duplicate = RequestContext::builder("demo-operation")
        .header("X-Demo", "one")
        .expect("first header")
        .header("x-demo", "two");
    assert!(matches!(duplicate, Err(Error::HeaderConflict)));
}

#[test]
fn request_context_generates_metadata_when_omitted() {
    let context = RequestContext::builder("demo-operation")
        .build()
        .expect("generated request context");

    assert!(!context.protocol().metadata().request_id().is_empty());
    assert!(is_generated_timestamp(
        context.protocol().metadata().request_time()
    ));
}

#[test]
fn secure_envelope_serde_round_trip_uses_neutral_field_names() {
    let envelope = SecureEnvelope {
        cipher: "ciphertext".to_owned(),
        wrapped_session_key: "wrapped-key".to_owned(),
        signature: "signature".to_owned(),
    };

    let json = serde_json::to_value(&envelope).expect("serialize envelope");
    assert_eq!(json["cipher"], "ciphertext");
    assert_eq!(json["wrapped_session_key"], "wrapped-key");
    assert_eq!(json["signature"], "signature");
    assert_eq!(json.as_object().expect("object").len(), 3);

    let decoded: SecureEnvelope = serde_json::from_value(json).expect("deserialize envelope");
    assert_eq!(decoded, envelope);
}

fn header_hash(name: &HeaderName) -> u64 {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    hasher.finish()
}

fn is_generated_timestamp(value: &str) -> bool {
    value.len() == 26
        && value.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 | 10 => byte == b'-',
            13 | 16 | 19 => byte == b'.',
            _ => byte.is_ascii_digit(),
        })
}
