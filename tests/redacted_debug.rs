#![forbid(unsafe_code)]

use gmcrypto_envelope_lite::{
    AuthenticationContext, AuthenticationMode, CipherLocation, HeaderSchema, HeaderSchemaBuilder,
    HeaderValue, ParsedResponse, RequestParts, ResponseParts, SecureEnvelope,
};

const SECRET: &str = "sentinel-private-diagnostic-value-91f8";

#[test]
fn header_value_debug_is_redacted() {
    let value = HeaderValue::new(SECRET).expect("valid header value");

    assert_safe_debug(&value, "HeaderValue");
}

#[test]
fn envelope_and_authentication_context_debug_are_redacted() {
    let envelope = secret_envelope();
    let context =
        AuthenticationContext::context_bound(SECRET.as_bytes().to_vec()).expect("nonempty context");
    let mode = AuthenticationMode::context_bound(SECRET.as_bytes().to_vec())
        .expect("nonempty domain separator");

    let envelope_debug = assert_safe_debug(&envelope, "SecureEnvelope");
    assert!(envelope_debug.contains("cipher_len"));
    assert!(envelope_debug.contains("wrapped_session_key_len"));
    assert!(envelope_debug.contains("signature_len"));

    let context_debug = assert_safe_debug(&context, "AuthenticationContext");
    assert!(context_debug.contains("ContextBound"));
    let mode_debug = assert_safe_debug(&mode, "AuthenticationMode");
    assert!(mode_debug.contains("ContextBound"));
}

#[test]
fn request_parts_debug_keeps_names_and_lengths_but_not_values_or_body() {
    let request =
        RequestParts::new([("X-Envelope-Trace", SECRET)], SECRET).expect("valid request parts");

    let debug = assert_safe_debug(&request, "RequestParts");
    assert!(debug.contains("X-Envelope-Trace"));
    assert!(debug.contains("body_len"));
}

#[test]
fn response_parts_debug_keeps_names_and_lengths_but_not_values_or_body() {
    let response = ResponseParts::new([("X-Envelope-Trace", SECRET)], SECRET);

    let debug = assert_safe_debug(&response, "ResponseParts");
    assert!(debug.contains("X-Envelope-Trace"));
    assert!(debug.contains("body_len"));
}

#[test]
fn parsed_response_debug_redacts_envelope_and_bound_context() {
    let context =
        AuthenticationContext::context_bound(SECRET.as_bytes().to_vec()).expect("nonempty context");
    let parsed =
        ParsedResponse::new(secret_envelope(), SECRET, context).expect("valid parsed response");

    assert_eq!(parsed.remote_signing_certificate_id(), SECRET);
    let debug = assert_safe_debug(&parsed, "ParsedResponse");
    assert!(debug.contains("remote_signing_certificate_id_len"));
    assert!(debug.contains("SecureEnvelope"));
    assert!(debug.contains("ContextBound"));
}

#[test]
fn schema_builder_and_schema_debug_never_echo_static_values() {
    let unvalidated = HeaderSchema::builder().static_request_header(SECRET, SECRET);
    let builder_debug = assert_safe_debug(&unvalidated, "HeaderSchemaBuilder");
    assert!(builder_debug.contains("static_request_header_count"));

    let schema = complete_schema_builder(SECRET)
        .build()
        .expect("complete schema");
    let schema_debug = assert_safe_debug(&schema, "HeaderSchema");
    assert!(schema_debug.contains("X-Envelope-Operation"));
}

fn assert_safe_debug(value: &impl std::fmt::Debug, type_name: &str) -> String {
    let debug = format!("{value:?}");
    assert!(debug.contains(type_name), "missing type name in {debug}");
    assert!(
        !debug.contains(SECRET),
        "debug output exposed the sentinel: {debug}"
    );
    debug
}

fn secret_envelope() -> SecureEnvelope {
    SecureEnvelope {
        cipher: SECRET.to_owned(),
        wrapped_session_key: SECRET.to_owned(),
        signature: SECRET.to_owned(),
    }
}

fn complete_schema_builder(static_value: &str) -> HeaderSchemaBuilder {
    HeaderSchema::builder()
        .static_request_header("Content-Type", static_value)
        .local_identity_header("X-Envelope-Local-Identity")
        .operation_header("X-Envelope-Operation")
        .request_id_header("X-Envelope-Request-Id")
        .request_time_header("X-Envelope-Request-Time")
        .api_version_header("X-Envelope-Api-Version")
        .local_certificate_header("X-Envelope-Local-Certificate")
        .remote_signing_certificate_header("X-Envelope-Remote-Signing-Certificate")
        .remote_encryption_certificate_header("X-Envelope-Remote-Encryption-Certificate")
        .request_signature_header("X-Envelope-Request-Signature")
        .request_wrapped_key_header("X-Envelope-Request-Wrapped-Key")
        .request_cipher(CipherLocation::Body)
        .response_signature_header("X-Envelope-Response-Signature")
        .response_wrapped_key_header("X-Envelope-Response-Wrapped-Key")
        .response_remote_signing_certificate_header(
            "X-Envelope-Response-Remote-Signing-Certificate",
        )
        .response_cipher(CipherLocation::Body)
        .legacy_authentication()
}
