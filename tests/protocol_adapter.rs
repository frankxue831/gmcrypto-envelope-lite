use std::sync::Arc;

use gmcrypto_envelope_lite::{
    AdapterError, AdapterErrorKind, AdapterResult, AuthenticationContext, CipherLocation,
    ClientIdentity, HeaderName, HeaderProtocolAdapter, HeaderSchema, HeaderSchemaBuilder,
    ParsedResponse, ProtocolAdapter, ProtocolRequestContext, RequestMetadata, RequestParts,
    ResponseParts, SecureEnvelope,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequiredMapping {
    StaticRequestHeader,
    LocalIdentity,
    Operation,
    RequestId,
    RequestTime,
    ApiVersion,
    LocalCertificate,
    RemoteSigningCertificate,
    RemoteEncryptionCertificate,
    RequestSignature,
    RequestWrappedKey,
    RequestCipher,
    ResponseSignature,
    ResponseWrappedKey,
    ResponseRemoteSigningCertificate,
    ResponseCipher,
    LegacyAuthentication,
}

#[test]
fn protocol_adapter_is_object_safe_and_arc_compatible() {
    let adapter: Arc<dyn ProtocolAdapter> = Arc::new(HeaderProtocolAdapter::new(schema()));

    let authentication = adapter
        .request_authentication_context(&identity(), &request_context())
        .expect("legacy authentication context");

    assert_eq!(authentication, AuthenticationContext::legacy());
}

fn context_bound_schema_builder() -> HeaderSchemaBuilder {
    schema_builder_omitting(Some(RequiredMapping::LegacyAuthentication))
        .context_bound_authentication()
}

const DEMO_REQUEST_CONTEXT: &[u8] = &[
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, b'd', b'e', b'm', b'o', b'-', b'o',
    b'p', b'e', b'r', b'a', b't', b'i', b'o', b'n', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e,
    b'd', b'e', b'm', b'o', b'-', b'r', b'e', b'q', b'u', b'e', b's', b't', b'-', b'1',
];

const DEMO_RESPONSE_CONTEXT: &[u8] = &[
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, b'd', b'e', b'm', b'o', b'-', b'r',
    b'e', b'q', b'u', b'e', b's', b't', b'-', b'1',
];

fn context_bound_response_headers() -> Vec<(&'static str, &'static str)> {
    let mut headers = response_headers().to_vec();
    headers.push(("X-Demo-Request-Id", "demo-request-1"));
    headers
}

fn context_bound_adapter() -> HeaderProtocolAdapter {
    HeaderProtocolAdapter::new(
        context_bound_schema_builder()
            .build()
            .expect("context-bound schema"),
    )
}

#[test]
fn context_bound_request_context_matches_versioned_kat() {
    let context = context_bound_adapter()
        .request_authentication_context(&identity(), &request_context())
        .expect("bound request context");
    assert_eq!(
        context,
        AuthenticationContext::context_bound(DEMO_REQUEST_CONTEXT).expect("kat")
    );
}

#[test]
fn context_bound_request_encoding_separates_delimiter_tuples() {
    let adapter = context_bound_adapter();
    let time = "2026-07-12T10:11:12Z";
    let left = ProtocolRequestContext::new(
        "pay",
        RequestMetadata::new("1&request-id=2", time).expect("left id"),
    )
    .expect("left");
    let right = ProtocolRequestContext::new(
        "pay&request-id=1",
        RequestMetadata::new("2", time).expect("right id"),
    )
    .expect("right");
    let left_ctx = adapter
        .request_authentication_context(&identity(), &left)
        .expect("left context");
    let right_ctx = adapter
        .request_authentication_context(&identity(), &right)
        .expect("right context");
    assert_ne!(left_ctx, right_ctx);
}

#[test]
fn context_bound_request_rejects_surrounding_whitespace() {
    let adapter = context_bound_adapter();
    let time = "2026-07-12T10:11:12Z";
    let padded_operation = ProtocolRequestContext::new(
        " pay",
        RequestMetadata::new("demo-request-1", time).expect("id"),
    )
    .expect("padded operation is stored");
    let error = adapter
        .request_authentication_context(&identity(), &padded_operation)
        .expect_err("surrounding whitespace");
    assert_eq!(error.kind(), AdapterErrorKind::InvalidField);
}

#[test]
fn context_bound_parse_response_matches_versioned_kat() {
    let parsed = context_bound_adapter()
        .parse_response(ResponseParts::new(
            context_bound_response_headers(),
            "demo-response-cipher",
        ))
        .expect("bound response");
    assert_eq!(
        parsed.authentication_context(),
        &AuthenticationContext::context_bound(DEMO_RESPONSE_CONTEXT).expect("kat")
    );
}

#[test]
fn context_bound_parse_response_matches_request_id_header_case_insensitively() {
    let mut headers = response_headers().to_vec();
    headers.push(("x-demo-request-id", "demo-request-1"));
    let parsed = context_bound_adapter()
        .parse_response(ResponseParts::new(headers, "demo-response-cipher"))
        .expect("case-insensitive echo");
    assert_eq!(
        parsed.authentication_context(),
        &AuthenticationContext::context_bound(DEMO_RESPONSE_CONTEXT).expect("kat")
    );
}

#[test]
fn context_bound_parse_response_requires_untrimmed_request_id() {
    let adapter = context_bound_adapter();
    let missing = adapter
        .parse_response(ResponseParts::new(
            response_headers(),
            "demo-response-cipher",
        ))
        .expect_err("missing request id");
    assert_eq!(missing.kind(), AdapterErrorKind::MissingField);

    let mut padded = response_headers().to_vec();
    padded.push(("X-Demo-Request-Id", " demo-request-1"));
    let whitespace = adapter
        .parse_response(ResponseParts::new(padded, "demo-response-cipher"))
        .expect_err("surrounding whitespace");
    assert_eq!(whitespace.kind(), AdapterErrorKind::InvalidField);

    let mut duplicated = context_bound_response_headers();
    duplicated.push(("x-demo-request-id", "other"));
    let duplicate = adapter
        .parse_response(ResponseParts::new(duplicated, "demo-response-cipher"))
        .expect_err("duplicate");
    assert_eq!(duplicate.kind(), AdapterErrorKind::DuplicateField);
}

#[test]
fn legacy_parse_response_still_ignores_request_id_and_returns_legacy_context() {
    let parsed = HeaderProtocolAdapter::new(schema())
        .parse_response(ResponseParts::new(
            response_headers(),
            "demo-response-cipher",
        ))
        .expect("legacy response");
    assert_eq!(
        parsed.authentication_context(),
        &AuthenticationContext::legacy()
    );
}

#[test]
fn context_bound_request_preserves_interior_whitespace() {
    let adapter = context_bound_adapter();
    let time = "2026-07-12T10:11:12Z";
    let spaced =
        ProtocolRequestContext::new("pay now", RequestMetadata::new("id-1", time).expect("id"))
            .expect("interior space");
    let compact =
        ProtocolRequestContext::new("paynow", RequestMetadata::new("id-1", time).expect("id"))
            .expect("compact");
    let spaced_ctx = adapter
        .request_authentication_context(&identity(), &spaced)
        .expect("spaced");
    let compact_ctx = adapter
        .request_authentication_context(&identity(), &compact)
        .expect("compact");
    assert_ne!(spaced_ctx, compact_ctx);
}

#[test]
fn schema_rejects_both_authentication_acknowledgements() {
    let error = complete_schema_builder()
        .context_bound_authentication()
        .build()
        .expect_err("exactly one acknowledgement");
    assert_eq!(error.kind(), AdapterErrorKind::InvalidMapping);
}

#[test]
fn schema_accepts_exclusive_context_bound_authentication() {
    context_bound_schema_builder()
        .build()
        .expect("context-bound acknowledgement is sufficient");
}

#[test]
fn schema_requires_every_mapping_and_explicit_legacy_authentication() {
    let required = [
        RequiredMapping::StaticRequestHeader,
        RequiredMapping::LocalIdentity,
        RequiredMapping::Operation,
        RequiredMapping::RequestId,
        RequiredMapping::RequestTime,
        RequiredMapping::ApiVersion,
        RequiredMapping::LocalCertificate,
        RequiredMapping::RemoteSigningCertificate,
        RequiredMapping::RemoteEncryptionCertificate,
        RequiredMapping::RequestSignature,
        RequiredMapping::RequestWrappedKey,
        RequiredMapping::RequestCipher,
        RequiredMapping::ResponseSignature,
        RequiredMapping::ResponseWrappedKey,
        RequiredMapping::ResponseRemoteSigningCertificate,
        RequiredMapping::ResponseCipher,
        RequiredMapping::LegacyAuthentication,
    ];

    for omitted in required {
        let error = schema_builder_omitting(Some(omitted))
            .build()
            .expect_err("every mapping must be explicit");
        assert_eq!(
            error.kind(),
            AdapterErrorKind::MissingField,
            "unexpected error when omitting {omitted:?}"
        );
    }

    schema_builder_omitting(None)
        .build()
        .expect("complete schema");
}

#[test]
fn request_mapping_uses_only_semantic_inputs_and_places_cipher_in_body() {
    let adapter = HeaderProtocolAdapter::new(schema());
    let request = adapter
        .build_request(&identity(), &request_context(), &request_envelope())
        .expect("mapped request");

    let headers = request
        .headers()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        headers,
        vec![
            ("Content-Type", "application/demo+json"),
            ("X-Demo-Local-Identity", "demo-client"),
            ("X-Demo-Operation", "demo-operation"),
            ("X-Demo-Request-Id", "demo-request-1"),
            ("X-Demo-Request-Time", "2026-07-12T10:11:12Z"),
            ("X-Demo-Api-Version", "demo-v1"),
            ("X-Demo-Local-Certificate", "demo-local-signing-cert"),
            (
                "X-Demo-Remote-Signing-Certificate",
                "demo-remote-signing-cert",
            ),
            (
                "X-Demo-Remote-Encryption-Certificate",
                "demo-remote-encryption-cert",
            ),
            ("X-Demo-Request-Signature", "demo-request-signature"),
            ("X-Demo-Request-Wrapped-Key", "demo-request-wrapped-key"),
        ]
    );
    assert_eq!(request.len(), 11);
    assert_eq!(request.body(), "demo-request-cipher");
}

#[test]
fn request_cipher_can_be_mapped_to_a_header_with_an_empty_body() {
    let schema = complete_schema_builder()
        .request_cipher(CipherLocation::Header(demo_header("X-Demo-Request-Cipher")))
        .build()
        .expect("header cipher schema");
    let adapter = HeaderProtocolAdapter::new(schema);

    let request = adapter
        .build_request(&identity(), &request_context(), &request_envelope())
        .expect("mapped request");

    assert_eq!(
        request.header("x-demo-request-cipher"),
        Some("demo-request-cipher")
    );
    assert_eq!(request.body(), "");
    assert_eq!(request.len(), 12);
}

#[test]
fn response_parser_matches_case_insensitively_trims_and_ignores_unknown_headers() {
    let adapter = HeaderProtocolAdapter::new(schema());
    let response = ResponseParts::new(
        [
            ("x-demo-response-signature", "  demo-response-signature\t"),
            ("X-DEMO-RESPONSE-WRAPPED-KEY", " demo-response-wrapped-key "),
            (
                "x-Demo-Response-Remote-Signing-Certificate",
                " demo-claimed-signing-cert ",
            ),
            ("X-Demo-Unknown", "ignored"),
        ],
        "\n  demo-response-cipher \r\n",
    );

    let parsed = adapter.parse_response(response).expect("parsed response");

    assert_eq!(
        parsed.envelope(),
        &SecureEnvelope {
            cipher: "demo-response-cipher".to_owned(),
            wrapped_session_key: "demo-response-wrapped-key".to_owned(),
            signature: "demo-response-signature".to_owned(),
        }
    );
    assert_eq!(
        parsed.remote_signing_certificate_id(),
        "demo-claimed-signing-cert"
    );
    assert_eq!(
        parsed.authentication_context(),
        &AuthenticationContext::legacy()
    );
}

#[test]
fn response_cipher_can_be_mapped_to_a_header_and_body_is_ignored() {
    let schema = complete_schema_builder()
        .response_cipher(CipherLocation::Header(demo_header(
            "X-Demo-Response-Cipher",
        )))
        .build()
        .expect("header cipher schema");
    let adapter = HeaderProtocolAdapter::new(schema);
    let response = ResponseParts::new(
        [
            ("X-Demo-Response-Signature", "demo-response-signature"),
            ("X-Demo-Response-Wrapped-Key", "demo-response-wrapped-key"),
            (
                "X-Demo-Response-Remote-Signing-Certificate",
                "demo-claimed-signing-cert",
            ),
            ("x-demo-response-cipher", "  demo-response-cipher  "),
        ],
        "ignored response body",
    );

    let parsed = adapter.parse_response(response).expect("parsed response");

    assert_eq!(parsed.envelope().cipher, "demo-response-cipher");
}

#[test]
fn schema_rejects_invalid_names_and_static_values() {
    for invalid in ["", "Bad Header", "X-Demo-Bad:Name", "X-Demo-café"] {
        let error = complete_schema_builder()
            .operation_header(invalid)
            .build()
            .expect_err("invalid dynamic header name");
        assert_eq!(error.kind(), AdapterErrorKind::InvalidMapping);
    }

    for invalid in ["", "   ", "demo\rvalue", "demo\nvalue", "demo\0value"] {
        let error = complete_schema_builder()
            .static_request_header("X-Demo-Static", invalid)
            .build()
            .expect_err("invalid static header value");
        assert_eq!(error.kind(), AdapterErrorKind::InvalidMapping);
    }

    let error = complete_schema_builder()
        .static_request_header("X-Demo Bad", "demo-value")
        .build()
        .expect_err("invalid static header name");
    assert_eq!(error.kind(), AdapterErrorKind::InvalidMapping);
}

#[test]
fn schema_rejects_case_insensitive_request_direction_collisions() {
    let collision_builders = [
        complete_schema_builder().operation_header("x-demo-local-identity"),
        complete_schema_builder().static_request_header("x-demo-operation", "demo-static-value"),
        complete_schema_builder().static_request_header("content-type", "text/demo"),
        complete_schema_builder().request_cipher(CipherLocation::Header(demo_header(
            "x-demo-request-signature",
        ))),
    ];

    for builder in collision_builders {
        let error = builder
            .build()
            .expect_err("request header collision must be rejected");
        assert_eq!(error.kind(), AdapterErrorKind::InvalidMapping);
    }
}

#[test]
fn schema_rejects_case_insensitive_response_direction_collisions() {
    let collision_builders = [
        complete_schema_builder().response_wrapped_key_header("x-demo-response-signature"),
        complete_schema_builder().response_cipher(CipherLocation::Header(demo_header(
            "x-demo-response-remote-signing-certificate",
        ))),
    ];

    for builder in collision_builders {
        let error = builder
            .build()
            .expect_err("response header collision must be rejected");
        assert_eq!(error.kind(), AdapterErrorKind::InvalidMapping);
    }
}

#[test]
fn schema_allows_the_same_names_in_opposite_directions() {
    complete_schema_builder()
        .request_cipher(CipherLocation::Header(demo_header("X-Demo-Request-Cipher")))
        .response_signature_header("x-demo-request-signature")
        .response_wrapped_key_header("x-demo-request-wrapped-key")
        .response_remote_signing_certificate_header("x-demo-remote-signing-certificate")
        .response_cipher(CipherLocation::Header(demo_header("x-demo-request-cipher")))
        .build()
        .expect("directions have independent collision sets");
}

#[test]
fn context_bound_schema_rejects_request_id_collision_with_response_headers() {
    let error = context_bound_schema_builder()
        .response_signature_header("X-Demo-Request-Id")
        .build()
        .expect_err("request-id reused on the response");
    assert_eq!(error.kind(), AdapterErrorKind::InvalidMapping);
}

#[test]
fn response_parser_rejects_missing_and_empty_required_fields() {
    let adapter = HeaderProtocolAdapter::new(schema());
    let complete_headers = response_headers();

    for omitted in 0..complete_headers.len() {
        let headers = complete_headers
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != omitted)
            .map(|(_, pair)| *pair)
            .collect::<Vec<_>>();
        let error = adapter
            .parse_response(ResponseParts::new(headers, "demo-response-cipher"))
            .expect_err("missing mapped header");
        assert_eq!(error.kind(), AdapterErrorKind::MissingField);
    }

    for index in 0..complete_headers.len() {
        let mut headers = complete_headers;
        headers[index].1 = " \t ";
        let error = adapter
            .parse_response(ResponseParts::new(headers, "demo-response-cipher"))
            .expect_err("empty mapped header");
        assert_eq!(error.kind(), AdapterErrorKind::InvalidField);
    }

    let error = adapter
        .parse_response(ResponseParts::new(complete_headers, " \n\t "))
        .expect_err("empty body cipher");
    assert_eq!(error.kind(), AdapterErrorKind::InvalidField);
}

#[test]
fn response_parser_rejects_missing_and_empty_header_cipher() {
    let schema = complete_schema_builder()
        .response_cipher(CipherLocation::Header(demo_header(
            "X-Demo-Response-Cipher",
        )))
        .build()
        .expect("header cipher schema");
    let adapter = HeaderProtocolAdapter::new(schema);

    let missing = adapter
        .parse_response(ResponseParts::new(response_headers(), "ignored"))
        .expect_err("missing mapped cipher header");
    assert_eq!(missing.kind(), AdapterErrorKind::MissingField);

    let mut empty_headers = response_headers().to_vec();
    empty_headers.push(("X-Demo-Response-Cipher", "  "));
    let empty = adapter
        .parse_response(ResponseParts::new(empty_headers, "ignored"))
        .expect_err("empty mapped cipher header");
    assert_eq!(empty.kind(), AdapterErrorKind::InvalidField);
}

#[test]
fn response_parser_rejects_mapped_duplicates_under_any_casing() {
    let adapter = HeaderProtocolAdapter::new(schema());

    for duplicate in [
        ("x-demo-response-signature", "second-signature"),
        ("x-demo-response-wrapped-key", "second-response-wrapped-key"),
        (
            "x-demo-response-remote-signing-certificate",
            "second-certificate-claim",
        ),
    ] {
        let mut headers = response_headers().to_vec();
        headers.push(duplicate);
        let error = adapter
            .parse_response(ResponseParts::new(headers, "demo-response-cipher"))
            .expect_err("duplicate mapped field");
        assert_eq!(error.kind(), AdapterErrorKind::DuplicateField);
    }

    let header_schema = complete_schema_builder()
        .response_cipher(CipherLocation::Header(demo_header(
            "X-Demo-Response-Cipher",
        )))
        .build()
        .expect("header cipher schema");
    let adapter = HeaderProtocolAdapter::new(header_schema);
    let mut headers = response_headers().to_vec();
    headers.extend([
        ("X-Demo-Response-Cipher", "first-cipher"),
        ("x-demo-response-cipher", "second-cipher"),
    ]);
    let error = adapter
        .parse_response(ResponseParts::new(headers, "ignored"))
        .expect_err("duplicate mapped cipher");
    assert_eq!(error.kind(), AdapterErrorKind::DuplicateField);
}

#[test]
fn response_parser_ignores_unknown_duplicates() {
    let adapter = HeaderProtocolAdapter::new(schema());
    let mut headers = response_headers().to_vec();
    headers.extend([("X-Demo-Unknown", "first"), ("x-demo-unknown", "second")]);

    let parsed = adapter
        .parse_response(ResponseParts::new(headers, "demo-response-cipher"))
        .expect("unknown headers are outside the schema");

    assert_eq!(parsed.envelope().signature, "demo-response-signature");
}

#[test]
fn parsed_response_constructor_supports_external_custom_adapters() {
    struct CustomAdapter;

    impl ProtocolAdapter for CustomAdapter {
        fn request_authentication_context(
            &self,
            _identity: &ClientIdentity,
            _context: &ProtocolRequestContext,
        ) -> AdapterResult<AuthenticationContext> {
            Ok(AuthenticationContext::legacy())
        }

        fn build_request(
            &self,
            _identity: &ClientIdentity,
            _context: &ProtocolRequestContext,
            _envelope: &SecureEnvelope,
        ) -> AdapterResult<RequestParts> {
            Err(AdapterError::new(AdapterErrorKind::InvalidMapping))
        }

        fn parse_response(&self, _response: ResponseParts) -> AdapterResult<ParsedResponse> {
            ParsedResponse::new(
                SecureEnvelope {
                    cipher: "custom-cipher".to_owned(),
                    wrapped_session_key: "custom-wrapped-key".to_owned(),
                    signature: "custom-signature".to_owned(),
                },
                "custom-remote-signing-certificate",
                AuthenticationContext::legacy(),
            )
        }
    }

    let adapter: Arc<dyn ProtocolAdapter> = Arc::new(CustomAdapter);
    let parsed = adapter
        .parse_response(ResponseParts::new(
            std::iter::empty::<(&str, &str)>(),
            "ignored",
        ))
        .expect("custom parsed response");

    assert_eq!(parsed.envelope().cipher, "custom-cipher");
    assert_eq!(
        parsed.remote_signing_certificate_id(),
        "custom-remote-signing-certificate"
    );
    assert_eq!(
        parsed.authentication_context(),
        &AuthenticationContext::legacy()
    );

    let (envelope, certificate_id, authentication) = parsed.into_parts();
    assert_eq!(envelope.signature, "custom-signature");
    assert_eq!(certificate_id, "custom-remote-signing-certificate");
    assert_eq!(authentication, AuthenticationContext::legacy());
}

#[test]
fn parsed_response_constructor_rejects_invalid_certificate_claims() {
    for invalid in ["", "  ", "demo\rclaim", "demo\nclaim"] {
        let error =
            ParsedResponse::new(request_envelope(), invalid, AuthenticationContext::legacy())
                .expect_err("invalid certificate claim");
        assert_eq!(error.kind(), AdapterErrorKind::InvalidField);
    }
}

#[test]
fn adapter_errors_are_classified_and_do_not_echo_mapped_data() {
    let mapping_error = complete_schema_builder()
        .operation_header("X-Demo-Sensitive Bad")
        .build()
        .expect_err("invalid sensitive mapping");
    assert_redacted(mapping_error, "X-Demo-Sensitive Bad");

    let adapter = HeaderProtocolAdapter::new(schema());
    let mut headers = response_headers();
    headers[0].1 = "sensitive\rvalue";
    let field_error = adapter
        .parse_response(ResponseParts::new(headers, "demo-response-cipher"))
        .expect_err("invalid sensitive response value");
    assert_eq!(field_error.kind(), AdapterErrorKind::InvalidField);
    assert_redacted(field_error, "sensitive");

    let mut invalid_envelope = request_envelope();
    invalid_envelope.signature = "sensitive\rvalue".to_owned();
    let request_error = adapter
        .build_request(&identity(), &request_context(), &invalid_envelope)
        .expect_err("invalid sensitive request value");
    assert_eq!(request_error.kind(), AdapterErrorKind::InvalidField);
    assert_redacted(request_error, "sensitive");
}

fn schema() -> HeaderSchema {
    complete_schema_builder().build().expect("complete schema")
}

fn complete_schema_builder() -> HeaderSchemaBuilder {
    schema_builder_omitting(None)
}

fn schema_builder_omitting(omitted: Option<RequiredMapping>) -> HeaderSchemaBuilder {
    let mut builder = HeaderSchema::builder();
    if omitted != Some(RequiredMapping::StaticRequestHeader) {
        builder = builder.static_request_header("Content-Type", "application/demo+json");
    }
    if omitted != Some(RequiredMapping::LocalIdentity) {
        builder = builder.local_identity_header("X-Demo-Local-Identity");
    }
    if omitted != Some(RequiredMapping::Operation) {
        builder = builder.operation_header("X-Demo-Operation");
    }
    if omitted != Some(RequiredMapping::RequestId) {
        builder = builder.request_id_header("X-Demo-Request-Id");
    }
    if omitted != Some(RequiredMapping::RequestTime) {
        builder = builder.request_time_header("X-Demo-Request-Time");
    }
    if omitted != Some(RequiredMapping::ApiVersion) {
        builder = builder.api_version_header("X-Demo-Api-Version");
    }
    if omitted != Some(RequiredMapping::LocalCertificate) {
        builder = builder.local_certificate_header("X-Demo-Local-Certificate");
    }
    if omitted != Some(RequiredMapping::RemoteSigningCertificate) {
        builder = builder.remote_signing_certificate_header("X-Demo-Remote-Signing-Certificate");
    }
    if omitted != Some(RequiredMapping::RemoteEncryptionCertificate) {
        builder =
            builder.remote_encryption_certificate_header("X-Demo-Remote-Encryption-Certificate");
    }
    if omitted != Some(RequiredMapping::RequestSignature) {
        builder = builder.request_signature_header("X-Demo-Request-Signature");
    }
    if omitted != Some(RequiredMapping::RequestWrappedKey) {
        builder = builder.request_wrapped_key_header("X-Demo-Request-Wrapped-Key");
    }
    if omitted != Some(RequiredMapping::RequestCipher) {
        builder = builder.request_cipher(CipherLocation::Body);
    }
    if omitted != Some(RequiredMapping::ResponseSignature) {
        builder = builder.response_signature_header("X-Demo-Response-Signature");
    }
    if omitted != Some(RequiredMapping::ResponseWrappedKey) {
        builder = builder.response_wrapped_key_header("X-Demo-Response-Wrapped-Key");
    }
    if omitted != Some(RequiredMapping::ResponseRemoteSigningCertificate) {
        builder = builder.response_remote_signing_certificate_header(
            "X-Demo-Response-Remote-Signing-Certificate",
        );
    }
    if omitted != Some(RequiredMapping::ResponseCipher) {
        builder = builder.response_cipher(CipherLocation::Body);
    }
    if omitted != Some(RequiredMapping::LegacyAuthentication) {
        builder = builder.legacy_authentication();
    }
    builder
}

fn identity() -> ClientIdentity {
    ClientIdentity::new(
        "demo-client",
        "demo-v1",
        "demo-local-signing-cert",
        "demo-remote-signing-cert",
        "demo-remote-encryption-cert",
    )
    .expect("demo identity")
}

fn request_context() -> ProtocolRequestContext {
    ProtocolRequestContext::new(
        "demo-operation",
        RequestMetadata::new("demo-request-1", "2026-07-12T10:11:12Z")
            .expect("demo request metadata"),
    )
    .expect("demo protocol context")
}

fn request_envelope() -> SecureEnvelope {
    SecureEnvelope {
        cipher: "demo-request-cipher".to_owned(),
        wrapped_session_key: "demo-request-wrapped-key".to_owned(),
        signature: "demo-request-signature".to_owned(),
    }
}

fn response_headers() -> [(&'static str, &'static str); 3] {
    [
        ("X-Demo-Response-Signature", "demo-response-signature"),
        ("X-Demo-Response-Wrapped-Key", "demo-response-wrapped-key"),
        (
            "X-Demo-Response-Remote-Signing-Certificate",
            "demo-claimed-signing-cert",
        ),
    ]
}

fn demo_header(name: &str) -> HeaderName {
    HeaderName::new(name).expect("valid demo header")
}

fn assert_redacted(error: AdapterError, sensitive: &str) {
    assert!(!error.to_string().contains(sensitive));
    assert!(!format!("{error:?}").contains(sensitive));
}
