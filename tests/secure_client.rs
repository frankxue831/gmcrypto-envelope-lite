mod support;

use std::sync::{Arc, Mutex};

use gmcrypto_envelope_lite::{
    AdapterError, AdapterErrorKind, AdapterResult, AuthenticationContext, AuthenticationMode,
    CipherLocation, ClientConfig, ClientIdentity, Error, HeaderProtocolAdapter, HeaderSchema,
    ParsedResponse, ProtocolAdapter, ProtocolRequestContext, RequestContext, RequestMetadata,
    RequestParts, ResponseParts, SecureClient, SecureEnvelope,
};

use support::{
    client_parts_with_mode, legacy_client_parts, response_from_request, secure_client_with_seed,
};

fn bound_header_schema() -> HeaderSchema {
    HeaderSchema::builder()
        .static_request_header("Content-Type", "application/demo+octets")
        .local_identity_header("X-Demo-Local-Identity")
        .operation_header("X-Demo-Operation")
        .request_id_header("X-Demo-Request-Id")
        .request_time_header("X-Demo-Request-Time")
        .api_version_header("X-Demo-Api-Version")
        .local_certificate_header("X-Demo-Local-Certificate")
        .remote_signing_certificate_header("X-Demo-Remote-Signing-Certificate")
        .remote_encryption_certificate_header("X-Demo-Remote-Encryption-Certificate")
        .request_signature_header("X-Demo-Request-Signature")
        .request_wrapped_key_header("X-Demo-Request-Wrapped-Key")
        .request_cipher(CipherLocation::Body)
        .response_signature_header("X-Demo-Response-Signature")
        .response_wrapped_key_header("X-Demo-Response-Wrapped-Key")
        .response_remote_signing_certificate_header("X-Demo-Response-Remote-Signing-Certificate")
        .response_cipher(CipherLocation::Body)
        .context_bound_authentication()
        .build()
        .expect("bound schema")
}

fn config_with_mode(base: &ClientConfig, mode: AuthenticationMode) -> ClientConfig {
    let identity = base.identity();
    ClientConfig::builder()
        .local_identity_id(identity.local_identity_id())
        .api_version(identity.api_version())
        .local_certificate_id(identity.local_certificate_id())
        .expected_remote_signing_certificate_id(identity.expected_remote_signing_certificate_id())
        .remote_encryption_certificate_id(identity.remote_encryption_certificate_id())
        .local_signer_id(base.local_signer_id())
        .expected_remote_signer_id(base.expected_remote_signer_id())
        .authentication_mode(mode)
        .iv(*base.iv())
        .build()
        .expect("config with swapped mode")
}

fn request_context(operation: &str) -> RequestContext {
    RequestContext::builder(operation)
        .metadata(
            RequestMetadata::new(format!("request-{operation}"), "2026-07-12-01.02.03.123456")
                .expect("valid request metadata"),
        )
        .build()
        .expect("valid request context")
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn secure_client_is_send_sync_and_exposes_only_immutable_configuration() {
    assert_send_sync::<SecureClient>();
    let client = secure_client_with_seed(2);

    assert_eq!(client.config().identity().local_identity_id(), "identity-2");
    assert_eq!(client.config().identity().api_version(), "version-2");
}

#[test]
fn one_client_builds_distinct_operations_with_exact_adapter_values() {
    let client = secure_client_with_seed(3);

    let create = client
        .build_request(b"first", request_context("create"))
        .expect("create request");
    let cancel = client
        .build_request(b"second", request_context("cancel"))
        .expect("cancel request");

    assert_eq!(create.header("X-Demo-Operation"), Some("create"));
    assert_eq!(cancel.header("X-Demo-Operation"), Some("cancel"));
    assert_eq!(create.header("X-Demo-Local-Identity"), Some("identity-3"));
    assert_eq!(cancel.header("X-Demo-Api-Version"), Some("version-3"));
    assert_ne!(create.body(), cancel.body());
}

#[test]
fn additive_custom_header_is_appended_and_preserved() {
    let client = secure_client_with_seed(4);
    let context = RequestContext::builder("create")
        .metadata(
            RequestMetadata::new("request-custom", "2026-07-12-01.02.03.123456").expect("metadata"),
        )
        .header("X-Caller-Trace", "trace-4")
        .expect("additional header")
        .build()
        .expect("request context");

    let request = client
        .build_request(b"payload", context)
        .expect("request with additive header");

    assert_eq!(request.header("x-caller-trace"), Some("trace-4"));
    assert_eq!(
        request
            .headers()
            .last()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        Some(("X-Caller-Trace", "trace-4"))
    );
}

#[test]
fn actual_emitted_header_collision_is_case_insensitive_and_atomic() {
    let client = secure_client_with_seed(5);
    let context = RequestContext::builder("create")
        .metadata(
            RequestMetadata::new("request-collision", "2026-07-12-01.02.03.123456")
                .expect("metadata"),
        )
        .header("X-Caller-First", "must-not-be-partially-appended")
        .expect("first additional header")
        .header("x-DEMO-operation", "caller-must-not-override")
        .expect("collision is with adapter output, not another caller header")
        .build()
        .expect("request context");

    let result = client.build_request(b"payload", context);

    assert!(matches!(result, Err(Error::HeaderConflict)));
}

#[derive(Default)]
struct ContextAdapter {
    calls: Mutex<Vec<&'static str>>,
    observed: Mutex<Vec<(String, String, String)>>,
}

impl ProtocolAdapter for ContextAdapter {
    fn request_authentication_context(
        &self,
        identity: &ClientIdentity,
        context: &ProtocolRequestContext,
    ) -> AdapterResult<AuthenticationContext> {
        self.calls.lock().expect("calls").push("auth");
        self.observed.lock().expect("observed").push((
            identity.local_identity_id().to_owned(),
            context.operation().to_owned(),
            context.metadata().request_id().to_owned(),
        ));
        AuthenticationContext::context_bound(context.operation().as_bytes())
            .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidField))
    }

    fn build_request(
        &self,
        identity: &ClientIdentity,
        context: &ProtocolRequestContext,
        envelope: &SecureEnvelope,
    ) -> AdapterResult<RequestParts> {
        self.calls.lock().expect("calls").push("build");
        RequestParts::new(
            [
                ("X-Context-Identity", identity.local_identity_id()),
                ("X-Context-Operation", context.operation()),
                ("X-Context-Signature", envelope.signature.as_str()),
                (
                    "X-Context-Wrapped-Key",
                    envelope.wrapped_session_key.as_str(),
                ),
            ],
            envelope.cipher.as_str(),
        )
        .map_err(|_| AdapterError::new(AdapterErrorKind::InvalidField))
    }

    fn parse_response(&self, _response: ResponseParts) -> AdapterResult<ParsedResponse> {
        Err(AdapterError::new(AdapterErrorKind::InvalidMapping))
    }
}

#[test]
fn adapter_context_is_obtained_before_seal_and_adapter_inputs_are_semantic_only() {
    let mode = AuthenticationMode::context_bound(b"demo-domain").expect("bound mode");
    let (config, keys, _) = client_parts_with_mode(6, mode);
    let adapter = Arc::new(ContextAdapter::default());
    let client = SecureClient::new(config, keys, adapter.clone());
    let context = RequestContext::builder("operation-bound-context")
        .metadata(
            RequestMetadata::new("context-request", "2026-07-12-01.02.03.123456")
                .expect("metadata"),
        )
        .header("X-Secret-Additional", "adapter-must-not-receive-this")
        .expect("additional header")
        .build()
        .expect("request context");

    let request = client
        .build_request(b"plaintext-never-passed-to-adapter", context)
        .expect("context-bound request");
    let envelope = SecureEnvelope {
        cipher: request.body().to_owned(),
        wrapped_session_key: request
            .header("X-Context-Wrapped-Key")
            .expect("wrapped key")
            .to_owned(),
        signature: request
            .header("X-Context-Signature")
            .expect("signature")
            .to_owned(),
    };

    assert_eq!(*adapter.calls.lock().expect("calls"), ["auth", "build"]);
    assert_eq!(
        *adapter.observed.lock().expect("observed"),
        [(
            "identity-6".to_owned(),
            "operation-bound-context".to_owned(),
            "context-request".to_owned()
        )]
    );
    assert_eq!(
        request.header("X-Secret-Additional"),
        Some("adapter-must-not-receive-this")
    );
    assert_eq!(
        client
            .open(
                &envelope,
                &AuthenticationContext::context_bound(b"operation-bound-context")
                    .expect("bound context"),
            )
            .expect("envelope authenticated with adapter-selected context"),
        b"plaintext-never-passed-to-adapter"
    );
}

#[derive(Clone, Copy)]
enum FailurePoint {
    Authentication,
    Build,
    Parse,
}

struct FailingAdapter(FailurePoint);

impl ProtocolAdapter for FailingAdapter {
    fn request_authentication_context(
        &self,
        _identity: &ClientIdentity,
        _context: &ProtocolRequestContext,
    ) -> AdapterResult<AuthenticationContext> {
        match self.0 {
            FailurePoint::Authentication => Err(AdapterError::new(AdapterErrorKind::InvalidField)),
            FailurePoint::Build | FailurePoint::Parse => Ok(AuthenticationContext::legacy()),
        }
    }

    fn build_request(
        &self,
        _identity: &ClientIdentity,
        _context: &ProtocolRequestContext,
        _envelope: &SecureEnvelope,
    ) -> AdapterResult<RequestParts> {
        Err(AdapterError::new(AdapterErrorKind::DuplicateField))
    }

    fn parse_response(&self, _response: ResponseParts) -> AdapterResult<ParsedResponse> {
        Err(AdapterError::new(AdapterErrorKind::MissingField))
    }
}

#[test]
fn every_adapter_error_is_redacted_to_unit_protocol_adapter_error() {
    for failure in [FailurePoint::Authentication, FailurePoint::Build] {
        let (config, keys, _) = legacy_client_parts();
        let client = SecureClient::new(config, keys, Arc::new(FailingAdapter(failure)));
        assert!(matches!(
            client.build_request(b"secret", request_context("fail")),
            Err(Error::ProtocolAdapter)
        ));
    }

    let (config, keys, _) = legacy_client_parts();
    let client = SecureClient::new(config, keys, Arc::new(FailingAdapter(FailurePoint::Parse)));
    assert!(matches!(
        client.open_response(ResponseParts::new(
            std::iter::empty::<(&str, &str)>(),
            "secret response",
        )),
        Err(Error::ProtocolAdapter)
    ));
}

#[test]
fn legacy_response_self_loop_opens_only_after_certificate_claim_matches() {
    let client = secure_client_with_seed(7);
    let request = client
        .build_request(b"verified response bytes", request_context("self-loop"))
        .expect("sealed request");
    let response = response_from_request(
        &request,
        client
            .config()
            .identity()
            .expected_remote_signing_certificate_id(),
    );

    assert_eq!(
        client.open_response(response).expect("verified response"),
        b"verified response bytes"
    );
}

#[test]
fn mismatched_certificate_claim_wins_before_any_plaintext_or_crypto_processing() {
    let client = secure_client_with_seed(8);
    let response = ResponseParts::new(
        [
            ("X-Demo-Response-Signature", "not-base64"),
            ("X-Demo-Response-Wrapped-Key", "not-base64"),
            (
                "X-Demo-Response-Remote-Signing-Certificate",
                "different-certificate",
            ),
        ],
        "not-base64",
    );

    assert!(matches!(
        client.open_response(response),
        Err(Error::ProtocolAdapter)
    ));
}

#[test]
fn malformed_response_mapping_is_protocol_error_and_crypto_tampering_is_invalid_envelope() {
    let client = secure_client_with_seed(9);
    let request = client
        .build_request(b"response", request_context("tamper"))
        .expect("request");
    let certificate = client
        .config()
        .identity()
        .expected_remote_signing_certificate_id();

    let missing = ResponseParts::new(
        [
            (
                "X-Demo-Response-Wrapped-Key",
                request.header("X-Demo-Request-Wrapped-Key").expect("key"),
            ),
            ("X-Demo-Response-Remote-Signing-Certificate", certificate),
        ],
        request.body(),
    );
    assert!(matches!(
        client.open_response(missing),
        Err(Error::ProtocolAdapter)
    ));

    let duplicate = ResponseParts::new(
        [
            (
                "X-Demo-Response-Signature",
                request
                    .header("X-Demo-Request-Signature")
                    .expect("signature"),
            ),
            ("x-demo-response-signature", "duplicate"),
            (
                "X-Demo-Response-Wrapped-Key",
                request.header("X-Demo-Request-Wrapped-Key").expect("key"),
            ),
            ("X-Demo-Response-Remote-Signing-Certificate", certificate),
        ],
        request.body(),
    );
    assert!(matches!(
        client.open_response(duplicate),
        Err(Error::ProtocolAdapter)
    ));

    let cases = [
        ResponseParts::new(
            [
                ("X-Demo-Response-Signature", "not-base64!"),
                (
                    "X-Demo-Response-Wrapped-Key",
                    request.header("X-Demo-Request-Wrapped-Key").expect("key"),
                ),
                ("X-Demo-Response-Remote-Signing-Certificate", certificate),
            ],
            request.body(),
        ),
        ResponseParts::new(
            [
                (
                    "X-Demo-Response-Signature",
                    request
                        .header("X-Demo-Request-Signature")
                        .expect("signature"),
                ),
                ("X-Demo-Response-Wrapped-Key", "not-base64!"),
                ("X-Demo-Response-Remote-Signing-Certificate", certificate),
            ],
            request.body(),
        ),
        ResponseParts::new(
            [
                (
                    "X-Demo-Response-Signature",
                    request
                        .header("X-Demo-Request-Signature")
                        .expect("signature"),
                ),
                (
                    "X-Demo-Response-Wrapped-Key",
                    request.header("X-Demo-Request-Wrapped-Key").expect("key"),
                ),
                ("X-Demo-Response-Remote-Signing-Certificate", certificate),
            ],
            "not-base64!",
        ),
    ];
    for tampered in cases {
        assert!(matches!(
            client.open_response(tampered),
            Err(Error::InvalidEnvelope)
        ));
    }
}

#[test]
fn direct_seal_and_open_enforce_explicit_keys_modes_and_contexts() {
    let mode = AuthenticationMode::context_bound(b"direct-domain").expect("mode");
    let (config, keys, _) = client_parts_with_mode(10, mode);
    let client = SecureClient::new(config, keys, Arc::new(ContextAdapter::default()));
    let correct = AuthenticationContext::context_bound(b"direct-context").expect("context");
    let envelope = client
        .seal(b"direct plaintext", &correct)
        .expect("direct seal");

    assert_eq!(
        client.open(&envelope, &correct).expect("direct open"),
        b"direct plaintext"
    );
    assert!(matches!(
        client.open(
            &envelope,
            &AuthenticationContext::context_bound(b"wrong-context").expect("wrong context")
        ),
        Err(Error::InvalidEnvelope)
    ));
    assert!(matches!(
        client.seal(b"direct plaintext", &AuthenticationContext::legacy()),
        Err(Error::AuthenticationContext)
    ));

    let other = secure_client_with_seed(11);
    assert!(matches!(
        other.open(&envelope, &AuthenticationContext::legacy()),
        Err(Error::InvalidEnvelope)
    ));
}

#[test]
fn header_adapter_mode_mismatch_is_authentication_context_outbound_and_invalid_envelope_inbound() {
    let (legacy_config, keys, _legacy_schema) = legacy_client_parts();
    let certificate = legacy_config
        .identity()
        .expected_remote_signing_certificate_id()
        .to_owned();

    let legacy_mode_bound_schema = SecureClient::new(
        legacy_config,
        keys,
        Arc::new(HeaderProtocolAdapter::new(bound_header_schema())),
    );
    assert!(matches!(
        legacy_mode_bound_schema.build_request(b"payload", request_context("pay")),
        Err(Error::AuthenticationContext)
    ));
    let sealed = legacy_mode_bound_schema
        .seal(b"payload", &AuthenticationContext::legacy())
        .expect("legacy seal");
    assert!(matches!(
        legacy_mode_bound_schema.open_response(ResponseParts::new(
            [
                ("X-Demo-Response-Signature", sealed.signature.clone(),),
                (
                    "X-Demo-Response-Wrapped-Key",
                    sealed.wrapped_session_key.clone(),
                ),
                (
                    "X-Demo-Response-Remote-Signing-Certificate",
                    certificate.clone(),
                ),
                ("X-Demo-Request-Id", "request-pay".to_owned()),
            ],
            sealed.cipher.clone(),
        )),
        Err(Error::InvalidEnvelope)
    ));

    let (legacy_config, keys, legacy_schema) = legacy_client_parts();
    let certificate = legacy_config
        .identity()
        .expected_remote_signing_certificate_id()
        .to_owned();
    let bound_mode = AuthenticationMode::context_bound(b"mismatch-domain").expect("domain");
    let bound_mode_legacy_schema = SecureClient::new(
        config_with_mode(&legacy_config, bound_mode),
        keys,
        Arc::new(HeaderProtocolAdapter::new(legacy_schema)),
    );
    assert!(matches!(
        bound_mode_legacy_schema.build_request(b"payload", request_context("pay")),
        Err(Error::AuthenticationContext)
    ));
    let bound = AuthenticationContext::context_bound(b"explicit-bound").expect("context");
    let bound_envelope = bound_mode_legacy_schema
        .seal(b"payload", &bound)
        .expect("bound seal");
    assert!(matches!(
        bound_mode_legacy_schema.open_response(ResponseParts::new(
            [
                (
                    "X-Demo-Response-Signature",
                    bound_envelope.signature.clone(),
                ),
                (
                    "X-Demo-Response-Wrapped-Key",
                    bound_envelope.wrapped_session_key.clone(),
                ),
                ("X-Demo-Response-Remote-Signing-Certificate", certificate,),
            ],
            bound_envelope.cipher.clone(),
        )),
        Err(Error::InvalidEnvelope)
    ));
}

#[test]
fn public_request_parts_constructor_prevents_faulty_adapter_duplicates() {
    let attempted = RequestParts::new([("X-Faulty", "first"), ("x-faulty", "second")], "body");

    assert!(matches!(attempted, Err(Error::HeaderConflict)));
}
