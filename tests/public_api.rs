#![forbid(unsafe_code)]

mod support;

use std::sync::Arc;

use gmcrypto_envelope_lite::{
    AuthenticationMode, ClientConfig, HeaderProtocolAdapter, HeaderSchema, KeyMaterial,
    RequestContext, RequestParts, ResponseParts, SecureClient,
};

use support::legacy_client_parts;

#[test]
fn root_api_builds_and_opens_a_verified_legacy_envelope() {
    assert_send_sync::<SecureClient>();
    assert_public_types_are_available();

    let (config, keys, schema) = legacy_client_parts();
    let client = SecureClient::new(config, keys, Arc::new(HeaderProtocolAdapter::new(schema)));
    let request = client
        .build_request(
            b"public API payload",
            RequestContext::builder("demo-operation")
                .header("X-Envelope-Trace", "demo-trace")
                .expect("valid custom header")
                .build()
                .expect("valid request context"),
        )
        .expect("sealed request");

    assert_eq!(request.header("X-Demo-Operation"), Some("demo-operation"));
    assert_eq!(request.header("X-Envelope-Trace"), Some("demo-trace"));

    let response = response_from_request(&request);
    let verified = client.open_response(response).expect("verified response");
    assert_eq!(verified, b"public API payload");
}

fn assert_send_sync<T: Send + Sync>() {}

fn assert_public_types_are_available() {
    let _ = std::any::TypeId::of::<RequestContext>();
    let _ = std::any::TypeId::of::<RequestParts>();
    let _ = std::any::TypeId::of::<ResponseParts>();
    let _ = std::any::TypeId::of::<HeaderProtocolAdapter>();
    let _ = std::any::TypeId::of::<HeaderSchema>();
    let _ = std::any::TypeId::of::<KeyMaterial>();
    let _ = std::any::TypeId::of::<AuthenticationMode>();
    let _ = std::any::TypeId::of::<ClientConfig>();
}

fn response_from_request(request: &RequestParts) -> ResponseParts {
    ResponseParts::new(
        [
            (
                "X-Demo-Response-Signature",
                request
                    .header("X-Demo-Request-Signature")
                    .expect("request signature"),
            ),
            (
                "X-Demo-Response-Wrapped-Key",
                request
                    .header("X-Demo-Request-Wrapped-Key")
                    .expect("wrapped session key"),
            ),
            (
                "X-Demo-Response-Remote-Signing-Certificate",
                "certificate-1",
            ),
        ],
        request.body(),
    )
}
