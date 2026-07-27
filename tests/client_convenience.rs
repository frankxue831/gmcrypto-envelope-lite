mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use gmcrypto_envelope_lite::{
    AdapterError, AdapterErrorKind, AdapterResult, AuthenticationContext, AuthenticationMode,
    ClientIdentity, Error, HeaderProtocolAdapter, ParsedResponse, ProtocolAdapter,
    ProtocolRequestContext, RequestBuilder, RequestContext, RequestMetadata, RequestParts,
    ResponseParts, SecureClient, SecureEnvelope,
};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct Payload {
    amount: String,
}

fn assert_send_sync<T: Send + Sync>() {}

fn assert_root_request_builder_type(_builder: RequestBuilder<'_>) {}

#[test]
fn secure_client_is_shareable() {
    assert_send_sync::<SecureClient>();
    let client = support::secure_client_with_seed(10);
    assert_root_request_builder_type(client.request("type-check"));
}

#[test]
fn fluent_builder_maps_json_metadata_operation_and_additional_header() {
    let client = support::secure_client_with_seed(11);
    let metadata = RequestMetadata::new("request-explicit", "2026-07-12-01.02.03.123456").unwrap();

    let request = client
        .request("demo-operation")
        .metadata(metadata)
        .header("X-Demo-Trace", "trace-11")
        .expect("valid additional header")
        .json(&Payload {
            amount: "10.00".to_owned(),
        })
        .expect("JSON request");

    assert_eq!(request.header("X-Demo-Operation"), Some("demo-operation"));
    assert_eq!(
        request.header("X-Demo-Request-Id"),
        Some("request-explicit")
    );
    assert_eq!(
        request.header("X-Demo-Request-Time"),
        Some("2026-07-12-01.02.03.123456")
    );
    assert_eq!(request.header("x-demo-trace"), Some("trace-11"));
}

#[test]
fn fluent_builder_generates_fresh_well_formed_metadata_when_omitted() {
    let client = support::secure_client_with_seed(12);

    let first = client.request("first").bytes(b"first").unwrap();
    let second = client.request("second").bytes(b"second").unwrap();
    let first_id = first.header("X-Demo-Request-Id").unwrap();
    let second_id = second.header("X-Demo-Request-Id").unwrap();

    assert_ne!(first_id, second_id);
    assert!(is_lowercase_hex_id(first_id));
    assert!(is_lowercase_hex_id(second_id));
    assert!(is_generated_timestamp(
        first.header("X-Demo-Request-Time").unwrap()
    ));
    assert!(is_generated_timestamp(
        second.header("X-Demo-Request-Time").unwrap()
    ));
}

#[test]
fn fluent_header_errors_are_redacted_and_protocol_headers_remain_additive_only() {
    let client = support::secure_client_with_seed(13);

    let invalid_name = match client
        .request("operation")
        .header("Bad Header secret-name", "value")
    {
        Err(error) => error,
        Ok(_) => panic!("invalid header name must fail"),
    };
    assert!(matches!(invalid_name, Error::InvalidHeader));
    assert_eq!(invalid_name.to_string(), "invalid header");
    assert!(!format!("{invalid_name:?}").contains("secret-name"));

    let invalid_value = match client
        .request("operation")
        .header("X-Demo-Trace", "secret-value\rforged")
    {
        Err(error) => error,
        Ok(_) => panic!("invalid header value must fail"),
    };
    assert!(matches!(invalid_value, Error::InvalidHeader));
    assert_eq!(invalid_value.to_string(), "invalid header");
    assert!(!format!("{invalid_value:?}").contains("secret-value"));

    let collision = client
        .request("operation")
        .header("x-demo-operation", "caller-override")
        .expect("syntactically valid caller header")
        .bytes(b"payload");
    assert!(matches!(collision, Err(Error::HeaderConflict)));
}

#[test]
fn fluent_header_rejects_case_insensitive_duplicates_immediately() {
    let client = support::secure_client_with_seed(20);
    let builder = client
        .request("duplicate-header")
        .header("X-Trace", "first")
        .expect("first header");

    let duplicate = builder.header("x-trace", "second");

    assert!(matches!(duplicate, Err(Error::HeaderConflict)));
}

#[test]
fn direct_json_convenience_reuses_an_explicit_request_context() {
    let client = support::secure_client_with_seed(14);
    let context = RequestContext::builder("direct-operation")
        .metadata(RequestMetadata::new("request-direct", "2026-07-12-01.02.03.123456").unwrap())
        .header("X-Direct-Trace", "trace-14")
        .unwrap()
        .build()
        .unwrap();

    let request = client
        .build_json_request(
            &Payload {
                amount: "14.00".to_owned(),
            },
            context,
        )
        .expect("direct JSON request");

    assert_eq!(request.header("X-Demo-Operation"), Some("direct-operation"));
    assert_eq!(request.header("X-Demo-Request-Id"), Some("request-direct"));
    assert_eq!(request.header("X-Direct-Trace"), Some("trace-14"));
}

#[test]
fn json_response_is_deserialized_only_after_envelope_verification() {
    let client = support::secure_client_with_seed(15);
    let request = client
        .request("json-roundtrip")
        .json(&Payload {
            amount: "15.00".to_owned(),
        })
        .unwrap();
    let certificate = client
        .config()
        .identity()
        .expected_remote_signing_certificate_id();
    let response = support::response_from_request(&request, certificate);

    let opened: Payload = client.open_json_response(response).unwrap();
    assert_eq!(
        opened,
        Payload {
            amount: "15.00".to_owned()
        }
    );

    let tampered = ResponseParts::new(
        [
            ("X-Demo-Response-Signature", "not-valid-base64!"),
            (
                "X-Demo-Response-Wrapped-Key",
                request.header("X-Demo-Request-Wrapped-Key").unwrap(),
            ),
            ("X-Demo-Response-Remote-Signing-Certificate", certificate),
        ],
        request.body(),
    );
    let error = client
        .open_json_response::<Payload>(tampered)
        .expect_err("tampered envelope must fail before JSON decoding");
    assert!(matches!(error, Error::InvalidEnvelope));
    assert_eq!(error.to_string(), "invalid secure envelope");
}

#[test]
fn verified_invalid_json_returns_only_the_redacted_serialization_error() {
    let client = support::secure_client_with_seed(16);
    let request = client
        .request("invalid-json")
        .bytes(b"plaintext-secret-not-json")
        .unwrap();
    let response = support::response_from_request(
        &request,
        client
            .config()
            .identity()
            .expected_remote_signing_certificate_id(),
    );

    let error = client
        .open_json_response::<Payload>(response)
        .expect_err("verified non-JSON plaintext must fail decoding");

    assert!(matches!(error, Error::Serialization));
    assert_eq!(error.to_string(), "serialization failed");
    let debug = format!("{error:?}");
    assert!(!debug.contains("plaintext-secret-not-json"));
    assert!(!debug.contains("expected value"));
}

#[test]
fn replacement_client_rotation_keeps_old_and_new_clients_isolated() {
    let (config, old_keys, schema) =
        support::client_parts_with_mode(17, AuthenticationMode::LegacyPlaintext);
    let (_, replacement_keys, _) =
        support::client_parts_with_mode(27, AuthenticationMode::LegacyPlaintext);
    let old = Arc::new(SecureClient::new(
        config.clone(),
        old_keys,
        Arc::new(HeaderProtocolAdapter::new(schema.clone())),
    ));
    let replacement = Arc::new(SecureClient::new(
        config.clone(),
        replacement_keys,
        Arc::new(HeaderProtocolAdapter::new(schema)),
    ));
    let context = AuthenticationContext::legacy();
    let old_envelope = old.seal(b"old", &context).unwrap();
    let new_envelope = replacement.seal(b"new", &context).unwrap();

    assert_eq!(old.open(&old_envelope, &context).unwrap(), b"old");
    assert_eq!(replacement.open(&new_envelope, &context).unwrap(), b"new");
    assert!(matches!(
        replacement.open(&old_envelope, &context),
        Err(Error::InvalidEnvelope)
    ));
    assert!(matches!(
        old.open(&new_envelope, &context),
        Err(Error::InvalidEnvelope)
    ));
    assert_eq!(old.config(), &config);
    assert_eq!(replacement.config(), &config);
    assert_eq!(old.config().identity(), replacement.config().identity());
}

#[derive(Default)]
struct RendezvousState {
    arrivals: usize,
    failed: bool,
}

struct RendezvousAdapter {
    inner: HeaderProtocolAdapter,
    state: Mutex<RendezvousState>,
    arrivals_changed: Condvar,
    timeout: Duration,
}

impl RendezvousAdapter {
    fn new(inner: HeaderProtocolAdapter, timeout: Duration) -> Self {
        Self {
            inner,
            state: Mutex::new(RendezvousState::default()),
            arrivals_changed: Condvar::new(),
            timeout,
        }
    }

    fn rendezvous(&self) -> AdapterResult<()> {
        let mut state = self.state.lock().map_err(|_| rendezvous_error())?;
        if state.failed {
            return Err(rendezvous_error());
        }

        state.arrivals += 1;
        if state.arrivals >= 2 {
            self.arrivals_changed.notify_all();
            return Ok(());
        }

        let (mut state, wait_result) = self
            .arrivals_changed
            .wait_timeout_while(state, self.timeout, |state| {
                state.arrivals < 2 && !state.failed
            })
            .map_err(|_| rendezvous_error())?;
        if state.failed {
            return Err(rendezvous_error());
        }
        if wait_result.timed_out() && state.arrivals < 2 {
            state.failed = true;
            self.arrivals_changed.notify_all();
            return Err(rendezvous_error());
        }
        Ok(())
    }

    fn poison_for_test(&self) {
        let _guard = self.state.lock().expect("unpoisoned rendezvous state");
        panic!("poison rendezvous state for error-path coverage");
    }
}

fn rendezvous_error() -> AdapterError {
    AdapterError::new(AdapterErrorKind::InvalidMapping)
}

impl ProtocolAdapter for RendezvousAdapter {
    fn request_authentication_context(
        &self,
        identity: &ClientIdentity,
        context: &ProtocolRequestContext,
    ) -> AdapterResult<AuthenticationContext> {
        self.rendezvous()?;
        self.inner.request_authentication_context(identity, context)
    }

    fn build_request(
        &self,
        identity: &ClientIdentity,
        context: &ProtocolRequestContext,
        envelope: &SecureEnvelope,
    ) -> AdapterResult<RequestParts> {
        self.inner.build_request(identity, context, envelope)
    }

    fn parse_response(&self, response: ResponseParts) -> AdapterResult<ParsedResponse> {
        self.inner.parse_response(response)
    }
}

#[test]
fn rendezvous_timeout_returns_a_redacted_adapter_error() {
    let (config, keys, schema) =
        support::client_parts_with_mode(21, AuthenticationMode::LegacyPlaintext);
    let client = SecureClient::new(
        config,
        keys,
        Arc::new(RendezvousAdapter::new(
            HeaderProtocolAdapter::new(schema),
            Duration::from_millis(25),
        )),
    );

    let error = client
        .request("only-arrival")
        .bytes(b"payload")
        .expect_err("missing peer must time out");

    assert!(matches!(error, Error::ProtocolAdapter));
    assert_eq!(error.to_string(), "protocol adapter failed");
}

#[test]
fn poisoned_rendezvous_returns_a_redacted_adapter_error() {
    let (config, keys, schema) =
        support::client_parts_with_mode(22, AuthenticationMode::LegacyPlaintext);
    let adapter = Arc::new(RendezvousAdapter::new(
        HeaderProtocolAdapter::new(schema),
        Duration::from_secs(10),
    ));
    let poisoner = Arc::clone(&adapter);
    let poison_result = std::thread::spawn(move || poisoner.poison_for_test()).join();
    assert!(poison_result.is_err(), "poisoning thread must panic");
    let client = SecureClient::new(config, keys, adapter);

    let error = client
        .request("poisoned-rendezvous")
        .bytes(b"payload")
        .expect_err("poisoned state must fail closed");

    assert!(matches!(error, Error::ProtocolAdapter));
    assert_eq!(error.to_string(), "protocol adapter failed");
}

#[test]
fn shared_client_overlaps_and_builds_independent_requests_in_parallel() {
    let (config, keys, schema) =
        support::client_parts_with_mode(18, AuthenticationMode::LegacyPlaintext);
    let client = Arc::new(SecureClient::new(
        config,
        keys,
        Arc::new(RendezvousAdapter::new(
            HeaderProtocolAdapter::new(schema),
            Duration::from_secs(10),
        )),
    ));
    let handles = [
        ("operation-one", "thread-one"),
        ("operation-two", "thread-two"),
    ]
    .map(|(operation, trace)| {
        let client = Arc::clone(&client);
        std::thread::spawn(move || {
            client
                .request(operation)
                .header("X-Thread-Trace", trace)
                .unwrap()
                .bytes(operation.as_bytes())
                .unwrap()
        })
    });
    let [first, second] = handles.map(|handle| handle.join().expect("request thread"));

    assert_eq!(first.header("X-Demo-Operation"), Some("operation-one"));
    assert_eq!(second.header("X-Demo-Operation"), Some("operation-two"));
    assert_eq!(first.header("X-Thread-Trace"), Some("thread-one"));
    assert_eq!(second.header("X-Thread-Trace"), Some("thread-two"));
    assert_ne!(
        first.header("X-Demo-Request-Id"),
        second.header("X-Demo-Request-Id")
    );
}

struct FailingSerialize;

impl Serialize for FailingSerialize {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(serde::ser::Error::custom(
            "plaintext-secret-serde-diagnostic",
        ))
    }
}

struct CountingAdapter {
    authentication_calls: AtomicUsize,
}

impl ProtocolAdapter for CountingAdapter {
    fn request_authentication_context(
        &self,
        _identity: &ClientIdentity,
        _context: &ProtocolRequestContext,
    ) -> AdapterResult<AuthenticationContext> {
        self.authentication_calls.fetch_add(1, Ordering::SeqCst);
        Err(AdapterError::new(AdapterErrorKind::InvalidMapping))
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
        Err(AdapterError::new(AdapterErrorKind::InvalidMapping))
    }
}

#[test]
fn fluent_json_serialization_failure_is_redacted_and_stops_before_encryption() {
    let (config, keys, _) = support::legacy_client_parts();
    let adapter = Arc::new(CountingAdapter {
        authentication_calls: AtomicUsize::new(0),
    });
    let client = SecureClient::new(config, keys, adapter.clone());

    let error = client
        .request("serialize-failure")
        .json(&FailingSerialize)
        .expect_err("serialization must fail");

    assert!(matches!(error, Error::Serialization));
    assert_eq!(error.to_string(), "serialization failed");
    assert!(!format!("{error:?}").contains("plaintext-secret-serde-diagnostic"));
    assert_eq!(adapter.authentication_calls.load(Ordering::SeqCst), 0);
}

struct CountedSerialize<'a>(&'a AtomicUsize);

impl Serialize for CountedSerialize<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.fetch_add(1, Ordering::SeqCst);
        serializer.serialize_str("serialized-once")
    }
}

#[test]
fn fluent_json_serializes_the_value_exactly_once() {
    let client = support::secure_client_with_seed(19);
    let calls = AtomicUsize::new(0);

    client
        .request("serialize-once")
        .json(&CountedSerialize(&calls))
        .expect("JSON request");

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn fluent_json_validates_context_before_calling_user_serialize() {
    let (config, keys, _) = support::legacy_client_parts();
    let adapter = Arc::new(CountingAdapter {
        authentication_calls: AtomicUsize::new(0),
    });
    let client = SecureClient::new(config, keys, adapter.clone());
    let serialize_calls = AtomicUsize::new(0);

    let error = client
        .request("   ")
        .json(&CountedSerialize(&serialize_calls))
        .expect_err("invalid operation must fail before serialization");

    assert!(matches!(error, Error::InvalidHeader));
    assert_eq!(serialize_calls.load(Ordering::SeqCst), 0);
    assert_eq!(adapter.authentication_calls.load(Ordering::SeqCst), 0);
}

fn is_lowercase_hex_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_generated_timestamp(value: &str) -> bool {
    value.len() == 26
        && value.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 | 10 => byte == b'-',
            13 | 16 | 19 => byte == b'.',
            _ => byte.is_ascii_digit(),
        })
}
