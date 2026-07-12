use secure_envelope_lite::{
    AdapterError, AdapterErrorKind, AuthenticationContext, AuthenticationMode, ClientConfig,
    ClientConfigBuilder, ClientIdentity, DEFAULT_MAX_PLAINTEXT_BYTES, Error,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum OmittedField {
    LocalIdentityId,
    ApiVersion,
    LocalCertificateId,
    ExpectedRemoteSigningCertificateId,
    RemoteEncryptionCertificateId,
    LocalSignerId,
    ExpectedRemoteSignerId,
    Iv,
    AuthenticationMode,
    None,
}

fn config_builder() -> ClientConfigBuilder {
    config_builder_omitting(OmittedField::None)
}

fn config_builder_omitting(omitted: OmittedField) -> ClientConfigBuilder {
    let mut builder = ClientConfig::builder();
    if omitted != OmittedField::LocalIdentityId {
        builder = builder.local_identity_id("demo-client");
    }
    if omitted != OmittedField::ApiVersion {
        builder = builder.api_version("1");
    }
    if omitted != OmittedField::LocalCertificateId {
        builder = builder.local_certificate_id("local-signing-v1");
    }
    if omitted != OmittedField::ExpectedRemoteSigningCertificateId {
        builder = builder.expected_remote_signing_certificate_id("remote-signing-v1");
    }
    if omitted != OmittedField::RemoteEncryptionCertificateId {
        builder = builder.remote_encryption_certificate_id("remote-encryption-v1");
    }
    if omitted != OmittedField::LocalSignerId {
        builder = builder.local_signer_id(b"local-sm2-id");
    }
    if omitted != OmittedField::ExpectedRemoteSignerId {
        builder = builder.expected_remote_signer_id(b"remote-sm2-id");
    }
    if omitted != OmittedField::Iv {
        builder = builder.iv(*b"example-iv-00001");
    }
    if omitted != OmittedField::AuthenticationMode {
        builder = builder.authentication_mode(AuthenticationMode::LegacyPlaintext);
    }
    builder
}

fn assert_configuration_field(error: Error, field: &'static str) {
    assert!(matches!(error, Error::Configuration { field: actual } if actual == field));
}

#[test]
fn context_bound_transcript_is_versioned_and_length_delimited() {
    let mode = AuthenticationMode::context_bound(b"example-domain").unwrap();
    let context = AuthenticationContext::context_bound(b"operation=demo").unwrap();
    let input = mode.authentication_input(&context, b"payload").unwrap();

    let mut expected = vec![1];
    expected.extend_from_slice(&(14_u64).to_be_bytes());
    expected.extend_from_slice(b"example-domain");
    expected.extend_from_slice(&(14_u64).to_be_bytes());
    expected.extend_from_slice(b"operation=demo");
    expected.extend_from_slice(&(7_u64).to_be_bytes());
    expected.extend_from_slice(b"payload");
    assert_eq!(&*input, &expected);
}

#[test]
fn authentication_modes_reject_the_wrong_context_kind() {
    let legacy = AuthenticationMode::LegacyPlaintext;
    let bound = AuthenticationMode::context_bound(b"example-domain").unwrap();

    assert!(matches!(
        legacy.authentication_input(
            &AuthenticationContext::context_bound(b"context").unwrap(),
            b"payload",
        ),
        Err(Error::AuthenticationContext)
    ));
    assert!(matches!(
        bound.authentication_input(&AuthenticationContext::legacy(), b"payload"),
        Err(Error::AuthenticationContext)
    ));
}

#[test]
fn legacy_authentication_input_owns_the_exact_plaintext() {
    let mut plaintext = b"payload".to_vec();
    let input = AuthenticationMode::LegacyPlaintext
        .authentication_input(&AuthenticationContext::legacy(), &plaintext)
        .unwrap();
    plaintext.fill(0);

    assert_eq!(&*input, b"payload");
}

#[test]
fn authentication_constructors_reject_empty_bound_values() {
    assert!(matches!(
        AuthenticationMode::context_bound(Vec::<u8>::new()),
        Err(Error::Configuration {
            field: "domain_separator"
        })
    ));
    assert!(matches!(
        AuthenticationContext::context_bound(Vec::<u8>::new()),
        Err(Error::AuthenticationContext)
    ));
}

#[test]
fn valid_config_preserves_identity_and_cryptographic_settings() {
    let config = config_builder().build().unwrap();
    let identity = config.identity();

    assert_eq!(identity.local_identity_id(), "demo-client");
    assert_eq!(identity.api_version(), "1");
    assert_eq!(identity.local_certificate_id(), "local-signing-v1");
    assert_eq!(
        identity.expected_remote_signing_certificate_id(),
        "remote-signing-v1"
    );
    assert_eq!(
        identity.remote_encryption_certificate_id(),
        "remote-encryption-v1"
    );
    assert_eq!(config.local_signer_id(), b"local-sm2-id");
    assert_eq!(config.expected_remote_signer_id(), b"remote-sm2-id");
    assert_eq!(
        config.authentication_mode(),
        &AuthenticationMode::LegacyPlaintext
    );
    assert_eq!(config.iv(), b"example-iv-00001");
    assert_eq!(config.max_plaintext_bytes(), DEFAULT_MAX_PLAINTEXT_BYTES);
}

#[test]
fn config_requires_every_protocol_specific_value_explicitly() {
    let cases = [
        (OmittedField::LocalIdentityId, "local_identity_id"),
        (OmittedField::ApiVersion, "api_version"),
        (OmittedField::LocalCertificateId, "local_certificate_id"),
        (
            OmittedField::ExpectedRemoteSigningCertificateId,
            "expected_remote_signing_certificate_id",
        ),
        (
            OmittedField::RemoteEncryptionCertificateId,
            "remote_encryption_certificate_id",
        ),
        (OmittedField::LocalSignerId, "local_signer_id"),
        (
            OmittedField::ExpectedRemoteSignerId,
            "expected_remote_signer_id",
        ),
        (OmittedField::Iv, "iv"),
        (OmittedField::AuthenticationMode, "authentication_mode"),
    ];

    for (omitted, expected_field) in cases {
        let error = config_builder_omitting(omitted).build().unwrap_err();
        assert_configuration_field(error, expected_field);
    }
}

#[test]
fn config_rejects_an_empty_remote_signer_id() {
    let error = config_builder()
        .expected_remote_signer_id(Vec::<u8>::new())
        .build()
        .unwrap_err();
    assert_configuration_field(error, "expected_remote_signer_id");
}

#[test]
fn identity_fields_reject_blank_or_header_injection_values() {
    let blank = ClientIdentity::new(
        "  ",
        "1",
        "local-signing-v1",
        "remote-signing-v1",
        "remote-encryption-v1",
    )
    .unwrap_err();
    assert_configuration_field(blank, "local_identity_id");

    let injected = ClientIdentity::new(
        "demo-client",
        "1\r\nx-injected: true",
        "local-signing-v1",
        "remote-signing-v1",
        "remote-encryption-v1",
    )
    .unwrap_err();
    assert_configuration_field(injected, "api_version");
}

#[test]
fn config_enforces_signer_and_plaintext_size_bounds() {
    let oversized_local_signer = config_builder()
        .local_signer_id(vec![0; 8192])
        .build()
        .unwrap_err();
    assert_configuration_field(oversized_local_signer, "local_signer_id");

    let oversized_remote_signer = config_builder()
        .expected_remote_signer_id(vec![0; 8192])
        .build()
        .unwrap_err();
    assert_configuration_field(oversized_remote_signer, "expected_remote_signer_id");

    let maximum_signer_ids = config_builder()
        .local_signer_id(vec![0; 8191])
        .expected_remote_signer_id(vec![1; 8191])
        .build()
        .unwrap();
    assert_eq!(maximum_signer_ids.local_signer_id().len(), 8191);
    assert_eq!(maximum_signer_ids.expected_remote_signer_id().len(), 8191);

    let zero_limit = config_builder().max_plaintext_bytes(0).build().unwrap_err();
    assert_configuration_field(zero_limit, "max_plaintext_bytes");

    let config = config_builder().max_plaintext_bytes(4096).build().unwrap();
    assert_eq!(config.max_plaintext_bytes(), 4096);
}

#[test]
fn adapter_errors_are_constructible_and_redacted() {
    for (kind, expected_display) in [
        (
            AdapterErrorKind::InvalidMapping,
            "protocol adapter failed: InvalidMapping",
        ),
        (
            AdapterErrorKind::MissingField,
            "protocol adapter failed: MissingField",
        ),
        (
            AdapterErrorKind::DuplicateField,
            "protocol adapter failed: DuplicateField",
        ),
        (
            AdapterErrorKind::InvalidField,
            "protocol adapter failed: InvalidField",
        ),
    ] {
        let error = AdapterError::new(kind);
        assert_eq!(error.kind(), kind);
        assert_eq!(error.to_string(), expected_display);
    }
}
