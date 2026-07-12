mod support;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use gmcrypto_core::pem;
use secure_envelope_lite::{
    AuthenticationContext, AuthenticationMode, ClientConfig, Error, HeaderProtocolAdapter, KeyKind,
    KeyMaterial, PeerKeySource, PrivateKey, PublicKey, SecureClient,
};

use support::{TEST_PASSWORD, neutral_header_schema, test_key_pair};

#[test]
fn four_independent_key_slots_are_accepted() {
    let signing = test_key_pair(1);
    let decryption = test_key_pair(2);
    let verification = test_key_pair(3);
    let encryption = test_key_pair(4);

    let keys = KeyMaterial::new(
        PrivateKey::from_encrypted_der(&signing.encrypted_private_der, TEST_PASSWORD)
            .expect("local signing key"),
        PrivateKey::from_encrypted_der(&decryption.encrypted_private_der, TEST_PASSWORD)
            .expect("local decryption key"),
        PublicKey::from_der(&verification.public_der).expect("remote verification key"),
        PublicKey::from_der(&encryption.public_der).expect("remote encryption key"),
    );

    assert!(!keys.uses_shared_roles());
    assert_eq!(keys.remote_verification_source(), PeerKeySource::Spki);
    assert_eq!(keys.remote_encryption_source(), PeerKeySource::Spki);
}

#[test]
fn directional_roles_drive_two_party_cryptography() {
    let alice_signing = test_key_pair(20);
    let alice_decryption = test_key_pair(21);
    let bob_signing = test_key_pair(22);
    let bob_decryption = test_key_pair(23);

    let alice = client(
        b"alice-signer",
        b"bob-signer",
        KeyMaterial::new(
            load_private(&alice_signing),
            load_private(&alice_decryption),
            load_public(&bob_signing),
            load_public(&bob_decryption),
        ),
    );
    let bob = client(
        b"bob-signer",
        b"alice-signer",
        KeyMaterial::new(
            load_private(&bob_signing),
            load_private(&bob_decryption),
            load_public(&alice_signing),
            load_public(&alice_decryption),
        ),
    );

    let alice_message = b"signed by Alice and encrypted for Bob";
    let context = AuthenticationContext::legacy();
    let alice_package = alice
        .seal(alice_message, &context)
        .expect("Alice builds envelope");
    assert_eq!(
        bob.open(&alice_package, &context)
            .expect("Bob opens Alice envelope"),
        alice_message
    );

    let bob_message = b"signed by Bob and encrypted for Alice";
    let bob_package = bob
        .seal(bob_message, &context)
        .expect("Bob builds envelope");
    assert_eq!(
        alice
            .open(&bob_package, &context)
            .expect("Alice opens Bob envelope"),
        bob_message
    );
}

#[test]
fn shared_constructor_is_explicit() {
    let local = test_key_pair(5);
    let remote = test_key_pair(6);

    let keys = KeyMaterial::shared(
        PrivateKey::from_encrypted_der(&local.encrypted_private_der, TEST_PASSWORD)
            .expect("shared local key"),
        PublicKey::from_der(&remote.public_der).expect("shared remote key"),
    );

    assert!(keys.uses_shared_roles());
    assert_eq!(
        keys.remote_verification_source(),
        keys.remote_encryption_source()
    );
}

#[test]
fn encrypted_private_and_public_der_loaders_are_independent() {
    let pair = test_key_pair(7);

    PrivateKey::from_encrypted_der(&pair.encrypted_private_der, TEST_PASSWORD)
        .expect("encrypted PKCS#8 DER");
    let public = PublicKey::from_der(&pair.public_der).expect("SPKI DER");

    assert_eq!(public.source(), PeerKeySource::Spki);
}

#[test]
fn public_key_debug_is_sdk_owned_and_opaque() {
    let pair = test_key_pair(15);
    let public = PublicKey::from_der(&pair.public_der).expect("SPKI DER");

    assert_eq!(format!("{public:?}"), "PublicKey { source: Spki }");
}

#[test]
fn encrypted_private_and_public_pem_loaders_accept_runtime_values() {
    let pair = test_key_pair(8);
    let private_pem = pem::encode("ENCRYPTED PRIVATE KEY", &pair.encrypted_private_der);
    let public_pem = pem::encode("PUBLIC KEY", &pair.public_der);

    PrivateKey::from_encrypted_pem(private_pem.as_bytes(), TEST_PASSWORD)
        .expect("encrypted PKCS#8 PEM");
    let public = PublicKey::from_pem(public_pem.as_bytes()).expect("SPKI PEM");

    assert_eq!(public.source(), PeerKeySource::Spki);
}

#[test]
fn shared_pem_and_der_loaders_make_role_reuse_explicit() {
    let pair = test_key_pair(25);
    let private_pem = pem::encode("ENCRYPTED PRIVATE KEY", &pair.encrypted_private_der);
    let public_pem = pem::encode("PUBLIC KEY", &pair.public_der);

    let from_pem =
        KeyMaterial::shared_from_pem(private_pem.as_bytes(), TEST_PASSWORD, public_pem.as_bytes())
            .expect("shared PEM roles");
    let from_der =
        KeyMaterial::shared_from_der(&pair.encrypted_private_der, TEST_PASSWORD, &pair.public_der)
            .expect("shared DER roles");

    assert!(from_pem.uses_shared_roles());
    assert!(from_der.uses_shared_roles());
}

#[test]
fn public_spki_fixture_reports_spki_source() {
    let public = PublicKey::from_pem(include_bytes!("public-fixtures/test-peer-public.pem"))
        .expect("public SPKI fixture");

    assert_eq!(public.source(), PeerKeySource::Spki);
}

#[test]
fn public_certificate_fixture_reports_certificate_source() {
    let public = PublicKey::from_pem(include_bytes!("public-fixtures/test-peer-certificate.pem"))
        .expect("public certificate fixture");

    assert_eq!(public.source(), PeerKeySource::Certificate);
}

#[test]
fn file_loaders_detect_private_and_public_pem_independently() {
    let pair = test_key_pair(9);
    let private_pem = pem::encode("ENCRYPTED PRIVATE KEY", &pair.encrypted_private_der);
    let public_pem = pem::encode("PUBLIC KEY", &pair.public_der);
    let temp = UniqueTempDir::new();
    let private_path = temp.path().join("local-signing.pem");
    let public_path = temp.path().join("remote-verification.pem");
    fs::write(&private_path, private_pem).expect("write private key fixture");
    fs::write(&public_path, public_pem).expect("write public key fixture");

    PrivateKey::from_encrypted_file(&private_path, TEST_PASSWORD)
        .expect("encrypted private key file");
    let public = PublicKey::from_file(&public_path).expect("public key file");

    assert_eq!(public.source(), PeerKeySource::Spki);
}

#[test]
fn shared_file_loader_detects_mixed_pem_and_der_independently() {
    let pair = test_key_pair(24);
    let private_pem = pem::encode("ENCRYPTED PRIVATE KEY", &pair.encrypted_private_der);
    let public_pem = pem::encode("PUBLIC KEY", &pair.public_der);
    let temp = UniqueTempDir::new();
    let private_pem_path = temp.path().join("local.pem");
    let private_der_path = temp.path().join("local.der");
    let public_pem_path = temp.path().join("remote.pem");
    let public_der_path = temp.path().join("remote.der");
    fs::write(&private_pem_path, private_pem).expect("write private PEM");
    fs::write(&private_der_path, &pair.encrypted_private_der).expect("write private DER");
    fs::write(&public_pem_path, public_pem).expect("write public PEM");
    fs::write(&public_der_path, &pair.public_der).expect("write public DER");

    let pem_private_der_public =
        KeyMaterial::shared_from_files(&private_pem_path, TEST_PASSWORD, &public_der_path)
            .expect("PEM private key with DER public key");
    let der_private_pem_public =
        KeyMaterial::shared_from_files(&private_der_path, TEST_PASSWORD, &public_pem_path)
            .expect("DER private key with PEM public key");

    assert!(pem_private_der_public.uses_shared_roles());
    assert!(der_private_pem_public.uses_shared_roles());
    assert_eq!(
        pem_private_der_public.remote_verification_source(),
        PeerKeySource::Spki
    );
    assert_eq!(
        der_private_pem_public.remote_encryption_source(),
        PeerKeySource::Spki
    );
}

#[test]
fn shared_file_loader_reads_remote_key_before_parsing_invalid_private_material() {
    let temp = UniqueTempDir::new();
    let private_path = temp.path().join("invalid-private.der");
    let missing_peer_path = temp.path().join("missing-peer.der");
    fs::write(&private_path, b"not an encrypted private key").expect("write invalid private key");

    let error = KeyMaterial::shared_from_files(&private_path, TEST_PASSWORD, &missing_peer_path)
        .err()
        .expect("missing peer file must fail before private parsing");

    match error {
        Error::Io {
            operation,
            path,
            source,
        } => {
            assert_eq!(operation, "read peer key");
            assert_eq!(path, missing_peer_path);
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        }
        other => panic!("expected peer-file I/O error, got {other:?}"),
    }
}

#[test]
fn loader_errors_keep_safe_key_material_classification() {
    let pair = test_key_pair(10);

    let private_error =
        PrivateKey::from_encrypted_der(&pair.encrypted_private_der, b"wrong-password")
            .err()
            .expect("wrong password must fail");
    assert!(matches!(
        private_error,
        Error::KeyMaterial {
            kind: KeyKind::LocalPrivate
        }
    ));

    let public_error =
        PublicKey::from_der(b"not a public key").expect_err("malformed public input must fail");
    assert!(matches!(
        public_error,
        Error::KeyMaterial {
            kind: KeyKind::PeerPublic
        }
    ));
}

#[test]
fn public_source_getters_report_each_runtime_remote_role() {
    let signing = test_key_pair(11);
    let decryption = test_key_pair(12);
    let verification = test_key_pair(13);
    let encryption = test_key_pair(14);

    let keys = KeyMaterial::new(
        PrivateKey::from_encrypted_der(&signing.encrypted_private_der, TEST_PASSWORD)
            .expect("local signing key"),
        PrivateKey::from_encrypted_der(&decryption.encrypted_private_der, TEST_PASSWORD)
            .expect("local decryption key"),
        PublicKey::from_der(&verification.public_der).expect("remote verification key"),
        PublicKey::from_der(&encryption.public_der).expect("remote encryption key"),
    );

    assert_eq!(keys.remote_verification_source(), PeerKeySource::Spki);
    assert_eq!(keys.remote_encryption_source(), PeerKeySource::Spki);
}

#[test]
fn temp_dir_paths_are_unique_for_the_same_timestamp() {
    let first = unique_temp_dir_path(UNIX_EPOCH);
    let second = unique_temp_dir_path(UNIX_EPOCH);

    assert_ne!(first, second);
}

struct UniqueTempDir(PathBuf);

static NEXT_TEMP_DIR_ID: AtomicU64 = AtomicU64::new(0);

impl UniqueTempDir {
    fn new() -> Self {
        let path = unique_temp_dir_path(SystemTime::now());
        fs::create_dir(&path).expect("create unique test directory");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

fn unique_temp_dir_path(timestamp: SystemTime) -> PathBuf {
    let timestamp = timestamp
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let sequence = NEXT_TEMP_DIR_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "secure-envelope-lite-key-roles-{}-{timestamp}-{sequence}",
        std::process::id()
    ))
}

impl Drop for UniqueTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn load_private(pair: &support::TestKeyPair) -> PrivateKey {
    PrivateKey::from_encrypted_der(&pair.encrypted_private_der, TEST_PASSWORD)
        .expect("test-only private key")
}

fn load_public(pair: &support::TestKeyPair) -> PublicKey {
    PublicKey::from_der(&pair.public_der).expect("test-only public key")
}

fn client(local_signer_id: &[u8], remote_signer_id: &[u8], keys: KeyMaterial) -> SecureClient {
    let config = ClientConfig::builder()
        .local_identity_id("demo-client")
        .api_version("example-v1")
        .local_certificate_id("example-local-certificate")
        .expected_remote_signing_certificate_id("example-remote-signing-certificate")
        .remote_encryption_certificate_id("example-remote-encryption-certificate")
        .local_signer_id(local_signer_id)
        .expected_remote_signer_id(remote_signer_id)
        .authentication_mode(AuthenticationMode::LegacyPlaintext)
        .iv(*b"0123456789abcdef")
        .build()
        .expect("test configuration");
    SecureClient::new(
        config,
        keys,
        Arc::new(HeaderProtocolAdapter::new(neutral_header_schema())),
    )
}
