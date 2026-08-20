#![no_main]

mod support;

use gmcrypto_envelope_lite::ResponseParts;
use libfuzzer_sys::fuzz_target;

const FULL_VALID: &[u8] = include_bytes!("../corpus/aead_ccm_envelope/full_valid_open");

fuzz_target!(|data: &[u8]| {
    let (signature, wrapped_key, cipher) = support::ccm_encoded_values(data);
    let response = ResponseParts::new(
        [
            ("X-Fuzz-Response-Signature", signature),
            ("X-Fuzz-Response-Wrapped-Key", wrapped_key),
            (
                "X-Fuzz-Response-Remote-Signing-Certificate",
                "fuzz-certificate".to_owned(),
            ),
        ],
        cipher,
    );
    let opened = support::ccm_client().open_response(response);
    if data == FULL_VALID {
        assert_eq!(
            opened.expect("full valid CCM envelope opens"),
            support::VALID_PLAINTEXT
        );
    }
});
