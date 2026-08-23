#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;

const FULL_VALID: &[u8] = include_bytes!("../corpus/aead_envelope/full_valid_open");

fuzz_target!(|data: &[u8]| {
    let opened = support::aead_client().open_response(support::aead_response_parts(data));
    if data == FULL_VALID {
        assert_eq!(
            opened.expect("full valid AEAD envelope opens"),
            support::VALID_PLAINTEXT
        );
    }
});
