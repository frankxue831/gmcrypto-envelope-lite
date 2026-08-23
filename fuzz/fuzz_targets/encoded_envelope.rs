#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;

const FULL_VALID: &[u8] = include_bytes!("../corpus/encoded_envelope/full_valid_open");

fuzz_target!(|data: &[u8]| {
    let opened = support::client().open_response(support::encoded_response_parts(data));
    if data == FULL_VALID {
        assert_eq!(
            opened.expect("full valid envelope opens"),
            support::VALID_PLAINTEXT
        );
    }
});
