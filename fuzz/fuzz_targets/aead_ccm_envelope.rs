#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;

const FULL_VALID: &[u8] = include_bytes!("../corpus/aead_ccm_envelope/full_valid_open");

fuzz_target!(|data: &[u8]| {
    let opened = support::ccm_client().open_response(support::ccm_response_parts(data));
    if data == FULL_VALID {
        assert_eq!(
            opened.expect("full valid CCM envelope opens"),
            support::VALID_PLAINTEXT
        );
    }
});
