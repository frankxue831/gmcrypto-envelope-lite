#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use gmcrypto_envelope_lite::ProtocolAdapter;

fuzz_target!(|data: &[u8]| {
    let scenario = support::transport_scenario(data);
    if let Some(expected) = scenario.expected_outcome() {
        assert_eq!(support::transport_outcome(scenario), Some(expected));
    } else {
        let _ = support::adapter().parse_response(support::generic_transport_parts(data));
    }
});
