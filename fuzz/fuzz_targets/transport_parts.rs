#![no_main]

mod support;

use gmcrypto_envelope_lite::ProtocolAdapter;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let scenario = support::transport_scenario(data);
    if let Some(expected) = scenario.expected_outcome() {
        assert_eq!(support::transport_outcome(scenario), Some(expected));
    } else if scenario == support::TransportScenario::HeaderCipherGeneric {
        let _ = support::header_cipher_adapter()
            .parse_response(support::generic_header_cipher_parts(data));
    } else {
        let _ = support::adapter().parse_response(support::generic_transport_parts(data));
    }
});
