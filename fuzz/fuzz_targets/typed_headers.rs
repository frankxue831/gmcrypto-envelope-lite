#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let scenario = support::typed_scenario(data);
    if let Some(expected) = scenario.expected_outcome() {
        assert_eq!(support::typed_outcome(scenario), Some(expected));
    } else {
        let _ = support::generic_typed_parts(data);
    }
});
