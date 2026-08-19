#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;

// The encoded and AEAD targets both pin `LegacyPlaintext`, so the context-bound
// transcript builder — the mode the README actually recommends — saw no fuzz
// input in either direction. This target drives fuzzer-controlled protocol
// context and plaintext through seal *and* open, which is also the only fuzz
// coverage of the seal direction.
fuzz_target!(|data: &[u8]| {
    let outcome = support::context_outcome(data);
    if let Some(expected) = support::context_scenario(data).expected_outcome() {
        assert_eq!(
            outcome,
            expected,
            "context-bound scenario {:?} must reach its declared outcome",
            support::context_scenario(data)
        );
    }
});
