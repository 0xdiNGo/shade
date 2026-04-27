#![no_main]

use libfuzzer_sys::fuzz_target;

// The contract under test: parse() must never panic on any byte input.
// ParseError is the legitimate failure mode; UB, panics, slice-bounds
// errors, and UTF-8 surprises are bugs.
fuzz_target!(|data: &[u8]| {
    let _ = shade_ircd::parse(data);
});
