//! Fuzzing target for ClientHello parsing
//!
//! Usage (requires nightly Rust):
//!   cargo +nightly fuzz build fuzz_client_hello
//!   cargo +nightly fuzz run fuzz_client_hello

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_client_hello(data);
});

fn parse_client_hello(data: &[u8]) -> Result<(), &'static str> {
    if data.len() < 2 {
        return Err("Buffer too short");
    }

    let version = data[0];
    if version != 0x05 {
        return Err("Invalid version");
    }

    let nmethods = data[1] as usize;
    if nmethods == 0 {
        return Err("No auth methods");
    }

    let expected_len = 2 + nmethods;
    if data.len() < expected_len {
        return Err("Buffer too short");
    }

    Ok(())
}
