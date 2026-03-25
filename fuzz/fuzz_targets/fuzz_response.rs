//! Fuzzing target for SocksResponse parsing
//!
//! Usage (requires nightly Rust):
//!   cargo +nightly fuzz build fuzz_response
//!   cargo +nightly fuzz run fuzz_response

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_socks_response(data);
});

fn parse_socks_response(data: &[u8]) -> Result<(), &'static str> {
    if data.len() < 4 {
        return Err("Buffer too short");
    }

    let version = data[0];
    if version != 0x05 {
        return Err("Invalid version");
    }

    let _reply = data[1];
    let rsv = data[2];
    if rsv != 0x00 {
        return Err("Invalid reserved");
    }

    let atyp = data[3];
    let mut offset = 4;

    match atyp {
        0x01 => {
            if data.len() < offset + 6 {
                return Err("Buffer too short for IPv4");
            }
            offset += 6;
        }
        0x03 => {
            if data.len() < offset + 1 {
                return Err("Buffer too short for domain");
            }
            let domain_len = data[offset] as usize;
            offset += 1 + domain_len + 2;
        }
        0x04 => {
            if data.len() < offset + 18 {
                return Err("Buffer too short for IPv6");
            }
            offset += 18;
        }
        _ => return Err("Unsupported address type"),
    }

    if data.len() < offset {
        return Err("Buffer too short");
    }

    Ok(())
}
