//! Fuzzing target for SocksAddress parsing
//!
//! Usage (requires nightly Rust):
//!   cargo +nightly fuzz build fuzz_address
//!   cargo +nightly fuzz run fuzz_address

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_socks_address(data);
});

fn parse_socks_address(data: &[u8]) -> Result<(), &'static str> {
    if data.is_empty() {
        return Err("Buffer empty");
    }

    let atyp = data[0];
    let mut offset = 1;

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
            if domain_len == 0 || domain_len > 255 {
                return Err("Invalid domain length");
            }
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
