# SOCKS5 Server Testing Guide

This document describes how to run various tests for the SOCKS5 server implementation.

## Table of Contents

- [Unit Tests](#unit-tests)
- [Integration Tests](#integration-tests)
- [Fuzzing Tests](#fuzzing-tests)
- [Load Testing with Docker](#load-testing-with-docker)
- [Manual Testing](#manual-testing)

## Unit Tests

Run all unit tests for the protocol implementation:

```bash
cargo test --lib
```

This runs 74 tests including:
- ClientHello parsing and serialization
- ServerHello parsing and serialization
- SOCKS address parsing (IPv4, IPv6, Domain)
- SOCKS request/response parsing and serialization
- Property-based tests using Proptest
- Fuzzing-style tests with random input

## Integration Tests

Run integration tests that verify the complete SOCKS5 handshake:

```bash
cargo test --test integration
```

This runs 9 tests including:
- Successful handshake with NO_AUTH
- Handshake rejection (no acceptable methods)
- CONNECT requests with IPv4, IPv6, and domain addresses
- Unsupported commands (BIND, UDP ASSOCIATE)
- Invalid SOCKS version handling

## Fuzzing Tests

The project includes two fuzzing setups:

### 1. cargo-afl (Stable Rust) - Main Project

Basic fuzzing using proptest-style tests built into the main crate:

```bash
# Run built-in fuzzing tests (stable Rust)
cargo test fuzz_tests
```

### 2. cargo-fuzz (Nightly Rust) - Separate Crate

Coverage-guided fuzzing with libFuzzer in a separate crate.
**Requires nightly Rust!**

#### Setup

```bash
# Install cargo-fuzz (requires nightly)
./scripts/fuzz.sh setup

# Or manually:
cargo +nightly install cargo-fuzz
```

#### Build Fuzzing Targets

```bash
# Build all fuzzing targets
./scripts/fuzz.sh build

# Or manually:
cd fuzz
cargo +nightly fuzz build
```

#### Run Fuzzing

```bash
# Run specific fuzzing target (default: 60 seconds)
./scripts/fuzz.sh run fuzz_client_hello

# Run with custom time limit
./scripts/fuzz.sh run fuzz_request 5m

# Or manually:
cd fuzz
cargo +nightly fuzz run fuzz_request -- -max_total_time=300
```

#### Available Fuzzing Targets

| Target | Description | Seed Directory |
|--------|-------------|----------------|
| `fuzz_client_hello` | Fuzz ClientHello parsing | `fuzz/seeds/hello/` |
| `fuzz_request` | Fuzz SOCKS request parsing | `fuzz/seeds/request/` |
| `fuzz_response` | Fuzz SOCKS response parsing | `fuzz/seeds/response/` |
| `fuzz_address` | Fuzz SOCKS address parsing | `fuzz/seeds/address/` |

#### Fuzzing Output

Fuzzing results are stored in `fuzz/artifacts/<target>/`:
- `crashes/` - Files that caused crashes
- `hangs/` - Files that caused timeouts

#### Analyzing Crashes

If a crash is found:

```bash
# Reproduce the crash
cargo +nightly fuzz run fuzz_request fuzz/artifacts/fuzz_request/crashes/<crash_file>

# Analyze with gdb
gdb -ex run --args target/<target-triple>/release/fuzz_request < crash_file
```

### Quick Reference

```bash
# Full workflow (stable Rust - basic fuzzing)
cargo test fuzz_tests

# Full workflow (nightly Rust - coverage-guided fuzzing)
./scripts/fuzz.sh setup    # Install cargo-fuzz (one time)
./scripts/fuzz.sh build    # Build targets
./scripts/fuzz.sh run fuzz_request  # Run fuzzing
```

## Load Testing with Docker

### Prerequisites

- Docker and Docker Compose installed
- At least 2GB of free memory

### Quick Start

Run the complete test suite with Docker Compose:

```bash
# Build and run all services
docker-compose up --build

# Run only the server (for manual testing)
docker-compose up socks-server

# Run load test with custom parameters
SOCKS_HOST=socks-server TEST_DURATION=30 CONCURRENT_CONNECTIONS=20 \
  docker-compose up load-tester
```

### Configuration

Environment variables for load testing:

| Variable | Default | Description |
|----------|---------|-------------|
| `SOCKS_HOST` | `socks-server` | SOCKS server hostname |
| `SOCKS_PORT` | `1080` | SOCKS server port |
| `TEST_DURATION` | `60` | Test duration in seconds |
| `CONCURRENT_CONNECTIONS` | `10` | Number of parallel connections |

### Manual Load Testing

Run load test directly (requires Python 3.11+):

```bash
# Install dependencies
pip install aiohttp socksio

# Run test
python scripts/load_test.py
```

Or with custom parameters:

```bash
SOCKS_HOST=127.0.0.1 SOCKS_PORT=1080 \
TEST_DURATION=30 CONCURRENT_CONNECTIONS=50 \
python scripts/load_test.py
```

## Manual Testing

### Using curl

Test SOCKS5 proxy with curl:

```bash
# Simple HTTP request through SOCKS5
curl --socks5 127.0.0.1:1080 http://example.com

# With verbose output
curl -v --socks5 127.0.0.1:1080 http://example.com
```

### Using Python

```python
import socket
import socks

# Connect through SOCKS5
s = socks.socksocket()
s.set_proxy(socks.SOCKS5, "127.0.0.1", 1080)
s.connect(("example.com", 80))
s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
print(s.recv(4096).decode())
s.close()
```

### Using netcat

Test raw SOCKS5 handshake:

```bash
# Connect to SOCKS server
nc 127.0.0.1 1080

# Send client hello (hex):
# 05 01 00  (VER=5, NMETHODS=1, METHODS=[NO_AUTH])
xxd -r -p <<< "050100"

# Expected server response:
# 05 00  (VER=5, METHOD=NO_AUTH)
```

## Running the Server

### Development Mode

```bash
# Run with debug logging
RUST_LOG=debug cargo run

# Run on custom port (modify source or use environment)
RUST_LOG=info cargo run
```

### Production Mode

```bash
# Build release binary
cargo build --release

# Run with optimized settings
RUST_LOG=info ./target/release/sockserv
```

### Docker

```bash
# Build image
docker build -t sockserv .

# Run container
docker run -p 1080:1080 -e RUST_LOG=info sockserv
```

## Test Coverage

To generate test coverage report:

```bash
# Install cargo-tarpaulin
cargo install cargo-tarpaulin

# Run with coverage
cargo tarpaulin --out Html

# View report
open ./tarpaulin-report.html  # macOS
xdg-open ./tarpaulin-report.html  # Linux
```

## Benchmarking

For benchmarking the protocol parsing:

```bash
# Install criterion
cargo add criterion --dev

# Run benchmarks
cargo bench
```

## Troubleshooting

### Connection Refused

Ensure the server is running:
```bash
netstat -tlnp | grep 1080
```

### Test Timeouts

Increase timeout in integration tests or reduce concurrent connections.

### Docker Issues

Reset Docker environment:
```bash
docker-compose down -v
docker system prune -a
```

## RFC 1928 Compliance

The implementation follows RFC 1928 for:
- Method selection (NO_AUTH supported)
- CONNECT command
- IPv4, IPv6, and Domain address types
- Proper error codes and responses

Unsupported features:
- GSSAPI authentication
- Username/Password authentication
- BIND command
- UDP ASSOCIATE command
