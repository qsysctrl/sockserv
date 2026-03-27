# SOCKS5 Proxy Server

A high-performance SOCKS5 proxy server implementation in Rust, built with Tokio.

## Features

- **RFC 1928 Compliant**: Full implementation of SOCKS5 protocol specification
- **High Performance**: Built on Tokio for async I/O and concurrent connections
- **Comprehensive Testing**:
  - 74 unit tests with property-based testing (Proptest)
  - 13 integration tests
  - Fuzzing tests for parser robustness
  - Load testing with Docker Compose
- **Graceful Shutdown**: Clean handling of SIGINT/SIGTERM
- **Structured Logging**: Full tracing support with configurable log levels
- **Security Hardened**: SSRF prevention, DNS rebinding protection, rate limiting

## Supported Features

- NO_AUTH authentication
- Username/Password authentication (RFC 1929)
- CONNECT command with TCP relay
- BIND command (RFC 1928)
- UDP ASSOCIATE (RFC 1928)
- IPv4, IPv6, and Domain name address types
- DNS resolution for domain names
- Connection timeout (10s default)
- Bidirectional data relay
- Rate limiting (per-IP, connection, bandwidth)
- **Access Control Lists (ACL)**:
  - IP whitelist/blacklist with CIDR notation
  - Domain filtering with wildcard support
  - Port restrictions with range support
  - Per-IP connection limit overrides

## Roadmap

### Completed

- BIND command support (RFC 1928)
- UDP ASSOCIATE support (RFC 1928)
- Username/Password authentication (RFC 1929)
- Rate limiting (Token Bucket algorithm)
- Configuration file support (TOML)
- **Access Control Lists (ACL)**
- **Prometheus Metrics/Monitoring**

### In Progress

- None (all major features implemented)

### Future

- GSSAPI authentication (RFC 1961)
- Proxy Protocol v2
- TLS/SSL support

---

## Quick Start

### Build

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release
```

### Run

```bash
# Run with default logging
cargo run

# Run with debug logging
RUST_LOG=debug cargo run

# Run release binary
./target/release/sockserv
```

The server listens on `127.0.0.1:1080` by default.

### Docker

```bash
# Build image
docker build -t sockserv .

# Run container
docker run -p 1080:1080 -e RUST_LOG=info sockserv

# Or use docker-compose
docker-compose up --build
```

## Testing

This project follows a comprehensive testing strategy with multiple layers of verification.

### Quick Test Commands

```bash
# Run all tests (stable Rust)
cargo test

# Run all tests with output
cargo test -- --nocapture

# Run specific test category
cargo test --lib          # Unit tests
cargo test --test integration  # Integration tests
```

---

### 1. Unit Tests (74 tests)

Test individual components of the SOCKS5 protocol implementation.

```bash
cargo test --lib
```

**Coverage:**
- `ClientHello` parsing and serialization
- `ServerHello` parsing and serialization
- `SocksAddress` parsing (IPv4, IPv6, Domain)
- `SocksRequest` parsing and serialization
- `SocksResponse` parsing and serialization
- Async read/write operations
- Property-based tests (Proptest)
- Fuzzing-style tests with random data

**Example output:**
```
running 74 tests
test server::protocol::tests::client_hello::test_parse_valid_client_hello_no_auth ... ok
test server::protocol::tests::socks_address::test_parse_ipv4_address ... ok
test server::protocol::tests::proptests::prop_ipv4_roundtrip ... ok
...
test result: ok. 74 passed; 0 failed
```

---

### 2. Integration Tests (9 tests)

Test the complete SOCKS5 handshake and request/response flow.

```bash
cargo test --test integration
```

**Coverage:**
- Full SOCKS5 handshake with NO_AUTH
- Handshake rejection (no acceptable methods)
- CONNECT requests with IPv4, IPv6, and domain addresses
- Unsupported commands (BIND, UDP ASSOCIATE)
- Invalid SOCKS version handling

---

### 3. Fuzzing Tests

Two fuzzing options available for finding edge cases and crashes.

#### Option A: Built-in Fuzzing (Stable Rust)

Quick fuzzing using proptest-style tests:

```bash
cargo test fuzz_tests
```

Runs 9 fuzzing tests that generate random input data.

#### Option B: Coverage-Guided Fuzzing (Nightly Rust)

**Requires nightly Rust!** Uses libFuzzer for coverage-guided fuzzing.

```bash
# Setup (one time, requires nightly)
./scripts/fuzz.sh setup

# Build fuzz targets
./scripts/fuzz.sh build

# Run specific target (default: 60 seconds)
./scripts/fuzz.sh run fuzz_client_hello

# Run with custom time
./scripts/fuzz.sh run fuzz_request 5m

# List available targets
./scripts/fuzz.sh list
```

**Available targets:**
| Target | Description |
|--------|-------------|
| `fuzz_client_hello` | Fuzz ClientHello parsing |
| `fuzz_request` | Fuzz SOCKS request parsing |
| `fuzz_response` | Fuzz SOCKS response parsing |
| `fuzz_address` | Fuzz SOCKS address parsing |

**Results:**
- Artifacts stored in `fuzz/artifacts/<target>/`
- Crashes saved to `fuzz/artifacts/<target>/crashes/`

---

### 4. Load Testing

Test server performance under load.

#### Using Docker Compose

```bash
# Run full stack (server + load tester)
docker-compose up --build

# Run only load tester (connects to existing server)
docker-compose up load-tester
```

#### Using Python Script Directly

```bash
# Install dependencies
pip install socksio

# Run load test
python scripts/load_test.py

# With custom parameters
SOCKS_HOST=127.0.0.1 SOCKS_PORT=1080 \
TEST_DURATION=30 CONCURRENT_CONNECTIONS=50 \
python scripts/load_test.py
```

**Environment variables:**
| Variable | Default | Description |
|----------|---------|-------------|
| `SOCKS_HOST` | `socks-server` | Server hostname |
| `SOCKS_PORT` | `1080` | Server port |
| `TEST_DURATION` | `60` | Test duration (seconds) |
| `CONCURRENT_CONNECTIONS` | `10` | Parallel connections |

---

### 5. Real-World Integration Tests

Test with actual HTTP traffic through the proxy:

```bash
# Install dependencies
sudo pacman -S proxychains-ng  # Or apt-get install proxychains

# Run integration tests
./scripts/test_integration.sh
```

**Test coverage:**
- Basic HTTP through SOCKS5
- HTTPS through CONNECT tunnel
- Large file downloads (1MB)
- Multiple concurrent connections
- Graceful error handling
- IPv6 connectivity (if available)
- Response time measurement

---

### 6. Manual Testing

#### Using curl

```bash
# HTTP request through SOCKS5
curl --socks5 127.0.0.1:1080 http://example.com

# With verbose output
curl -v --socks5 127.0.0.1:1080 http://example.com
```

#### Using Python

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

---

### Test Coverage Summary

| Test Type | Count | Rust Version | Time |
|-----------|-------|--------------|------|
| Unit Tests | 74 | Stable | ~1s |
| Integration Tests (Rust) | 9 | Stable | ~1s |
| Integration Tests (curl) | 7 | N/A | ~15s |
| Fuzzing (built-in) | 9 | Stable | ~1s |
| Fuzzing (cargo-fuzz) | 4 targets | Nightly | 1-5 min |
| Benchmarks | 6 | Stable | ~30s |
| Load Testing | - | Python | 30-60s |

**Total: 105+ tests** — all passing

---

### Troubleshooting

**Tests fail:**
```bash
# Clean and rebuild
cargo clean && cargo build

# Run with backtrace
RUST_BACKTRACE=1 cargo test
```

**Fuzzing fails:**
```bash
# Ensure nightly is installed
rustup install nightly
rustup default nightly

# Reinstall cargo-fuzz
cargo +nightly install cargo-fuzz
```

**Load testing fails:**
```bash
# Check server is running
netstat -tlnp | grep 1080

# Install Python dependencies
pip install --upgrade socksio aiohttp
```

For detailed testing documentation, see [TESTING.md](TESTING.md).

## Project Structure

```
socks_server/
├── src/
│   ├── main.rs                    # Application entry point
│   ├── server.rs                  # Server implementation
│   └── server/
│       └── protocol.rs            # SOCKS5 protocol (RFC 1928)
├── tests/
│   └── integration.rs             # Integration tests
├── fuzz/
│   ├── Cargo.toml                 # Fuzzing crate (cargo-fuzz)
│   ├── fuzz_targets/
│   │   ├── fuzz_client_hello.rs   # ClientHello fuzzer
│   │   ├── fuzz_request.rs        # Request fuzzer
│   │   ├── fuzz_response.rs       # Response fuzzer
│   │   └── fuzz_address.rs        # Address fuzzer
│   ├── seeds/                     # Seed corpus for fuzzing
│   │   ├── hello/
│   │   ├── request/
│   │   ├── response/
│   │   └── address/
│   └── artifacts/                 # Fuzzing results (crashes, hangs)
├── scripts/
│   ├── fuzz.sh                    # Fuzzing management script
│   └── load_test.py               # Load testing script
├── Dockerfile                     # Production Docker image
├── docker-compose.yml             # Load testing orchestration
├── README.md                      # This file
└── TESTING.md                     # Detailed testing guide
```

## Protocol Implementation

The protocol module (`src/server/protocol.rs`) implements:

### Types
- `ClientHello` - Method selection request
- `ServerHello` - Method selection response
- `SocksRequest` - SOCKS command request
- `SocksResponse` - SOCKS command response
- `SocksAddress` - Address type (IPv4/IPv6/Domain)
- `SocksError` - Protocol errors

### Constants
- Auth methods: `AUTH_NO_AUTH`, `AUTH_GSSAPI`, `AUTH_USERNAME_PASSWORD`
- Commands: `CMD_CONNECT`, `CMD_BIND`, `CMD_UDP_ASSOCIATE`
- Address types: `ATYP_IPV4`, `ATYP_DOMAIN`, `ATYP_IPV6`
- Reply codes: `REP_SUCCESS`, `REP_GENERAL_FAILURE`, etc.

## Configuration

Configuration is done via a TOML file. Pass the config file path as an argument:

```bash
cargo run -- config.toml
```

See [config.example.toml](config.example.toml) for a complete example with all options.

### Access Control Lists (ACL)

The ACL system provides fine-grained control over which clients and destinations are allowed:

```toml
[acl]
# IP-based access control (CIDR notation supported)
# Whitelist mode: only allow these networks
ip_whitelist = ["10.0.0.0/8", "192.168.1.0/24"]
# OR blacklist mode: deny these networks
# ip_blacklist = ["192.168.100.0/24"]

# Domain-based access control (wildcards supported)
# Whitelist mode: only allow these domains
# domain_whitelist = ["*.trusted.com", "example.com"]
# Blacklist mode: deny these domains
domain_blacklist = ["*.evil.com", "badsite.com"]

# Port-based access control (ranges supported)
# Whitelist mode: only allow these ports
port_whitelist = ["80", "443", "8000-9000"]
# OR blacklist mode: deny these ports
# port_blacklist = ["22", "23", "25"]

# Override max connections per IP (optional)
max_connections_per_ip = 50
```

**Important**: Whitelist and blacklist are mutually exclusive for each category. If both are empty, all traffic is allowed (subject to other security settings).

### Prometheus Metrics

The server exposes Prometheus-compatible metrics on a separate HTTP endpoint.

**Default endpoint**: `http://127.0.0.1:9090/metrics`

**Available metrics**:

| Metric | Type | Description |
|--------|------|-------------|
| `connections_total` | Counter | Total connections accepted (by remote IP) |
| `connections_active` | Gauge | Current active connections |
| `connections_rejected_total` | Counter | Total connections rejected (by remote IP) |
| `acl_decisions_total` | Counter | ACL decisions by type (ip/domain/port) and result (allow/deny) |
| `bytes_transferred_total` | Histogram | Bytes transferred (rx/tx) with size buckets |
| `errors_total` | Counter | Errors by type |
| `requests_total` | Counter | SOCKS requests by command (CONNECT/BIND/UDP_ASSOCIATE) |
| `request_duration_seconds` | Histogram | Request duration in seconds |
| `auth_attempts_total` | Counter | Total authentication attempts |
| `auth_success_total` | Counter | Successful authentications |
| `auth_failure_total` | Counter | Failed authentications |

**Example scrape**:
```bash
curl http://127.0.0.1:9090/metrics
```

**Health check endpoint**: `http://127.0.0.1:9090/health`

**Example Prometheus config**:
```yaml
scrape_configs:
  - job_name: 'sockserv'
    static_configs:
      - targets: ['localhost:9090']
```

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `RUST_LOG` | `info` | Log level (trace, debug, info, warn, error) |

## Performance

- Concurrent connections via `tokio::task::JoinSet`
- Zero-copy parsing with `bytes` crate
- Async I/O with Tokio runtime
- Minimal memory footprint

## Dependencies

- `tokio` - Async runtime
- `bytes` - Zero-copy byte handling
- `tracing` / `tracing-subscriber` - Structured logging
- `proptest` - Property-based testing (dev)
- `tokio-test` - Async test utilities (dev)
- `rand` - Random number generation (dev)

## License

MIT

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass: `cargo test`
5. Submit a pull request

## References

- [RFC 1928 - SOCKS Protocol Version 5](https://www.rfc-editor.org/rfc/rfc1928)
- [Tokio Documentation](https://tokio.rs/)
- [Bytes Crate](https://docs.rs/bytes/)
