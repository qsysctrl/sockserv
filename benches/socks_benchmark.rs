//! SOCKS5 Protocol Benchmarks
//!
//! Production-level benchmarks for comparing with other SOCKS implementations.
//!
//! Usage:
//!   cargo bench --bench socks_benchmark
//!
//! For detailed HTML report:
//!   cargo bench --bench socks_benchmark -- --output-format bencher | tee benchmark.txt
//!   # Then open target/criterion/report/index.html

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

// Import real protocol functions
use sockserv::server::protocol::{ClientHello, SocksRequest, SocksResponse};

// ============================================================================
// Benchmark Data
// ============================================================================

const CLIENT_HELLO_NO_AUTH: &[u8] = &[0x05, 0x01, 0x00];
const CLIENT_HELLO_MULTI: &[u8] = &[0x05, 0x03, 0x00, 0x01, 0x02];

const REQUEST_IPV4: &[u8] = &[
    0x05, 0x01, 0x00, 0x01, // VER, CMD, RSV, ATYP(IPv4)
    192, 168, 1, 100, // IP
    0x1F, 0x90, // Port 8080
];

const REQUEST_DOMAIN: &[u8] = &[
    0x05, 0x01, 0x00, 0x03, // VER, CMD, RSV, ATYP(Domain)
    11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', // Domain
    0x01, 0xBB, // Port 443
];

const REQUEST_IPV6: &[u8] = &[
    0x05, 0x01, 0x00, 0x04, // VER, CMD, RSV, ATYP(IPv6)
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // IP (::1)
    0x1F, 0x90, // Port 8080
];

const RESPONSE_SUCCESS: &[u8] = &[
    0x05, 0x00, 0x00, 0x01, // VER, REP, RSV, ATYP(IPv4)
    127, 0, 0, 1, // IP
    0x00, 0x50, // Port 80
];

// ============================================================================
// Benchmarks
// ============================================================================

fn bench_client_hello(c: &mut Criterion) {
    let mut group = c.benchmark_group("client_hello");
    group.throughput(Throughput::Bytes(CLIENT_HELLO_NO_AUTH.len() as u64));

    group.bench_function("parse_no_auth", |b| {
        b.iter(|| ClientHello::parse(black_box(CLIENT_HELLO_NO_AUTH)))
    });

    group.bench_function("parse_multi", |b| {
        b.iter(|| ClientHello::parse(black_box(CLIENT_HELLO_MULTI)))
    });

    group.finish();
}

fn bench_request_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("request_parsing");

    group.bench_with_input(
        BenchmarkId::new("ipv4", REQUEST_IPV4.len()),
        REQUEST_IPV4,
        |b, data| b.iter(|| SocksRequest::parse(black_box(data))),
    );

    group.bench_with_input(
        BenchmarkId::new("domain", REQUEST_DOMAIN.len()),
        REQUEST_DOMAIN,
        |b, data| b.iter(|| SocksRequest::parse(black_box(data))),
    );

    group.bench_with_input(
        BenchmarkId::new("ipv6", REQUEST_IPV6.len()),
        REQUEST_IPV6,
        |b, data| b.iter(|| SocksRequest::parse(black_box(data))),
    );

    group.finish();
}

fn bench_response_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("response_parsing");
    group.throughput(Throughput::Bytes(RESPONSE_SUCCESS.len() as u64));

    group.bench_function("parse_success", |b| {
        b.iter(|| SocksResponse::parse(black_box(RESPONSE_SUCCESS)))
    });

    group.finish();
}

fn bench_full_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_handshake");
    group.throughput(Throughput::Bytes(
        (CLIENT_HELLO_NO_AUTH.len() + 2 + REQUEST_IPV4.len() + RESPONSE_SUCCESS.len()) as u64
    ));

    group.bench_function("complete_flow", |b| {
        b.iter(|| {
            let _ = ClientHello::parse(black_box(CLIENT_HELLO_NO_AUTH));
            let _ = SocksRequest::parse(black_box(REQUEST_IPV4));
            let _ = SocksResponse::parse(black_box(RESPONSE_SUCCESS));
        })
    });

    group.finish();
}

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");

    // Measure requests per second
    group.bench_function("requests_per_second_ipv4", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                let _ = SocksRequest::parse(black_box(REQUEST_IPV4));
            }
        })
    });

    group.bench_function("requests_per_second_domain", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                let _ = SocksRequest::parse(black_box(REQUEST_DOMAIN));
            }
        })
    });

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(100)
        .measurement_time(Duration::from_secs(5))
        .warm_up_time(Duration::from_secs(1))
        .noise_threshold(0.05)
        .confidence_level(0.95)
        .nresamples(100_000);
    targets =
        bench_client_hello,
        bench_request_parsing,
        bench_response_parsing,
        bench_full_handshake,
        bench_throughput
);

criterion_main!(benches);
