# Production Load Testing Guide

## Overview

This guide provides production-level load testing for the SOCKS5 server with industry-standard benchmarks.

## Tools

### 1. wrk (HTTP Load Testing)
Best for HTTP throughput testing through SOCKS proxy.

### 2. hey (HTTP Load Testing)
Alternative to wrk with SOCKS5 support.

### 3. Custom Rust Benchmark
For raw SOCKS protocol performance testing.

### 4. tcpping / netcat
For connection latency testing.

---

## Quick Start

### Install Dependencies

```bash
# Ubuntu/Debian
sudo apt-get install -y wrk hey netcat-openbsd

# Or use pre-built binaries
# wrk: https://github.com/wg/wrk
# hey: https://github.com/rakyll/hey
```

### Run Server

```bash
# Production build
cargo build --release

# Run with optimized settings
RUST_LOG=warn ./target/release/sockserv
```

---

## Benchmark Scenarios

### Scenario 1: HTTP Throughput (wrk)

Tests HTTP request throughput through SOCKS5 proxy.

```bash
# Basic test
wrk -t4 -c100 -d30s --latency \
  -H "Proxy-Authorization: Basic" \
  --timeout 30s \
  http://example.com/

# With SOCKS5 (requires socksify or similar)
socksify wrk -t4 -c100 -d30s --latency http://example.com/
```

**Metrics to track:**
- Requests/sec
- Latency (p50, p75, p90, p99)
- Transfer rate

### Scenario 2: Connection Latency

Tests TCP connection establishment time.

```bash
# Using tcpping (if available)
tcpping -x 127.0.0.1:1080 100

# Using bash
for i in {1..100}; do
  time (echo -ne '\x05\x01\x00' | nc -q1 127.0.0.1 1080 > /dev/null)
done | awk '{sum+=$2} END {print "Avg:", sum/NR, "ms"}'
```

### Scenario 3: Concurrent Connections

Tests maximum concurrent connections.

```bash
# Test with increasing concurrency
for concurrent in 10 50 100 200 500 1000; do
  echo "Testing with $concurrent connections..."
  hey -c $concurrent -n 1000 \
    -h "Host: example.com" \
    http://127.0.0.1:1080/
done
```

### Scenario 4: SOCKS Protocol Benchmark

Custom benchmark for raw SOCKS operations.

```bash
# Run custom benchmark
cargo bench --bench socks_benchmark

# Or run directly
./scripts/benchmark.py --host 127.0.0.1 --port 1080 --duration 60
```

---

## Comparison Benchmarks

### vs Other SOCKS Servers

Compare against:
- **Dante** (C-based, industry standard)
- **ss5** (lightweight SOCKS server)
- **Go-socks** (Go implementation)

```bash
# Run comparison
./scripts/compare_servers.sh
```

### Expected Performance Targets

| Metric | Target | Excellent | Good | Poor |
|--------|--------|-----------|------|------|
| Requests/sec | >10,000 | >50,000 | 10,000-50,000 | <10,000 |
| p99 Latency | <10ms | <5ms | 5-10ms | >10ms |
| Concurrent Connections | >1000 | >5000 | 1000-5000 | <1000 |
| Memory Usage | <50MB | <20MB | 20-50MB | >50MB |
| CPU Usage (1000 req/s) | <10% | <5% | 5-10% | >10% |

---

## Detailed Testing

### 1. Throughput Test

```bash
#!/bin/bash
# throughput_test.sh

DURATION=60
CONCURRENCY="10 50 100 200 500 1000"
URL="http://example.com/"

echo "SOCKS5 Server Throughput Test"
echo "=============================="
echo ""

for c in $CONCURRENCY; do
  echo "Concurrency: $c"
  wrk -t4 -c$c -d${DURATION}s --latency \
    -H "Connection: close" \
    $URL 2>&1 | grep -E "(Req/Sec|Latency|p99)"
  echo ""
done
```

### 2. Stress Test

```bash
#!/bin/bash
# stress_test.sh

echo "SOCKS5 Server Stress Test"
echo "=========================="
echo ""

# Ramp up test
for c in 100 200 500 1000 2000 5000; do
  echo "Stress test: $c concurrent connections"
  
  # Start connections
  for i in $(seq 1 $c); do
    (echo -ne '\x05\x01\x00'; sleep 0.1; echo -ne '\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50') | \
      nc -w2 127.0.0.1 1080 > /dev/null 2>&1 &
  done
  
  # Wait and check
  sleep 2
  echo "Active connections: $(netstat -an | grep 1080 | grep ESTABLISHED | wc -l)"
  
  # Cleanup
  pkill -f "nc.*1080"
  sleep 1
done
```

### 3. Endurance Test

```bash
#!/bin/bash
# endurance_test.sh

DURATION=3600  # 1 hour
echo "SOCKS5 Server Endurance Test (${DURATION}s)"
echo "============================================"
echo ""

# Monitor resources
while true; do
  echo "=== $(date) ==="
  ps aux | grep sockserv | grep -v grep
  netstat -an | grep 1080 | wc -l
  sleep 60
done &

MONITOR_PID=$!

# Run load
timeout ${DURATION}s wrk -t4 -c100 -d${DURATION}s http://example.com/

# Cleanup
kill $MONITOR_PID
```

---

## Metrics Collection

### System Metrics

```bash
# CPU usage
top -bn1 | grep "Cpu(s)" | awk '{print $2}'

# Memory usage
ps -o rss,vsz,pid,comm -p $(pgrep sockserv) | tail -1

# Network I/O
iftop -P -n -i eth0 -f "port 1080"

# File descriptors
lsof -p $(pgrep sockserv) | wc -l
```

### Application Metrics

```bash
# Connection count
netstat -an | grep :1080 | grep ESTABLISHED | wc -l

# Error rate (from logs)
tail -f /var/log/sockserv.log | grep -c "ERROR"

# Response time (from traces)
# Requires tracing enabled
```

---

## Reporting

### Generate Report

```bash
./scripts/generate_report.sh
```

### Report Template

```markdown
# Load Test Report

## Date
YYYY-MM-DD HH:MM:SS

## Server Configuration
- Version: X.X.X
- CPU: X cores
- Memory: X GB
- OS: XXX

## Test Results

### Throughput
- Max Requests/sec: XXXX
- Avg Requests/sec: XXXX

### Latency
- p50: X.XX ms
- p90: X.XX ms
- p99: X.XX ms

### Resource Usage
- CPU: XX%
- Memory: XXX MB
- File Descriptors: XXXX

## Comparison

| Metric | This Server | Dante | ss5 |
|--------|-------------|-------|-----|
| Req/s | XXXX | XXXX | XXXX |
| p99 | X.XXms | X.XXms | X.XXms |
| Memory | XXXMB | XXXMB | XXXMB |

## Conclusion
[Summary of findings]
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Load Testing

on: [push, pull_request]

jobs:
  load-test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install wrk
      run: sudo apt-get install -y wrk
    
    - name: Build server
      run: cargo build --release
    
    - name: Start server
      run: ./target/release/sockserv &
      background: true
    
    - name: Wait for server
      run: sleep 5
    
    - name: Run load test
      run: |
        wrk -t2 -c50 -d30s http://example.com/ > results.txt
    
    - name: Check results
      run: |
        REQ_SEC=$(grep "Req/Sec" results.txt | awk '{print $2}')
        if (( $(echo "$REQ_SEC < 1000" | bc -l) )); then
          echo "Performance regression detected!"
          exit 1
        fi
```

---

## Troubleshooting

### High Latency

```bash
# Check system load
uptime

# Check network
ss -s

# Check file descriptors
ulimit -n
```

### Connection Refused

```bash
# Check if server is running
netstat -tlnp | grep 1080

# Check firewall
iptables -L -n | grep 1080

# Check max connections
cat /proc/sys/fs/file-max
```

### Memory Issues

```bash
# Check memory usage
free -h

# Check for leaks
valgrind --leak-check=full ./target/release/sockserv
```

---

## Best Practices

1. **Always test in production-like environment**
2. **Run tests multiple times and average results**
3. **Monitor system resources during tests**
4. **Start with small loads and ramp up gradually**
5. **Document all test configurations**
6. **Compare against baseline regularly**
7. **Test edge cases (high latency, packet loss)**
8. **Use realistic traffic patterns**
