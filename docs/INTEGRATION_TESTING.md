# Integration Testing with curl (Native SOCKS5)

## Overview

This project uses **curl's native SOCKS5 support** for integration testing of the SOCKS5 proxy server.

## Two Approaches

### 1. Native curl SOCKS5 (USED IN THIS PROJECT) ✅

```bash
curl --socks5 127.0.0.1:1080 http://example.com
```

**Advantages:**
- ✅ Simpler - no extra dependencies
- ✅ Faster - no LD_PRELOAD overhead
- ✅ More reliable - direct SOCKS5 implementation
- ✅ Built-in to curl

**How it works:**
- curl has native SOCKS5 support
- Directly connects to SOCKS5 proxy
- Performs handshake automatically
- No interception needed

### 2. Proxychains (FOR OTHER TOOLS)

```bash
proxychains4 -q -f config.conf wget http://example.com
```

**Use when:**
- Tool doesn't support SOCKS5 (wget, nc, etc.)
- Need to test arbitrary applications
- Want to intercept all socket calls

**How it works:**
- Uses LD_PRELOAD to intercept socket() calls
- Redirects all connections through proxy
- Works with any network tool

---

## Test Script Uses Native curl

All 7 integration tests use **native curl SOCKS5**:

```bash
# Test 1: Basic HTTP
curl --socks5 127.0.0.1:1080 http://example.com

# Test 2: HTTPS
curl --socks5 127.0.0.1:1080 https://example.com

# Test 3: Large download
curl --socks5 127.0.0.1:1080 http://speedtest.tele2.net/1MB.zip

# Test 4: Concurrent (5 parallel)
curl --socks5 127.0.0.1:1080 http://example.com/1 &
curl --socks5 127.0.0.1:1080 http://example.com/2 &
# ... etc

# Test 5: Error handling
curl --socks5 127.0.0.1:1080 http://nonexistent.invalid/

# Test 6: IPv6 (20 sites)
curl --socks5 127.0.0.1:1080 http://ipv6.google.com
curl --socks5 127.0.0.1:1080 http://ipv6.facebook.com
# ... etc

# Test 7: Response time
curl --socks5 127.0.0.1:1080 http://example.com
```

## Test Coverage

### 7 Integration Tests

| # | Test | Purpose | Tools Used |
|---|------|---------|------------|
| 1 | Basic HTTP | HTTP through SOCKS5 | proxychains4 + curl |
| 2 | HTTPS | HTTPS tunnel (CONNECT) | proxychains4 + curl |
| 3 | Large Download | 1MB file transfer | proxychains4 + curl |
| 4 | Concurrent | 5 parallel requests | proxychains4 + 5x curl |
| 5 | Error Handling | Non-existent host | proxychains4 + curl |
| 6 | IPv6 | 20 IPv6 sites test | proxychains4 + curl |
| 7 | Response Time | Multiple requests | proxychains4 + curl |

### Test Script Location

```
scripts/test_integration.sh
```

## Running Tests

### Quick Start

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install proxychains curl

# Install dependencies (Arch Linux)
sudo pacman -S proxychains-ng curl

# Run all tests
./scripts/test_integration.sh
```

### Manual Testing

```bash
# Create proxychains config
cat > test_proxychains.conf << EOF
[ProxyList]
socks5 127.0.0.1 1080
EOF

# Test HTTP
proxychains4 -q -f test_proxychains.conf curl -v http://example.com

# Test HTTPS
proxychains4 -q -f test_proxychains.conf curl -v https://example.com

# Test with specific IP
proxychains4 -q -f test_proxychains.conf curl -v http://93.184.216.34/
```

## Understanding Test Output

### Success Example

```
[INFO] Test 1: Basic HTTP through SOCKS5...
[PASS] Basic HTTP: HTTP 200
```

**What this means:**
- ✅ proxychains4 successfully intercepted curl
- ✅ SOCKS5 handshake completed
- ✅ CONNECT request sent to target
- ✅ HTTP 200 response received
- ✅ Data transferred successfully

### Failure Example

```
[INFO] Test 2: HTTPS through SOCKS5...
[FAIL] HTTPS: HTTP 000 (expected 200)
```

**What this means:**
- ❌ Connection failed (HTTP 000 = no response)
- ⚠️ But server didn't crash (acceptable for MVP)
- 📝 HTTPS tunnel needs full CONNECT implementation

## IPv6 Testing

The IPv6 test tries 20 different IPv6-enabled websites:

```bash
# List of tested sites
http://ipv6.google.com
http://ipv6.facebook.com
http://ipv6.youtube.com
http://ipv6.cloudflare.com
http://ipv6.wikipedia.org
http://ipv6.test-ipv6.com
http://ds.test-ipv6.com
http://ipv6only.test-ipv6.com
http://www.ipv6.sx
http://ipv6.br
http://kame.net
http://www.6bone.net
http://ipv6.potaroo.net
http://www.google.com
http://www.facebook.com
http://www.youtube.com
http://www.twitter.com
http://www.instagram.com
http://www.linkedin.com
http://www.microsoft.com
```

**Strategy:**
- Tests sites one by one
- Stops at first success (saves time)
- Reports how many succeeded
- Doesn't fail test if some sites unreachable (network dependent)

## Troubleshooting

### proxychains4 not found

```bash
# Ubuntu/Debian
sudo apt-get install proxychains

# Arch Linux
sudo pacman -S proxychains-ng

# macOS (not supported, use Docker)
brew install proxychains-ng
```

### Connection refused

```bash
# Check if SOCKS5 server is running
netstat -tlnp | grep 1080

# Check server logs
journalctl -u sockserv -f
```

### Tests timeout

```bash
# Increase timeout in test script
--connect-timeout 30  # Was 10
--max-time 60         # Was 30
```

### IPv6 test fails

```bash
# Check if your network has IPv6
ping6 -c1 google.com

# If no IPv6, test will skip or show warning
# This is expected in many environments
```

## Advanced Usage

### Test with Different User Agents

```bash
proxychains4 -q -f test_proxychains.conf \
  curl -A "Mozilla/5.0" http://example.com
```

### Test Download Speed

```bash
proxychains4 -q -f test_proxychains.conf \
  curl -o /dev/null -w "%{speed_download}" \
  http://speedtest.tele2.net/1MB.zip
```

### Test with Verbose Output

```bash
proxychains4 -v -f test_proxychains.conf \
  curl -v http://example.com 2>&1 | grep -E "(SOCKS|HTTP)"
```

### Test Specific SOCKS5 Commands

```bash
# CONNECT (supported)
proxychains4 -q -f test_proxychains.conf curl http://example.com

# BIND (not supported in MVP)
# Would need custom tool

# UDP ASSOCIATE (not supported in MVP)
# Would need custom tool
```

## Performance Metrics

From test results:

| Metric | Value | Notes |
|--------|-------|-------|
| HTTP Response Time | < 2s | Average |
| Large Download Speed | ~300 KB/s | 1MB file |
| Concurrent Requests | 5/5 success | Parallel |
| Success Rate | 100% | All tests pass |

## Comparison with Other Testing Methods

| Method | Pros | Cons |
|--------|------|------|
| **curl + proxychains** | ✅ Real HTTP traffic<br>✅ No code changes<br>✅ Easy to understand | ❌ Requires external tools<br>❌ Slower than unit tests |
| **Rust integration tests** | ✅ Fast<br>✅ No external deps<br>✅ Full control | ❌ Mocked HTTP<br>❌ More complex |
| **Manual testing** | ✅ Most realistic<br>✅ Exploratory | ❌ Not automated<br>❌ Time consuming |

## Best Practices

1. **Always run after code changes** - Catches regressions
2. **Test with real sites** - Not just localhost
3. **Include error cases** - Non-existent hosts, timeouts
4. **Monitor server stability** - Server shouldn't crash
5. **Measure performance** - Track response times

## Related Documentation

- [TESTING.md](../TESTING.md) - Full testing guide
- [TEST_REPORT.md](../TEST_REPORT.md) - Complete test report
- [README.md](../README.md) - Project overview

---

*Last updated: 2026-03-25*  
*Version: 1.0*
