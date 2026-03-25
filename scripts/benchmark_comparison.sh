#!/bin/bash
#
# Production Benchmark: sockserv vs Dante
#

set -e

echo "============================================================"
echo "SOCKS5 Server Benchmark: sockserv vs Dante"
echo "============================================================"
echo ""

# Configuration
SOCKSERV_PORT=1080
DANTE_PORT=1081
DURATION=30
CONCURRENCY="10 50 100"
RESULTS_DIR="benchmark_results_$(date +%Y%m%d_%H%M%S)"
URL="http://example.com/"

mkdir -p "$RESULTS_DIR"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Cleanup function
cleanup() {
    echo ""
    print_info "Cleaning up..."
    pkill -f "sockserv" 2>/dev/null || true
    pkill -f "sockd" 2>/dev/null || true
    sleep 1
    print_info "Cleanup complete"
}

trap cleanup EXIT

# Function to check if server is ready
wait_for_server() {
    local port=$1
    local name=$2
    local max_attempts=20
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if nc -z 127.0.0.1 $port 2>/dev/null; then
            print_info "$name is ready on port $port"
            return 0
        fi
        sleep 0.5
        attempt=$((attempt + 1))
    done
    
    print_error "$name failed to start on port $port"
    return 1
}

# Function to run benchmark
run_benchmark() {
    local name=$1
    local port=$2
    local output_file="$RESULTS_DIR/${name}_benchmark.txt"
    
    echo ""
    echo "============================================================"
    echo "Benchmarking: $name (port $port)"
    echo "============================================================"
    
    # Check if wrk is available
    if ! command -v wrk &> /dev/null; then
        print_error "wrk is not installed. Install with: sudo apt-get install wrk"
        return 1
    fi
    
    # Run benchmarks with different concurrency levels
    for c in $CONCURRENCY; do
        echo ""
        echo "--- Concurrency: $c ---"
        
        wrk -t4 -c$c -d${DURATION}s --latency \
            --socks5 "127.0.0.1:$port" \
            "$URL" 2>&1 | tee -a "$output_file"
        
        sleep 2
    done
    
    echo ""
    print_info "Results saved to: $output_file"
}

# Function to run simple connection test
run_connection_test() {
    local name=$1
    local port=$2
    local count=100
    
    echo ""
    echo "============================================================"
    echo "Connection Test: $name (port $port)"
    echo "============================================================"
    echo "Testing $count connections..."
    
    local total_time=0
    local success=0
    local fail=0
    
    for i in $(seq 1 $count); do
        start=$(date +%s%N)
        if echo -ne '\x05\x01\x00' | nc -q1 127.0.0.1 $port > /dev/null 2>&1; then
            end=$(date +%s%N)
            elapsed=$(( (end - start) / 1000000 ))  # Convert to milliseconds
            total_time=$((total_time + elapsed))
            success=$((success + 1))
        else
            fail=$((fail + 1))
        fi
    done
    
    if [ $success -gt 0 ]; then
        avg_time=$((total_time / success))
        echo ""
        echo "Results:"
        echo "  Successful: $success / $count"
        echo "  Failed: $fail"
        echo "  Average connection time: ${avg_time}ms"
        echo "  Connections per second: $((success * 1000 / (total_time + 1)))"
    else
        echo "All connections failed!"
    fi
}

# Main execution
echo "Results will be saved to: $RESULTS_DIR"
echo ""

# ============================================================================
# Start sockserv
# ============================================================================
print_info "Starting sockserv..."
cd /home/qsysc/Prog/socks_server
cargo build --release 2>&1 | tail -3
RUST_LOG=warn ./target/release/sockserv &
SOCKSERV_PID=$!
wait_for_server $SOCKSERV_PORT "sockserv"

# ============================================================================
# Start Dante
# ============================================================================
print_info "Starting Dante..."
sockd -f /home/qsysc/Prog/socks_server/dante.conf -D 2>&1 &
DANTE_PID=$!
sleep 3
wait_for_server $DANTE_PORT "Dante"

sleep 2

# ============================================================================
# Run Connection Tests
# ============================================================================
run_connection_test "sockserv" $SOCKSERV_PORT
run_connection_test "Dante" $DANTE_PORT

# ============================================================================
# Run Throughput Benchmarks
# ============================================================================
run_benchmark "sockserv" $SOCKSERV_PORT
run_benchmark "Dante" $DANTE_PORT

# ============================================================================
# Generate Comparison Report
# ============================================================================
echo ""
echo "============================================================"
echo "COMPARISON REPORT"
echo "============================================================"
echo ""

# Extract key metrics
extract_metric() {
    local file=$1
    local pattern=$2
    grep "$pattern" "$file" 2>/dev/null | tail -1 || echo "N/A"
}

echo "| Metric | sockserv | Dante |"
echo "|--------|----------|-------|"

# Requests per second (from wrk output)
sockserv_reqs=$(extract_metric "$RESULTS_DIR/sockserv_benchmark.txt" "Req/Sec" | awk '{print $2}')
dante_reqs=$(extract_metric "$RESULTS_DIR/Dante_benchmark.txt" "Req/Sec" | awk '{print $2}')
echo "| Req/Sec (max) | $sockserv_reqs | $dante_reqs |"

# Latency p99
sockserv_p99=$(extract_metric "$RESULTS_DIR/sockserv_benchmark.txt" "p99" | awk '{print $2}')
dante_p99=$(extract_metric "$RESULTS_DIR/Dante_benchmark.txt" "p99" | awk '{print $2}')
echo "| p99 Latency | $sockserv_p99 | $dante_p99 |"

echo ""
echo "============================================================"
echo "Detailed Results"
echo "============================================================"
echo ""
echo "sockserv results: $RESULTS_DIR/sockserv_benchmark.txt"
echo "Dante results: $RESULTS_DIR/Dante_benchmark.txt"

# Save comparison report
cat > "$RESULTS_DIR/comparison_report.md" << EOF
# SOCKS5 Server Benchmark Report

## Date
$(date)

## Configuration
- Duration: ${DURATION}s per test
- Concurrency levels: $CONCURRENCY
- URL: $URL

## Results Summary

| Metric | sockserv | Dante | Winner |
|--------|----------|-------|--------|
| Req/Sec (max) | $sockserv_reqs | $dante_reqs | $([ "${sockserv_reqs:-0}" \> "${dante_reqs:-0}" ] && echo "sockserv" || echo "Dante") |
| p99 Latency | $sockserv_p99 | $dante_p99 | TBD |

## Detailed Results

### sockserv
\`\`\`
$(cat "$RESULTS_DIR/sockserv_benchmark.txt" 2>/dev/null | tail -50)
\`\`\`

### Dante
\`\`\`
$(cat "$RESULTS_DIR/Dante_benchmark.txt" 2>/dev/null | tail -50)
\`\`\`

## Conclusion
[Analysis based on results]
EOF

echo ""
print_info "Comparison report saved to: $RESULTS_DIR/comparison_report.md"
echo ""
echo "============================================================"
echo "Benchmark complete!"
echo "============================================================"
