#!/bin/bash
#
# SOCKS5 Server Comparison Benchmark
# Compares sockserv against other SOCKS implementations
#

set -e

echo "============================================================"
echo "SOCKS5 Server Comparison Benchmark"
echo "============================================================"
echo ""

# Configuration
DURATION=30
CONCURRENCY=100
URL="http://example.com/"
RESULTS_DIR="benchmark_results_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR"

# Function to run benchmark
run_benchmark() {
    local name=$1
    local port=$2
    
    echo "Benchmarking $name on port $port..."
    
    if command -v wrk &> /dev/null; then
        wrk -t4 -c$CONCURRENCY -d${DURATION}s --latency \
            --socks5 "127.0.0.1:$port" \
            "$URL" 2>&1 | tee "$RESULTS_DIR/${name}_wrk.txt"
    elif command -v hey &> /dev/null; then
        hey -c $CONCURRENCY -n 10000 \
            -m GET \
            "$URL" 2>&1 | tee "$RESULTS_DIR/${name}_hey.txt"
    else
        echo "ERROR: Neither wrk nor hey installed"
        return 1
    fi
    
    echo ""
}

# Function to start sockserv
start_sockserv() {
    echo "Starting sockserv..."
    cargo build --release 2>&1 | tail -3
    RUST_LOG=warn ./target/release/sockserv &
    SERVSERV_PID=$!
    sleep 2
    echo "sockserv started (PID: $SERVSERV_PID)"
}

# Function to start dante (if available)
start_dante() {
    if command -v sockd &> /dev/null; then
        echo "Starting Dante..."
        # Dante config would go here
        echo "Dante started"
    else
        echo "Dante not installed, skipping..."
    fi
}

# Function to start ss5 (if available)
start_ss5() {
    if command -v ss5 &> /dev/null; then
        echo "Starting ss5..."
        # ss5 config would go here
        echo "ss5 started"
    else
        echo "ss5 not installed, skipping..."
    fi
}

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    pkill -f sockserv 2>/dev/null || true
    pkill -f sockd 2>/dev/null || true
    pkill -f ss5 2>/dev/null || true
    echo "Cleanup complete"
}

trap cleanup EXIT

# Main benchmark
echo "Results will be saved to: $RESULTS_DIR"
echo ""

# Benchmark sockserv
start_sockserv
run_benchmark "sockserv" 1080

# Benchmark other servers (if available)
# start_dante
# run_benchmark "dante" 1080

# start_ss5
# run_benchmark "ss5" 1080

# Generate comparison report
echo "============================================================"
echo "Generating comparison report..."
echo "============================================================"

if [ -f "$RESULTS_DIR/sockserv_wrk.txt" ]; then
    echo ""
    echo "=== sockserv Results ==="
    grep -E "(Req/Sec|Latency|p50|p75|p90|p99)" "$RESULTS_DIR/sockserv_wrk.txt" || echo "No wrk results"
fi

echo ""
echo "============================================================"
echo "Benchmark complete!"
echo "Results saved to: $RESULTS_DIR"
echo "============================================================"
echo ""
echo "To view detailed HTML report:"
echo "  cargo bench --bench socks_benchmark"
echo "  open target/criterion/report/index.html"
