#!/bin/bash
#
# Simple load testing script for SOCKS5 server
# Uses curl to make concurrent requests through the proxy
#

SOCKS_HOST="${SOCKS_HOST:-127.0.0.1}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
DURATION="${DURATION:-30}"
CONCURRENT="${CONCURRENT:-10}"
URL="${URL:-http://example.com}"

echo "============================================================"
echo "SOCKS5 Load Test (curl-based)"
echo "============================================================"
echo "Target: $URL"
echo "SOCKS Proxy: $SOCKS_HOST:$SOCKS_PORT"
echo "Duration: ${DURATION}s"
echo "Concurrent connections: $CONCURRENT"
echo "Start time: $(date)"
echo "============================================================"
echo ""

# Create temp directory for results
RESULTS_DIR=$(mktemp -d)
trap "rm -rf $RESULTS_DIR" EXIT

# Function to make a single request
make_request() {
    local id=$1
    local start=$(date +%s.%N)
    
    local result=$(curl -s -o /dev/null -w "%{http_code},%{time_total},%{size_download}" \
        --socks5 "$SOCKS_HOST:$SOCKS_PORT" \
        --connect-timeout 10 \
        --max-time 30 \
        "$URL" 2>&1)
    
    local end=$(date +%s.%N)
    local total_time=$(echo "$end - $start" | bc)
    
    echo "$id,$result,$total_time" >> "$RESULTS_DIR/results.csv"
}

# Start time
START_TIME=$(date +%s)
END_TIME=$((START_TIME + DURATION))

echo "Starting load test..."
echo ""

# Counter for requests
REQUEST_COUNT=0
SUCCESS_COUNT=0
FAIL_COUNT=0

# Run concurrent requests for specified duration
while [ $(date +%s) -lt $END_TIME ]; do
    # Launch concurrent requests
    for i in $(seq 1 $CONCURRENT); do
        REQUEST_COUNT=$((REQUEST_COUNT + 1))
        make_request $REQUEST_COUNT &
    done
    
    # Wait a bit before next batch
    sleep 0.1
done

# Wait for all background jobs to complete
wait

echo ""
echo "Load test completed!"
echo ""

# Analyze results
if [ -f "$RESULTS_DIR/results.csv" ]; then
    TOTAL=$(wc -l < "$RESULTS_DIR/results.csv")
    
    # Count HTTP 200 responses
    SUCCESS=$(grep -c ",200," "$RESULTS_DIR/results.csv" 2>/dev/null || echo "0")
    FAIL=$((TOTAL - SUCCESS))
    
    echo "============================================================"
    echo "RESULTS"
    echo "============================================================"
    echo "Total requests: $TOTAL"
    echo "Successful (HTTP 200): $SUCCESS"
    echo "Failed: $FAIL"
    
    if [ $TOTAL -gt 0 ]; then
        SUCCESS_RATE=$(echo "scale=2; $SUCCESS * 100 / $TOTAL" | bc)
        echo "Success rate: ${SUCCESS_RATE}%"
    fi
    
    echo ""
    
    # Calculate timing statistics if bc is available
    if command -v bc &> /dev/null; then
        # Extract response times (3rd column)
        TIMES=$(cut -d',' -f5 "$RESULTS_DIR/results.csv" 2>/dev/null)
        
        if [ -n "$TIMES" ]; then
            echo "Response Time Statistics:"
            
            # Min
            MIN=$(echo "$TIMES" | sort -n | head -1)
            echo "  Min: ${MIN}s"
            
            # Max
            MAX=$(echo "$TIMES" | sort -n | tail -1)
            echo "  Max: ${MAX}s"
            
            # Average (approximate)
            SUM=$(echo "$TIMES" | awk '{sum+=$1} END {print sum}')
            AVG=$(echo "scale=3; $SUM / $TOTAL" | bc)
            echo "  Avg: ${AVG}s"
        fi
    fi
    
    echo ""
    echo "Requests per second: $(echo "scale=2; $TOTAL / $DURATION" | bc)"
    echo "============================================================"
else
    echo "ERROR: No results generated"
    echo "Check if the SOCKS5 server is running on $SOCKS_HOST:$SOCKS_PORT"
fi

echo ""
echo "End time: $(date)"
