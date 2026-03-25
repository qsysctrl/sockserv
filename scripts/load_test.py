#!/usr/bin/env python3
"""
SOCKS5 Load Testing Script

This script performs load testing on a SOCKS5 server by creating multiple
concurrent connections and measuring performance metrics.

Usage:
    python load_test.py

Environment variables:
    SOCKS_HOST: SOCKS server hostname (default: socks-server)
    SOCKS_PORT: SOCKS server port (default: 1080)
    TEST_DURATION: Test duration in seconds (default: 60)
    CONCURRENT_CONNECTIONS: Number of concurrent connections (default: 10)
"""

import asyncio
import os
import time
import statistics
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

import socksio.embassy as socks


@dataclass
class ConnectionMetrics:
    """Metrics for a single connection"""
    connect_time: float = 0.0
    handshake_time: float = 0.0
    request_time: float = 0.0
    total_time: float = 0.0
    success: bool = False
    error: Optional[str] = None


@dataclass
class TestResults:
    """Aggregated test results"""
    total_connections: int = 0
    successful_connections: int = 0
    failed_connections: int = 0
    connection_times: List[float] = field(default_factory=list)
    handshake_times: List[float] = field(default_factory=list)
    request_times: List[float] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def add_metrics(self, metrics: ConnectionMetrics):
        """Add metrics from a single connection"""
        self.total_connections += 1
        if metrics.success:
            self.successful_connections += 1
            self.connection_times.append(metrics.connect_time)
            self.handshake_times.append(metrics.handshake_time)
            self.request_times.append(metrics.request_time)
        else:
            self.failed_connections += 1
            if metrics.error:
                self.errors.append(metrics.error)

    def report(self) -> str:
        """Generate a human-readable report"""
        lines = [
            "\n" + "=" * 60,
            "SOCKS5 LOAD TEST RESULTS",
            "=" * 60,
            f"Total Connections: {self.total_connections}",
            f"Successful: {self.successful_connections} ({self.success_rate:.1f}%)",
            f"Failed: {self.failed_connections} ({self.failure_rate:.1f}%)",
            "",
        ]

        if self.connection_times:
            lines.extend([
                "Connection Times (ms):",
                f"  Min: {min(self.connection_times) * 1000:.2f}",
                f"  Max: {max(self.connection_times) * 1000:.2f}",
                f"  Mean: {statistics.mean(self.connection_times) * 1000:.2f}",
                f"  Median: {statistics.median(self.connection_times) * 1000:.2f}",
                f"  Std Dev: {statistics.stdev(self.connection_times) * 1000:.2f}" if len(self.connection_times) > 1 else "",
                "",
                "Handshake Times (ms):",
                f"  Min: {min(self.handshake_times) * 1000:.2f}",
                f"  Max: {max(self.handshake_times) * 1000:.2f}",
                f"  Mean: {statistics.mean(self.handshake_times) * 1000:.2f}",
                f"  Median: {statistics.median(self.handshake_times) * 1000:.2f}",
                f"  Std Dev: {statistics.stdev(self.handshake_times) * 1000:.2f}" if len(self.handshake_times) > 1 else "",
                "",
                "Request Times (ms):",
                f"  Min: {min(self.request_times) * 1000:.2f}",
                f"  Max: {max(self.request_times) * 1000:.2f}",
                f"  Mean: {statistics.mean(self.request_times) * 1000:.2f}",
                f"  Median: {statistics.median(self.request_times) * 1000:.2f}",
                f"  Std Dev: {statistics.stdev(self.request_times) * 1000:.2f}" if len(self.request_times) > 1 else "",
            ])

        if self.errors:
            lines.extend([
                "",
                "Errors:",
            ] + [f"  - {e}" for e in self.errors[:10]])  # Show first 10 errors
            if len(self.errors) > 10:
                lines.append(f"  ... and {len(self.errors) - 10} more")

        lines.append("=" * 60)
        return "\n".join(lines)

    @property
    def success_rate(self) -> float:
        if self.total_connections == 0:
            return 0.0
        return (self.successful_connections / self.total_connections) * 100

    @property
    def failure_rate(self) -> float:
        return 100 - self.success_rate


async def test_socks_connection(
    host: str,
    port: int,
    connection_id: int,
) -> ConnectionMetrics:
    """Test a single SOCKS5 connection"""
    metrics = ConnectionMetrics()
    
    try:
        start_time = time.perf_counter()
        
        # Connect to SOCKS server
        reader, writer = await asyncio.open_connection(host, port)
        metrics.connect_time = time.perf_counter() - start_time
        
        # Perform SOCKS handshake
        handshake_start = time.perf_counter()
        
        # Send client hello (NO_AUTH only)
        client_hello = bytes([0x05, 0x01, 0x00])  # VER, NMETHODS, METHODS
        writer.write(client_hello)
        await writer.drain()
        
        # Read server hello
        server_hello = await reader.readexactly(2)
        if server_hello[1] != 0x00:
            metrics.error = f"Server rejected auth method: {server_hello[1]}"
            writer.close()
            await writer.wait_closed()
            return metrics
        
        metrics.handshake_time = time.perf_counter() - handshake_start
        
        # Send CONNECT request to example.com:80
        request_start = time.perf_counter()
        
        # CONNECT to example.com:80 (using domain name)
        domain = b"example.com"
        request = bytes([
            0x05,  # VER
            0x01,  # CMD (CONNECT)
            0x00,  # RSV
            0x03,  # ATYP (domain name)
            len(domain),
        ]) + domain + bytes([0x00, 80])  # PORT 80
        
        writer.write(request)
        await writer.drain()
        
        # Read response (first 4 bytes)
        response = await reader.readexactly(4)
        
        # Read remaining address bytes
        atyp = response[3]
        if atyp == 0x01:  # IPv4
            addr_len = 6
        elif atyp == 0x03:  # Domain
            domain_len = await reader.readexactly(1)
            addr_len = 1 + domain_len[0] + 2
        elif atyp == 0x04:  # IPv6
            addr_len = 18
        else:
            metrics.error = f"Unknown address type: {atyp}"
            writer.close()
            await writer.wait_closed()
            return metrics
        
        if addr_len > 0:
            await reader.readexactly(addr_len)
        
        metrics.request_time = time.perf_counter() - request_start
        metrics.total_time = time.perf_counter() - start_time
        
        # Check response code
        if response[1] == 0x00:
            metrics.success = True
        else:
            metrics.error = f"Server returned error: {response[1]}"
        
        # Close connection
        writer.close()
        await writer.wait_closed()
        
    except Exception as e:
        metrics.error = str(e)
    
    return metrics


async def run_load_test(
    host: str,
    port: int,
    concurrent_connections: int,
    test_duration: int,
) -> TestResults:
    """Run the load test"""
    results = TestResults()
    start_time = time.perf_counter()
    
    print(f"Starting load test...")
    print(f"  Target: {host}:{port}")
    print(f"  Concurrent connections: {concurrent_connections}")
    print(f"  Duration: {test_duration} seconds")
    print(f"  Start time: {datetime.now().isoformat()}")
    print()
    
    connection_id = 0
    
    while time.perf_counter() - start_time < test_duration:
        # Create batch of concurrent connections
        tasks = []
        for _ in range(concurrent_connections):
            connection_id += 1
            task = asyncio.create_task(
                test_socks_connection(host, port, connection_id)
            )
            tasks.append(task)
        
        # Wait for all connections to complete
        completed = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(completed):
            if isinstance(result, Exception):
                results.failed_connections += 1
                results.errors.append(f"Task {connection_id - concurrent_connections + i}: {result}")
            elif isinstance(result, ConnectionMetrics):
                results.add_metrics(result)
        
        # Progress update
        elapsed = time.perf_counter() - start_time
        print(f"\rProgress: {elapsed:.1f}s / {test_duration}s | "
              f"Connections: {results.total_connections} | "
              f"Success: {results.successful_connections} | "
              f"Failed: {results.failed_connections}", end="")
    
    print()  # New line after progress
    return results


async def main():
    """Main entry point"""
    # Get configuration from environment
    host = os.environ.get("SOCKS_HOST", "socks-server")
    port = int(os.environ.get("SOCKS_PORT", "1080"))
    test_duration = int(os.environ.get("TEST_DURATION", "60"))
    concurrent_connections = int(os.environ.get("CONCURRENT_CONNECTIONS", "10"))
    
    print("=" * 60)
    print("SOCKS5 LOAD TEST")
    print("=" * 60)
    print(f"Configuration:")
    print(f"  Host: {host}")
    print(f"  Port: {port}")
    print(f"  Duration: {test_duration}s")
    print(f"  Concurrent connections: {concurrent_connections}")
    print()
    
    # Run the test
    results = await run_load_test(
        host=host,
        port=port,
        concurrent_connections=concurrent_connections,
        test_duration=test_duration,
    )
    
    # Print report
    print(results.report())
    
    # Exit with error code if failure rate is too high
    if results.failure_rate > 10:
        print("\n⚠️  WARNING: High failure rate detected!")
        exit(1)
    elif results.failure_rate > 0:
        print("\n⚠️  Some connections failed. Check errors above.")
        exit(0)
    else:
        print("\n✓ All connections successful!")
        exit(0)


if __name__ == "__main__":
    asyncio.run(main())
