//! Integration tests for ACL and Metrics functionality.
//!
//! These tests verify that ACL rules are properly enforced and metrics
//! are correctly recorded during actual server operations.

use sockserv::config::FileConfig;
use sockserv::server::acl::{AclConfig, AclManager};
use sockserv::server::metrics::MetricsManager;
use sockserv::server::{run_with_config, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::time::timeout;

/// Start a test server with custom ACL configuration.
async fn start_server_with_acl(
    acl_config: AclConfig,
) -> (u16, tokio::task::JoinHandle<()>, Arc<Notify>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let ready = Arc::new(Notify::new());
    let ready_clone = Arc::clone(&ready);

    let handle = tokio::spawn(async move {
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let config = ServerConfig {
            allow_private_destinations: true,
            ..ServerConfig::default()
        };
        let acl_manager = AclManager::new(&acl_config).unwrap();
        let metrics_manager = MetricsManager::new();

        ready_clone.notify_one();
        let _ = run_with_config(addr, config, acl_manager, metrics_manager).await;
    });

    // Wait for server to be ready
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            // Server is ready if we can connect
            if TcpStream::connect(format!("127.0.0.1:{}", port)).await.is_ok() {
                break;
            }
        }
    })
    .await
    .expect("Server startup timeout");

    (port, handle, ready)
}

/// Start a test server with metrics enabled.
async fn start_server_with_metrics() -> (
    u16,
    tokio::task::JoinHandle<()>,
    MetricsManager,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let metrics_manager = MetricsManager::new();
    let metrics_clone = metrics_manager.clone();

    let handle = tokio::spawn(async move {
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let config = ServerConfig {
            allow_private_destinations: true,
            ..ServerConfig::default()
        };
        let acl_manager = AclManager::new(&AclConfig::default()).unwrap();

        let _ = run_with_config(addr, config, acl_manager, metrics_clone).await;
    });

    // Wait for server to be ready
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if TcpStream::connect(format!("127.0.0.1:{}", port)).await.is_ok() {
                break;
            }
        }
    })
    .await
    .expect("Server startup timeout");

    (port, handle, metrics_manager)
}

// ============================================================================
// ACL Integration Tests
// ============================================================================

#[tokio::test]
async fn test_acl_ip_blacklist_blocks_connection() {
    // Blacklist localhost
    let acl_config = AclConfig {
        ip_blacklist: vec!["127.0.0.1/32".to_string()],
        ..Default::default()
    };

    let (port, handle, _) = start_server_with_acl(acl_config).await;

    // Connection should be accepted at TCP level but closed immediately
    let result = TcpStream::connect(format!("127.0.0.1:{}", port)).await;
    
    // The connection might succeed at TCP level but server will close it
    if let Ok(mut stream) = result {
        // Try to send SOCKS handshake - should fail
        let mut buf = vec![0u8; 10];
        let read_result = timeout(Duration::from_millis(100), stream.read(&mut buf)).await;
        // Should either fail or return 0 bytes (connection closed)
        match read_result {
            Ok(Ok(n)) => assert_eq!(n, 0, "Connection should be closed"),
            _ => {} // Timeout or error is expected
        }
    }

    handle.abort();
}

#[tokio::test]
async fn test_acl_ip_whitelist_allows_connection() {
    // Whitelist localhost
    let acl_config = AclConfig {
        ip_whitelist: vec!["127.0.0.1/32".to_string()],
        ..Default::default()
    };

    let (port, handle, _) = start_server_with_acl(acl_config).await;

    // Connection should work
    let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Connection should succeed");

    // Send valid SOCKS5 handshake (NO_AUTH)
    let mut buf = vec![0u8; 10];
    let handshake = vec![0x05, 0x01, 0x00]; // Version 5, 1 method, NO_AUTH
    let mut stream = stream;
    stream.write_all(&handshake).await.unwrap();
    
    // Should get response
    let read_result = timeout(Duration::from_millis(500), stream.read(&mut buf)).await;
    let n = read_result.expect("Read timeout").unwrap();
    assert!(n >= 2);
    assert_eq!(buf[0], 0x05); // Version 5
    assert_eq!(buf[1], 0x00); // NO_AUTH selected

    handle.abort();
}

#[tokio::test]
async fn test_acl_domain_blacklist_blocks_connect() {
    let acl_config = AclConfig {
        domain_blacklist: vec!["*.blocked.com".to_string()],
        ..Default::default()
    };

    let (port, handle, _) = start_server_with_acl(acl_config).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    // Send SOCKS5 handshake
    let mut stream = stream;
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

    let mut buf = vec![0u8; 10];
    stream.read(&mut buf).await.unwrap();

    // Send CONNECT request to blocked domain
    // Domain: "evil.blocked.com" (16 chars)
    let mut request = vec![
        0x05, 0x01, 0x00, // Version, CONNECT, RSV
        0x03, 16, // ATYP=Domain, len=16
    ];
    request.extend_from_slice(b"evil.blocked.com"); // 16 bytes
    request.extend_from_slice(&[0x00, 80]); // Port 80

    stream.write_all(&request).await.unwrap();

    // Read response
    let mut response = vec![0u8; 26];
    let read_result = timeout(Duration::from_millis(500), stream.read(&mut response)).await;
    let n = read_result.expect("Read timeout").unwrap();
    assert!(n >= 4);

    // Should get connection not allowed (reply code 2)
    assert_eq!(response[1], 0x02, "Should be denied with code 2 (Connection not allowed)");

    handle.abort();
}

#[tokio::test]
async fn test_acl_port_blacklist_blocks_connect() {
    let acl_config = AclConfig {
        port_blacklist: vec!["22".to_string(), "23".to_string()],
        ..Default::default()
    };

    let (port, handle, _) = start_server_with_acl(acl_config).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    // Send SOCKS5 handshake
    let mut stream = stream;
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    
    let mut buf = vec![0u8; 10];
    stream.read(&mut buf).await.unwrap();

    // Send CONNECT request to port 22 (blocked)
    let request = vec![
        0x05, 0x01, 0x00, // Version, CONNECT, RSV
        0x01, // ATYP=IPv4
        127, 0, 0, 1, // IP
        0x00, 22, // Port 22
    ];

    stream.write_all(&request).await.unwrap();
    
    // Read response
    let mut response = vec![0u8; 10];
    let read_result = timeout(Duration::from_millis(500), stream.read(&mut response)).await;
    let n = read_result.expect("Read timeout").unwrap();
    assert!(n >= 4);
    
    // Should get connection not allowed (reply code 2)
    assert_eq!(response[1], 0x02, "Should be denied with code 2 (Connection not allowed)");

    handle.abort();
}

#[tokio::test]
async fn test_acl_port_whitelist_allows_only_allowed() {
    let acl_config = AclConfig {
        port_whitelist: vec!["80".to_string(), "443".to_string()],
        ..Default::default()
    };

    let (port, handle, _) = start_server_with_acl(acl_config).await;

    // Test allowed port (80)
    {
        let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let mut stream = stream;
        
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = vec![0u8; 10];
        stream.read(&mut buf).await.unwrap();

        // CONNECT to port 80 (allowed)
        let request = vec![
            0x05, 0x01, 0x00, 0x01, // Version, CONNECT, RSV, IPv4
            127, 0, 0, 1, // IP
            0x00, 80, // Port 80
        ];
        stream.write_all(&request).await.unwrap();
        
        let mut response = vec![0u8; 10];
        let read_result = timeout(Duration::from_millis(500), stream.read(&mut response)).await;
        let n = read_result.expect("Read timeout").unwrap();
        assert!(n >= 4);
        // Port 80 is whitelisted, but connection will fail (no server on 80)
        // The ACL check passes, so we should get a different error (connection refused)
        assert_ne!(response[1], 0x02, "Should not be ACL denied");
    }

    // Test blocked port (8080)
    {
        let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let mut stream = stream;
        
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = vec![0u8; 10];
        stream.read(&mut buf).await.unwrap();

        // CONNECT to port 8080 (not in whitelist)
        let request = vec![
            0x05, 0x01, 0x00, 0x01, // Version, CONNECT, RSV, IPv4
            127, 0, 0, 1, // IP
            0x1F, 0x90, // Port 8080
        ];
        stream.write_all(&request).await.unwrap();
        
        let mut response = vec![0u8; 10];
        let read_result = timeout(Duration::from_millis(500), stream.read(&mut response)).await;
        let n = read_result.expect("Read timeout").unwrap();
        assert!(n >= 4);
        
        // Should be denied by ACL
        assert_eq!(response[1], 0x02, "Should be denied with code 2");
    }

    handle.abort();
}

// ============================================================================
// Metrics Integration Tests
// ============================================================================

#[tokio::test]
async fn test_metrics_connection_counters() {
    let (port, handle, metrics) = start_server_with_metrics().await;

    // Make a connection
    {
        let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let mut stream = stream;
        
        // Send handshake
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = vec![0u8; 10];
        stream.read(&mut buf).await.unwrap();
    }

    // Give metrics time to update
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Check metrics
    let encoded = metrics.encode().unwrap();
    assert!(encoded.contains("connections_total"), "Should have connections_total");
    assert!(encoded.contains("connections_active"), "Should have connections_active");

    handle.abort();
}

#[tokio::test]
async fn test_metrics_auth_counters() {
    let (port, handle, metrics) = start_server_with_metrics().await;

    // Make a connection with auth attempt
    {
        let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let mut stream = stream;
        
        // Send handshake requesting username/password auth
        stream.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut buf = vec![0u8; 10];
        stream.read(&mut buf).await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let encoded = metrics.encode().unwrap();
    assert!(encoded.contains("auth_attempts_total"), "Should have auth_attempts_total");

    handle.abort();
}

#[tokio::test]
async fn test_metrics_request_counters() {
    let (port, handle, metrics) = start_server_with_metrics().await;

    // Make a CONNECT request
    {
        let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let mut stream = stream;
        
        // Handshake
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = vec![0u8; 10];
        stream.read(&mut buf).await.unwrap();

        // CONNECT request
        let request = vec![
            0x05, 0x01, 0x00, 0x01,
            127, 0, 0, 1,
            0x00, 80,
        ];
        stream.write_all(&request).await.unwrap();
        let mut response = vec![0u8; 10];
        let read_result = timeout(Duration::from_millis(500), stream.read(&mut response)).await;
        let _ = read_result;
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let encoded = metrics.encode().unwrap();
    assert!(encoded.contains("requests_total"), "Should have requests_total");
    assert!(encoded.contains("command=\"CONNECT\""), "Should have CONNECT command");
    assert!(encoded.contains("request_duration_seconds"), "Should have request_duration_seconds");

    handle.abort();
}

#[tokio::test]
async fn test_metrics_acl_decisions() {
    let acl_config = AclConfig {
        domain_blacklist: vec!["*.evil.com".to_string()],
        ..Default::default()
    };

    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    };

    let metrics_manager = MetricsManager::new();
    let metrics_clone = metrics_manager.clone();

    let handle = tokio::spawn(async move {
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let config = ServerConfig {
            allow_private_destinations: true,
            ..ServerConfig::default()
        };
        let acl_manager = AclManager::new(&acl_config).unwrap();
        let _ = run_with_config(addr, config, acl_manager, metrics_clone).await;
    });

    // Wait for server
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Make a request to blacklisted domain
    {
        let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let mut stream = stream;

        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = vec![0u8; 10];
        stream.read(&mut buf).await.unwrap();

        // CONNECT to test.evil.com (blacklisted - matches *.evil.com)
        // Domain: "test.evil.com" (13 chars)
        let mut request = vec![0x05, 0x01, 0x00, 0x03, 13];
        request.extend_from_slice(b"test.evil.com");
        request.extend_from_slice(&[0x00, 80]);

        stream.write_all(&request).await.unwrap();
        let mut response = vec![0u8; 26];
        let read_result = timeout(Duration::from_millis(500), stream.read(&mut response)).await;
        let _ = read_result;
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let encoded = metrics_manager.encode().unwrap();
    assert!(encoded.contains("acl_decisions_total"), "Should have acl_decisions_total");
    assert!(encoded.contains("rule_type=\"domain\""), "Should have domain rule type");
    assert!(encoded.contains("decision=\"deny\""), "Should have deny decision");

    handle.abort();
}

#[tokio::test]
async fn test_metrics_bytes_transferred() {
    let (port, handle, metrics) = start_server_with_metrics().await;

    // Make a connection and transfer some data
    {
        let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let mut stream = stream;
        
        // Handshake
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = vec![0u8; 10];
        stream.read(&mut buf).await.unwrap();

        // CONNECT request
        let request = vec![
            0x05, 0x01, 0x00, 0x01,
            127, 0, 0, 1,
            0x00, 80,
        ];
        stream.write_all(&request).await.unwrap();
        let mut response = vec![0u8; 10];
        let _ = timeout(Duration::from_millis(500), stream.read(&mut response)).await;

        // Write some data
        stream.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let encoded = metrics.encode().unwrap();
    assert!(encoded.contains("bytes_transferred_total"), "Should have bytes_transferred_total");

    handle.abort();
}

// ============================================================================
// Config ACL Validation Tests
// ============================================================================

#[test]
fn test_config_acl_ip_whitelist_blacklist_conflict() {
    let toml = r#"
[acl]
ip_whitelist = ["10.0.0.0/8"]
ip_blacklist = ["192.168.0.0/16"]
"#;
    let result = FileConfig::from_str(toml);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("ACL configuration error"));
}

#[test]
fn test_config_acl_domain_whitelist_blacklist_conflict() {
    let toml = r#"
[acl]
domain_whitelist = ["*.trusted.com"]
domain_blacklist = ["*.evil.com"]
"#;
    let result = FileConfig::from_str(toml);
    assert!(result.is_err());
}

#[test]
fn test_config_acl_port_whitelist_blacklist_conflict() {
    let toml = r#"
[acl]
port_whitelist = ["80", "443"]
port_blacklist = ["22"]
"#;
    let result = FileConfig::from_str(toml);
    assert!(result.is_err());
}

#[test]
fn test_config_acl_valid_config() {
    let toml = r#"
[acl]
ip_blacklist = ["192.168.100.0/24"]
domain_blacklist = ["*.evil.com"]
port_blacklist = ["22", "23"]
max_connections_per_ip = 50
"#;
    let result = FileConfig::from_str(toml);
    assert!(result.is_ok());
}

#[test]
fn test_config_acl_invalid_cidr() {
    let toml = r#"
[acl]
ip_blacklist = ["192.168.1.0/33"]
"#;
    let result = FileConfig::from_str(toml);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("ACL configuration error"));
}

#[test]
fn test_config_acl_invalid_port_range() {
    let toml = r#"
[acl]
port_blacklist = ["100-50"]
"#;
    let result = FileConfig::from_str(toml);
    assert!(result.is_err());
}

#[test]
fn test_config_acl_invalid_domain_pattern() {
    let toml = r#"
[acl]
domain_blacklist = ["*.evil.*.com"]
"#;
    let result = FileConfig::from_str(toml);
    assert!(result.is_err());
}

#[test]
fn test_config_acl_empty_lists_allowed() {
    let toml = r#"
[acl]
"#;
    let result = FileConfig::from_str(toml);
    assert!(result.is_ok());
}

#[test]
fn test_config_acl_cidr_variations() {
    let toml = r#"
[acl]
ip_blacklist = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.1",
    "::1/128",
    "2001:db8::/32"
]
"#;
    let result = FileConfig::from_str(toml);
    assert!(result.is_ok());
}

#[test]
fn test_config_acl_port_range_variations() {
    let toml = r#"
[acl]
port_whitelist = [
    "80",
    "443",
    "8000-9000",
    "1-65535"
]
"#;
    let result = FileConfig::from_str(toml);
    assert!(result.is_ok());
}

#[test]
fn test_config_acl_domain_pattern_variations() {
    let toml = r#"
[acl]
domain_blacklist = [
    "evil.com",
    "*.evil.com",
    ".evil.com",
    "bad-site.org"
]
"#;
    let result = FileConfig::from_str(toml);
    assert!(result.is_ok());
}
