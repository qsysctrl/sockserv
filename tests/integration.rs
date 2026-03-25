//! Integration tests for SOCKS5 server
//!
//! These tests verify the complete SOCKS5 handshake and request/response flow
//! by spawning a real server using `server::run_on_port()` and connecting to it as a client.

use bytes::{BufMut, BytesMut};
use sockserv::server;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

// ============================================================================
// Helper Functions
// ============================================================================

/// Write SOCKS5 client hello with specified auth methods
async fn send_client_hello(stream: &mut TcpStream, methods: &[u8]) -> std::io::Result<()> {
    let mut buf = BytesMut::with_capacity(2 + methods.len());
    buf.put_u8(0x05); // SOCKS5 version
    buf.put_u8(methods.len() as u8);
    buf.put_slice(methods);
    stream.write_all(&buf).await
}

/// Read server hello response
async fn read_server_hello(stream: &mut TcpStream) -> std::io::Result<(u8, u8)> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    Ok((buf[0], buf[1]))
}

/// Send SOCKS5 CONNECT request
async fn send_connect_request(
    stream: &mut TcpStream,
    addr: &[u8],
) -> std::io::Result<()> {
    let mut buf = BytesMut::with_capacity(4 + addr.len());
    buf.put_u8(0x05); // SOCKS5 version
    buf.put_u8(0x01); // CMD_CONNECT
    buf.put_u8(0x00); // RSV (reserved)
    buf.put_slice(addr);
    stream.write_all(&buf).await
}

/// Read full SOCKS5 response including address
async fn read_full_response(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await?;

    let atyp = buf[3];
    let addr_len = match atyp {
        0x01 => 6,  // IPv4: 4 bytes IP + 2 bytes port
        0x03 => {
            // Domain: 1 byte len + N bytes domain + 2 bytes port
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            1 + len_buf[0] as usize + 2
        }
        0x04 => 18, // IPv6: 16 bytes IP + 2 bytes port
        _ => 0,
    };

    let mut full_response = vec![buf[0], buf[1], buf[2], buf[3]];
    if addr_len > 0 {
        let mut addr_buf = vec![0u8; addr_len];
        stream.read_exact(&mut addr_buf).await?;
        full_response.extend(addr_buf);
    }

    Ok(full_response)
}

/// Start a test server on the given port and return a handle to the server task
async fn start_test_server(port: u16) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _ = server::run_on_port(port).await;
    })
}

/// Start a mock target server that accepts connections and sends a simple response
async fn start_mock_target_server() -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    
    let handle = tokio::spawn(async move {
        // Accept one connection and keep it open briefly
        if let Ok((mut stream, _)) = listener.accept().await {
            // Send some data to simulate a working connection
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    
    (port, handle)
}

/// Helper to find an available port for testing
async fn find_available_port() -> u16 {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

// ============================================================================
// Integration Tests
// ============================================================================

/// Test successful handshake with NO_AUTH authentication
#[tokio::test]
async fn test_handshake_no_auth() {
    // Initialize tracing for test output (optional, can be removed)
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    // Find available port and start server
    let socks_port = find_available_port().await;
    let server_handle = start_test_server(socks_port).await;

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect as client
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
        .await
        .expect("Failed to connect to server");

    // Send client hello with NO_AUTH
    send_client_hello(&mut stream, &[0x00]).await.unwrap();

    // Read server hello
    let (version, method) = read_server_hello(&mut stream).await.unwrap();
    assert_eq!(version, 0x05);
    assert_eq!(method, 0x00); // NO_AUTH

    // Send CONNECT request to 127.0.0.1:80 (will fail - connection refused)
    let addr_bytes = [
        0x01, // ATYP IPv4
        127, 0, 0, 1,
        0x00, 80,
    ];
    send_connect_request(&mut stream, &addr_bytes).await.unwrap();

    // Read response - should get ConnectionRefused (0x05) since nothing listens on port 80
    let response = read_full_response(&mut stream).await.unwrap();
    assert_eq!(response[0], 0x05); // Version
    assert_eq!(response[1], 0x05); // ConnectionRefused

    // Cleanup: abort server task
    server_handle.abort();
    let _ = server_handle.await;
}

/// Test successful connection to a mock target server
#[tokio::test]
async fn test_connect_success() {
    let _ = tracing_subscriber::fmt().try_init();

    // Start mock target server
    let (target_port, target_handle) = start_mock_target_server().await;
    
    // Start SOCKS server
    let socks_port = find_available_port().await;
    let server_handle = start_test_server(socks_port).await;
    
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
        .await
        .unwrap();

    // Handshake
    send_client_hello(&mut stream, &[0x00]).await.unwrap();
    let (version, method) = read_server_hello(&mut stream).await.unwrap();
    assert_eq!(version, 0x05);
    assert_eq!(method, 0x00);

    // Send CONNECT to mock target
    let addr_bytes = [
        0x01, // ATYP IPv4
        127, 0, 0, 1,
        (target_port >> 8) as u8,
        (target_port & 0xFF) as u8,
    ];
    send_connect_request(&mut stream, &addr_bytes).await.unwrap();

    // Read response - should be success
    let response = read_full_response(&mut stream).await.unwrap();
    assert_eq!(response[0], 0x05);
    assert_eq!(response[1], 0x00); // Success
    assert_eq!(response[3], 0x01); // IPv4

    // Cleanup
    server_handle.abort();
    target_handle.abort();
    let _ = server_handle.await;
    let _ = target_handle.await;
}

/// Test handshake rejection when no acceptable methods
#[tokio::test]
async fn test_handshake_no_acceptable_methods() {
    let _ = tracing_subscriber::fmt().try_init();

    let port = find_available_port().await;
    let server_handle = start_test_server(port).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    // Send client hello with only GSSAPI (0x01) - not supported
    send_client_hello(&mut stream, &[0x01]).await.unwrap();

    // Read server hello - should get NO_ACCEPTABLE_METHODS (0xFF)
    let (version, method) = read_server_hello(&mut stream).await.unwrap();
    assert_eq!(version, 0x05);
    assert_eq!(method, 0xFF); // NO_ACCEPTABLE_METHODS

    // Server should close connection after sending NO_ACCEPTABLE_METHODS
    // Verify by trying to read - should get EOF
    let mut buf = [0u8; 1];
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        stream.read(&mut buf)
    ).await;

    // Should get EOF (0 bytes) or error (connection closed)
    assert!(result.is_err() || result.unwrap().map(|n| n == 0).unwrap_or(true));

    server_handle.abort();
    let _ = server_handle.await;
}

/// Test CONNECT request with IPv4 address (connection refused case)
#[tokio::test]
async fn test_connect_ipv4_refused() {
    let _ = tracing_subscriber::fmt().try_init();

    let port = find_available_port().await;
    let server_handle = start_test_server(port).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    // Handshake
    send_client_hello(&mut stream, &[0x00]).await.unwrap();
    let (version, method) = read_server_hello(&mut stream).await.unwrap();
    assert_eq!(version, 0x05);
    assert_eq!(method, 0x00);

    // Send CONNECT to 127.0.0.1:1 (port 1 is typically closed)
    // Using localhost to ensure the connection attempt is made locally
    let addr_bytes = [
        0x01, // ATYP IPv4
        127, 0, 0, 1,
        0x00, 0x01, // Port 1 (typically closed)
    ];
    send_connect_request(&mut stream, &addr_bytes).await.unwrap();

    // Read response - should get an error code
    let response = read_full_response(&mut stream).await.unwrap();
    assert_eq!(response[0], 0x05);
    // Reply code should be an error (not success)
    // Common codes: 0x03 (NetworkUnreachable), 0x04 (HostUnreachable), 
    // 0x05 (ConnectionRefused), 0x01 (GeneralFailure)
    assert_ne!(response[1], 0x00, "Expected error response, got success");

    server_handle.abort();
    let _ = server_handle.await;
}

/// Test CONNECT request with domain name
#[tokio::test]
async fn test_connect_domain() {
    let _ = tracing_subscriber::fmt().try_init();

    // Start mock target server
    let (target_port, target_handle) = start_mock_target_server().await;
    
    // Start SOCKS server
    let socks_port = find_available_port().await;
    let server_handle = start_test_server(socks_port).await;
    
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
        .await
        .unwrap();

    // Handshake
    send_client_hello(&mut stream, &[0x00]).await.unwrap();
    let (_version, method) = read_server_hello(&mut stream).await.unwrap();
    assert_eq!(method, 0x00);

    // Send CONNECT to localhost with target port
    let mut addr_bytes = vec![0x03, 9]; // ATYP Domain, len=9
    addr_bytes.extend_from_slice(b"127.0.0.1");
    addr_bytes.extend_from_slice(&[(target_port >> 8) as u8, (target_port & 0xFF) as u8]);

    send_connect_request(&mut stream, &addr_bytes).await.unwrap();

    // Read response - should be success
    let response = read_full_response(&mut stream).await.unwrap();
    assert_eq!(response[0], 0x05);
    assert_eq!(response[1], 0x00); // Success

    server_handle.abort();
    target_handle.abort();
    let _ = server_handle.await;
    let _ = target_handle.await;
}

/// Test CONNECT request with IPv6 address (localhost)
#[tokio::test]
async fn test_connect_ipv6() {
    let _ = tracing_subscriber::fmt().try_init();

    // Start mock target server on IPv6
    let listener = TcpListener::bind("[::1]:0").await.unwrap();
    let target_port = listener.local_addr().unwrap().port();
    
    let target_handle = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(b"OK").await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    
    // Start SOCKS server
    let socks_port = find_available_port().await;
    let server_handle = start_test_server(socks_port).await;
    
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
        .await
        .unwrap();

    // Handshake
    send_client_hello(&mut stream, &[0x00]).await.unwrap();
    let (_version, method) = read_server_hello(&mut stream).await.unwrap();
    assert_eq!(method, 0x00);

    // Send CONNECT to ::1 with target port
    let addr_bytes = [
        0x04, // ATYP IPv6
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // ::1
        (target_port >> 8) as u8,
        (target_port & 0xFF) as u8,
    ];
    send_connect_request(&mut stream, &addr_bytes).await.unwrap();

    // Read response - should be success
    let response = read_full_response(&mut stream).await.unwrap();
    assert_eq!(response[0], 0x05);
    assert_eq!(response[1], 0x00); // Success
    assert_eq!(response[3], 0x04); // IPv6

    server_handle.abort();
    target_handle.abort();
    let _ = server_handle.await;
    let _ = target_handle.await;
}

/// Test multiple auth methods - server selects NO_AUTH
#[tokio::test]
async fn test_multiple_auth_methods() {
    let _ = tracing_subscriber::fmt().try_init();

    let port = find_available_port().await;
    let server_handle = start_test_server(port).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    // Send multiple methods: GSSAPI, NO_AUTH, USERNAME/PASSWORD
    send_client_hello(&mut stream, &[0x01, 0x00, 0x02]).await.unwrap();

    // Server should select NO_AUTH
    let (version, method) = read_server_hello(&mut stream).await.unwrap();
    assert_eq!(version, 0x05);
    assert_eq!(method, 0x00); // NO_AUTH selected

    // Send request to non-existent target (will fail)
    let addr_bytes = [0x01, 0, 0, 0, 0, 0, 0];
    send_connect_request(&mut stream, &addr_bytes).await.unwrap();

    // Read response - should be error (connection refused or network unreachable)
    let response = read_full_response(&mut stream).await.unwrap();
    assert_eq!(response[0], 0x05);
    assert!(response[1] != 0x00); // Should be an error, not success

    server_handle.abort();
    let _ = server_handle.await;
}

/// Test invalid SOCKS version
#[tokio::test]
async fn test_invalid_version() {
    let _ = tracing_subscriber::fmt().try_init();

    let port = find_available_port().await;
    let server_handle = start_test_server(port).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    // Send SOCKS4 version (should be rejected)
    let buf = [0x04, 0x01, 0x00];
    stream.write_all(&buf).await.unwrap();

    // Server should close connection without response for invalid version
    // Try to read - should get EOF (0 bytes) since server closes connection
    let mut response = [0u8; 2];
    let read_result = tokio::time::timeout(
        Duration::from_millis(200),
        stream.read(&mut response)
    ).await;

    match read_result {
        Ok(Ok(0)) => {
            // EOF - server closed connection (expected behavior)
        }
        Ok(Ok(n)) => {
            // Got some data - this is unexpected but might happen
            // Just verify it's not a valid SOCKS5 response
            assert_ne!(response[0], 0x05, "Should not get valid SOCKS5 response for invalid version");
        }
        Ok(Err(_)) => {
            // Connection error - also acceptable
        }
        Err(_) => {
            // Timeout - server didn't respond and didn't close (unexpected)
            panic!("Timeout waiting for server response - expected connection close");
        }
    }

    server_handle.abort();
    let _ = server_handle.await;
}

/// Test unsupported command (BIND)
#[tokio::test]
async fn test_unsupported_command_bind() {
    let _ = tracing_subscriber::fmt().try_init();

    let port = find_available_port().await;
    let server_handle = start_test_server(port).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    // Handshake
    send_client_hello(&mut stream, &[0x00]).await.unwrap();
    let (_version, method) = read_server_hello(&mut stream).await.unwrap();
    assert_eq!(method, 0x00);

    // Send BIND request
    let addr_bytes = [0x01, 0, 0, 0, 0, 0, 0];
    let mut buf = vec![0x05, 0x02, 0x00]; // CMD_BIND
    buf.extend_from_slice(&addr_bytes);
    stream.write_all(&buf).await.unwrap();

    // Read response
    let response = read_full_response(&mut stream).await.unwrap();
    assert_eq!(response[1], 0x07); // Command not supported

    server_handle.abort();
    let _ = server_handle.await;
}

/// Test unsupported command (UDP ASSOCIATE)
#[tokio::test]
async fn test_unsupported_command_udp() {
    let _ = tracing_subscriber::fmt().try_init();

    let port = find_available_port().await;
    let server_handle = start_test_server(port).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    // Handshake
    send_client_hello(&mut stream, &[0x00]).await.unwrap();
    let (_version, method) = read_server_hello(&mut stream).await.unwrap();
    assert_eq!(method, 0x00);

    // Send UDP ASSOCIATE request
    let addr_bytes = [0x01, 0, 0, 0, 0, 0, 0];
    let mut buf = vec![0x05, 0x03, 0x00]; // CMD_UDP_ASSOCIATE
    buf.extend_from_slice(&addr_bytes);
    stream.write_all(&buf).await.unwrap();

    // Read response
    let response = read_full_response(&mut stream).await.unwrap();
    assert_eq!(response[1], 0x07); // Command not supported

    server_handle.abort();
    let _ = server_handle.await;
}
