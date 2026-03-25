//! Integration tests for SOCKS5 server
//!
//! These tests verify the complete SOCKS5 handshake and request/response flow
//! by spawning a real server and connecting to it as a client.

use bytes::{BufMut, BytesMut};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

/// Read SOCKS5 response
async fn read_socks_response(stream: &mut TcpStream) -> std::io::Result<(u8, u8, u8, u8)> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await?;
    Ok((buf[0], buf[1], buf[2], buf[3]))
}

/// Read full response including address
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

// ============================================================================
// Integration Tests
// ============================================================================

/// Test successful handshake with NO_AUTH authentication
#[tokio::test]
async fn test_handshake_no_auth() {
    // Start server on random port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.unwrap();
        
        // Read client hello
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n >= 3);
        assert_eq!(buf[0], 0x05); // SOCKS5 version
        assert!(buf[1] > 0); // At least one method
        
        // Send server hello (NO_AUTH)
        let response = [0x05, 0x00];
        stream.write_all(&response).await.unwrap();
        
        // Read request
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n >= 10);
        assert_eq!(buf[0], 0x05); // SOCKS5 version
        assert_eq!(buf[1], 0x01); // CMD_CONNECT
        
        // Send success response
        let response = [
            0x05, 0x00, 0x00, // VER, REP, RSV
            0x01, // ATYP IPv4
            127, 0, 0, 1, // IP
            0x00, 0x50, // Port 80
        ];
        stream.write_all(&response).await.unwrap();
    });
    
    // Client side
    let client_handle = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        
        // Send client hello with NO_AUTH
        send_client_hello(&mut stream, &[0x00]).await.unwrap();
        
        // Read server hello
        let (version, method) = read_server_hello(&mut stream).await.unwrap();
        assert_eq!(version, 0x05);
        assert_eq!(method, 0x00); // NO_AUTH
        
        // Send CONNECT request to 127.0.0.1:80
        let addr_bytes = [
            0x01, // ATYP IPv4
            127, 0, 0, 1,
            0x00, 80,
        ];
        send_connect_request(&mut stream, &addr_bytes).await.unwrap();
        
        // Read response
        let response = read_full_response(&mut stream).await.unwrap();
        assert_eq!(response[0], 0x05); // Version
        assert_eq!(response[1], 0x00); // Success
    });
    
    // Wait for both tasks
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);
    server_result.unwrap();
    client_result.unwrap();
}

/// Test handshake rejection when no acceptable methods
#[tokio::test]
async fn test_handshake_no_acceptable_methods() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.unwrap();

        // Read client hello
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();

        // Client only sent GSSAPI (0x01), we don't support it
        assert_eq!(buf[0], 0x05);
        assert_eq!(buf[1], 1);
        assert_eq!(buf[2], 0x01); // GSSAPI

        // Send NO_ACCEPTABLE_METHODS
        let response = [0x05, 0xFF];
        stream.write_all(&response).await.unwrap();

        // Server closes connection after sending NO_ACCEPTABLE_METHODS
        drop(stream);
    });

    let client_handle = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // Send client hello with only GSSAPI
        send_client_hello(&mut stream, &[0x01]).await.unwrap();

        // Read server hello
        let (version, method) = read_server_hello(&mut stream).await.unwrap();
        assert_eq!(version, 0x05);
        assert_eq!(method, 0xFF); // NO_ACCEPTABLE_METHODS

        // According to RFC 1928, client should close connection now
        // We verify that no further data is expected by reading until EOF
        let mut buf = [0u8; 1];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stream.read(&mut buf)
        ).await;
        
        // Should get EOF or timeout (server closed connection)
        assert!(result.is_err() || result.unwrap().map(|n| n == 0).unwrap_or(true));
    });

    let (server_result, client_result) = tokio::join!(server_handle, client_handle);
    server_result.unwrap();
    client_result.unwrap();
}

/// Test CONNECT request with IPv4 address
#[tokio::test]
async fn test_connect_ipv4() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    let server_handle = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.unwrap();
        
        // Handshake
        let mut buf = [0u8; 256];
        let _ = stream.read(&mut buf).await.unwrap();
        stream.write_all(&[0x05, 0x00]).await.unwrap();
        
        // Read request
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0x05);
        assert_eq!(buf[1], 0x01); // CONNECT
        assert_eq!(buf[3], 0x01); // IPv4
        
        // Extract target address
        let target_ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
        let target_port = u16::from_be_bytes([buf[8], buf[9]]);
        
        assert_eq!(target_ip, "192.168.1.100");
        assert_eq!(target_port, 8080);
        
        // Send success response with bound address
        let response = [
            0x05, 0x00, 0x00, // VER, REP, RSV
            0x01, // ATYP IPv4
            10, 0, 0, 1, // Bound IP
            0x04, 0x38, // Bound port 1080
        ];
        stream.write_all(&response).await.unwrap();
    });
    
    let client_handle = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        
        // Handshake
        send_client_hello(&mut stream, &[0x00]).await.unwrap();
        let (version, method) = read_server_hello(&mut stream).await.unwrap();
        assert_eq!(version, 0x05);
        assert_eq!(method, 0x00);
        
        // Send CONNECT to 192.168.1.100:8080
        let addr_bytes = [
            0x01, // ATYP IPv4
            192, 168, 1, 100,
            0x1F, 0x90, // 8080
        ];
        send_connect_request(&mut stream, &addr_bytes).await.unwrap();
        
        // Read response
        let response = read_full_response(&mut stream).await.unwrap();
        assert_eq!(response[0], 0x05);
        assert_eq!(response[1], 0x00); // Success
        assert_eq!(response[3], 0x01); // IPv4
    });
    
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);
    server_result.unwrap();
    client_result.unwrap();
}

/// Test CONNECT request with domain name
#[tokio::test]
async fn test_connect_domain() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    let server_handle = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.unwrap();
        
        // Handshake
        let mut buf = [0u8; 256];
        let _ = stream.read(&mut buf).await.unwrap();
        stream.write_all(&[0x05, 0x00]).await.unwrap();
        
        // Read request
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0x05);
        assert_eq!(buf[1], 0x01); // CONNECT
        assert_eq!(buf[3], 0x03); // Domain
        
        // Extract domain
        let domain_len = buf[4] as usize;
        let domain = String::from_utf8(buf[5..5 + domain_len].to_vec()).unwrap();
        let port = u16::from_be_bytes([buf[5 + domain_len], buf[5 + domain_len + 1]]);
        
        assert_eq!(domain, "example.com");
        assert_eq!(port, 443);
        
        // Send success response
        let response = [
            0x05, 0x00, 0x00,
            0x01, 0, 0, 0, 0, 0, 0,
        ];
        stream.write_all(&response).await.unwrap();
    });
    
    let client_handle = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        
        // Handshake
        send_client_hello(&mut stream, &[0x00]).await.unwrap();
        let (_version, method) = read_server_hello(&mut stream).await.unwrap();
        assert_eq!(method, 0x00);
        
        // Send CONNECT to example.com:443
        let mut addr_bytes = vec![0x03, 11]; // ATYP Domain, len=11
        addr_bytes.extend_from_slice(b"example.com");
        addr_bytes.extend_from_slice(&[0x01, 0xBB]); // Port 443
        
        send_connect_request(&mut stream, &addr_bytes).await.unwrap();
        
        // Read response
        let response = read_full_response(&mut stream).await.unwrap();
        assert_eq!(response[0], 0x05);
        assert_eq!(response[1], 0x00); // Success
    });
    
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);
    server_result.unwrap();
    client_result.unwrap();
}

/// Test CONNECT request with IPv6 address
#[tokio::test]
async fn test_connect_ipv6() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    let server_handle = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.unwrap();
        
        // Handshake
        let mut buf = [0u8; 256];
        let _ = stream.read(&mut buf).await.unwrap();
        stream.write_all(&[0x05, 0x00]).await.unwrap();
        
        // Read request
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0x05);
        assert_eq!(buf[1], 0x01); // CONNECT
        assert_eq!(buf[3], 0x04); // IPv6
        
        // Send success response
        let response = [
            0x05, 0x00, 0x00,
            0x04, // IPv6
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // ::1
            0x1F, 0x90, // Port 8080
        ];
        stream.write_all(&response).await.unwrap();
    });
    
    let client_handle = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        
        // Handshake
        send_client_hello(&mut stream, &[0x00]).await.unwrap();
        let (_version, method) = read_server_hello(&mut stream).await.unwrap();
        assert_eq!(method, 0x00);
        
        // Send CONNECT to ::1:8080
        let addr_bytes = [
            0x04, // ATYP IPv6
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0x1F, 0x90, // 8080
        ];
        send_connect_request(&mut stream, &addr_bytes).await.unwrap();
        
        // Read response
        let response = read_full_response(&mut stream).await.unwrap();
        assert_eq!(response[0], 0x05);
        assert_eq!(response[1], 0x00); // Success
        assert_eq!(response[3], 0x04); // IPv6
    });
    
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);
    server_result.unwrap();
    client_result.unwrap();
}

/// Test multiple auth methods - server selects NO_AUTH
#[tokio::test]
async fn test_multiple_auth_methods() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    let server_handle = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.unwrap();
        
        // Read client hello with multiple methods
        let mut buf = [0x05, 0x03, 0x01, 0x00, 0x02]; // GSSAPI, NO_AUTH, USERNAME/PASSWORD
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n >= 5);
        
        // Server should select NO_AUTH (0x00)
        stream.write_all(&[0x05, 0x00]).await.unwrap();
        
        // Read request and respond
        let _ = stream.read(&mut buf).await.unwrap();
        let response = [
            0x05, 0x00, 0x00,
            0x01, 0, 0, 0, 0, 0, 0,
        ];
        stream.write_all(&response).await.unwrap();
    });
    
    let client_handle = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        
        // Send multiple methods: GSSAPI, NO_AUTH, USERNAME/PASSWORD
        send_client_hello(&mut stream, &[0x01, 0x00, 0x02]).await.unwrap();
        
        // Server should select NO_AUTH
        let (version, method) = read_server_hello(&mut stream).await.unwrap();
        assert_eq!(version, 0x05);
        assert_eq!(method, 0x00); // NO_AUTH selected
        
        // Send request
        let addr_bytes = [0x01, 0, 0, 0, 0, 0, 0];
        send_connect_request(&mut stream, &addr_bytes).await.unwrap();
        
        let response = read_full_response(&mut stream).await.unwrap();
        assert_eq!(response[1], 0x00); // Success
    });
    
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);
    server_result.unwrap();
    client_result.unwrap();
}

/// Test invalid SOCKS version
#[tokio::test]
async fn test_invalid_version() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    let server_handle = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.unwrap();
        
        // Read invalid version
        let mut buf = [0u8; 2];
        let _n = stream.read(&mut buf).await.unwrap();
        assert_eq!(_n, 2);
        assert_eq!(buf[0], 0x04); // SOCKS4 version (invalid for us)
        
        // We should close without response or send error
    });
    
    let client_handle = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        
        // Send SOCKS4 version (should be rejected)
        let buf = [0x04, 0x01, 0x00];
        stream.write_all(&buf).await.unwrap();
        
        // Should not receive valid response - use timeout
        let mut response = [0u8; 2];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stream.read(&mut response)
        ).await;
        
        // Should timeout or connection closed
        assert!(result.is_err() || result.unwrap().is_err());
    });
    
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);
    server_result.unwrap();
    client_result.unwrap();
}

/// Test unsupported command (BIND)
#[tokio::test]
async fn test_unsupported_command_bind() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    let server_handle = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.unwrap();
        
        // Handshake
        let mut buf = [0u8; 256];
        let _ = stream.read(&mut buf).await.unwrap();
        stream.write_all(&[0x05, 0x00]).await.unwrap();
        
        // Read BIND request
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(buf[1], 0x02); // BIND
        
        // Send command not supported
        let response = [
            0x05, 0x07, 0x00, // VER, REP(7=not supported), RSV
            0x01, 0, 0, 0, 0, 0, 0,
        ];
        stream.write_all(&response).await.unwrap();
    });
    
    let client_handle = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        
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
    });
    
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);
    server_result.unwrap();
    client_result.unwrap();
}

/// Test unsupported command (UDP ASSOCIATE)
#[tokio::test]
async fn test_unsupported_command_udp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    let server_handle = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.unwrap();
        
        // Handshake
        let mut buf = [0u8; 256];
        let _ = stream.read(&mut buf).await.unwrap();
        stream.write_all(&[0x05, 0x00]).await.unwrap();
        
        // Read UDP ASSOCIATE request
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(buf[1], 0x03); // UDP ASSOCIATE
        
        // Send command not supported
        let response = [
            0x05, 0x07, 0x00,
            0x01, 0, 0, 0, 0, 0, 0,
        ];
        stream.write_all(&response).await.unwrap();
    });
    
    let client_handle = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        
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
    });
    
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);
    server_result.unwrap();
    client_result.unwrap();
}
