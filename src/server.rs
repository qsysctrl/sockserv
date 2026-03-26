pub mod protocol;

use protocol::{
    AuthMethod, ClientHello, ReplyCode, ServerHello, SocksAddress, SocksCommand, SocksError,
    SocksRequest, SocksResponse, SOCKS_VERSION,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{timeout, Duration};

/// Maximum number of authentication methods we accept
const MAX_AUTH_METHODS: usize = 128;

/// Timeout for reading from client (prevents Slowloris attacks)
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for connecting to remote servers (prevents hanging on slow/unreachable hosts)
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum concurrent connections (prevents DoS)
const MAX_CONCURRENT_CONNECTIONS: usize = 10_000;

/// Maximum connections per IP address (prevents single-IP DoS)
const MAX_CONNECTIONS_PER_IP: usize = 100;

/// Tracks active connections for rate limiting
struct ConnectionTracker {
    ip_counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_ip: usize,
    semaphore: Arc<Semaphore>,
}

impl ConnectionTracker {
    fn new(max_per_ip: usize, max_total: usize) -> Self {
        Self {
            ip_counts: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip,
            semaphore: Arc::new(Semaphore::new(max_total)),
        }
    }

    /// Try to acquire a permit for a new connection from the given IP
    /// Returns true if the connection is allowed, false if limits are exceeded
    async fn try_acquire(&self, ip: IpAddr) -> bool {
        // Check total connection limit first (fast path)
        if self.semaphore.available_permits() == 0 {
            return false;
        }

        // Check and update per-IP limit
        let mut counts = self.ip_counts.lock().await;
        let count = counts.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            return false;
        }
        *count += 1;
        true
    }

    /// Release a permit when a connection closes
    async fn release(&self, ip: IpAddr) {
        let mut counts = self.ip_counts.lock().await;
        if let Some(count) = counts.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&ip);
            }
        }
    }
}

/// RAII guard to ensure connection tracker is updated when connection closes
struct ConnectionGuard {
    tracker: Arc<ConnectionTracker>,
    ip: IpAddr,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        // Clone the data we need for the async release
        let tracker = Arc::clone(&self.tracker);
        let ip = self.ip;

        // Spawn a task to release the permit (non-blocking)
        // Since Drop is synchronous, we spawn an async task
        tokio::spawn(async move {
            tracker.release(ip).await;
        });
    }
}

/// Map TCP connection errors to SOCKS reply codes
///
/// This function analyzes the underlying IO error kind and maps it to the
/// appropriate SOCKS5 reply code according to RFC 1928 semantics.
fn map_connect_error(err: std::io::Error) -> SocksError {
    use std::io::ErrorKind;

    match err.kind() {
        ErrorKind::ConnectionRefused => SocksError::ConnectionRefused,
        ErrorKind::NetworkUnreachable => SocksError::NetworkUnreachable,
        ErrorKind::HostUnreachable => SocksError::HostUnreachable,
        ErrorKind::TimedOut => SocksError::TtlExpired,
        ErrorKind::PermissionDenied => SocksError::ConnectionNotAllowed,
        // For other errors, use invalid request as general failure
        _ => SocksError::InvalidRequest,
    }
}

/// Resolve a SocksAddress to a SocketAddr
///
/// For IPv4 and IPv6 addresses, returns the address directly.
/// For domain names, performs DNS lookup and returns the first resolved address.
async fn resolve_address(address: &SocksAddress) -> Result<SocketAddr, SocksError> {
    match address {
        SocksAddress::Ipv4(ip, port) => Ok(SocketAddr::new(IpAddr::V4(*ip), *port)),
        SocksAddress::Ipv6(ip, port) => Ok(SocketAddr::new(IpAddr::V6(*ip), *port)),
        SocksAddress::Domain(domain, port) => {
            // DNS lookup using tokio's async resolver
            let mut addrs = tokio::net::lookup_host((domain.as_str(), *port))
                .await
                .map_err(|_| SocksError::HostUnreachable)?;

            // Return the first resolved address
            addrs.next().ok_or(SocksError::HostUnreachable)
        }
    }
}

/// SOCKS5 server connection handler
struct Connection {
    socket: TcpStream,
    remote_peer: SocketAddr,
}

impl Connection {
    fn new(socket: TcpStream, remote_peer: SocketAddr) -> Self {
        Self {
            socket,
            remote_peer,
        }
    }

    /// Process a single SOCKS5 connection
    #[tracing::instrument(
        name = "Connection::process",
        level = "debug",
        skip(self),
        fields(
            remote_peer = %self.remote_peer.ip(),
        ),
    )]
    async fn process(self) -> Result<(), SocksError> {
        tracing::debug!("Session start");

        // Perform handshake
        let (mut read_half, mut write_half) = self.socket.into_split();

        // Step 1: Read client hello
        let client_hello = Self::read_client_hello(&mut read_half).await?;
        tracing::debug!(
            methods = ?client_hello.methods.iter().map(|m| m.0).collect::<Vec<_>>(),
            "Received client hello"
        );

        // Step 2: Select authentication method (we only support NO_AUTH)
        let selected_method = Self::select_auth_method(&client_hello);
        tracing::debug!(method = selected_method.0, "Selected auth method");

        // Step 3: Send server hello
        Self::send_server_hello(&mut write_half, selected_method).await?;

        // If no acceptable methods, close connection
        if selected_method == AuthMethod::NO_ACCEPTABLE {
            tracing::info!("No acceptable auth methods, closing connection");
            return Ok(());
        }

        // Step 4: Read SOCKS request
        let request = Self::read_request(&mut read_half).await?;
        tracing::debug!(
            command = request.command as u8,
            address = ?request.address,
            "Received SOCKS request"
        );

        // Step 5: Process request and establish connection to target
        let result = Self::process_request(&request, &self.remote_peer).await;

        match result {
            Ok((response, Some(remote_stream))) => {
                // Successful connection - send response and start relay
                tracing::debug!(reply = response.reply as u8, "Sending SOCKS response");
                Self::send_response(&mut write_half, &response).await?;

                tracing::debug!("Starting data relay");
                // Recombine the client socket halves for bidirectional relay
                let mut client_stream = read_half.reunite(write_half)
                    .map_err(|_| SocksError::InvalidRequest)?;

                Self::relay_data(&mut client_stream, remote_stream).await;
            }
            Ok((response, None)) => {
                // Failed connection - send error response and close
                tracing::debug!(reply = response.reply as u8, "Sending error response");
                Self::send_response(&mut write_half, &response).await?;
            }
            Err(e) => {
                // Error during request processing
                let reply_code = match &e {
                    SocksError::ConnectionRefused => ReplyCode::ConnectionRefused,
                    SocksError::NetworkUnreachable => ReplyCode::NetworkUnreachable,
                    SocksError::HostUnreachable => ReplyCode::HostUnreachable,
                    SocksError::TtlExpired => ReplyCode::TtlExpired,
                    SocksError::ConnectionNotAllowed => ReplyCode::ConnectionNotAllowed,
                    _ => ReplyCode::GeneralFailure,
                };
                let response = SocksResponse::new(reply_code, Self::get_unspec_address());
                tracing::debug!(reply = response.reply as u8, "Sending error response");
                Self::send_response(&mut write_half, &response).await?;
            }
        }

        tracing::debug!("Session end");
        Ok(())
    }

    /// Read client hello message with timeout to prevent Slowloris attacks
    async fn read_client_hello<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<ClientHello, SocksError> {
        timeout(CLIENT_READ_TIMEOUT, async {
            // Read version byte
            let version = reader.read_u8().await?;
            if version != SOCKS_VERSION {
                return Err(SocksError::InvalidVersion);
            }

            // Read number of methods
            let nmethods = reader.read_u8().await? as usize;
            if nmethods == 0 {
                return Err(SocksError::NoAuthMethods);
            }

            // CRITICAL FIX: Validate BEFORE allocation to prevent DoS
            if nmethods > MAX_AUTH_METHODS {
                return Err(SocksError::InvalidRequest);
            }

            // PERF FIX: Read methods one-by-one to avoid unnecessary allocation
            let mut methods = Vec::with_capacity(nmethods);
            for _ in 0..nmethods {
                let method = reader.read_u8().await?;
                methods.push(AuthMethod(method));
            }

            Ok(ClientHello {
                version,
                methods,
            })
        })
        .await
        .map_err(|_| SocksError::IoError("Client read timeout".into()))?
    }

    /// Select authentication method from client's list
    fn select_auth_method(client_hello: &ClientHello) -> AuthMethod {
        // We only support NO_AUTH (0x00)
        if client_hello.methods.iter().any(|m| m.0 == AuthMethod::NO_AUTH.0) {
            AuthMethod::NO_AUTH
        } else {
            AuthMethod::NO_ACCEPTABLE
        }
    }

    /// Send server hello message
    async fn send_server_hello<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        method: AuthMethod,
    ) -> Result<(), SocksError> {
        let hello = ServerHello::new(method);
        hello.write_to(writer).await
    }

    /// Read SOCKS request with timeout to prevent Slowloris attacks
    async fn read_request<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<SocksRequest, SocksError> {
        timeout(CLIENT_READ_TIMEOUT, async {
            SocksRequest::read_from(reader).await
        })
        .await
        .map_err(|_| SocksError::IoError("Client read timeout".into()))?
    }

    /// Process SOCKS request and create connection to target server
    ///
    /// Returns a tuple of (response, remote_stream):
    /// - On success: (Success response with bind address, Some(remote TcpStream))
    /// - On failure: (Error response, None)
    ///
    /// This function handles:
    /// - Address resolution (IPv4, IPv6, domain names)
    /// - TCP connection establishment with timeout
    /// - Error mapping to appropriate SOCKS reply codes
    async fn process_request(
        request: &SocksRequest,
        _remote_peer: &SocketAddr,
    ) -> Result<(SocksResponse, Option<TcpStream>), SocksError> {
        match request.command {
            SocksCommand::Connect => {
                // Resolve the target address to a SocketAddr
                let target_addr = resolve_address(&request.address).await?;

                tracing::debug!(
                    target = %target_addr,
                    "Connecting to target server"
                );

                // Connect with timeout to prevent hanging on unreachable hosts
                let remote_stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(target_addr)).await {
                    Ok(Ok(stream)) => {
                        tracing::debug!("Successfully connected to target");
                        stream
                    }
                    Ok(Err(err)) => {
                        // Map the connection error to a SOCKS error
                        let socks_error = map_connect_error(err);
                        tracing::debug!(
                            error = %socks_error,
                            "Connection failed"
                        );
                        let reply_code = match &socks_error {
                            SocksError::ConnectionRefused => ReplyCode::ConnectionRefused,
                            SocksError::NetworkUnreachable => ReplyCode::NetworkUnreachable,
                            SocksError::HostUnreachable => ReplyCode::HostUnreachable,
                            SocksError::TtlExpired => ReplyCode::TtlExpired,
                            SocksError::ConnectionNotAllowed => ReplyCode::ConnectionNotAllowed,
                            _ => ReplyCode::GeneralFailure,
                        };
                        return Ok((
                            SocksResponse::new(reply_code, Self::get_unspec_address()),
                            None,
                        ));
                    }
                    Err(_) => {
                        // Timeout occurred
                        tracing::debug!("Connection timed out");
                        return Ok((
                            SocksResponse::new(ReplyCode::TtlExpired, Self::get_unspec_address()),
                            None,
                        ));
                    }
                };

                // Get the local address of our connection to the target
                // This will be used as the bind address in the response
                let bind_addr = remote_stream
                    .local_addr()
                    .map(|addr| match addr {
                        SocketAddr::V4(v4) => SocksAddress::Ipv4(*v4.ip(), v4.port()),
                        SocketAddr::V6(v6) => SocksAddress::Ipv6(*v6.ip(), v6.port()),
                    })
                    .unwrap_or_else(|_| Self::get_unspec_address());

                Ok((
                    SocksResponse::new(ReplyCode::Success, bind_addr),
                    Some(remote_stream),
                ))
            }
            SocksCommand::Bind => {
                // BIND is not supported
                Ok((
                    SocksResponse::new(ReplyCode::CommandNotSupported, Self::get_unspec_address()),
                    None,
                ))
            }
            SocksCommand::UdpAssociate => {
                // UDP ASSOCIATE is not supported
                Ok((
                    SocksResponse::new(ReplyCode::CommandNotSupported, Self::get_unspec_address()),
                    None,
                ))
            }
        }
    }

    /// Get unspecified address based on what makes sense
    fn get_unspec_address() -> SocksAddress {
        SocksAddress::Ipv4(Ipv4Addr::UNSPECIFIED, 0)
    }

    /// Send SOCKS response
    async fn send_response<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        response: &SocksResponse,
    ) -> Result<(), SocksError> {
        response.write_to(writer).await
    }

    /// Relay data between client and remote server bidirectionally
    ///
    /// Uses tokio's copy_bidirectional for efficient data transfer.
    /// This function runs until either side closes the connection or an error occurs.
    async fn relay_data<C, R>(client: &mut C, remote: R)
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut remote_ref = remote;

        // Use copy_bidirectional for efficient relay
        // This copies data in both directions simultaneously
        let result = tokio::io::copy_bidirectional(&mut *client, &mut remote_ref).await;

        match result {
            Ok((client_to_remote, remote_to_client)) => {
                tracing::debug!(
                    bytes_client_to_remote = client_to_remote,
                    bytes_remote_to_client = remote_to_client,
                    "Relay completed"
                );
            }
            Err(err) => {
                tracing::debug!("Relay error: {}", err);
            }
        }
    }
}

/// Run the SOCKS5 server on the default port (1080)
#[tracing::instrument(name = "server")]
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    run_on_port(1080).await
}

/// Run the SOCKS5 server on a specific port
///
/// This function is used for both production and testing.
/// For tests, use a port in the range 10000+ to avoid conflicts.
#[tracing::instrument(name = "server", skip())]
pub async fn run_on_port(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("SOCKS5 server listening on {}", addr);

    let mut join_set = tokio::task::JoinSet::<Result<(), SocksError>>::new();

    // CRITICAL FIX: Connection rate limiting
    let tracker = Arc::new(ConnectionTracker::new(
        MAX_CONNECTIONS_PER_IP,
        MAX_CONCURRENT_CONNECTIONS,
    ));

    // Graceful shutdown configuration
    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

    // Setup SIGTERM handler (Unix only)
    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            // Accept new connections
            result = listener.accept() => {
                match result {
                    Ok((socket, remote_peer)) => {
                        // CRITICAL FIX: Check connection limits
                        let client_ip = remote_peer.ip();
                        if !tracker.try_acquire(client_ip).await {
                            tracing::warn!(
                                ip = %client_ip,
                                "Connection limit exceeded, rejecting"
                            );
                            drop(socket);
                            continue;
                        }

                        // PERF FIX: Set TCP_NODELAY for lower latency
                        if let Err(e) = socket.set_nodelay(true) {
                            tracing::warn!("Failed to set TCP_NODELAY: {}", e);
                        }

                        tracing::debug!(%remote_peer, "Accepted connection");

                        // Clone tracker for this connection
                        let conn_tracker = Arc::clone(&tracker);

                        join_set.spawn(async move {
                            // Create guard to ensure we release the permit when connection ends
                            let _guard = ConnectionGuard {
                                tracker: conn_tracker,
                                ip: client_ip,
                            };

                            Connection::new(socket, remote_peer).process().await
                        });
                    }
                    Err(err) => {
                        tracing::error!("Accept error: {}", err);
                    }
                }
            },
            // Handle SIGINT (Ctrl+C)
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Received SIGINT, initiating graceful shutdown...");
                break;
            }
            // Handle SIGTERM (Unix only)
            _ = sigterm.recv(), if cfg!(unix) => {
                tracing::info!("Received SIGTERM, initiating graceful shutdown...");
                break;
            }
        }
    }

    // Graceful shutdown with timeout
    let active_connections = join_set.len();
    tracing::info!("Waiting for {} active connections to close (timeout: {:?})...",
                   active_connections, SHUTDOWN_TIMEOUT);

    match tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    tracing::debug!("Connection completed with error: {}", err);
                }
                Err(err) => {
                    tracing::debug!("Task cancelled: {}", err);
                }
            }
        }
    }).await {
        Ok(()) => {
            tracing::info!("All {} connections closed gracefully", active_connections);
        }
        Err(_) => {
            tracing::warn!("Timeout waiting for connections to close, aborting {} tasks...",
                          join_set.len());
            join_set.abort_all();
            // Give aborted tasks a moment to clean up
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    tracing::info!("SOCKS5 server shutdown complete");
    Ok(())
}
