pub mod protocol;

use protocol::{
    AuthMethod, ClientHello, ReplyCode, ServerHello, SocksAddress, SocksCommand, SocksError,
    SocksRequest, SocksResponse, SOCKS_VERSION,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Duration};

// ============================================================================
// Configuration
// ============================================================================

/// Server configuration with sensible defaults
pub struct ServerConfig {
    /// Maximum number of authentication methods accepted from a client
    pub max_auth_methods: usize,
    /// Timeout for reading from client (prevents Slowloris attacks)
    pub client_read_timeout: Duration,
    /// Timeout for connecting to remote servers
    pub connect_timeout: Duration,
    /// Timeout for DNS resolution
    pub dns_timeout: Duration,
    /// Total connection timeout
    pub connection_timeout: Duration,
    /// Maximum concurrent connections
    pub max_concurrent_connections: usize,
    /// Maximum connections per IP address
    pub max_connections_per_ip: usize,
    /// Allow connections to private/reserved IP ranges (DANGEROUS — enables SSRF)
    pub allow_private_destinations: bool,
    /// Timeout for graceful shutdown
    pub shutdown_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_auth_methods: 128,
            client_read_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            dns_timeout: Duration::from_secs(5),
            connection_timeout: Duration::from_secs(120),
            max_concurrent_connections: 10_000,
            max_connections_per_ip: 100,
            allow_private_destinations: false,
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

// ============================================================================
// Address validation (SSRF protection)
// ============================================================================

/// Check if an IP address is in a private, reserved, or otherwise non-public range.
///
/// Used to prevent SSRF attacks where a client requests the proxy to connect
/// to internal network resources (localhost, cloud metadata endpoints, etc.).
fn is_private_or_reserved(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_or_reserved_v4(v4),
        IpAddr::V6(v6) => is_private_or_reserved_v6(v6),
    }
}

fn is_private_or_reserved_v4(v4: &Ipv4Addr) -> bool {
    let octets = v4.octets();
    v4.is_loopback()                                        // 127.0.0.0/8
        || v4.is_private()                                  // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()                               // 169.254.0.0/16
        || v4.is_broadcast()                                // 255.255.255.255
        || v4.is_unspecified()                              // 0.0.0.0
        || v4.is_documentation()                            // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || (octets[0] == 100 && (octets[1] & 0xC0) == 64)  // Shared/CGNAT 100.64.0.0/10
        || (octets[0] == 198 && (octets[1] & 0xFE) == 18)  // Benchmarking 198.18.0.0/15
        || octets[0] >= 240                                 // Reserved 240.0.0.0/4 + broadcast
        || (octets[0] == 0)                                 // "This network" 0.0.0.0/8
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) // IETF protocol 192.0.0.0/24
}

fn is_private_or_reserved_v6(v6: &Ipv6Addr) -> bool {
    let seg = v6.segments();
    v6.is_loopback()                            // ::1
        || v6.is_unspecified()                  // ::
        || (seg[0] & 0xfe00) == 0xfc00         // Unique local fc00::/7
        || (seg[0] & 0xffc0) == 0xfe80         // Link-local fe80::/10
        || v6.to_ipv4_mapped()                  // IPv4-mapped ::ffff:x.x.x.x
            .is_some_and(|v4| is_private_or_reserved_v4(&v4))
}

// ============================================================================
// Connection tracking and rate limiting
// ============================================================================

/// Tracks active connections for rate limiting.
///
/// Uses `std::sync::Mutex` (not tokio) for the per-IP map because the lock
/// is held for nanoseconds (just an integer increment/decrement). This also
/// allows synchronous release in `Drop`, eliminating the need for
/// `tokio::spawn` during cleanup.
struct ConnectionTracker {
    ip_counts: StdMutex<HashMap<IpAddr, usize>>,
    max_per_ip: usize,
    semaphore: Arc<Semaphore>,
}

impl ConnectionTracker {
    fn new(max_per_ip: usize, max_total: usize) -> Self {
        Self {
            ip_counts: StdMutex::new(HashMap::new()),
            max_per_ip,
            semaphore: Arc::new(Semaphore::new(max_total)),
        }
    }

    /// Try to acquire a permit for a new connection from the given IP.
    ///
    /// Acquires the semaphore permit atomically first (total limit),
    /// then checks the per-IP limit under a std mutex. This eliminates
    /// the TOCTOU race from the previous implementation.
    fn try_acquire(&self, ip: IpAddr) -> Option<ConnectionPermit> {
        // Acquire semaphore permit (atomic, no race condition)
        let permit = Arc::clone(&self.semaphore).try_acquire_owned().ok()?;

        // Check and increment per-IP count
        let mut counts = self.ip_counts.lock().unwrap_or_else(|e| e.into_inner());
        let count = counts.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            // permit is dropped here, automatically releasing the semaphore slot
            return None;
        }
        *count += 1;

        Some(ConnectionPermit { _permit: permit })
    }

    /// Release the per-IP counter. Called synchronously from `ConnectionGuard::drop`.
    fn release_ip(&self, ip: IpAddr) {
        let mut counts = self.ip_counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = counts.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&ip);
            }
        }
    }
}

/// Holds the semaphore permit. Dropped automatically when the guard is dropped.
struct ConnectionPermit {
    _permit: OwnedSemaphorePermit,
}

/// RAII guard — releases per-IP count synchronously and semaphore permit
/// via `Drop` of the inner `ConnectionPermit`. No `tokio::spawn` needed.
struct ConnectionGuard {
    tracker: Arc<ConnectionTracker>,
    ip: IpAddr,
    _permit: ConnectionPermit,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.tracker.release_ip(self.ip);
        // _permit is dropped here → OwnedSemaphorePermit released
    }
}

// ============================================================================
// Error mapping
// ============================================================================

/// Map TCP connection errors to SOCKS reply codes per RFC 1928.
fn map_connect_error(err: std::io::Error) -> SocksError {
    use std::io::ErrorKind;

    match err.kind() {
        ErrorKind::ConnectionRefused => SocksError::ConnectionRefused,
        ErrorKind::NetworkUnreachable => SocksError::NetworkUnreachable,
        ErrorKind::HostUnreachable => SocksError::HostUnreachable,
        ErrorKind::TimedOut => SocksError::TtlExpired,
        ErrorKind::PermissionDenied => SocksError::ConnectionNotAllowed,
        _ => SocksError::InvalidRequest,
    }
}

// ============================================================================
// Address resolution
// ============================================================================

/// Resolve a `SocksAddress` to a `SocketAddr` with SSRF protection.
///
/// For domain names, performs DNS lookup with a configurable timeout.
/// After resolution, all addresses are checked against private/reserved
/// ranges (unless `allow_private_destinations` is set).
async fn resolve_address(
    address: &SocksAddress,
    config: &ServerConfig,
) -> Result<SocketAddr, SocksError> {
    match address {
        SocksAddress::Ipv4(ip, port) => {
            let addr = SocketAddr::new(IpAddr::V4(*ip), *port);
            if !config.allow_private_destinations && is_private_or_reserved(&addr.ip()) {
                return Err(SocksError::ConnectionNotAllowed);
            }
            Ok(addr)
        }
        SocksAddress::Ipv6(ip, port) => {
            let addr = SocketAddr::new(IpAddr::V6(*ip), *port);
            if !config.allow_private_destinations && is_private_or_reserved(&addr.ip()) {
                return Err(SocksError::ConnectionNotAllowed);
            }
            Ok(addr)
        }
        SocksAddress::Domain(domain, port) => {
            // DNS lookup with timeout to prevent hanging on slow resolvers
            let addrs = timeout(
                config.dns_timeout,
                tokio::net::lookup_host((domain.as_str(), *port)),
            )
            .await
            .map_err(|_| SocksError::TtlExpired)?
            .map_err(|_| SocksError::HostUnreachable)?;

            // Find the first address that passes the private-range check
            for addr in addrs {
                if config.allow_private_destinations || !is_private_or_reserved(&addr.ip()) {
                    return Ok(addr);
                }
            }
            // All resolved addresses were private/reserved
            Err(SocksError::ConnectionNotAllowed)
        }
    }
}

// ============================================================================
// Shutdown signal
// ============================================================================

/// Wait for a shutdown signal (SIGINT on all platforms, SIGTERM on Unix).
#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received SIGINT, initiating graceful shutdown...");
        }
        _ = sigterm.recv() => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown...");
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to register Ctrl+C handler");
    tracing::info!("Received SIGINT, initiating graceful shutdown...");
}

// ============================================================================
// Connection handler
// ============================================================================

/// SOCKS5 server connection handler
struct Connection {
    socket: TcpStream,
    remote_peer: SocketAddr,
    config: Arc<ServerConfig>,
}

impl Connection {
    fn new(socket: TcpStream, remote_peer: SocketAddr, config: Arc<ServerConfig>) -> Self {
        Self {
            socket,
            remote_peer,
            config,
        }
    }

    /// Process a single SOCKS5 connection
    #[tracing::instrument(
        name = "Connection::process",
        level = "debug",
        skip(self),
        fields(remote_peer = %self.remote_peer.ip()),
    )]
    async fn process(self) -> Result<(), SocksError> {
        let config = Arc::clone(&self.config);

        tokio::time::timeout(config.connection_timeout, async {
            tracing::debug!("Session start");

            let (mut read_half, mut write_half) = self.socket.into_split();

            // Step 1: Read client hello
            let client_hello = Self::read_client_hello(&mut read_half, &config).await?;
            tracing::debug!(
                methods = ?client_hello.methods.iter().map(|m| m.0).collect::<Vec<_>>(),
                "Received client hello"
            );

            // Step 2: Select authentication method (NO_AUTH only)
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
            let request = Self::read_request(&mut read_half, &config).await?;
            tracing::debug!(
                command = request.command as u8,
                address = ?request.address,
                "Received SOCKS request"
            );

            // Step 5: Process request and establish connection to target
            let result = Self::process_request(&request, &config).await;

            match result {
                Ok((response, Some(remote_stream))) => {
                    tracing::debug!(reply = response.reply as u8, "Sending SOCKS response");
                    Self::send_response(&mut write_half, &response).await?;

                    tracing::debug!("Starting data relay");
                    let mut client_stream = read_half
                        .reunite(write_half)
                        .map_err(|_| SocksError::InvalidRequest)?;

                    Self::relay_data(&mut client_stream, remote_stream).await;
                }
                Ok((response, None)) => {
                    tracing::debug!(reply = response.reply as u8, "Sending error response");
                    Self::send_response(&mut write_half, &response).await?;
                }
                Err(e) => {
                    let reply_code = match &e {
                        SocksError::ConnectionRefused => ReplyCode::ConnectionRefused,
                        SocksError::NetworkUnreachable => ReplyCode::NetworkUnreachable,
                        SocksError::HostUnreachable => ReplyCode::HostUnreachable,
                        SocksError::TtlExpired => ReplyCode::TtlExpired,
                        SocksError::ConnectionNotAllowed => ReplyCode::ConnectionNotAllowed,
                        _ => ReplyCode::GeneralFailure,
                    };
                    let response =
                        SocksResponse::new(reply_code, Self::get_unspec_address());
                    tracing::debug!(reply = response.reply as u8, "Sending error response");
                    Self::send_response(&mut write_half, &response).await?;
                }
            }

            tracing::debug!("Session end");
            Ok(())
        })
        .await
        .map_err(|_| {
            SocksError::IoError(std::io::ErrorKind::TimedOut, "Connection timeout".into())
        })?
    }

    /// Read client hello message with timeout.
    async fn read_client_hello<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        config: &ServerConfig,
    ) -> Result<ClientHello, SocksError> {
        timeout(config.client_read_timeout, async {
            let version = reader.read_u8().await?;
            if version != SOCKS_VERSION {
                return Err(SocksError::InvalidVersion);
            }

            let nmethods = reader.read_u8().await? as usize;
            if nmethods == 0 {
                return Err(SocksError::NoAuthMethods);
            }
            if nmethods > config.max_auth_methods {
                return Err(SocksError::InvalidRequest);
            }

            let mut methods = Vec::with_capacity(nmethods);
            for _ in 0..nmethods {
                let method = reader.read_u8().await?;
                methods.push(AuthMethod(method));
            }

            Ok(ClientHello { version, methods })
        })
        .await
        .map_err(|_| {
            SocksError::IoError(
                std::io::ErrorKind::TimedOut,
                "Client read timeout".into(),
            )
        })?
    }

    /// Select authentication method from client's list
    fn select_auth_method(client_hello: &ClientHello) -> AuthMethod {
        if client_hello
            .methods
            .iter()
            .any(|m| m.0 == AuthMethod::NO_AUTH.0)
        {
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

    /// Read SOCKS request with timeout.
    async fn read_request<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        config: &ServerConfig,
    ) -> Result<SocksRequest, SocksError> {
        timeout(config.client_read_timeout, SocksRequest::read_from(reader))
            .await
            .map_err(|_| {
                SocksError::IoError(
                    std::io::ErrorKind::TimedOut,
                    "Client read timeout".into(),
                )
            })?
    }

    /// Process SOCKS request and optionally establish connection to target.
    ///
    /// Returns `(response, Option<remote_stream>)`.
    async fn process_request(
        request: &SocksRequest,
        config: &ServerConfig,
    ) -> Result<(SocksResponse, Option<TcpStream>), SocksError> {
        match request.command {
            SocksCommand::Connect => {
                let target_addr = resolve_address(&request.address, config).await?;

                tracing::debug!(target = %target_addr, "Connecting to target server");

                let remote_stream =
                    match timeout(config.connect_timeout, TcpStream::connect(target_addr)).await {
                        Ok(Ok(stream)) => {
                            tracing::debug!("Successfully connected to target");
                            stream
                        }
                        Ok(Err(err)) => {
                            let socks_error = map_connect_error(err);
                            tracing::debug!(error = %socks_error, "Connection failed");
                            let reply_code = match &socks_error {
                                SocksError::ConnectionRefused => ReplyCode::ConnectionRefused,
                                SocksError::NetworkUnreachable => ReplyCode::NetworkUnreachable,
                                SocksError::HostUnreachable => ReplyCode::HostUnreachable,
                                SocksError::TtlExpired => ReplyCode::TtlExpired,
                                SocksError::ConnectionNotAllowed => {
                                    ReplyCode::ConnectionNotAllowed
                                }
                                _ => ReplyCode::GeneralFailure,
                            };
                            return Ok((
                                SocksResponse::new(reply_code, Self::get_unspec_address()),
                                None,
                            ));
                        }
                        Err(_) => {
                            tracing::debug!("Connection timed out");
                            return Ok((
                                SocksResponse::new(
                                    ReplyCode::TtlExpired,
                                    Self::get_unspec_address(),
                                ),
                                None,
                            ));
                        }
                    };

                // Return unspecified address to avoid leaking internal network topology
                let bind_addr = Self::get_unspec_address();

                Ok((
                    SocksResponse::new(ReplyCode::Success, bind_addr),
                    Some(remote_stream),
                ))
            }
            SocksCommand::Bind | SocksCommand::UdpAssociate => Ok((
                SocksResponse::new(ReplyCode::CommandNotSupported, Self::get_unspec_address()),
                None,
            )),
        }
    }

    fn get_unspec_address() -> SocksAddress {
        SocksAddress::Ipv4(Ipv4Addr::UNSPECIFIED, 0)
    }

    async fn send_response<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        response: &SocksResponse,
    ) -> Result<(), SocksError> {
        response.write_to(writer).await
    }

    /// Relay data between client and remote server bidirectionally.
    async fn relay_data<C, R>(client: &mut C, remote: R)
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut remote_ref = remote;

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

// ============================================================================
// Server entry points
// ============================================================================

/// Run the SOCKS5 server on the default port (1080) with default config.
#[tracing::instrument(name = "server")]
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    run_with_config(1080, ServerConfig::default()).await
}

/// Run the SOCKS5 server on a specific port with default config.
#[tracing::instrument(name = "server", skip())]
pub async fn run_on_port(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    run_with_config(port, ServerConfig::default()).await
}

/// Run the SOCKS5 server on a specific port with the given configuration.
#[tracing::instrument(name = "server", skip(config))]
pub async fn run_with_config(
    port: u16,
    config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("SOCKS5 server listening on {}", addr);

    let config = Arc::new(config);
    let mut join_set = tokio::task::JoinSet::<Result<(), SocksError>>::new();

    let tracker = Arc::new(ConnectionTracker::new(
        config.max_connections_per_ip,
        config.max_concurrent_connections,
    ));

    let shutdown_timeout = config.shutdown_timeout;

    // Pin the shutdown signal future so it can be polled repeatedly in select!
    let mut shutdown = std::pin::pin!(wait_for_shutdown_signal());

    loop {
        tokio::select! {
            // Accept new connections
            result = listener.accept() => {
                match result {
                    Ok((socket, remote_peer)) => {
                        let client_ip = remote_peer.ip();

                        // Check connection limits (semaphore + per-IP, no race condition)
                        let permit = match tracker.try_acquire(client_ip) {
                            Some(p) => p,
                            None => {
                                tracing::warn!(ip = %client_ip, "Connection limit exceeded, rejecting");
                                drop(socket);
                                continue;
                            }
                        };

                        if let Err(e) = socket.set_nodelay(true) {
                            tracing::warn!("Failed to set TCP_NODELAY: {}", e);
                        }

                        tracing::debug!(%remote_peer, "Accepted connection");

                        let conn_tracker = Arc::clone(&tracker);
                        let conn_config = Arc::clone(&config);

                        join_set.spawn(async move {
                            // RAII guard: releases per-IP count + semaphore on drop
                            let _guard = ConnectionGuard {
                                tracker: conn_tracker,
                                ip: client_ip,
                                _permit: permit,
                            };

                            Connection::new(socket, remote_peer, conn_config)
                                .process()
                                .await
                        });
                    }
                    Err(err) => {
                        tracing::error!("Accept error: {}", err);
                    }
                }
            },
            // Drain completed tasks to prevent memory accumulation
            Some(result) = join_set.join_next() => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => tracing::debug!("Connection error: {}", err),
                    Err(err) => tracing::debug!("Task panic: {}", err),
                }
            },
            // Shutdown signal
            _ = &mut shutdown => {
                break;
            }
        }
    }

    // Graceful shutdown with timeout
    let active_connections = join_set.len();
    tracing::info!(
        "Waiting for {} active connections to close (timeout: {:?})...",
        active_connections,
        shutdown_timeout
    );

    match tokio::time::timeout(shutdown_timeout, async {
        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(err)) => tracing::debug!("Connection completed with error: {}", err),
                Err(err) => tracing::debug!("Task cancelled: {}", err),
            }
        }
    })
    .await
    {
        Ok(()) => {
            tracing::info!("All {} connections closed gracefully", active_connections);
        }
        Err(_) => {
            tracing::warn!(
                "Timeout waiting for connections to close, aborting {} tasks...",
                join_set.len()
            );
            join_set.abort_all();
            // Give aborted tasks a moment to run Drop handlers
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    tracing::info!("SOCKS5 server shutdown complete");
    Ok(())
}
