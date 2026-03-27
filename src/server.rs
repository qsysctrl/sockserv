pub mod protocol;

use protocol::{
    AuthMethod, AuthRequest, AuthResponse, ClientHello, ReplyCode, ServerHello, SocksAddress,
    SocksCommand, SocksError, SocksRequest, SocksResponse, UdpRelayHeader, SOCKS_VERSION,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Duration, Instant, Sleep};

// ============================================================================
// Configuration
// ============================================================================

/// Server configuration with sensible defaults.
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
    /// Optional username/password credentials. If `Some`, USERNAME_PASSWORD
    /// authentication (RFC 1929) is required. If `None`, NO_AUTH is used.
    pub credentials: Option<HashMap<String, String>>,
    /// Timeout for BIND command waiting for an incoming connection
    pub bind_timeout: Duration,
    /// Idle timeout for UDP ASSOCIATE relay
    pub udp_idle_timeout: Duration,
    /// Buffer size for UDP relay datagrams
    pub udp_buffer_size: usize,
    /// Maximum new connections accepted per second globally (0 = unlimited)
    pub connection_rate_limit: u32,
    /// Maximum requests per second per IP address (0 = unlimited)
    pub per_ip_rps: u32,
    /// Maximum bandwidth per connection in bytes/sec (0 = unlimited)
    pub bandwidth_per_connection: u64,
    /// Maximum total bandwidth in bytes/sec (0 = unlimited)
    pub bandwidth_total: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_auth_methods: 128,
            client_read_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            dns_timeout: Duration::from_secs(5),
            connection_timeout: Duration::from_secs(300),
            max_concurrent_connections: 10_000,
            max_connections_per_ip: 100,
            allow_private_destinations: false,
            shutdown_timeout: Duration::from_secs(30),
            credentials: None,
            bind_timeout: Duration::from_secs(60),
            udp_idle_timeout: Duration::from_secs(120),
            udp_buffer_size: 65535,
            connection_rate_limit: 0,
            per_ip_rps: 0,
            bandwidth_per_connection: 0,
            bandwidth_total: 0,
        }
    }
}

impl ServerConfig {
    /// Check credentials. Returns `true` if the username/password match.
    fn authenticate(&self, username: &str, password: &str) -> bool {
        match &self.credentials {
            Some(creds) => creds.get(username).is_some_and(|p| p == password),
            None => true,
        }
    }
}

// ============================================================================
// Address validation (SSRF protection)
// ============================================================================

fn is_private_or_reserved(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_or_reserved_v4(v4),
        IpAddr::V6(v6) => is_private_or_reserved_v6(v6),
    }
}

fn is_private_or_reserved_v4(v4: &Ipv4Addr) -> bool {
    let octets = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_unspecified()
        || v4.is_documentation()
        || (octets[0] == 100 && (octets[1] & 0xC0) == 64) // CGNAT 100.64.0.0/10
        || (octets[0] == 198 && (octets[1] & 0xFE) == 18) // Benchmarking 198.18.0.0/15
        || octets[0] >= 240                                 // Reserved 240.0.0.0/4
        || octets[0] == 0                                   // "This network" 0.0.0.0/8
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) // IETF protocol 192.0.0.0/24
}

fn is_private_or_reserved_v6(v6: &Ipv6Addr) -> bool {
    let seg = v6.segments();
    v6.is_loopback()
        || v6.is_unspecified()
        || (seg[0] & 0xfe00) == 0xfc00 // Unique local fc00::/7
        || (seg[0] & 0xffc0) == 0xfe80 // Link-local fe80::/10
        || v6
            .to_ipv4_mapped()
            .is_some_and(|v4| is_private_or_reserved_v4(&v4))
}

// ============================================================================
// Token bucket rate limiter
// ============================================================================

/// A simple token bucket for rate limiting.
/// Thread-safe via interior `StdMutex`.
struct TokenBucket {
    state: StdMutex<TokenBucketState>,
}

struct TokenBucketState {
    tokens: f64,
    capacity: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket.
    /// `capacity` is the burst size, `rate` is tokens added per second.
    fn new(capacity: f64, rate: f64) -> Self {
        Self {
            state: StdMutex::new(TokenBucketState {
                tokens: capacity,
                capacity,
                refill_rate: rate,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Try to consume `n` tokens. Returns `true` if allowed.
    fn try_consume(&self, n: f64) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.refill();
        if state.tokens >= n {
            state.tokens -= n;
            true
        } else {
            false
        }
    }

    /// Consume up to `n` tokens. Returns the number of tokens actually consumed (may be 0).
    fn consume_up_to(&self, n: f64) -> f64 {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.refill();
        let consumed = n.min(state.tokens).max(0.0);
        state.tokens -= consumed;
        consumed
    }

    /// Time until at least `n` tokens are available. Returns `Duration::ZERO` if already available.
    fn time_until(&self, n: f64) -> Duration {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let deficit = n - state.tokens;
        if deficit <= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(deficit / state.refill_rate)
        }
    }
}

impl TokenBucketState {
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }
}

// ============================================================================
// Per-IP rate limiter
// ============================================================================

/// Tracks per-IP request rates using token buckets.
struct IpRateLimiter {
    buckets: StdMutex<HashMap<IpAddr, Arc<TokenBucket>>>,
    rps: u32,
}

impl IpRateLimiter {
    fn new(rps: u32) -> Self {
        Self {
            buckets: StdMutex::new(HashMap::new()),
            rps,
        }
    }

    /// Check if an IP is allowed to make a request. Returns `true` if allowed.
    fn check(&self, ip: IpAddr) -> bool {
        if self.rps == 0 {
            return true;
        }
        let bucket = {
            let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(buckets.entry(ip).or_insert_with(|| {
                // Burst = 2x RPS to allow short spikes
                Arc::new(TokenBucket::new(self.rps as f64 * 2.0, self.rps as f64))
            }))
        };
        bucket.try_consume(1.0)
    }

    /// Remove stale entries (IPs with no active connections).
    /// Called periodically from the accept loop.
    fn cleanup(&self, active_ips: &HashMap<IpAddr, usize>) {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        buckets.retain(|ip, _| active_ips.contains_key(ip));
    }
}

// ============================================================================
// Bandwidth limiter
// ============================================================================

/// Global bandwidth limiter shared across all connections.
struct BandwidthLimiter {
    bucket: TokenBucket,
}

impl BandwidthLimiter {
    fn new(bytes_per_sec: u64) -> Self {
        // Burst = 1 second worth of bandwidth
        let bps = bytes_per_sec as f64;
        Self {
            bucket: TokenBucket::new(bps, bps),
        }
    }

    /// Consume up to `requested` bytes. Returns actual bytes allowed.
    fn consume(&self, requested: usize) -> usize {
        self.bucket.consume_up_to(requested as f64) as usize
    }

    /// Time until at least 1 byte is available.
    fn time_until_available(&self) -> Duration {
        self.bucket.time_until(1.0)
    }
}

/// Wraps an async stream with per-connection + global bandwidth throttling.
struct ThrottledStream<S> {
    inner: S,
    per_conn: Option<Arc<TokenBucket>>,
    global: Option<Arc<BandwidthLimiter>>,
    delay: Option<Pin<Box<Sleep>>>,
}

impl<S> ThrottledStream<S> {
    fn new(
        inner: S,
        per_conn_bps: u64,
        global: Option<Arc<BandwidthLimiter>>,
    ) -> Self {
        let per_conn = if per_conn_bps > 0 {
            let bps = per_conn_bps as f64;
            Some(Arc::new(TokenBucket::new(bps, bps)))
        } else {
            None
        };
        Self {
            inner,
            per_conn,
            global,
            delay: None,
        }
    }

    fn limit_bytes(&self, requested: usize) -> usize {
        let mut allowed = requested;

        if let Some(ref pc) = self.per_conn {
            let consumed = pc.consume_up_to(allowed as f64) as usize;
            allowed = consumed;
        }

        if let Some(ref g) = self.global {
            let consumed = g.consume(allowed);
            allowed = consumed;
        }

        allowed
    }

    fn min_wait_time(&self) -> Duration {
        let mut wait = Duration::ZERO;

        if let Some(ref pc) = self.per_conn {
            let t = pc.time_until(1.0);
            if t > wait {
                wait = t;
            }
        }

        if let Some(ref g) = self.global {
            let t = g.time_until_available();
            if t > wait {
                wait = t;
            }
        }

        wait
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ThrottledStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // If we're waiting on a delay, poll it first
        if let Some(ref mut delay) = this.delay {
            match delay.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    this.delay = None;
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // Check how many bytes we're allowed to read
        let remaining = buf.remaining();
        if remaining == 0 {
            return Poll::Ready(Ok(()));
        }

        let allowed = this.limit_bytes(remaining);
        if allowed == 0 {
            // Schedule a wake-up after a short wait
            let wait = this.min_wait_time().max(Duration::from_millis(1));
            this.delay = Some(Box::pin(tokio::time::sleep(wait)));
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        // Limit the buffer size to what we're allowed
        let mut limited_buf = buf.take(allowed);
        let before = limited_buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, &mut limited_buf);
        let after = limited_buf.filled().len();
        let bytes_read = after - before;

        // Advance the original buffer by however many bytes were read
        // We need to unsafe-advance buf because take() created a separate view
        if bytes_read > 0 {
            // The bytes were written into buf's underlying memory via limited_buf
            unsafe { buf.assume_init(buf.filled().len() + bytes_read) };
            buf.advance(bytes_read);
        }

        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ThrottledStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // If we're waiting on a delay, poll it first
        if let Some(ref mut delay) = this.delay {
            match delay.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    this.delay = None;
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let allowed = this.limit_bytes(buf.len());
        if allowed == 0 {
            let wait = this.min_wait_time().max(Duration::from_millis(1));
            this.delay = Some(Box::pin(tokio::time::sleep(wait)));
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        Pin::new(&mut this.inner).poll_write(cx, &buf[..allowed])
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ============================================================================
// Connection tracking and rate limiting
// ============================================================================

struct ConnectionTracker {
    ip_counts: StdMutex<HashMap<IpAddr, usize>>,
    max_per_ip: usize,
    semaphore: Arc<Semaphore>,
    ip_rate_limiter: IpRateLimiter,
    accept_rate: Option<TokenBucket>,
}

impl ConnectionTracker {
    fn new(max_per_ip: usize, max_total: usize, per_ip_rps: u32, accept_rate: u32) -> Self {
        Self {
            ip_counts: StdMutex::new(HashMap::new()),
            max_per_ip,
            semaphore: Arc::new(Semaphore::new(max_total)),
            ip_rate_limiter: IpRateLimiter::new(per_ip_rps),
            accept_rate: if accept_rate > 0 {
                // Burst = 2x rate for small spikes
                Some(TokenBucket::new(accept_rate as f64 * 2.0, accept_rate as f64))
            } else {
                None
            },
        }
    }

    /// Check global connection accept rate. Returns `true` if allowed.
    fn check_accept_rate(&self) -> bool {
        match &self.accept_rate {
            Some(bucket) => bucket.try_consume(1.0),
            None => true,
        }
    }

    /// Check per-IP request rate. Returns `true` if allowed.
    fn check_ip_rate(&self, ip: IpAddr) -> bool {
        self.ip_rate_limiter.check(ip)
    }

    fn try_acquire(&self, ip: IpAddr) -> Option<ConnectionPermit> {
        let permit = Arc::clone(&self.semaphore).try_acquire_owned().ok()?;
        let mut counts = self.ip_counts.lock().unwrap_or_else(|e| e.into_inner());
        let count = counts.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            return None;
        }
        *count += 1;
        Some(ConnectionPermit { _permit: permit })
    }

    fn release_ip(&self, ip: IpAddr) {
        let mut counts = self.ip_counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = counts.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&ip);
            }
        }
    }

    /// Periodically clean up stale per-IP rate limiter entries.
    fn cleanup_rate_limiters(&self) {
        let counts = self.ip_counts.lock().unwrap_or_else(|e| e.into_inner());
        self.ip_rate_limiter.cleanup(&counts);
    }
}

struct ConnectionPermit {
    _permit: OwnedSemaphorePermit,
}

struct ConnectionGuard {
    tracker: Arc<ConnectionTracker>,
    ip: IpAddr,
    _permit: ConnectionPermit,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.tracker.release_ip(self.ip);
    }
}

// ============================================================================
// Helpers
// ============================================================================

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

fn socks_error_to_reply(e: &SocksError) -> ReplyCode {
    match e {
        SocksError::ConnectionRefused => ReplyCode::ConnectionRefused,
        SocksError::NetworkUnreachable => ReplyCode::NetworkUnreachable,
        SocksError::HostUnreachable => ReplyCode::HostUnreachable,
        SocksError::TtlExpired => ReplyCode::TtlExpired,
        SocksError::ConnectionNotAllowed => ReplyCode::ConnectionNotAllowed,
        _ => ReplyCode::GeneralFailure,
    }
}

fn socket_addr_to_socks(addr: &SocketAddr) -> SocksAddress {
    match addr {
        SocketAddr::V4(v4) => SocksAddress::Ipv4(*v4.ip(), v4.port()),
        SocketAddr::V6(v6) => SocksAddress::Ipv6(*v6.ip(), v6.port()),
    }
}

/// Resolve a `SocksAddress` to a `SocketAddr` with SSRF protection and DNS timeout.
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
            let addrs = timeout(
                config.dns_timeout,
                tokio::net::lookup_host((domain.as_str(), *port)),
            )
            .await
            .map_err(|_| SocksError::TtlExpired)?
            .map_err(|_| SocksError::HostUnreachable)?;

            for addr in addrs {
                if config.allow_private_destinations || !is_private_or_reserved(&addr.ip()) {
                    return Ok(addr);
                }
            }
            Err(SocksError::ConnectionNotAllowed)
        }
    }
}

// ============================================================================
// Shutdown signal
// ============================================================================

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
// Request outcome (replaces the old (SocksResponse, Option<TcpStream>) tuple)
// ============================================================================

enum RequestOutcome {
    /// CONNECT succeeded: response + TCP stream to relay
    Connect(SocksResponse, TcpStream),
    /// BIND: first response (bound address) + listener awaiting one connection
    Bind(SocksResponse, tokio::net::TcpListener),
    /// UDP ASSOCIATE: response (relay address) + UDP socket
    UdpAssociate(SocksResponse, UdpSocket),
    /// Error / unsupported: single response, no further action
    Error(SocksResponse),
}

// ============================================================================
// Connection handler
// ============================================================================

struct Connection {
    socket: TcpStream,
    remote_peer: SocketAddr,
    config: Arc<ServerConfig>,
    global_bandwidth: Option<Arc<BandwidthLimiter>>,
}

impl Connection {
    fn new(
        socket: TcpStream,
        remote_peer: SocketAddr,
        config: Arc<ServerConfig>,
        global_bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> Self {
        Self {
            socket,
            remote_peer,
            config,
            global_bandwidth,
        }
    }

    #[tracing::instrument(
        name = "Connection::process",
        level = "debug",
        skip(self),
        fields(remote_peer = %self.remote_peer.ip()),
    )]
    async fn process(self) -> Result<(), SocksError> {
        let config = Arc::clone(&self.config);
        let global_bw = self.global_bandwidth.clone();
        let per_conn_bps = config.bandwidth_per_connection;
        let local_addr = self
            .socket
            .local_addr()
            .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));

        tokio::time::timeout(config.connection_timeout, async {
            tracing::debug!("Session start");

            let (mut read_half, mut write_half) = self.socket.into_split();

            // --- Handshake ---
            let client_hello = Self::read_client_hello(&mut read_half, &config).await?;
            tracing::debug!(
                methods = ?client_hello.methods.iter().map(|m| m.0).collect::<Vec<_>>(),
                "Received client hello"
            );

            let selected_method = Self::select_auth_method(&client_hello, &config);
            tracing::debug!(method = selected_method.0, "Selected auth method");

            Self::send_server_hello(&mut write_half, selected_method).await?;

            if selected_method == AuthMethod::NO_ACCEPTABLE {
                tracing::info!("No acceptable auth methods, closing connection");
                return Ok(());
            }

            // --- Username/Password subnegotiation (RFC 1929) ---
            if selected_method == AuthMethod::USERNAME_PASSWORD {
                let auth_req = timeout(
                    config.client_read_timeout,
                    AuthRequest::read_from(&mut read_half),
                )
                .await
                .map_err(|_| {
                    SocksError::IoError(
                        std::io::ErrorKind::TimedOut,
                        "Auth read timeout".into(),
                    )
                })??;

                if config.authenticate(&auth_req.username, &auth_req.password) {
                    tracing::debug!(user = %auth_req.username, "Authentication succeeded");
                    AuthResponse::success().write_to(&mut write_half).await?;
                } else {
                    tracing::info!(user = %auth_req.username, "Authentication failed");
                    AuthResponse::failure().write_to(&mut write_half).await?;
                    return Ok(());
                }
            }

            // --- SOCKS request ---
            let request = Self::read_request(&mut read_half, &config).await?;
            tracing::debug!(
                command = request.command as u8,
                address = ?request.address,
                "Received SOCKS request"
            );

            // --- Process request ---
            let outcome = Self::process_request(&request, &config, local_addr).await;

            match outcome {
                // ---- CONNECT ----
                Ok(RequestOutcome::Connect(response, remote_stream)) => {
                    tracing::debug!(reply = response.reply as u8, "Sending CONNECT response");
                    Self::send_response(&mut write_half, &response).await?;

                    let client_stream = read_half
                        .reunite(write_half)
                        .map_err(|_| SocksError::InvalidRequest)?;
                    let mut throttled_client = ThrottledStream::new(
                        client_stream, per_conn_bps, global_bw.clone(),
                    );
                    let mut throttled_remote = ThrottledStream::new(
                        remote_stream, per_conn_bps, global_bw.clone(),
                    );
                    Self::relay_data(&mut throttled_client, &mut throttled_remote).await;
                }

                // ---- BIND ----
                Ok(RequestOutcome::Bind(first_response, listener)) => {
                    tracing::debug!("Sending BIND first response (bound address)");
                    Self::send_response(&mut write_half, &first_response).await?;

                    // Wait for incoming connection
                    match timeout(config.bind_timeout, listener.accept()).await {
                        Ok(Ok((remote_stream, remote_addr))) => {
                            // SSRF check on the connecting peer
                            if !config.allow_private_destinations
                                && is_private_or_reserved(&remote_addr.ip())
                            {
                                let resp = SocksResponse::new(
                                    ReplyCode::ConnectionNotAllowed,
                                    Self::get_unspec_address(),
                                );
                                Self::send_response(&mut write_half, &resp).await?;
                                return Ok(());
                            }

                            let peer_socks = socket_addr_to_socks(&remote_addr);
                            let second_response =
                                SocksResponse::new(ReplyCode::Success, peer_socks);
                            tracing::debug!(
                                peer = %remote_addr,
                                "Sending BIND second response (peer connected)"
                            );
                            Self::send_response(&mut write_half, &second_response).await?;

                            let client_stream = read_half
                                .reunite(write_half)
                                .map_err(|_| SocksError::InvalidRequest)?;
                            let mut throttled_client = ThrottledStream::new(
                                client_stream, per_conn_bps, global_bw.clone(),
                            );
                            let mut throttled_remote = ThrottledStream::new(
                                remote_stream, per_conn_bps, global_bw.clone(),
                            );
                            Self::relay_data(&mut throttled_client, &mut throttled_remote).await;
                        }
                        Ok(Err(e)) => {
                            tracing::debug!("BIND accept error: {}", e);
                            let resp = SocksResponse::new(
                                ReplyCode::GeneralFailure,
                                Self::get_unspec_address(),
                            );
                            Self::send_response(&mut write_half, &resp).await?;
                        }
                        Err(_) => {
                            tracing::debug!("BIND accept timed out");
                            let resp = SocksResponse::new(
                                ReplyCode::TtlExpired,
                                Self::get_unspec_address(),
                            );
                            Self::send_response(&mut write_half, &resp).await?;
                        }
                    }
                }

                // ---- UDP ASSOCIATE ----
                Ok(RequestOutcome::UdpAssociate(response, udp_socket)) => {
                    tracing::debug!("Sending UDP ASSOCIATE response");
                    Self::send_response(&mut write_half, &response).await?;

                    // Determine expected client UDP address from the request
                    let expected_client = Self::resolve_expected_client(&request.address);

                    // Reunite halves — we need to monitor TCP for closure
                    let mut client_tcp = read_half
                        .reunite(write_half)
                        .map_err(|_| SocksError::InvalidRequest)?;

                    Self::run_udp_relay(&mut client_tcp, udp_socket, expected_client, &config)
                        .await;
                }

                // ---- Error response ----
                Ok(RequestOutcome::Error(response)) => {
                    tracing::debug!(reply = response.reply as u8, "Sending error response");
                    Self::send_response(&mut write_half, &response).await?;
                }

                // ---- Processing error ----
                Err(e) => {
                    let reply_code = socks_error_to_reply(&e);
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

    // ========================================================================
    // Handshake helpers
    // ========================================================================

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
                methods.push(AuthMethod(reader.read_u8().await?));
            }
            Ok(ClientHello {
                version,
                methods,
            })
        })
        .await
        .map_err(|_| {
            SocksError::IoError(std::io::ErrorKind::TimedOut, "Client read timeout".into())
        })?
    }

    /// Select auth method. When credentials are configured, only accept
    /// USERNAME_PASSWORD. Otherwise, accept NO_AUTH.
    fn select_auth_method(client_hello: &ClientHello, config: &ServerConfig) -> AuthMethod {
        if config.credentials.is_some() {
            if client_hello
                .methods
                .iter()
                .any(|m| m.0 == AuthMethod::USERNAME_PASSWORD.0)
            {
                AuthMethod::USERNAME_PASSWORD
            } else {
                AuthMethod::NO_ACCEPTABLE
            }
        } else if client_hello
            .methods
            .iter()
            .any(|m| m.0 == AuthMethod::NO_AUTH.0)
        {
            AuthMethod::NO_AUTH
        } else {
            AuthMethod::NO_ACCEPTABLE
        }
    }

    async fn send_server_hello<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        method: AuthMethod,
    ) -> Result<(), SocksError> {
        ServerHello::new(method).write_to(writer).await
    }

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

    async fn send_response<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        response: &SocksResponse,
    ) -> Result<(), SocksError> {
        response.write_to(writer).await
    }

    fn get_unspec_address() -> SocksAddress {
        SocksAddress::Ipv4(Ipv4Addr::UNSPECIFIED, 0)
    }

    // ========================================================================
    // Request processing
    // ========================================================================

    async fn process_request(
        request: &SocksRequest,
        config: &ServerConfig,
        local_addr: SocketAddr,
    ) -> Result<RequestOutcome, SocksError> {
        match request.command {
            SocksCommand::Connect => Self::handle_connect(request, config).await,
            SocksCommand::Bind => Self::handle_bind(config, local_addr).await,
            SocksCommand::UdpAssociate => Self::handle_udp_associate(config, local_addr).await,
        }
    }

    // ---- CONNECT ----

    async fn handle_connect(
        request: &SocksRequest,
        config: &ServerConfig,
    ) -> Result<RequestOutcome, SocksError> {
        let target_addr = resolve_address(&request.address, config).await?;
        tracing::debug!(target = %target_addr, "Connecting to target server");

        match timeout(config.connect_timeout, TcpStream::connect(target_addr)).await {
            Ok(Ok(stream)) => {
                tracing::debug!("Successfully connected to target");
                // Don't leak real bind address
                let response =
                    SocksResponse::new(ReplyCode::Success, Self::get_unspec_address());
                Ok(RequestOutcome::Connect(response, stream))
            }
            Ok(Err(err)) => {
                let socks_err = map_connect_error(err);
                tracing::debug!(error = %socks_err, "Connection failed");
                let reply = socks_error_to_reply(&socks_err);
                Ok(RequestOutcome::Error(SocksResponse::new(
                    reply,
                    Self::get_unspec_address(),
                )))
            }
            Err(_) => {
                tracing::debug!("Connection timed out");
                Ok(RequestOutcome::Error(SocksResponse::new(
                    ReplyCode::TtlExpired,
                    Self::get_unspec_address(),
                )))
            }
        }
    }

    // ---- BIND ----

    async fn handle_bind(
        config: &ServerConfig,
        local_addr: SocketAddr,
    ) -> Result<RequestOutcome, SocksError> {
        // Bind on the same IP the SOCKS server is listening on, ephemeral port
        let bind_ip = local_addr.ip();
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(bind_ip, 0))
            .await
            .map_err(|e| {
                tracing::debug!("BIND listen failed: {}", e);
                SocksError::IoError(e.kind(), e.to_string())
            })?;

        let bound_addr = listener.local_addr().map_err(|e| {
            SocksError::IoError(e.kind(), e.to_string())
        })?;

        tracing::debug!(bind = %bound_addr, "BIND listener ready");

        // If SSRF protection is on, don't expose real bind address
        let bind_socks = if config.allow_private_destinations {
            socket_addr_to_socks(&bound_addr)
        } else {
            socket_addr_to_socks(&bound_addr)
        };

        let response = SocksResponse::new(ReplyCode::Success, bind_socks);
        Ok(RequestOutcome::Bind(response, listener))
    }

    // ---- UDP ASSOCIATE ----

    async fn handle_udp_associate(
        config: &ServerConfig,
        local_addr: SocketAddr,
    ) -> Result<RequestOutcome, SocksError> {
        let bind_ip = local_addr.ip();
        let udp_socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .map_err(|e| {
                tracing::debug!("UDP bind failed: {}", e);
                SocksError::IoError(e.kind(), e.to_string())
            })?;

        let udp_addr = udp_socket.local_addr().map_err(|e| {
            SocksError::IoError(e.kind(), e.to_string())
        })?;

        tracing::debug!(udp_relay = %udp_addr, "UDP relay socket ready");

        let response = SocksResponse::new(ReplyCode::Success, socket_addr_to_socks(&udp_addr));
        Ok(RequestOutcome::UdpAssociate(response, udp_socket))
    }

    /// Determine expected client UDP address from the DST.ADDR in the request.
    /// Returns `None` if the address is unspecified (client address will be
    /// learned from the first received datagram).
    fn resolve_expected_client(address: &SocksAddress) -> Option<SocketAddr> {
        match address {
            SocksAddress::Ipv4(ip, port) => {
                if ip.is_unspecified() && *port == 0 {
                    None
                } else {
                    Some(SocketAddr::new(IpAddr::V4(*ip), *port))
                }
            }
            SocksAddress::Ipv6(ip, port) => {
                if ip.is_unspecified() && *port == 0 {
                    None
                } else {
                    Some(SocketAddr::new(IpAddr::V6(*ip), *port))
                }
            }
            SocksAddress::Domain(..) => None,
        }
    }

    // ========================================================================
    // Data relay
    // ========================================================================

    /// Relay data bidirectionally between client and remote (TCP).
    async fn relay_data<C, R>(client: &mut C, remote: &mut R)
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let result = tokio::io::copy_bidirectional(client, remote).await;
        match result {
            Ok((c2r, r2c)) => {
                tracing::debug!(
                    bytes_client_to_remote = c2r,
                    bytes_remote_to_client = r2c,
                    "Relay completed"
                );
            }
            Err(err) => {
                tracing::debug!("Relay error: {}", err);
            }
        }
    }

    /// Run the UDP relay loop.
    ///
    /// - Datagrams from the client are parsed for a `UdpRelayHeader`, destination
    ///   is resolved (with SSRF checks), and the payload is forwarded.
    /// - Datagrams from remote destinations are wrapped with a `UdpRelayHeader`
    ///   and sent back to the client.
    /// - When the TCP control connection closes, the relay terminates.
    async fn run_udp_relay(
        client_tcp: &mut TcpStream,
        udp_socket: UdpSocket,
        expected_client: Option<SocketAddr>,
        config: &ServerConfig,
    ) {
        let mut buf = vec![0u8; config.udp_buffer_size];
        let mut tcp_buf = [0u8; 1];
        let mut client_addr: Option<SocketAddr> = expected_client;

        loop {
            tokio::select! {
                // Monitor TCP control connection for closure
                result = client_tcp.read(&mut tcp_buf) => {
                    match result {
                        Ok(0) | Err(_) => {
                            tracing::debug!("TCP control connection closed, terminating UDP relay");
                            break;
                        }
                        Ok(_) => {} // ignore stray TCP data
                    }
                }
                // Process UDP datagrams
                result = udp_socket.recv_from(&mut buf) => {
                    let (n, src) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!("UDP recv error: {}", e);
                            continue;
                        }
                    };

                    let is_from_client = match client_addr {
                        Some(ca) => src == ca,
                        None => true, // first packet — assume it's the client
                    };

                    if is_from_client {
                        // Learn client address from first packet
                        if client_addr.is_none() {
                            client_addr = Some(src);
                        }
                        // Client → destination
                        Self::handle_client_udp(
                            &udp_socket, &buf[..n], config,
                        ).await;
                    } else {
                        // Destination → client
                        if let Some(ca) = client_addr {
                            Self::handle_remote_udp(
                                &udp_socket, &buf[..n], src, ca,
                            ).await;
                        }
                    }
                }
            }
        }
    }

    /// Parse a client UDP datagram, resolve the destination, forward payload.
    async fn handle_client_udp(
        udp_socket: &UdpSocket,
        data: &[u8],
        config: &ServerConfig,
    ) {
        let (header, header_len) = match UdpRelayHeader::parse(data) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("Invalid UDP relay header: {}", e);
                return;
            }
        };

        // Drop fragmented packets (not supported)
        if header.frag != 0 {
            tracing::debug!("Dropping fragmented UDP packet (frag={})", header.frag);
            return;
        }

        let dest_addr = match resolve_address(&header.address, config).await {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!("UDP destination resolve failed: {}", e);
                return;
            }
        };

        let payload = &data[header_len..];
        if let Err(e) = udp_socket.send_to(payload, dest_addr).await {
            tracing::debug!("UDP send_to {} failed: {}", dest_addr, e);
        }
    }

    /// Wrap a remote response in a `UdpRelayHeader` and send to the client.
    async fn handle_remote_udp(
        udp_socket: &UdpSocket,
        data: &[u8],
        remote_addr: SocketAddr,
        client_addr: SocketAddr,
    ) {
        let header = UdpRelayHeader::new(socket_addr_to_socks(&remote_addr));
        let header_bytes = header.serialize();
        let total = header_bytes.len() + data.len();
        if total > 65535 {
            tracing::debug!("UDP response too large ({} bytes), dropping", total);
            return;
        }
        let mut response = Vec::with_capacity(total);
        response.extend_from_slice(&header_bytes);
        response.extend_from_slice(data);
        if let Err(e) = udp_socket.send_to(&response, client_addr).await {
            tracing::debug!("UDP send to client failed: {}", e);
        }
    }
}

// ============================================================================
// Server entry points
// ============================================================================

#[tracing::instrument(name = "server")]
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let addr: std::net::SocketAddr = "127.0.0.1:1080".parse().unwrap();
    run_with_config(addr, ServerConfig::default()).await
}

#[tracing::instrument(name = "server", skip())]
pub async fn run_on_port(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        port,
    );
    run_with_config(addr, ServerConfig::default()).await
}

#[tracing::instrument(name = "server", skip(config))]
pub async fn run_with_config(
    listen_addr: std::net::SocketAddr,
    config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    tracing::info!("SOCKS5 server listening on {}", listen_addr);

    let config = Arc::new(config);
    let mut join_set = tokio::task::JoinSet::<Result<(), SocksError>>::new();

    let tracker = Arc::new(ConnectionTracker::new(
        config.max_connections_per_ip,
        config.max_concurrent_connections,
        config.per_ip_rps,
        config.connection_rate_limit,
    ));

    let global_bandwidth = if config.bandwidth_total > 0 {
        Some(Arc::new(BandwidthLimiter::new(config.bandwidth_total)))
    } else {
        None
    };

    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));

    let shutdown_timeout = config.shutdown_timeout;
    let mut shutdown = std::pin::pin!(wait_for_shutdown_signal());

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((socket, remote_peer)) => {
                        let client_ip = remote_peer.ip();

                        // Global connection rate limit
                        if !tracker.check_accept_rate() {
                            tracing::debug!(ip = %client_ip, "Connection rate limited");
                            drop(socket);
                            continue;
                        }

                        // Per-IP request rate limit
                        if !tracker.check_ip_rate(client_ip) {
                            tracing::debug!(ip = %client_ip, "Per-IP rate limited");
                            drop(socket);
                            continue;
                        }

                        let permit = match tracker.try_acquire(client_ip) {
                            Some(p) => p,
                            None => {
                                tracing::warn!(ip = %client_ip, "Connection limit exceeded");
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
                        let conn_bw = global_bandwidth.clone();

                        join_set.spawn(async move {
                            let _guard = ConnectionGuard {
                                tracker: conn_tracker,
                                ip: client_ip,
                                _permit: permit,
                            };
                            Connection::new(socket, remote_peer, conn_config, conn_bw)
                                .process()
                                .await
                        });
                    }
                    Err(err) => {
                        tracing::error!("Accept error: {}", err);
                    }
                }
            },
            Some(result) = join_set.join_next() => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => tracing::debug!("Connection error: {}", err),
                    Err(err) => tracing::debug!("Task panic: {}", err),
                }
            },
            _ = cleanup_interval.tick() => {
                tracker.cleanup_rate_limiters();
            },
            _ = &mut shutdown => {
                break;
            }
        }
    }

    // Graceful shutdown
    let active = join_set.len();
    tracing::info!("Waiting for {} active connections (timeout: {:?})...", active, shutdown_timeout);

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
        Ok(()) => tracing::info!("All {} connections closed gracefully", active),
        Err(_) => {
            tracing::warn!("Timeout, aborting {} tasks...", join_set.len());
            join_set.abort_all();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    tracing::info!("SOCKS5 server shutdown complete");
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_basic() {
        let bucket = TokenBucket::new(10.0, 10.0);
        // Should allow 10 tokens initially (full bucket)
        for _ in 0..10 {
            assert!(bucket.try_consume(1.0));
        }
        // 11th should fail
        assert!(!bucket.try_consume(1.0));
    }

    #[test]
    fn test_token_bucket_consume_up_to() {
        let bucket = TokenBucket::new(5.0, 100.0);
        // Request 10, should only get 5
        let consumed = bucket.consume_up_to(10.0);
        assert!((consumed - 5.0).abs() < 0.01);
        // Bucket is empty now
        let consumed = bucket.consume_up_to(10.0);
        assert!(consumed < 0.01);
    }

    #[test]
    fn test_token_bucket_time_until() {
        let bucket = TokenBucket::new(10.0, 10.0);
        // Drain the bucket
        bucket.try_consume(10.0);
        // Should need ~1 second for 10 tokens at rate 10/s
        let wait = bucket.time_until(10.0);
        assert!(wait.as_secs_f64() > 0.9 && wait.as_secs_f64() < 1.1);
        // Already available = zero wait
        let bucket2 = TokenBucket::new(10.0, 10.0);
        assert_eq!(bucket2.time_until(5.0), Duration::ZERO);
    }

    #[test]
    fn test_ip_rate_limiter_unlimited() {
        let limiter = IpRateLimiter::new(0);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // Should always allow when rps = 0
        for _ in 0..1000 {
            assert!(limiter.check(ip));
        }
    }

    #[test]
    fn test_ip_rate_limiter_limited() {
        let limiter = IpRateLimiter::new(5);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // Burst = 2x RPS = 10
        for _ in 0..10 {
            assert!(limiter.check(ip));
        }
        // Next should be rate limited
        assert!(!limiter.check(ip));
    }

    #[test]
    fn test_ip_rate_limiter_per_ip_isolation() {
        let limiter = IpRateLimiter::new(5);
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        // Exhaust ip1's bucket
        for _ in 0..10 {
            limiter.check(ip1);
        }
        assert!(!limiter.check(ip1));
        // ip2 should still be fine
        assert!(limiter.check(ip2));
    }

    #[test]
    fn test_connection_tracker_accept_rate() {
        let tracker = ConnectionTracker::new(100, 1000, 0, 5);
        // Burst = 10
        for _ in 0..10 {
            assert!(tracker.check_accept_rate());
        }
        assert!(!tracker.check_accept_rate());
    }

    #[test]
    fn test_connection_tracker_accept_rate_unlimited() {
        let tracker = ConnectionTracker::new(100, 1000, 0, 0);
        for _ in 0..10000 {
            assert!(tracker.check_accept_rate());
        }
    }

    #[test]
    fn test_connection_tracker_ip_rate() {
        let tracker = ConnectionTracker::new(100, 1000, 10, 0);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // Burst = 20
        for _ in 0..20 {
            assert!(tracker.check_ip_rate(ip));
        }
        assert!(!tracker.check_ip_rate(ip));
    }

    #[test]
    fn test_bandwidth_limiter() {
        let limiter = BandwidthLimiter::new(1000);
        // Should allow up to 1000 bytes initially
        let consumed = limiter.consume(500);
        assert_eq!(consumed, 500);
        let consumed = limiter.consume(800);
        assert_eq!(consumed, 500); // only 500 left
        let consumed = limiter.consume(100);
        assert_eq!(consumed, 0); // empty
    }

    #[test]
    fn test_is_private_or_reserved_v4() {
        assert!(is_private_or_reserved_v4(&Ipv4Addr::LOCALHOST));
        assert!(is_private_or_reserved_v4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_or_reserved_v4(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_private_or_reserved_v4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_or_reserved_v4(&Ipv4Addr::new(100, 64, 0, 1))); // CGNAT
        assert!(!is_private_or_reserved_v4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_or_reserved_v4(&Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_cleanup_rate_limiters() {
        let tracker = ConnectionTracker::new(100, 1000, 10, 0);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // Generate a rate limiter entry
        tracker.check_ip_rate(ip);
        // No active connections → cleanup should remove it
        tracker.cleanup_rate_limiters();
        let buckets = tracker.ip_rate_limiter.buckets.lock().unwrap();
        assert!(buckets.is_empty());
    }
}
