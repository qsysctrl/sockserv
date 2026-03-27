//! TOML configuration file support.
//!
//! Loads a TOML config and converts it into a [`ServerConfig`](crate::server::ServerConfig)
//! plus the listen address and logging parameters that live outside `ServerConfig`.

use crate::server::ServerConfig;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use tokio::time::Duration;

// ============================================================================
// Top-level file config
// ============================================================================

/// Root of the TOML configuration file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub auth: AuthSection,
    #[serde(default)]
    pub timeouts: TimeoutsSection,
    #[serde(default)]
    pub limits: LimitsSection,
    #[serde(default)]
    pub rate_limit: RateLimitSection,
    #[serde(default)]
    pub security: SecuritySection,
    #[serde(default)]
    pub logging: LoggingSection,
}

// ============================================================================
// Sections
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// IP address to bind to (default: "127.0.0.1")
    #[serde(default = "default_listen_address")]
    pub listen_address: IpAddr,
    /// Port to listen on (default: 1080)
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            listen_address: default_listen_address(),
            listen_port: default_listen_port(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSection {
    /// Authentication method: "none" or "password" (default: "none")
    #[serde(default = "default_auth_method")]
    pub method: String,
    /// Username → password map. Only used when method = "password".
    #[serde(default)]
    pub users: HashMap<String, String>,
}

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            method: default_auth_method(),
            users: HashMap::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutsSection {
    /// Client read timeout in seconds (default: 30)
    #[serde(default = "default_30")]
    pub client_read: u64,
    /// Upstream connect timeout in seconds (default: 10)
    #[serde(default = "default_10")]
    pub connect: u64,
    /// DNS resolution timeout in seconds (default: 5)
    #[serde(default = "default_5")]
    pub dns: u64,
    /// Total connection lifetime in seconds (default: 300)
    #[serde(default = "default_300")]
    pub connection: u64,
    /// Graceful shutdown timeout in seconds (default: 30)
    #[serde(default = "default_30")]
    pub shutdown: u64,
    /// BIND accept timeout in seconds (default: 60)
    #[serde(default = "default_60")]
    pub bind: u64,
    /// UDP relay idle timeout in seconds (default: 120)
    #[serde(default = "default_120")]
    pub udp_idle: u64,
}

impl Default for TimeoutsSection {
    fn default() -> Self {
        Self {
            client_read: 30,
            connect: 10,
            dns: 5,
            connection: 300,
            shutdown: 30,
            bind: 60,
            udp_idle: 120,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    /// Maximum concurrent connections (default: 10000)
    #[serde(default = "default_10000")]
    pub max_concurrent_connections: usize,
    /// Maximum connections per IP (default: 100)
    #[serde(default = "default_100")]
    pub max_connections_per_ip: usize,
    /// Maximum auth methods per client hello (default: 128)
    #[serde(default = "default_128")]
    pub max_auth_methods: usize,
    /// UDP relay buffer size in bytes (default: 65535)
    #[serde(default = "default_65535")]
    pub udp_buffer_size: usize,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_concurrent_connections: 10_000,
            max_connections_per_ip: 100,
            max_auth_methods: 128,
            udp_buffer_size: 65535,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitSection {
    /// Maximum new connections accepted per second globally (0 = unlimited, default: 0)
    #[serde(default)]
    pub connection_rate: u32,
    /// Maximum requests per second per IP address (0 = unlimited, default: 0)
    #[serde(default)]
    pub per_ip_rps: u32,
    /// Maximum bandwidth per connection in bytes/sec (0 = unlimited, default: 0)
    #[serde(default)]
    pub bandwidth_per_connection: u64,
    /// Maximum total bandwidth in bytes/sec (0 = unlimited, default: 0)
    #[serde(default)]
    pub bandwidth_total: u64,
}

impl Default for RateLimitSection {
    fn default() -> Self {
        Self {
            connection_rate: 0,
            per_ip_rps: 0,
            bandwidth_per_connection: 0,
            bandwidth_total: 0,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecuritySection {
    /// Allow proxying to private/reserved IP ranges (default: false).
    /// WARNING: enabling this allows SSRF attacks.
    #[serde(default)]
    pub allow_private_destinations: bool,
}

impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            allow_private_destinations: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingSection {
    /// Log level filter (default: "info").
    /// Supports tracing directives: "debug", "info,sockserv=debug", etc.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log output format: "compact", "full", or "json" (default: "compact")
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

// ============================================================================
// Default value functions for serde
// ============================================================================

fn default_listen_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
}
fn default_listen_port() -> u16 {
    1080
}
fn default_auth_method() -> String {
    "none".into()
}
fn default_log_level() -> String {
    "info".into()
}
fn default_log_format() -> String {
    "compact".into()
}
fn default_5() -> u64 {
    5
}
fn default_10() -> u64 {
    10
}
fn default_30() -> u64 {
    30
}
fn default_60() -> u64 {
    60
}
fn default_120() -> u64 {
    120
}
fn default_300() -> u64 {
    300
}
fn default_100() -> usize {
    100
}
fn default_128() -> usize {
    128
}
fn default_10000() -> usize {
    10_000
}
fn default_65535() -> usize {
    65535
}

// ============================================================================
// Loading and conversion
// ============================================================================

impl FileConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        Self::from_str(&content)
    }

    /// Parse configuration from a TOML string.
    pub fn from_str(s: &str) -> Result<Self, ConfigError> {
        let config: FileConfig = toml::from_str(s).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the parsed configuration for semantic errors.
    fn validate(&self) -> Result<(), ConfigError> {
        match self.auth.method.as_str() {
            "none" => {}
            "password" => {
                if self.auth.users.is_empty() {
                    return Err(ConfigError::Validation(
                        "auth.method is \"password\" but no users are defined in [auth.users]"
                            .into(),
                    ));
                }
            }
            other => {
                return Err(ConfigError::Validation(format!(
                    "unknown auth method \"{other}\", expected \"none\" or \"password\""
                )));
            }
        }

        match self.logging.format.as_str() {
            "compact" | "full" | "json" => {}
            other => {
                return Err(ConfigError::Validation(format!(
                    "unknown log format \"{other}\", expected \"compact\", \"full\", or \"json\""
                )));
            }
        }

        if self.server.listen_port == 0 {
            return Err(ConfigError::Validation(
                "listen_port must not be 0".into(),
            ));
        }

        Ok(())
    }

    /// Convert into the runtime `ServerConfig` plus the listen address.
    pub fn into_server_config(self) -> (std::net::SocketAddr, ServerConfig) {
        let listen_addr =
            std::net::SocketAddr::new(self.server.listen_address, self.server.listen_port);

        let credentials = match self.auth.method.as_str() {
            "password" => Some(self.auth.users),
            _ => None,
        };

        let config = ServerConfig {
            max_auth_methods: self.limits.max_auth_methods,
            client_read_timeout: Duration::from_secs(self.timeouts.client_read),
            connect_timeout: Duration::from_secs(self.timeouts.connect),
            dns_timeout: Duration::from_secs(self.timeouts.dns),
            connection_timeout: Duration::from_secs(self.timeouts.connection),
            max_concurrent_connections: self.limits.max_concurrent_connections,
            max_connections_per_ip: self.limits.max_connections_per_ip,
            allow_private_destinations: self.security.allow_private_destinations,
            shutdown_timeout: Duration::from_secs(self.timeouts.shutdown),
            credentials,
            bind_timeout: Duration::from_secs(self.timeouts.bind),
            udp_idle_timeout: Duration::from_secs(self.timeouts.udp_idle),
            udp_buffer_size: self.limits.udp_buffer_size,
            connection_rate_limit: self.rate_limit.connection_rate,
            per_ip_rps: self.rate_limit.per_ip_rps,
            bandwidth_per_connection: self.rate_limit.bandwidth_per_connection,
            bandwidth_total: self.rate_limit.bandwidth_total,
        };

        (listen_addr, config)
    }
}

// ============================================================================
// Error type
// ============================================================================

#[derive(Debug)]
pub enum ConfigError {
    Io {
        path: String,
        source: std::io::Error,
    },
    Parse(toml::de::Error),
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "cannot read config \"{path}\": {source}"),
            Self::Parse(e) => write!(f, "config parse error: {e}"),
            Self::Validation(msg) => write!(f, "config validation error: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_config_uses_defaults() {
        let cfg = FileConfig::from_str("").unwrap();
        assert_eq!(cfg.server.listen_port, 1080);
        assert_eq!(cfg.server.listen_address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(cfg.auth.method, "none");
        assert_eq!(cfg.timeouts.connect, 10);
        assert_eq!(cfg.limits.max_concurrent_connections, 10_000);
        assert!(!cfg.security.allow_private_destinations);
        assert_eq!(cfg.rate_limit.connection_rate, 0);
        assert_eq!(cfg.rate_limit.per_ip_rps, 0);
        assert_eq!(cfg.rate_limit.bandwidth_per_connection, 0);
        assert_eq!(cfg.rate_limit.bandwidth_total, 0);
        assert_eq!(cfg.logging.level, "info");
        assert_eq!(cfg.logging.format, "compact");
    }

    #[test]
    fn test_full_config() {
        let toml = r#"
[server]
listen_address = "0.0.0.0"
listen_port = 9090

[auth]
method = "password"
[auth.users]
alice = "secret123"
bob = "hunter2"

[timeouts]
client_read = 15
connect = 5
dns = 3
connection = 600
shutdown = 10
bind = 30
udp_idle = 60

[limits]
max_concurrent_connections = 5000
max_connections_per_ip = 50
max_auth_methods = 64
udp_buffer_size = 32768

[rate_limit]
connection_rate = 500
per_ip_rps = 50
bandwidth_per_connection = 1048576
bandwidth_total = 104857600

[security]
allow_private_destinations = true

[logging]
level = "debug"
format = "json"
"#;
        let cfg = FileConfig::from_str(toml).unwrap();
        assert_eq!(cfg.server.listen_port, 9090);
        assert_eq!(
            cfg.server.listen_address,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(cfg.auth.method, "password");
        assert_eq!(cfg.auth.users.len(), 2);
        assert_eq!(cfg.auth.users["alice"], "secret123");
        assert_eq!(cfg.timeouts.connect, 5);
        assert_eq!(cfg.limits.max_concurrent_connections, 5000);
        assert_eq!(cfg.rate_limit.connection_rate, 500);
        assert_eq!(cfg.rate_limit.per_ip_rps, 50);
        assert_eq!(cfg.rate_limit.bandwidth_per_connection, 1_048_576);
        assert_eq!(cfg.rate_limit.bandwidth_total, 104_857_600);
        assert!(cfg.security.allow_private_destinations);
        assert_eq!(cfg.logging.format, "json");

        let (addr, server_cfg) = cfg.into_server_config();
        assert_eq!(addr.port(), 9090);
        assert!(server_cfg.credentials.is_some());
        assert_eq!(
            server_cfg.credentials.as_ref().unwrap()["bob"],
            "hunter2"
        );
        assert_eq!(server_cfg.connect_timeout, Duration::from_secs(5));
        assert!(server_cfg.allow_private_destinations);
        assert_eq!(server_cfg.connection_rate_limit, 500);
        assert_eq!(server_cfg.per_ip_rps, 50);
        assert_eq!(server_cfg.bandwidth_per_connection, 1_048_576);
        assert_eq!(server_cfg.bandwidth_total, 104_857_600);
    }

    #[test]
    fn test_partial_config() {
        let toml = r#"
[server]
listen_port = 2080

[timeouts]
connect = 20
"#;
        let cfg = FileConfig::from_str(toml).unwrap();
        assert_eq!(cfg.server.listen_port, 2080);
        assert_eq!(cfg.server.listen_address, IpAddr::V4(Ipv4Addr::LOCALHOST)); // default
        assert_eq!(cfg.timeouts.connect, 20);
        assert_eq!(cfg.timeouts.client_read, 30); // default
    }

    #[test]
    fn test_password_auth_without_users_fails() {
        let toml = r#"
[auth]
method = "password"
"#;
        let err = FileConfig::from_str(toml).unwrap_err();
        assert!(err.to_string().contains("no users are defined"));
    }

    #[test]
    fn test_unknown_auth_method_fails() {
        let toml = r#"
[auth]
method = "kerberos"
"#;
        let err = FileConfig::from_str(toml).unwrap_err();
        assert!(err.to_string().contains("unknown auth method"));
    }

    #[test]
    fn test_unknown_log_format_fails() {
        let toml = r#"
[logging]
format = "yaml"
"#;
        let err = FileConfig::from_str(toml).unwrap_err();
        assert!(err.to_string().contains("unknown log format"));
    }

    #[test]
    fn test_unknown_field_rejected() {
        let toml = r#"
[server]
listen_port = 1080
bogus_field = true
"#;
        assert!(FileConfig::from_str(toml).is_err());
    }

    #[test]
    fn test_port_zero_rejected() {
        let toml = r#"
[server]
listen_port = 0
"#;
        let err = FileConfig::from_str(toml).unwrap_err();
        assert!(err.to_string().contains("listen_port must not be 0"));
    }

    #[test]
    fn test_into_server_config_no_auth() {
        let cfg = FileConfig::from_str("").unwrap();
        let (addr, server_cfg) = cfg.into_server_config();
        assert_eq!(addr, "127.0.0.1:1080".parse().unwrap());
        assert!(server_cfg.credentials.is_none());
    }

    #[test]
    fn test_ipv6_listen_address() {
        let toml = r#"
[server]
listen_address = "::1"
listen_port = 1080
"#;
        let cfg = FileConfig::from_str(toml).unwrap();
        assert!(cfg.server.listen_address.is_ipv6());
    }
}
