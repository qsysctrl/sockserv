//! Access Control List (ACL) implementation.
//!
//! Provides IP whitelist/blacklist, domain filtering, port restrictions,
//! and per-IP connection limits with thread-safe matching.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// ACL evaluation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclDecision {
    /// Request is allowed.
    Allow,
    /// Request is denied with a reason.
    Deny(&'static str),
}

impl AclDecision {
    #[inline]
    pub fn is_allowed(&self) -> bool {
        matches!(self, AclDecision::Allow)
    }

    #[inline]
    pub fn is_deny(&self) -> bool {
        matches!(self, AclDecision::Deny(_))
    }
}

/// CIDR network range for IP matching.
#[derive(Debug, Clone)]
pub struct Cidr {
    network: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// Create a new CIDR from network address and prefix length.
    pub fn new(network: IpAddr, prefix_len: u8) -> Result<Self, AclError> {
        let max_prefix = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return Err(AclError::InvalidPrefixLength {
                prefix: prefix_len,
                max: max_prefix,
            });
        }
        Ok(Self { network, prefix_len })
    }

    /// Check if an IP address is within this CIDR range.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_bits = u32::from(net);
                let ip_bits = u32::from(*ip);
                let mask = !0u32 << (32 - self.prefix_len);
                (net_bits & mask) == (ip_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_bits = u128::from(net);
                let ip_bits = u128::from(*ip);
                let mask = !0u128 << (128 - self.prefix_len);
                (net_bits & mask) == (ip_bits & mask)
            }
            // IPv4-mapped IPv6 handling
            (IpAddr::V4(_net), IpAddr::V6(ip)) => {
                ip.to_ipv4_mapped().is_some_and(|v4| self.contains(&IpAddr::V4(v4)))
            }
            (IpAddr::V6(net), IpAddr::V4(ip)) => {
                net.to_ipv4_mapped()
                    .is_some_and(|v4| Cidr::new(IpAddr::V4(v4), self.prefix_len - 96).is_ok_and(|cidr_v4| cidr_v4.contains(&IpAddr::V4(*ip))))
            }
        }
    }
}

impl FromStr for Cidr {
    type Err = AclError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let ip = IpAddr::from_str(ip_str).map_err(|_| AclError::InvalidIpAddress {
                value: ip_str.to_string(),
            })?;
            let prefix_len: u8 = prefix_str.parse().map_err(|_| AclError::InvalidPrefixLength {
                prefix: 0,
                max: 0,
            })?;
            Self::new(ip, prefix_len)
        } else {
            // Single IP address = /32 or /128
            let ip = IpAddr::from_str(s).map_err(|_| AclError::InvalidIpAddress {
                value: s.to_string(),
            })?;
            let prefix_len = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Self::new(ip, prefix_len)
        }
    }
}

/// Domain pattern for matching. Supports:
/// - Exact match: `example.com`
/// - Wildcard prefix: `*.example.com` (matches any subdomain)
/// - Suffix match: `.example.com` (matches example.com and all subdomains)
#[derive(Debug, Clone)]
pub struct DomainPattern {
    pattern: String,
    is_wildcard: bool,
    is_suffix: bool,
}

impl DomainPattern {
    pub fn new(pattern: &str) -> Result<Self, AclError> {
        let pattern = pattern.to_lowercase();
        
        // No empty patterns
        if pattern.is_empty() {
            return Err(AclError::InvalidDomainPattern {
                value: pattern.to_string(),
            });
        }

        // No consecutive dots
        if pattern.contains("..") {
            return Err(AclError::InvalidDomainPattern {
                value: pattern.to_string(),
            });
        }
        
        // Only allow printable ASCII for domain names
        // Allowed: alphanumeric, dots, hyphens, asterisk (only at start for wildcard)
        if !pattern.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '*'
        }) {
            return Err(AclError::InvalidDomainPattern {
                value: pattern.to_string(),
            });
        }

        let is_wildcard = pattern.starts_with("*.");
        let is_suffix = pattern.starts_with('.') || is_wildcard;

        // Wildcard only allowed at the very start
        if is_wildcard && pattern[1..].contains('*') {
            return Err(AclError::InvalidDomainPattern {
                value: pattern.to_string(),
            });
        }

        // No other asterisks allowed
        if !is_wildcard && pattern.contains('*') {
            return Err(AclError::InvalidDomainPattern {
                value: pattern.to_string(),
            });
        }

        Ok(Self {
            pattern,
            is_wildcard,
            is_suffix,
        })
    }

    /// Check if a domain matches this pattern.
    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();

        if self.is_wildcard {
            // *.example.com matches foo.example.com but not example.com
            let suffix = &self.pattern[1..]; // .example.com
            domain.ends_with(suffix) && domain != suffix[1..]
        } else if self.is_suffix {
            // .example.com matches example.com and foo.example.com
            let suffix = if self.pattern.starts_with('.') {
                &self.pattern[1..]
            } else {
                &self.pattern
            };
            domain == suffix || domain.ends_with(suffix)
        } else {
            // Exact match
            domain == self.pattern
        }
    }
}

impl FromStr for DomainPattern {
    type Err = AclError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Port range for matching.
#[derive(Debug, Clone)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Result<Self, AclError> {
        if start > end {
            return Err(AclError::InvalidPortRange { start, end });
        }
        Ok(Self { start, end })
    }

    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

impl FromStr for PortRange {
    type Err = AclError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((start_str, end_str)) = s.split_once('-') {
            let start: u16 = start_str.parse().map_err(|_| AclError::InvalidPort {
                value: start_str.to_string(),
            })?;
            let end: u16 = end_str.parse().map_err(|_| AclError::InvalidPort {
                value: end_str.to_string(),
            })?;
            Self::new(start, end)
        } else {
            let port: u16 = s.parse().map_err(|_| AclError::InvalidPort {
                value: s.to_string(),
            })?;
            Self::new(port, port)
        }
    }
}

/// ACL error types.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AclError {
    #[error("invalid IP address: {value}")]
    InvalidIpAddress { value: String },

    #[error("invalid prefix length: {prefix} (max {max})")]
    InvalidPrefixLength { prefix: u8, max: u8 },

    #[error("invalid domain pattern: {value}")]
    InvalidDomainPattern { value: String },

    #[error("invalid port: {value}")]
    InvalidPort { value: String },

    #[error("invalid port range: {start}-{end}")]
    InvalidPortRange { start: u16, end: u16 },

    #[error("whitelist and blacklist cannot both be non-empty")]
    ConflictingLists,
}

/// Configuration for ACL rules.
#[derive(Debug, Clone, Default)]
pub struct AclConfig {
    /// IP addresses or CIDRs to always allow.
    pub ip_whitelist: Vec<String>,
    /// IP addresses or CIDRs to always deny.
    pub ip_blacklist: Vec<String>,
    /// Domain patterns to allow (wildcards supported).
    pub domain_whitelist: Vec<String>,
    /// Domain patterns to deny (wildcards supported).
    pub domain_blacklist: Vec<String>,
    /// Port ranges to allow.
    pub port_whitelist: Vec<String>,
    /// Port ranges to deny.
    pub port_blacklist: Vec<String>,
    /// Maximum connections per IP (overrides server default).
    pub max_connections_per_ip: Option<usize>,
}

/// Compiled ACL rules for efficient matching.
pub struct AclEngine {
    ip_whitelist: Option<Vec<Cidr>>,
    ip_blacklist: Vec<Cidr>,
    domain_whitelist: Option<Vec<DomainPattern>>,
    domain_blacklist: Vec<DomainPattern>,
    port_whitelist: Option<Vec<PortRange>>,
    port_blacklist: Vec<PortRange>,
    max_connections_per_ip: Option<usize>,
}

impl AclEngine {
    /// Create a new ACL engine from configuration.
    pub fn new(config: &AclConfig) -> Result<Self, AclError> {
        // Parse IP lists
        let ip_whitelist: Result<Vec<Cidr>, _> = config
            .ip_whitelist
            .iter()
            .map(|s| s.parse::<Cidr>())
            .collect();
        let ip_blacklist: Result<Vec<Cidr>, _> = config
            .ip_blacklist
            .iter()
            .map(|s| s.parse::<Cidr>())
            .collect();

        let ip_whitelist = ip_whitelist?;
        let ip_blacklist = ip_blacklist?;

        // Validate: can't have both whitelist and blacklist non-empty
        if !ip_whitelist.is_empty() && !ip_blacklist.is_empty() {
            return Err(AclError::ConflictingLists);
        }

        // Parse domain lists
        let domain_whitelist: Result<Vec<DomainPattern>, _> = config
            .domain_whitelist
            .iter()
            .map(|s| DomainPattern::new(s))
            .collect();
        let domain_blacklist: Result<Vec<DomainPattern>, _> = config
            .domain_blacklist
            .iter()
            .map(|s| DomainPattern::new(s))
            .collect();

        let domain_whitelist = domain_whitelist?;
        let domain_blacklist = domain_blacklist?;

        if !domain_whitelist.is_empty() && !domain_blacklist.is_empty() {
            return Err(AclError::ConflictingLists);
        }

        // Parse port lists
        let port_whitelist: Result<Vec<PortRange>, _> = config
            .port_whitelist
            .iter()
            .map(|s| s.parse::<PortRange>())
            .collect();
        let port_blacklist: Result<Vec<PortRange>, _> = config
            .port_blacklist
            .iter()
            .map(|s| s.parse::<PortRange>())
            .collect();

        let port_whitelist = port_whitelist?;
        let port_blacklist = port_blacklist?;

        if !port_whitelist.is_empty() && !port_blacklist.is_empty() {
            return Err(AclError::ConflictingLists);
        }

        Ok(Self {
            ip_whitelist: if ip_whitelist.is_empty() {
                None
            } else {
                Some(ip_whitelist)
            },
            ip_blacklist,
            domain_whitelist: if domain_whitelist.is_empty() {
                None
            } else {
                Some(domain_whitelist)
            },
            domain_blacklist,
            port_whitelist: if port_whitelist.is_empty() {
                None
            } else {
                Some(port_whitelist)
            },
            port_blacklist,
            max_connections_per_ip: config.max_connections_per_ip,
        })
    }

    /// Check if a client IP is allowed to connect.
    pub fn check_client_ip(&self, ip: &IpAddr) -> AclDecision {
        // Check blacklist first (if present)
        if !self.ip_blacklist.is_empty() {
            for cidr in &self.ip_blacklist {
                if cidr.contains(ip) {
                    return AclDecision::Deny("client IP is blacklisted");
                }
            }
        }

        // Check whitelist (if present)
        if let Some(whitelist) = &self.ip_whitelist {
            for cidr in whitelist {
                if cidr.contains(ip) {
                    return AclDecision::Allow;
                }
            }
            return AclDecision::Deny("client IP not in whitelist");
        }

        AclDecision::Allow
    }

    /// Check if a destination domain is allowed.
    pub fn check_domain(&self, domain: &str) -> AclDecision {
        // Check blacklist first
        if !self.domain_blacklist.is_empty() {
            for pattern in &self.domain_blacklist {
                if pattern.matches(domain) {
                    return AclDecision::Deny("domain is blacklisted");
                }
            }
        }

        // Check whitelist (if present)
        if let Some(whitelist) = &self.domain_whitelist {
            for pattern in whitelist {
                if pattern.matches(domain) {
                    return AclDecision::Allow;
                }
            }
            return AclDecision::Deny("domain not in whitelist");
        }

        AclDecision::Allow
    }

    /// Check if a destination port is allowed.
    pub fn check_port(&self, port: u16) -> AclDecision {
        // Check blacklist first
        if !self.port_blacklist.is_empty() {
            for range in &self.port_blacklist {
                if range.contains(port) {
                    return AclDecision::Deny("port is blacklisted");
                }
            }
        }

        // Check whitelist (if present)
        if let Some(whitelist) = &self.port_whitelist {
            for range in whitelist {
                if range.contains(port) {
                    return AclDecision::Allow;
                }
            }
            return AclDecision::Deny("port not in whitelist");
        }

        AclDecision::Allow
    }

    /// Get the max connections per IP override (if configured).
    pub fn max_connections_per_ip(&self) -> Option<usize> {
        self.max_connections_per_ip
    }
}

/// Thread-safe ACL engine wrapper for concurrent access.
#[derive(Clone)]
pub struct AclManager {
    engine: Arc<RwLock<AclEngine>>,
}

impl AclManager {
    /// Create a new ACL manager from configuration.
    pub fn new(config: &AclConfig) -> Result<Self, AclError> {
        let engine = AclEngine::new(config)?;
        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
        })
    }

    /// Check if a client IP is allowed.
    pub async fn check_client_ip(&self, ip: &IpAddr) -> AclDecision {
        self.engine.read().await.check_client_ip(ip)
    }

    /// Check if a destination domain is allowed.
    pub async fn check_domain(&self, domain: &str) -> AclDecision {
        self.engine.read().await.check_domain(domain)
    }

    /// Check if a destination port is allowed.
    pub async fn check_port(&self, port: u16) -> AclDecision {
        self.engine.read().await.check_port(port)
    }

    /// Get the max connections per IP override.
    pub async fn max_connections_per_ip(&self) -> Option<usize> {
        self.engine.read().await.max_connections_per_ip()
    }

    /// Reload the ACL configuration.
    pub async fn reload(&self, config: &AclConfig) -> Result<(), AclError> {
        let new_engine = AclEngine::new(config)?;
        let mut engine = self.engine.write().await;
        *engine = new_engine;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Cidr tests
    // ========================================================================

    #[test]
    fn test_cidr_parse_ipv4() {
        let cidr: Cidr = "192.168.1.0/24".parse().unwrap();
        assert!(cidr.contains(&"192.168.1.100".parse().unwrap()));
        assert!(!cidr.contains(&"192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn test_cidr_parse_ipv6() {
        let cidr: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(cidr.contains(&"2001:db8::1".parse().unwrap()));
        assert!(!cidr.contains(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_cidr_single_ip() {
        let cidr: Cidr = "10.0.0.1".parse().unwrap();
        assert!(cidr.contains(&"10.0.0.1".parse().unwrap()));
        assert!(!cidr.contains(&"10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_cidr_full_range() {
        let cidr: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(cidr.contains(&"1.2.3.4".parse().unwrap()));
        assert!(cidr.contains(&"255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_cidr_invalid_prefix() {
        assert!("192.168.1.0/33".parse::<Cidr>().is_err());
        assert!("2001:db8::/129".parse::<Cidr>().is_err());
    }

    // ========================================================================
    // DomainPattern tests
    // ========================================================================

    #[test]
    fn test_domain_exact_match() {
        let pattern = DomainPattern::new("example.com").unwrap();
        assert!(pattern.matches("example.com"));
        assert!(!pattern.matches("foo.example.com"));
        assert!(pattern.matches("EXAMPLE.COM")); // case insensitive
    }

    #[test]
    fn test_domain_wildcard_match() {
        let pattern = DomainPattern::new("*.example.com").unwrap();
        assert!(pattern.matches("foo.example.com"));
        assert!(pattern.matches("bar.baz.example.com"));
        assert!(!pattern.matches("example.com"));
    }

    #[test]
    fn test_domain_suffix_match() {
        let pattern = DomainPattern::new(".example.com").unwrap();
        assert!(pattern.matches("example.com"));
        assert!(pattern.matches("foo.example.com"));
        assert!(pattern.matches("bar.baz.example.com"));
    }

    #[test]
    fn test_domain_case_insensitive() {
        let pattern = DomainPattern::new("*.EXAMPLE.COM").unwrap();
        assert!(pattern.matches("foo.example.com"));
        assert!(pattern.matches("FOO.Example.Com"));
    }

    #[test]
    fn test_domain_invalid_pattern() {
        assert!(DomainPattern::new("*.example.*.com").is_err());
        assert!(DomainPattern::new("example..com").is_err());
    }

    // ========================================================================
    // PortRange tests
    // ========================================================================

    #[test]
    fn test_port_range_single() {
        let range: PortRange = "80".parse().unwrap();
        assert!(range.contains(80));
        assert!(!range.contains(81));
    }

    #[test]
    fn test_port_range_multiple() {
        let range: PortRange = "80-443".parse().unwrap();
        assert!(range.contains(80));
        assert!(range.contains(443));
        assert!(range.contains(200));
        assert!(!range.contains(79));
        assert!(!range.contains(444));
    }

    #[test]
    fn test_port_range_invalid() {
        assert!(PortRange::new(443, 80).is_err());
        assert!("abc".parse::<PortRange>().is_err());
    }

    // ========================================================================
    // AclEngine tests
    // ========================================================================

    #[test]
    fn test_acl_ip_blacklist() {
        let config = AclConfig {
            ip_blacklist: vec!["192.168.1.0/24".to_string()],
            ..Default::default()
        };
        let engine = AclEngine::new(&config).unwrap();

        assert!(engine.check_client_ip(&"192.168.1.100".parse().unwrap()).is_deny());
        assert!(engine.check_client_ip(&"192.168.2.1".parse().unwrap()).is_allowed());
    }

    #[test]
    fn test_acl_ip_whitelist() {
        let config = AclConfig {
            ip_whitelist: vec!["10.0.0.0/8".to_string()],
            ..Default::default()
        };
        let engine = AclEngine::new(&config).unwrap();

        assert!(engine.check_client_ip(&"10.1.2.3".parse().unwrap()).is_allowed());
        assert!(engine.check_client_ip(&"192.168.1.1".parse().unwrap()).is_deny());
    }

    #[test]
    fn test_acl_domain_blacklist() {
        let config = AclConfig {
            domain_blacklist: vec!["*.evil.com".to_string(), "badsite.com".to_string()],
            ..Default::default()
        };
        let engine = AclEngine::new(&config).unwrap();

        assert!(engine.check_domain("foo.evil.com").is_deny());
        assert!(engine.check_domain("badsite.com").is_deny());
        assert!(engine.check_domain("example.com").is_allowed());
    }

    #[test]
    fn test_acl_domain_whitelist() {
        let config = AclConfig {
            domain_whitelist: vec!["*.trusted.com".to_string()],
            ..Default::default()
        };
        let engine = AclEngine::new(&config).unwrap();

        assert!(engine.check_domain("foo.trusted.com").is_allowed());
        assert!(engine.check_domain("evil.com").is_deny());
    }

    #[test]
    fn test_acl_port_blacklist() {
        let config = AclConfig {
            port_blacklist: vec!["22".to_string(), "23-25".to_string()],
            ..Default::default()
        };
        let engine = AclEngine::new(&config).unwrap();

        assert!(engine.check_port(22).is_deny());
        assert!(engine.check_port(23).is_deny());
        assert!(engine.check_port(25).is_deny());
        assert!(engine.check_port(80).is_allowed());
    }

    #[test]
    fn test_acl_port_whitelist() {
        let config = AclConfig {
            port_whitelist: vec!["80".to_string(), "443".to_string()],
            ..Default::default()
        };
        let engine = AclEngine::new(&config).unwrap();

        assert!(engine.check_port(80).is_allowed());
        assert!(engine.check_port(443).is_allowed());
        assert!(engine.check_port(22).is_deny());
    }

    #[test]
    fn test_acl_conflicting_lists() {
        let config = AclConfig {
            ip_whitelist: vec!["10.0.0.0/8".to_string()],
            ip_blacklist: vec!["192.168.0.0/16".to_string()],
            ..Default::default()
        };
        assert!(AclEngine::new(&config).is_err());
    }

    #[tokio::test]
    async fn test_acl_manager() {
        let config = AclConfig {
            ip_blacklist: vec!["192.168.1.0/24".to_string()],
            domain_blacklist: vec!["*.evil.com".to_string()],
            port_blacklist: vec!["22".to_string()],
            max_connections_per_ip: Some(50),
            ..Default::default()
        };
        let manager = AclManager::new(&config).unwrap();

        assert!(manager.check_client_ip(&"192.168.1.100".parse().unwrap()).await.is_deny());
        assert!(manager.check_domain("foo.evil.com").await.is_deny());
        assert!(manager.check_port(22).await.is_deny());
        assert_eq!(manager.max_connections_per_ip().await, Some(50));
    }
}
