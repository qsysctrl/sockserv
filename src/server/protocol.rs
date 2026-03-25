//! SOCKS5 Protocol Implementation (RFC 1928)
//!
//! This module provides types and functions for parsing and serializing
//! SOCKS5 protocol messages.

use bytes::{BufMut, Bytes, BytesMut};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ============================================================================
// Constants
// ============================================================================

/// SOCKS protocol version
pub const SOCKS_VERSION: u8 = 0x05;

/// Reserved byte value (must be 0x00)
pub const RSV: u8 = 0x00;

// Auth Methods
pub const AUTH_NO_AUTH: u8 = 0x00;
pub const AUTH_GSSAPI: u8 = 0x01;
pub const AUTH_USERNAME_PASSWORD: u8 = 0x02;
pub const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

// Address Types
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

// ============================================================================
// Error Types
// ============================================================================

/// SOCKS protocol errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksError {
    InvalidVersion,
    NoAuthMethods,
    InvalidAuthMethod,
    UnsupportedAuthMethod,
    InvalidRequest,
    UnsupportedCommand,
    UnsupportedAddressType,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    BufferTooShort,
    InvalidMessageFormat,
    InvalidReserved,
    DomainNameTooLong,
    IoError(String),
}

impl std::fmt::Display for SocksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocksError::InvalidVersion => write!(f, "invalid SOCKS version"),
            SocksError::NoAuthMethods => write!(f, "no authentication methods provided"),
            SocksError::InvalidAuthMethod => write!(f, "invalid authentication method"),
            SocksError::UnsupportedAuthMethod => write!(f, "unsupported authentication method"),
            SocksError::InvalidRequest => write!(f, "invalid request"),
            SocksError::UnsupportedCommand => write!(f, "unsupported command"),
            SocksError::UnsupportedAddressType => write!(f, "unsupported address type"),
            SocksError::ConnectionNotAllowed => write!(f, "connection not allowed"),
            SocksError::NetworkUnreachable => write!(f, "network unreachable"),
            SocksError::HostUnreachable => write!(f, "host unreachable"),
            SocksError::ConnectionRefused => write!(f, "connection refused"),
            SocksError::TtlExpired => write!(f, "TTL expired"),
            SocksError::CommandNotSupported => write!(f, "command not supported"),
            SocksError::AddressTypeNotSupported => write!(f, "address type not supported"),
            SocksError::BufferTooShort => write!(f, "buffer too short"),
            SocksError::InvalidMessageFormat => write!(f, "invalid message format"),
            SocksError::InvalidReserved => write!(f, "invalid reserved byte"),
            SocksError::DomainNameTooLong => write!(f, "domain name too long (max 255)"),
            SocksError::IoError(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl std::error::Error for SocksError {}

impl From<std::io::Error> for SocksError {
    fn from(err: std::io::Error) -> Self {
        SocksError::IoError(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SocksError>;

// ============================================================================
// Command and Reply Enums (RFC 1928)
// ============================================================================

/// SOCKS5 command codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocksCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for SocksCommand {
    type Error = SocksError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::UdpAssociate),
            _ => Err(SocksError::UnsupportedCommand),
        }
    }
}

impl From<SocksCommand> for u8 {
    fn from(cmd: SocksCommand) -> Self {
        cmd as u8
    }
}

/// SOCKS5 reply codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplyCode {
    Success = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl ReplyCode {
    /// Check if this reply code indicates success
    pub fn is_success(self) -> bool {
        matches!(self, ReplyCode::Success)
    }
}

impl TryFrom<u8> for ReplyCode {
    type Error = SocksError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(Self::Success),
            0x01 => Ok(Self::GeneralFailure),
            0x02 => Ok(Self::ConnectionNotAllowed),
            0x03 => Ok(Self::NetworkUnreachable),
            0x04 => Ok(Self::HostUnreachable),
            0x05 => Ok(Self::ConnectionRefused),
            0x06 => Ok(Self::TtlExpired),
            0x07 => Ok(Self::CommandNotSupported),
            0x08 => Ok(Self::AddressTypeNotSupported),
            _ => Err(SocksError::InvalidMessageFormat),
        }
    }
}

impl From<ReplyCode> for u8 {
    fn from(reply: ReplyCode) -> Self {
        reply as u8
    }
}

// ============================================================================
// Handshake Types
// ============================================================================

/// Authentication method identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthMethod(pub u8);

impl AuthMethod {
    pub const NO_AUTH: Self = Self(AUTH_NO_AUTH);
    pub const GSSAPI: Self = Self(AUTH_GSSAPI);
    pub const USERNAME_PASSWORD: Self = Self(AUTH_USERNAME_PASSWORD);
    pub const NO_ACCEPTABLE: Self = Self(AUTH_NO_ACCEPTABLE);

    pub fn is_supported(&self) -> bool {
        matches!(self.0, AUTH_NO_AUTH | AUTH_GSSAPI | AUTH_USERNAME_PASSWORD)
    }
}

impl From<u8> for AuthMethod {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

/// Client handshake request (method selection)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub version: u8,
    pub methods: Vec<AuthMethod>,
}

impl ClientHello {
    /// Parse client hello from bytes
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 2 {
            return Err(SocksError::BufferTooShort);
        }

        let version = buf[0];
        if version != SOCKS_VERSION {
            return Err(SocksError::InvalidVersion);
        }

        let nmethods = buf[1] as usize;
        if nmethods == 0 {
            return Err(SocksError::NoAuthMethods);
        }

        let expected_len = 2 + nmethods;
        if buf.len() < expected_len {
            return Err(SocksError::BufferTooShort);
        }

        let methods: Vec<AuthMethod> = buf[2..expected_len]
            .iter()
            .map(|&b| AuthMethod::from(b))
            .collect();

        Ok(Self { version, methods })
    }

    /// Serialize client hello to bytes
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(2 + self.methods.len());
        buf.put_u8(self.version);
        buf.put_u8(self.methods.len() as u8);
        for method in &self.methods {
            buf.put_u8(method.0);
        }
        buf.freeze()
    }

    /// Read client hello from async reader
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let version = reader.read_u8().await?;
        if version != SOCKS_VERSION {
            return Err(SocksError::InvalidVersion);
        }

        let nmethods = reader.read_u8().await? as usize;
        if nmethods == 0 {
            return Err(SocksError::NoAuthMethods);
        }

        let mut methods = Vec::with_capacity(nmethods);
        for _ in 0..nmethods {
            let method = reader.read_u8().await?;
            methods.push(AuthMethod::from(method));
        }

        Ok(Self { version, methods })
    }
}

/// Server handshake response (method selection)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHello {
    pub version: u8,
    pub method: AuthMethod,
}

impl ServerHello {
    pub fn new(method: AuthMethod) -> Self {
        Self {
            version: SOCKS_VERSION,
            method,
        }
    }

    /// Parse server hello from bytes
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 2 {
            return Err(SocksError::BufferTooShort);
        }

        let version = buf[0];
        if version != SOCKS_VERSION {
            return Err(SocksError::InvalidVersion);
        }

        let method = AuthMethod::from(buf[1]);

        Ok(Self { version, method })
    }

    /// Serialize server hello to bytes
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(2);
        buf.put_u8(self.version);
        buf.put_u8(self.method.0);
        buf.freeze()
    }

    /// Write server hello to async writer
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.version).await?;
        writer.write_u8(self.method.0).await?;
        writer.flush().await?;
        Ok(())
    }
}

// ============================================================================
// Address Types
// ============================================================================

/// SOCKS5 address type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksAddress {
    Ipv4(Ipv4Addr, u16),
    Domain(String, u16),
    Ipv6(Ipv6Addr, u16),
}

impl SocksAddress {
    /// Maximum domain name length per RFC 1928
    const MAX_DOMAIN_LEN: usize = 255;

    /// Parse address from bytes
    pub fn parse(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.is_empty() {
            return Err(SocksError::BufferTooShort);
        }

        let atyp = buf[0];
        match atyp {
            ATYP_IPV4 => {
                if buf.len() < 7 {
                    return Err(SocksError::BufferTooShort);
                }
                let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok((Self::Ipv4(ip, port), 7))
            }
            ATYP_DOMAIN => {
                if buf.len() < 2 {
                    return Err(SocksError::BufferTooShort);
                }
                let domain_len = buf[1] as usize;
                // RFC 1928: domain length must be 1-255 (0 is invalid, >255 is too long)
                if domain_len == 0 || domain_len > Self::MAX_DOMAIN_LEN {
                    return Err(SocksError::DomainNameTooLong);
                }
                if buf.len() < 2 + domain_len + 2 {
                    return Err(SocksError::BufferTooShort);
                }
                // UTF-8 validation with single allocation (to_string)
                // Avoids intermediate Vec<u8> allocation
                let domain = str::from_utf8(&buf[2..2 + domain_len])
                    .map_err(|_| SocksError::InvalidMessageFormat)?
                    .to_string();
                let port = u16::from_be_bytes([
                    buf[2 + domain_len],
                    buf[2 + domain_len + 1],
                ]);
                Ok((Self::Domain(domain, port), 2 + domain_len + 2))
            }
            ATYP_IPV6 => {
                if buf.len() < 19 {
                    return Err(SocksError::BufferTooShort);
                }
                let ip = Ipv6Addr::from([
                    buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
                    buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16],
                ]);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok((Self::Ipv6(ip, port), 19))
            }
            _ => Err(SocksError::AddressTypeNotSupported),
        }
    }

    /// Serialize address to bytes
    pub fn serialize(&self) -> Bytes {
        match self {
            Self::Ipv4(ip, port) => {
                let mut buf = BytesMut::with_capacity(7);
                buf.put_u8(ATYP_IPV4);
                buf.put_slice(&ip.octets());
                buf.put_u16(*port);
                buf.freeze()
            }
            Self::Domain(domain, port) => {
                let mut buf = BytesMut::with_capacity(2 + domain.len() + 2);
                buf.put_u8(ATYP_DOMAIN);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
                buf.put_u16(*port);
                buf.freeze()
            }
            Self::Ipv6(ip, port) => {
                let mut buf = BytesMut::with_capacity(19);
                buf.put_u8(ATYP_IPV6);
                buf.put_slice(&ip.octets());
                buf.put_u16(*port);
                buf.freeze()
            }
        }
    }

    /// Get the address type byte
    pub fn atyp(&self) -> u8 {
        match self {
            Self::Ipv4(_, _) => ATYP_IPV4,
            Self::Domain(_, _) => ATYP_DOMAIN,
            Self::Ipv6(_, _) => ATYP_IPV6,
        }
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// SOCKS5 request command
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksRequest {
    pub version: u8,
    pub command: SocksCommand,
    pub address: SocksAddress,
}

impl SocksRequest {
    /// Parse request from bytes
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(SocksError::BufferTooShort);
        }

        let version = buf[0];
        if version != SOCKS_VERSION {
            return Err(SocksError::InvalidVersion);
        }

        // Use TryFrom for safe command conversion
        let command = SocksCommand::try_from(buf[1])?;
        let rsv = buf[2];
        if rsv != RSV {
            return Err(SocksError::InvalidReserved);
        }

        let (address, _) = SocksAddress::parse(&buf[3..])?;

        Ok(Self {
            version,
            command,
            address,
        })
    }

    /// Serialize request to bytes
    pub fn serialize(&self) -> Bytes {
        let addr_bytes = self.address.serialize();
        // Request: VER(1) + CMD(1) + RSV(1) + addr_bytes
        let mut buf = BytesMut::with_capacity(3 + addr_bytes.len());
        buf.put_u8(self.version);
        buf.put_u8(self.command as u8);
        buf.put_u8(RSV);
        buf.put_slice(&addr_bytes);
        buf.freeze()
    }

    /// Read request from async reader
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let version = reader.read_u8().await?;
        if version != SOCKS_VERSION {
            return Err(SocksError::InvalidVersion);
        }

        let command_byte = reader.read_u8().await?;
        let command = SocksCommand::try_from(command_byte)?;
        let rsv = reader.read_u8().await?;
        if rsv != RSV {
            return Err(SocksError::InvalidReserved);
        }

        // Read address type
        let atyp = reader.read_u8().await?;
        let address = match atyp {
            ATYP_IPV4 => {
                let mut ip = [0u8; 4];
                reader.read_exact(&mut ip).await?;
                let port = reader.read_u16().await?;
                SocksAddress::Ipv4(Ipv4Addr::from(ip), port)
            }
            ATYP_DOMAIN => {
                let domain_len = reader.read_u8().await? as usize;
                // RFC 1928: domain length must be 1-255
                if domain_len == 0 || domain_len > SocksAddress::MAX_DOMAIN_LEN {
                    return Err(SocksError::DomainNameTooLong);
                }
                let mut domain = vec![0u8; domain_len];
                reader.read_exact(&mut domain).await?;
                let port = reader.read_u16().await?;
                // UTF-8 validation with single allocation (to_string)
                // Avoids intermediate Vec<u8> allocation
                let domain_str = str::from_utf8(&domain)
                    .map_err(|_| SocksError::InvalidMessageFormat)?
                    .to_string();
                SocksAddress::Domain(domain_str, port)
            }
            ATYP_IPV6 => {
                let mut ip = [0u8; 16];
                reader.read_exact(&mut ip).await?;
                let port = reader.read_u16().await?;
                SocksAddress::Ipv6(Ipv6Addr::from(ip), port)
            }
            _ => return Err(SocksError::AddressTypeNotSupported),
        };

        Ok(Self {
            version,
            command,
            address,
        })
    }
}

// Reply codes removed - now using ReplyCode enum above

/// SOCKS5 response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksResponse {
    pub version: u8,
    pub reply: ReplyCode,
    pub address: SocksAddress,
}

impl SocksResponse {
    pub fn new(reply: ReplyCode, address: SocksAddress) -> Self {
        Self {
            version: SOCKS_VERSION,
            reply,
            address,
        }
    }

    /// Parse response from bytes
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(SocksError::BufferTooShort);
        }

        let version = buf[0];
        if version != SOCKS_VERSION {
            return Err(SocksError::InvalidVersion);
        }

        // Use TryFrom for safe reply code conversion
        let reply = ReplyCode::try_from(buf[1])?;
        let rsv = buf[2];
        if rsv != RSV {
            return Err(SocksError::InvalidReserved);
        }

        let (address, _) = SocksAddress::parse(&buf[3..])?;

        Ok(Self {
            version,
            reply,
            address,
        })
    }

    /// Serialize response to bytes
    pub fn serialize(&self) -> Bytes {
        let addr_bytes = self.address.serialize();
        // Response: VER(1) + REP(1) + RSV(1) + addr_bytes
        let mut buf = BytesMut::with_capacity(3 + addr_bytes.len());
        buf.put_u8(self.version);
        buf.put_u8(self.reply as u8);
        buf.put_u8(RSV);
        buf.put_slice(&addr_bytes);
        buf.freeze()
    }

    /// Write response to async writer
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.version).await?;
        // Use TryFrom for safe reply code conversion
        writer.write_u8(self.reply as u8).await?;
        writer.write_u8(RSV).await?;

        match &self.address {
            SocksAddress::Ipv4(ip, port) => {
                writer.write_u8(ATYP_IPV4).await?;
                writer.write_all(&ip.octets()).await?;
                writer.write_u16(*port).await?;
            }
            SocksAddress::Domain(domain, port) => {
                writer.write_u8(ATYP_DOMAIN).await?;
                // Safe length conversion with explicit check to prevent truncation
                let domain_len = domain.len();
                if domain_len > SocksAddress::MAX_DOMAIN_LEN {
                    return Err(SocksError::DomainNameTooLong);
                }
                writer.write_u8(domain_len as u8).await?;
                writer.write_all(domain.as_bytes()).await?;
                writer.write_u16(*port).await?;
            }
            SocksAddress::Ipv6(ip, port) => {
                writer.write_u8(ATYP_IPV6).await?;
                writer.write_all(&ip.octets()).await?;
                writer.write_u16(*port).await?;
            }
        }

        writer.flush().await?;
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tokio_test::io::Builder;

    // ========================================================================
    // Unit Tests: ClientHello
    // ========================================================================

    mod client_hello {
        use super::*;

        #[test]
        fn test_parse_valid_client_hello_no_auth() {
            // VER=0x05, NMETHODS=1, METHODS=[0x00]
            let buf = [0x05, 0x01, 0x00];
            let result = ClientHello::parse(&buf).unwrap();
            
            assert_eq!(result.version, 0x05);
            assert_eq!(result.methods.len(), 1);
            assert_eq!(result.methods[0], AuthMethod::NO_AUTH);
        }

        #[test]
        fn test_parse_valid_client_hello_multiple_methods() {
            // VER=0x05, NMETHODS=3, METHODS=[0x00, 0x01, 0x02]
            let buf = [0x05, 0x03, 0x00, 0x01, 0x02];
            let result = ClientHello::parse(&buf).unwrap();
            
            assert_eq!(result.version, 0x05);
            assert_eq!(result.methods.len(), 3);
            assert_eq!(result.methods[0], AuthMethod::NO_AUTH);
            assert_eq!(result.methods[1], AuthMethod::GSSAPI);
            assert_eq!(result.methods[2], AuthMethod::USERNAME_PASSWORD);
        }

        #[test]
        fn test_parse_invalid_version() {
            let buf = [0x04, 0x01, 0x00];
            let result = ClientHello::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::InvalidVersion);
        }

        #[test]
        fn test_parse_buffer_too_short() {
            let buf = [0x05];
            let result = ClientHello::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::BufferTooShort);
        }

        #[test]
        fn test_parse_no_auth_methods() {
            let buf = [0x05, 0x00];
            let result = ClientHello::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::NoAuthMethods);
        }

        #[test]
        fn test_parse_incomplete_methods() {
            // Claims 3 methods but only provides 2
            let buf = [0x05, 0x03, 0x00, 0x01];
            let result = ClientHello::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::BufferTooShort);
        }

        #[test]
        fn test_serialize_client_hello() {
            let hello = ClientHello {
                version: 0x05,
                methods: vec![AuthMethod::NO_AUTH, AuthMethod::GSSAPI],
            };
            let serialized = hello.serialize();
            
            assert_eq!(serialized.as_ref(), &[0x05, 0x02, 0x00, 0x01]);
        }

        #[test]
        fn test_roundtrip_serialize_parse() {
            let original = ClientHello {
                version: 0x05,
                methods: vec![
                    AuthMethod::NO_AUTH,
                    AuthMethod::GSSAPI,
                    AuthMethod::USERNAME_PASSWORD,
                ],
            };
            
            let serialized = original.serialize();
            let parsed = ClientHello::parse(&serialized).unwrap();
            
            assert_eq!(original, parsed);
        }
    }

    // ========================================================================
    // Unit Tests: ServerHello
    // ========================================================================

    mod server_hello {
        use super::*;

        #[test]
        fn test_server_hello_new() {
            let hello = ServerHello::new(AuthMethod::NO_AUTH);
            
            assert_eq!(hello.version, 0x05);
            assert_eq!(hello.method, AuthMethod::NO_AUTH);
        }

        #[test]
        fn test_parse_valid_server_hello() {
            let buf = [0x05, 0x00];
            let result = ServerHello::parse(&buf).unwrap();
            
            assert_eq!(result.version, 0x05);
            assert_eq!(result.method, AuthMethod::NO_AUTH);
        }

        #[test]
        fn test_parse_invalid_version() {
            let buf = [0x04, 0x00];
            let result = ServerHello::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::InvalidVersion);
        }

        #[test]
        fn test_parse_buffer_too_short() {
            let buf = [0x05];
            let result = ServerHello::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::BufferTooShort);
        }

        #[test]
        fn test_serialize_server_hello() {
            let hello = ServerHello::new(AuthMethod::USERNAME_PASSWORD);
            let serialized = hello.serialize();
            
            assert_eq!(serialized.as_ref(), &[0x05, 0x02]);
        }

        #[test]
        fn test_serialize_no_acceptable_methods() {
            let hello = ServerHello::new(AuthMethod::NO_ACCEPTABLE);
            let serialized = hello.serialize();
            
            assert_eq!(serialized.as_ref(), &[0x05, 0xFF]);
        }

        #[test]
        fn test_roundtrip_serialize_parse() {
            let original = ServerHello::new(AuthMethod::GSSAPI);
            
            let serialized = original.serialize();
            let parsed = ServerHello::parse(&serialized).unwrap();
            
            assert_eq!(original, parsed);
        }
    }

    // ========================================================================
    // Unit Tests: SocksAddress
    // ========================================================================

    mod socks_address {
        use super::*;

        #[test]
        fn test_parse_ipv4_address() {
            // ATYP=0x01, IP=192.168.1.1, PORT=8080 (0x1F90)
            let buf = [0x01, 192, 168, 1, 1, 0x1F, 0x90];
            let (addr, len) = SocksAddress::parse(&buf).unwrap();
            
            assert_eq!(len, 7);
            match addr {
                SocksAddress::Ipv4(ip, port) => {
                    assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
                    assert_eq!(port, 8080);
                }
                _ => panic!("Expected IPv4 address"),
            }
        }

        #[test]
        fn test_parse_ipv6_address() {
            // ATYP=0x04, IP=::1, PORT=443 (0x01BB)
            let mut buf = [0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xBB];
            let (addr, len) = SocksAddress::parse(&buf).unwrap();
            
            assert_eq!(len, 19);
            match addr {
                SocksAddress::Ipv6(ip, port) => {
                    assert_eq!(ip, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
                    assert_eq!(port, 443);
                }
                _ => panic!("Expected IPv6 address"),
            }
        }

        #[test]
        fn test_parse_domain_address() {
            // ATYP=0x03, LEN=9, DOMAIN="localhost", PORT=80
            let buf = [0x03, 9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0x00, 0x50];
            let (addr, len) = SocksAddress::parse(&buf).unwrap();
            
            assert_eq!(len, 13);
            match addr {
                SocksAddress::Domain(domain, port) => {
                    assert_eq!(domain, "localhost");
                    assert_eq!(port, 80);
                }
                _ => panic!("Expected domain address"),
            }
        }

        #[test]
        fn test_parse_invalid_atyp() {
            let buf = [0x02, 192, 168, 1, 1, 0x00, 0x50];
            let result = SocksAddress::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::AddressTypeNotSupported);
        }

        #[test]
        fn test_parse_ipv4_buffer_too_short() {
            let buf = [0x01, 192, 168, 1];
            let result = SocksAddress::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::BufferTooShort);
        }

        #[test]
        fn test_parse_ipv6_buffer_too_short() {
            let buf = [0x04, 0, 0, 0, 0, 0, 0, 0, 0];
            let result = SocksAddress::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::BufferTooShort);
        }

        #[test]
        fn test_parse_domain_buffer_too_short() {
            let buf = [0x03, 9, b'l', b'o', b'c'];
            let result = SocksAddress::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::BufferTooShort);
        }

        #[test]
        fn test_parse_domain_zero_length() {
            let buf = [0x03, 0, 0x00, 0x50];
            let result = SocksAddress::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::DomainNameTooLong);
        }

        #[test]
        fn test_serialize_ipv4_address() {
            let addr = SocksAddress::Ipv4(Ipv4Addr::new(192, 168, 1, 1), 8080);
            let serialized = addr.serialize();
            
            assert_eq!(serialized.as_ref(), &[0x01, 192, 168, 1, 1, 0x1F, 0x90]);
        }

        #[test]
        fn test_serialize_ipv6_address() {
            let addr = SocksAddress::Ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 443);
            let serialized = addr.serialize();
            
            let expected = [0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xBB];
            assert_eq!(serialized.as_ref(), &expected);
        }

        #[test]
        fn test_serialize_domain_address() {
            let addr = SocksAddress::Domain("localhost".to_string(), 80);
            let serialized = addr.serialize();
            
            let expected = [0x03, 9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0x00, 0x50];
            assert_eq!(serialized.as_ref(), &expected);
        }

        #[test]
        fn test_roundtrip_ipv4() {
            let original = SocksAddress::Ipv4(Ipv4Addr::new(10, 0, 0, 1), 1080);
            let serialized = original.serialize();
            let (parsed, _) = SocksAddress::parse(&serialized).unwrap();
            assert_eq!(original, parsed);
        }

        #[test]
        fn test_roundtrip_ipv6() {
            let original = SocksAddress::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443);
            let serialized = original.serialize();
            let (parsed, _) = SocksAddress::parse(&serialized).unwrap();
            assert_eq!(original, parsed);
        }

        #[test]
        fn test_roundtrip_domain() {
            let original = SocksAddress::Domain("example.com".to_string(), 8080);
            let serialized = original.serialize();
            let (parsed, _) = SocksAddress::parse(&serialized).unwrap();
            assert_eq!(original, parsed);
        }

        #[test]
        fn test_atyp_ipv4() {
            let addr = SocksAddress::Ipv4(Ipv4Addr::LOCALHOST, 80);
            assert_eq!(addr.atyp(), ATYP_IPV4);
        }

        #[test]
        fn test_atyp_domain() {
            let addr = SocksAddress::Domain("test".to_string(), 80);
            assert_eq!(addr.atyp(), ATYP_DOMAIN);
        }

        #[test]
        fn test_atyp_ipv6() {
            let addr = SocksAddress::Ipv6(Ipv6Addr::LOCALHOST, 80);
            assert_eq!(addr.atyp(), ATYP_IPV6);
        }
    }

    // ========================================================================
    // Unit Tests: SocksRequest
    // ========================================================================

    mod socks_request {
        use super::*;

        #[test]
        fn test_parse_connect_request_ipv4() {
            // VER=0x05, CMD=0x01, RSV=0x00, ATYP=0x01, IP=127.0.0.1, PORT=80
            let buf = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];
            let result = SocksRequest::parse(&buf).unwrap();
            
            assert_eq!(result.version, 0x05);
            assert_eq!(result.command, SocksCommand::Connect);
            match result.address {
                SocksAddress::Ipv4(ip, port) => {
                    assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1));
                    assert_eq!(port, 80);
                }
                _ => panic!("Expected IPv4 address"),
            }
        }

        #[test]
        fn test_parse_bind_request() {
            let buf = [0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            let result = SocksRequest::parse(&buf).unwrap();
            
            assert_eq!(result.command, SocksCommand::Bind);
        }

        #[test]
        fn test_parse_udp_associate_request() {
            let buf = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            let result = SocksRequest::parse(&buf).unwrap();
            
            assert_eq!(result.command, SocksCommand::UdpAssociate);
        }

        #[test]
        fn test_parse_invalid_version() {
            let buf = [0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];
            let result = SocksRequest::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::InvalidVersion);
        }

        #[test]
        fn test_parse_invalid_reserved() {
            let buf = [0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1, 0x00, 0x50];
            let result = SocksRequest::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::InvalidReserved);
        }

        #[test]
        fn test_parse_buffer_too_short() {
            let buf = [0x05, 0x01, 0x00];
            let result = SocksRequest::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::BufferTooShort);
        }

        #[test]
        fn test_serialize_connect_request() {
            let request = SocksRequest {
                version: 0x05,
                command: SocksCommand::Connect,
                address: SocksAddress::Ipv4(Ipv4Addr::new(192, 168, 1, 100), 8080),
            };
            let serialized = request.serialize();
            
            let expected = [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 100, 0x1F, 0x90];
            assert_eq!(serialized.as_ref(), &expected);
        }

        #[test]
        fn test_serialize_domain_request() {
            let request = SocksRequest {
                version: 0x05,
                command: SocksCommand::Connect,
                address: SocksAddress::Domain("google.com".to_string(), 443),
            };
            let serialized = request.serialize();
            
            let expected = [
                0x05, 0x01, 0x00, 0x03, 10,
                b'g', b'o', b'o', b'g', b'l', b'e', b'.', b'c', b'o', b'm',
                0x01, 0xBB,
            ];
            assert_eq!(serialized.as_ref(), &expected);
        }

        #[test]
        fn test_roundtrip_request() {
            let original = SocksRequest {
                version: 0x05,
                command: SocksCommand::Connect,
                address: SocksAddress::Ipv6(Ipv6Addr::LOCALHOST, 8080),
            };
            
            let serialized = original.serialize();
            let parsed = SocksRequest::parse(&serialized).unwrap();
            
            assert_eq!(original, parsed);
        }
    }

    // ========================================================================
    // Unit Tests: SocksResponse
    // ========================================================================

    mod socks_response {
        use super::*;

        #[test]
        fn test_new_success_response() {
            let addr = SocksAddress::Ipv4(Ipv4Addr::new(127, 0, 0, 1), 80);
            let response = SocksResponse::new(ReplyCode::Success, addr);
            
            assert_eq!(response.version, 0x05);
            assert!(response.reply.is_success());
        }

        #[test]
        fn test_parse_success_response() {
            let buf = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];
            let result = SocksResponse::parse(&buf).unwrap();
            
            assert_eq!(result.version, 0x05);
            assert_eq!(result.reply, ReplyCode::Success);
        }

        #[test]
        fn test_parse_failure_response() {
            let buf = [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            let result = SocksResponse::parse(&buf).unwrap();
            
            assert_eq!(result.reply, ReplyCode::HostUnreachable);
        }

        #[test]
        fn test_parse_invalid_version() {
            let buf = [0x04, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];
            let result = SocksResponse::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::InvalidVersion);
        }

        #[test]
        fn test_parse_invalid_reserved() {
            let buf = [0x05, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0x00, 0x50];
            let result = SocksResponse::parse(&buf);
            assert_eq!(result.unwrap_err(), SocksError::InvalidReserved);
        }

        #[test]
        fn test_serialize_success_response() {
            let response = SocksResponse::new(
                ReplyCode::Success,
                SocksAddress::Ipv4(Ipv4Addr::new(10, 0, 0, 1), 1080),
            );
            let serialized = response.serialize();
            
            let expected = [0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x04, 0x38];
            assert_eq!(serialized.as_ref(), &expected);
        }

        #[test]
        fn test_serialize_connection_refused() {
            let response = SocksResponse::new(
                ReplyCode::ConnectionRefused,
                SocksAddress::Ipv4(Ipv4Addr::UNSPECIFIED, 0),
            );
            let serialized = response.serialize();
            
            let expected = [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            assert_eq!(serialized.as_ref(), &expected);
        }

        #[test]
        fn test_roundtrip_response() {
            let original = SocksResponse::new(
                ReplyCode::NetworkUnreachable,
                SocksAddress::Domain("error.local".to_string(), 0),
            );
            
            let serialized = original.serialize();
            let parsed = SocksResponse::parse(&serialized).unwrap();
            
            assert_eq!(original, parsed);
        }
    }

    // ========================================================================
    // Unit Tests: Async Operations
    // ========================================================================

    mod async_operations {
        use super::*;

        #[tokio::test]
        async fn test_read_client_hello_async() {
            let mock = Builder::new()
                .read(&[0x05])
                .read(&[0x02])
                .read(&[0x00, 0x02])
                .build();
            
            let mut reader = mock;
            let result = ClientHello::read_from(&mut reader).await.unwrap();
            
            assert_eq!(result.version, 0x05);
            assert_eq!(result.methods.len(), 2);
            assert_eq!(result.methods[0], AuthMethod::NO_AUTH);
            assert_eq!(result.methods[1], AuthMethod::USERNAME_PASSWORD);
        }

        #[tokio::test]
        async fn test_write_server_hello_async() {
            let mut builder = Builder::new();
            builder.write(&[0x05, 0x00]);
            let mut writer = builder.build();
            
            let hello = ServerHello::new(AuthMethod::NO_AUTH);
            let result = hello.write_to(&mut writer).await;
            
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_read_request_async_ipv4() {
            let mock = Builder::new()
                .read(&[0x05, 0x01, 0x00, 0x01])
                .read(&[192, 168, 1, 1])
                .read(&[0x00, 0x50])
                .build();
            
            let mut reader = mock;
            let result = SocksRequest::read_from(&mut reader).await.unwrap();
            
            assert_eq!(result.command, SocksCommand::Connect);
            match result.address {
                SocksAddress::Ipv4(ip, port) => {
                    assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
                    assert_eq!(port, 80);
                }
                _ => panic!("Expected IPv4"),
            }
        }

        #[tokio::test]
        async fn test_write_response_async() {
            let mut builder = Builder::new();
            builder.write(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]);
            let mut writer = builder.build();
            
            let response = SocksResponse::new(
                ReplyCode::Success,
                SocksAddress::Ipv4(Ipv4Addr::new(127, 0, 0, 1), 80),
            );
            let result = response.write_to(&mut writer).await;
            
            assert!(result.is_ok());
        }
    }

    // ========================================================================
    // Property-Based Tests (Proptest)
    // ========================================================================

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn prop_client_hello_roundtrip(
                methods in prop::collection::vec(any::<u8>(), 1..=255)
            ) {
                let hello = ClientHello {
                    version: SOCKS_VERSION,
                    methods: methods.into_iter().map(AuthMethod).collect(),
                };
                let serialized = hello.serialize();
                let parsed = ClientHello::parse(&serialized).unwrap();
                assert_eq!(hello, parsed);
            }

            #[test]
            fn prop_server_hello_roundtrip(method_byte in any::<u8>()) {
                let hello = ServerHello::new(AuthMethod(method_byte));
                let serialized = hello.serialize();
                let parsed = ServerHello::parse(&serialized).unwrap();
                assert_eq!(hello, parsed);
            }

            #[test]
            fn prop_ipv4_roundtrip(
                a in any::<u8>(), b in any::<u8>(),
                c in any::<u8>(), d in any::<u8>(),
                port in any::<u16>()
            ) {
                let addr = SocksAddress::Ipv4(Ipv4Addr::new(a, b, c, d), port);
                let serialized = addr.serialize();
                let (parsed, _) = SocksAddress::parse(&serialized).unwrap();
                assert_eq!(addr, parsed);
            }

            #[test]
            fn prop_ipv6_roundtrip(
                ip_bytes in prop::array::uniform16(any::<u8>()),
                port in any::<u16>()
            ) {
                let addr = SocksAddress::Ipv6(Ipv6Addr::from(ip_bytes), port);
                let serialized = addr.serialize();
                let (parsed, _) = SocksAddress::parse(&serialized).unwrap();
                assert_eq!(addr, parsed);
            }

            #[test]
            fn prop_domain_roundtrip(
                domain in prop::string::string_regex("[a-zA-Z0-9.-]{1,100}").unwrap(),
                port in any::<u16>()
            ) {
                let addr = SocksAddress::Domain(domain, port);
                let serialized = addr.serialize();
                let (parsed, _) = SocksAddress::parse(&serialized).unwrap();
                assert_eq!(addr, parsed);
            }

            #[test]
            fn prop_request_roundtrip(
                command in prop_oneof![Just(SocksCommand::Connect), Just(SocksCommand::Bind), Just(SocksCommand::UdpAssociate)],
                a in any::<u8>(), b in any::<u8>(),
                c in any::<u8>(), d in any::<u8>(),
                port in any::<u16>()
            ) {
                let request = SocksRequest {
                    version: SOCKS_VERSION,
                    command,
                    address: SocksAddress::Ipv4(Ipv4Addr::new(a, b, c, d), port),
                };
                let serialized = request.serialize();
                let parsed = SocksRequest::parse(&serialized).unwrap();
                assert_eq!(request, parsed);
            }

            #[test]
            fn prop_response_roundtrip(
                reply_byte in prop_oneof![
                    Just(ReplyCode::Success),
                    Just(ReplyCode::GeneralFailure),
                    Just(ReplyCode::ConnectionNotAllowed),
                    Just(ReplyCode::NetworkUnreachable),
                    Just(ReplyCode::HostUnreachable),
                    Just(ReplyCode::ConnectionRefused),
                    Just(ReplyCode::TtlExpired),
                    Just(ReplyCode::CommandNotSupported),
                    Just(ReplyCode::AddressTypeNotSupported),
                ],
                a in any::<u8>(), b in any::<u8>(),
                c in any::<u8>(), d in any::<u8>(),
                port in any::<u16>()
            ) {
                let response = SocksResponse::new(
                    reply_byte,
                    SocksAddress::Ipv4(Ipv4Addr::new(a, b, c, d), port),
                );
                let serialized = response.serialize();
                let parsed = SocksResponse::parse(&serialized).unwrap();
                assert_eq!(response, parsed);
            }
        }
    }

    // ========================================================================
    // Fuzzing-style Tests
    // ========================================================================

    mod fuzz_tests {
        use super::*;
        use rand::Rng;

        /// Generate random bytes for fuzzing
        fn random_bytes(size: usize) -> Vec<u8> {
            let mut rng = rand::rng();
            (0..size).map(|_| rng.random::<u8>()).collect()
        }

        #[test]
        fn fuzz_client_hello_parse() {
            let mut rng = rand::rng();
            for _ in 0..100 {
                let size = rng.random_range(0..100);
                let buf = random_bytes(size);

                // Should not panic
                let _ = ClientHello::parse(&buf);
            }
        }

        #[test]
        fn fuzz_request_parse() {
            let mut rng = rand::rng();
            for _ in 0..100 {
                let size = rng.random_range(0..200);
                let buf = random_bytes(size);

                // Should not panic
                let _ = SocksRequest::parse(&buf);
            }
        }

        #[test]
        fn fuzz_response_parse() {
            let mut rng = rand::rng();
            for _ in 0..100 {
                let size = rng.random_range(0..200);
                let buf = random_bytes(size);

                // Should not panic
                let _ = SocksResponse::parse(&buf);
            }
        }

        #[test]
        fn fuzz_address_parse() {
            let mut rng = rand::rng();
            for _ in 0..100 {
                let size = rng.random_range(0..100);
                let buf = random_bytes(size);

                // Should not panic
                let _ = SocksAddress::parse(&buf);
            }
        }

        #[test]
        fn fuzz_edge_case_empty_buffer() {
            let empty: [u8; 0] = [];
            
            assert!(ClientHello::parse(&empty).is_err());
            assert!(SocksRequest::parse(&empty).is_err());
            assert!(SocksResponse::parse(&empty).is_err());
            assert!(SocksAddress::parse(&empty).is_err());
        }

        #[test]
        fn fuzz_edge_case_single_byte() {
            let buf = [0x00];
            
            assert!(ClientHello::parse(&buf).is_err());
            assert!(SocksRequest::parse(&buf).is_err());
            assert!(SocksResponse::parse(&buf).is_err());
            assert!(SocksAddress::parse(&buf).is_err());
        }

        #[test]
        fn fuzz_edge_case_all_zeros() {
            let buf = [0x00; 50];
            
            assert!(ClientHello::parse(&buf).is_err());
            assert!(SocksRequest::parse(&buf).is_err());
            assert!(SocksResponse::parse(&buf).is_err());
        }

        #[test]
        fn fuzz_edge_case_all_ones() {
            let buf = [0xFF; 50];
            
            assert!(ClientHello::parse(&buf).is_err());
            assert!(SocksRequest::parse(&buf).is_err());
            assert!(SocksResponse::parse(&buf).is_err());
        }

        #[test]
        fn fuzz_edge_case_invalid_domain_length() {
            // Domain with length 255 (max) + 1
            let mut buf = vec![0x03, 0xFF];
            buf.resize(2 + 255, 0x41); // Fill with 'A'
            
            let result = SocksAddress::parse(&buf);
            assert!(result.is_err());
        }
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    #[cfg(test)]
    mod integration {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        /// Full SOCKS5 handshake simulation
        #[tokio::test]
        async fn test_full_handshake_no_auth() {
            // Create a mock server
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let server_handle = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                
                // Read client hello
                let mut buf = [0u8; 256];
                let n = stream.read(&mut buf).await.unwrap();
                let client_hello = ClientHello::parse(&buf[..n]).unwrap();
                
                // Send server hello (no auth)
                let server_hello = ServerHello::new(AuthMethod::NO_AUTH);
                stream.write_all(&server_hello.serialize()).await.unwrap();
                
                // Read request
                let n = stream.read(&mut buf).await.unwrap();
                let request = SocksRequest::parse(&buf[..n]).unwrap();
                
                // Send success response
                let response = SocksResponse::new(
                    ReplyCode::Success,
                    SocksAddress::Ipv4(Ipv4Addr::new(127, 0, 0, 1), 80),
                );
                stream.write_all(&response.serialize()).await.unwrap();
                
                (client_hello, request)
            });

            // Client side
            let client_handle = tokio::spawn(async move {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                
                // Send client hello
                let client_hello = ClientHello {
                    version: 0x05,
                    methods: vec![AuthMethod::NO_AUTH],
                };
                stream.write_all(&client_hello.serialize()).await.unwrap();
                
                // Read server hello
                let mut buf = [0u8; 2];
                stream.read_exact(&mut buf).await.unwrap();
                let server_hello = ServerHello::parse(&buf).unwrap();
                assert_eq!(server_hello.method, AuthMethod::NO_AUTH);
                
                // Send CONNECT request
                let request = SocksRequest {
                    version: 0x05,
                    command: SocksCommand::Connect,
                    address: SocksAddress::Ipv4(Ipv4Addr::new(127, 0, 0, 1), 80),
                };
                stream.write_all(&request.serialize()).await.unwrap();
                
                // Read response
                let mut buf = [0u8; 256];
                let n = stream.read(&mut buf).await.unwrap();
                let response = SocksResponse::parse(&buf[..n]).unwrap();
                assert!(response.reply.is_success());
            });

            let (server_result, client_result) = tokio::join!(server_handle, client_handle);
            server_result.unwrap();
            client_result.unwrap();
        }

        #[tokio::test]
        async fn test_handshake_with_domain_address() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let server_handle = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                
                let mut buf = [0u8; 256];
                let n = stream.read(&mut buf).await.unwrap();
                let _ = ClientHello::parse(&buf[..n]).unwrap();
                
                let server_hello = ServerHello::new(AuthMethod::NO_AUTH);
                stream.write_all(&server_hello.serialize()).await.unwrap();
                
                let n = stream.read(&mut buf).await.unwrap();
                let request = SocksRequest::parse(&buf[..n]).unwrap();
                
                let response = SocksResponse::new(
                    ReplyCode::Success,
                    SocksAddress::Domain("example.com".to_string(), 443),
                );
                stream.write_all(&response.serialize()).await.unwrap();
                
                request
            });

            let client_handle = tokio::spawn(async move {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                
                let client_hello = ClientHello {
                    version: 0x05,
                    methods: vec![AuthMethod::NO_AUTH],
                };
                stream.write_all(&client_hello.serialize()).await.unwrap();
                
                let mut buf = [0u8; 2];
                stream.read_exact(&mut buf).await.unwrap();
                
                let request = SocksRequest {
                    version: 0x05,
                    command: SocksCommand::Connect,
                    address: SocksAddress::Domain("example.com".to_string(), 443),
                };
                stream.write_all(&request.serialize()).await.unwrap();
                
                let mut buf = [0u8; 256];
                let n = stream.read(&mut buf).await.unwrap();
                let response = SocksResponse::parse(&buf[..n]).unwrap();
                assert!(response.reply.is_success());
            });

            let (server_result, client_result) = tokio::join!(server_handle, client_handle);
            let request = server_result.unwrap();
            client_result.unwrap();
            
            match request.address {
                SocksAddress::Domain(domain, port) => {
                    assert_eq!(domain, "example.com");
                    assert_eq!(port, 443);
                }
                _ => panic!("Expected domain address"),
            }
        }

        #[tokio::test]
        async fn test_handshake_rejection_no_acceptable_methods() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let server_handle = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                
                let mut buf = [0u8; 256];
                let n = stream.read(&mut buf).await.unwrap();
                let client_hello = ClientHello::parse(&buf[..n]).unwrap();
                
                // Client only supports GSSAPI, server doesn't
                let server_hello = ServerHello::new(AuthMethod::NO_ACCEPTABLE);
                stream.write_all(&server_hello.serialize()).await.unwrap();
                
                client_hello
            });

            let client_handle = tokio::spawn(async move {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                
                // Client only supports GSSAPI
                let client_hello = ClientHello {
                    version: 0x05,
                    methods: vec![AuthMethod::GSSAPI],
                };
                stream.write_all(&client_hello.serialize()).await.unwrap();
                
                let mut buf = [0u8; 2];
                stream.read_exact(&mut buf).await.unwrap();
                let server_hello = ServerHello::parse(&buf).unwrap();
                assert_eq!(server_hello.method, AuthMethod::NO_ACCEPTABLE);
            });

            let (server_result, client_result) = tokio::join!(server_handle, client_handle);
            let client_hello = server_result.unwrap();
            client_result.unwrap();
            
            assert_eq!(client_hello.methods[0], AuthMethod::GSSAPI);
        }

        #[tokio::test]
        async fn test_error_response_host_unreachable() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let server_handle = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await.unwrap();
                
                let server_hello = ServerHello::new(AuthMethod::NO_AUTH);
                stream.write_all(&server_hello.serialize()).await.unwrap();
                
                let _ = stream.read(&mut buf).await.unwrap();
                
                let response = SocksResponse::new(
                    ReplyCode::HostUnreachable,
                    SocksAddress::Ipv4(Ipv4Addr::UNSPECIFIED, 0),
                );
                stream.write_all(&response.serialize()).await.unwrap();
            });

            let client_handle = tokio::spawn(async move {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                
                let client_hello = ClientHello {
                    version: 0x05,
                    methods: vec![AuthMethod::NO_AUTH],
                };
                stream.write_all(&client_hello.serialize()).await.unwrap();
                
                let mut buf = [0u8; 2];
                stream.read_exact(&mut buf).await.unwrap();
                
                let request = SocksRequest {
                    version: 0x05,
                    command: SocksCommand::Connect,
                    address: SocksAddress::Ipv4(Ipv4Addr::new(192, 168, 1, 1), 80),
                };
                stream.write_all(&request.serialize()).await.unwrap();
                
                let mut buf = [0u8; 256];
                let n = stream.read(&mut buf).await.unwrap();
                let response = SocksResponse::parse(&buf[..n]).unwrap();
                assert_eq!(response.reply, ReplyCode::HostUnreachable);
            });

            let (_, client_result) = tokio::join!(server_handle, client_handle);
            client_result.unwrap();
        }

        #[tokio::test]
        async fn test_ipv6_handshake() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let server_handle = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await.unwrap();
                
                let server_hello = ServerHello::new(AuthMethod::NO_AUTH);
                stream.write_all(&server_hello.serialize()).await.unwrap();
                
                let n = stream.read(&mut buf).await.unwrap();
                let request = SocksRequest::parse(&buf[..n]).unwrap();
                
                let response = SocksResponse::new(
                    ReplyCode::Success,
                    SocksAddress::Ipv6(Ipv6Addr::LOCALHOST, 8080),
                );
                stream.write_all(&response.serialize()).await.unwrap();
                
                request
            });

            let client_handle = tokio::spawn(async move {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                
                let client_hello = ClientHello {
                    version: 0x05,
                    methods: vec![AuthMethod::NO_AUTH],
                };
                stream.write_all(&client_hello.serialize()).await.unwrap();
                
                let mut buf = [0u8; 2];
                stream.read_exact(&mut buf).await.unwrap();
                
                let request = SocksRequest {
                    version: 0x05,
                    command: SocksCommand::Connect,
                    address: SocksAddress::Ipv6(Ipv6Addr::LOCALHOST, 8080),
                };
                stream.write_all(&request.serialize()).await.unwrap();
                
                let mut buf = [0u8; 256];
                let n = stream.read(&mut buf).await.unwrap();
                let response = SocksResponse::parse(&buf[..n]).unwrap();
                assert!(response.reply.is_success());
            });

            let (server_result, client_result) = tokio::join!(server_handle, client_handle);
            let request = server_result.unwrap();
            client_result.unwrap();
            
            match request.address {
                SocksAddress::Ipv6(ip, port) => {
                    assert_eq!(ip, Ipv6Addr::LOCALHOST);
                    assert_eq!(port, 8080);
                }
                _ => panic!("Expected IPv6 address"),
            }
        }
    }
}
