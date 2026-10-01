//! Target address sent to the AnyTLS server.

use bytes::{BufMut, BytesMut};
use std::{
    fmt,
    io::{Error, ErrorKind, Result},
    net::{IpAddr, SocketAddr},
};

/// Target that the AnyTLS server connects to, i.e. the Aggligator TCP acceptor.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnyTlsTarget {
    /// Target IP address.
    Ip(SocketAddr),
    /// Target domain name and port, resolved by the AnyTLS server.
    Domain(String, u16),
}

impl AnyTlsTarget {
    /// Parses a target address, using `default_port` if it does not specify a port number.
    ///
    /// A target that is not an IP address is passed to the AnyTLS server as domain name
    /// and thus resolved by the server.
    pub fn parse(target: &str, default_port: u16) -> Result<Self> {
        let target = with_default_port(target, default_port);
        if let Ok(addr) = target.parse::<SocketAddr>() {
            return Ok(Self::Ip(addr));
        }

        let invalid = || Error::new(ErrorKind::InvalidInput, format!("invalid AnyTLS target: {target}"));
        let (host, port) = target.rsplit_once(':').ok_or_else(invalid)?;
        let port = port.parse().map_err(|_| invalid())?;
        if host.contains(['[', ']', ':']) {
            return Err(invalid());
        }

        let target = Self::Domain(host.to_string(), port);
        target.validate()?;
        Ok(target)
    }

    /// Checks that the target can be encoded as a SOCKS address.
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Domain(host, _) if host.is_empty() || host.len() > u8::MAX as usize => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("AnyTLS target domain must be 1 to 255 bytes long: {host}"),
            )),
            _ => Ok(()),
        }
    }

    /// Appends the target in SOCKS address format.
    ///
    /// The target must have passed [`validate`](Self::validate).
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::Ip(SocketAddr::V4(addr)) => {
                buf.put_u8(0x01);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::Ip(SocketAddr::V6(addr)) => {
                buf.put_u8(0x04);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::Domain(host, port) => {
                buf.put_u8(0x03);
                buf.put_u8(host.len() as u8);
                buf.put_slice(host.as_bytes());
                buf.put_u16(*port);
            }
        }
    }
}

impl From<SocketAddr> for AnyTlsTarget {
    fn from(addr: SocketAddr) -> Self {
        Self::Ip(addr)
    }
}

impl fmt::Display for AnyTlsTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain(domain, port) => write!(f, "{domain}:{port}"),
        }
    }
}

/// Adds the specified port to an address that does not contain a port number.
pub(crate) fn with_default_port(addr: &str, default_port: u16) -> String {
    if addr.parse::<SocketAddr>().is_ok() {
        return addr.to_string();
    }

    if let Ok(ip) = addr.parse::<IpAddr>() {
        return SocketAddr::new(ip, default_port).to_string();
    }

    if addr.rsplit_once(':').is_some_and(|(_, port)| port.parse::<u16>().is_ok()) {
        return addr.to_string();
    }

    format!("{addr}:{default_port}")
}

/// Host part of an address with optional port, without IPv6 brackets.
pub(crate) fn host_part(addr: &str) -> &str {
    if addr.parse::<IpAddr>().is_ok() {
        return addr;
    }
    let host = match addr.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => host,
        _ => addr,
    };
    host.trim_start_matches('[').trim_end_matches(']')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn parses_target() {
        assert_eq!(
            AnyTlsTarget::parse("target.example", 5800).unwrap(),
            AnyTlsTarget::Domain("target.example".into(), 5800)
        );
        assert_eq!(
            AnyTlsTarget::parse("target.example:1234", 5800).unwrap(),
            AnyTlsTarget::Domain("target.example".into(), 1234)
        );
        assert_eq!(
            AnyTlsTarget::parse("127.0.0.1", 5800).unwrap(),
            AnyTlsTarget::Ip(SocketAddr::from(([127, 0, 0, 1], 5800)))
        );
        assert_eq!(
            AnyTlsTarget::parse("::1", 5800).unwrap(),
            AnyTlsTarget::Ip(SocketAddr::from((Ipv6Addr::LOCALHOST, 5800)))
        );
        assert!(AnyTlsTarget::parse("", 5800).is_err());
        assert!(AnyTlsTarget::parse(&"a".repeat(256), 5800).is_err());
    }

    #[test]
    fn encodes_socks_address() {
        let mut buf = BytesMut::new();
        AnyTlsTarget::Ip(SocketAddr::from(([10, 0, 0, 1], 5800))).encode(&mut buf);
        assert_eq!(&buf[..], &[0x01, 10, 0, 0, 1, 0x16, 0xa8]);

        let mut buf = BytesMut::new();
        AnyTlsTarget::Ip(SocketAddr::from((Ipv6Addr::LOCALHOST, 1))).encode(&mut buf);
        assert_eq!(buf[0], 0x04);
        assert_eq!(buf.len(), 1 + 16 + 2);

        let mut buf = BytesMut::new();
        AnyTlsTarget::Domain("ab".into(), 0x0102).encode(&mut buf);
        assert_eq!(&buf[..], &[0x03, 2, b'a', b'b', 0x01, 0x02]);
    }

    #[test]
    fn host_parts() {
        assert_eq!(host_part("server.example"), "server.example");
        assert_eq!(host_part("server.example:443"), "server.example");
        assert_eq!(host_part("10.0.0.1:443"), "10.0.0.1");
        assert_eq!(host_part("::1"), "::1");
        assert_eq!(host_part("[::1]:443"), "::1");
    }
}
