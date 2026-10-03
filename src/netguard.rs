//! Address safety rules: which IPs an agent refuses to contact unless it was
//! started with `allow_private = true`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::protocol::{CheckError, ErrorKind};

/// The policy applied to every address the agent is about to connect to
/// (including each redirect hop).
#[derive(Debug, Clone, Default)]
pub struct Guard {
    pub allow_private: bool,
    exempt: Vec<IpAddr>,
}

impl Guard {
    pub fn new(allow_private: bool) -> Self {
        Self {
            allow_private,
            exempt: Vec::new(),
        }
    }

    /// Test hook: treat `ip` as public. Lets integration tests run targets on
    /// loopback while still exercising the private-address rules.
    #[doc(hidden)]
    pub fn with_test_exemption(mut self, ip: IpAddr) -> Self {
        self.exempt.push(ip);
        self
    }

    pub fn check(&self, ip: IpAddr) -> Result<(), CheckError> {
        if self.allow_private || self.exempt.contains(&ip) {
            return Ok(());
        }
        match blocked_reason(ip) {
            None => Ok(()),
            Some(reason) => Err(CheckError::new(
                ErrorKind::Blocked,
                format!(
                    "refusing {reason} address {ip}; only agents started with allow_private = true check private targets"
                ),
            )),
        }
    }
}

/// Cloud metadata endpoints (AWS, GCP, Azure, ...). They are covered by the
/// link-local and ULA rules too; listed explicitly so the intent is obvious.
pub const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
pub const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// Why an address is refused, or `None` if it is a public address.
pub fn blocked_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => v4_reason(v4),
        IpAddr::V6(v6) => v6_reason(v6),
    }
}

/// True if the address is private, loopback, link-local, CGNAT, multicast,
/// unspecified, reserved, a ULA, a cloud metadata endpoint, or an IPv6 form
/// that embeds one of those IPv4 addresses.
pub fn is_blocked(ip: IpAddr) -> bool {
    blocked_reason(ip).is_some()
}

fn v4_reason(ip: Ipv4Addr) -> Option<&'static str> {
    let o = ip.octets();
    if ip == METADATA_V4 {
        return Some("cloud metadata");
    }
    if o[0] == 0 {
        return Some("unspecified"); // 0.0.0.0/8 ("this network")
    }
    if ip.is_loopback() {
        return Some("loopback"); // 127.0.0.0/8
    }
    if ip.is_private() {
        return Some("private"); // 10/8, 172.16/12, 192.168/16
    }
    if ip.is_link_local() {
        return Some("link-local"); // 169.254/16
    }
    if o[0] == 100 && (o[1] & 0xC0) == 64 {
        return Some("carrier-grade NAT"); // 100.64.0.0/10
    }
    if ip.is_multicast() {
        return Some("multicast"); // 224/4
    }
    if ip.is_broadcast() || o[0] >= 240 {
        return Some("reserved"); // 240/4 and 255.255.255.255
    }
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return Some("reserved"); // 192.0.0.0/24, IETF protocol assignments
    }
    if o[0] == 198 && (o[1] & 0xFE) == 18 {
        return Some("reserved"); // 198.18.0.0/15, benchmarking
    }
    None
}

fn v6_reason(ip: Ipv6Addr) -> Option<&'static str> {
    if ip == METADATA_V6 {
        return Some("cloud metadata");
    }
    if ip.is_unspecified() {
        return Some("unspecified");
    }
    if ip.is_loopback() {
        return Some("loopback");
    }
    let s = ip.segments();
    // IPv4-mapped ::ffff:a.b.c.d and the deprecated IPv4-compatible ::a.b.c.d
    if s[0..5] == [0, 0, 0, 0, 0] && (s[5] == 0xffff || s[5] == 0) {
        let v4 = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
        return v4_reason(v4);
    }
    // NAT64 well-known prefix 64:ff9b::/96 embeds an IPv4 address
    if s[0..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let v4 = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
        return v4_reason(v4);
    }
    // 6to4 2002:a.b.c.d::/48 embeds an IPv4 address
    if s[0] == 0x2002 {
        let v4 = Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8);
        return v4_reason(v4);
    }
    if (s[0] & 0xfe00) == 0xfc00 {
        return Some("unique local"); // fc00::/7
    }
    if (s[0] & 0xffc0) == 0xfe80 {
        return Some("link-local"); // fe80::/10
    }
    if (s[0] & 0xffc0) == 0xfec0 {
        return Some("site-local"); // fec0::/10, deprecated
    }
    if (s[0] & 0xff00) == 0xff00 {
        return Some("multicast"); // ff00::/8
    }
    if s[0..4] == [0x0100, 0, 0, 0] {
        return Some("reserved"); // 100::/64, discard-only
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(s: &str) -> bool {
        is_blocked(s.parse().unwrap())
    }

    #[test]
    fn ipv4_rules() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.255.255.254",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "192.0.0.8",
            "198.18.0.1",
            "198.19.255.255",
        ] {
            assert!(blocked(ip), "{ip} should be blocked");
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "172.15.255.255",
            "172.32.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "192.0.1.1",
            "198.20.0.1",
            "203.0.113.5",
            "9.9.9.9",
        ] {
            assert!(!blocked(ip), "{ip} should be allowed");
        }
    }

    #[test]
    fn ipv6_rules() {
        for ip in [
            "::",
            "::1",
            "fe80::1",
            "febf::1",
            "fc00::1",
            "fd12:3456::1",
            "fd00:ec2::254",
            "ff02::1",
            "fec0::1",
            "100::1",
        ] {
            assert!(blocked(ip), "{ip} should be blocked");
        }
        for ip in [
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "2a01:4f8::1",
        ] {
            assert!(!blocked(ip), "{ip} should be allowed");
        }
    }

    #[test]
    fn ipv4_embedded_in_ipv6() {
        // IPv4-mapped
        assert!(blocked("::ffff:127.0.0.1"));
        assert!(blocked("::ffff:10.1.2.3"));
        assert!(blocked("::ffff:169.254.169.254"));
        assert!(blocked("::ffff:100.64.1.1"));
        assert!(!blocked("::ffff:8.8.8.8"));
        // IPv4-compatible (deprecated)
        assert!(blocked("::127.0.0.1"));
        assert!(blocked("::192.168.0.1"));
        // NAT64
        assert!(blocked("64:ff9b::10.0.0.1"));
        assert!(!blocked("64:ff9b::1.1.1.1"));
        // 6to4
        assert!(blocked("2002:7f00:1::1"));
        assert!(blocked("2002:a9fe:a9fe::1"));
        assert!(!blocked("2002:0808:0808::1"));
    }

    #[test]
    fn guard_policy() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            Guard::new(false).check(ip).unwrap_err().kind,
            ErrorKind::Blocked
        );
        assert!(Guard::new(true).check(ip).is_ok());
        assert!(Guard::new(false).with_test_exemption(ip).check(ip).is_ok());
        assert!(Guard::new(false).check("1.1.1.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn metadata_endpoints() {
        assert_eq!(
            blocked_reason(IpAddr::V4(METADATA_V4)),
            Some("cloud metadata")
        );
        assert_eq!(
            blocked_reason(IpAddr::V6(METADATA_V6)),
            Some("cloud metadata")
        );
    }
}
