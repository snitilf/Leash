//! host-rule syntax for net rules (policy.md section 2.2).
//!
//! assumptions: a host rule is one of a fixed set of shapes, parsed and validated at load
//! time so the run never begins with a host the engine cannot reason about. the shapes are:
//! the catch-all `*`, an exact hostname, a `*.suffix` wildcard, a literal IP address, or a
//! CIDR block. address-family rules (IP, CIDR, `*`) match a connection's destination
//! address directly. name rules (exact, suffix) are enforced in slice 2 by the supervisor
//! resolving the rule's name itself and matching the child's destination IP against the
//! resolved set; the child's resolver is never trusted (policy.md section 2.2). the match
//! helpers here are the pure primitives that later step composes.
//!
//! not yet implemented here: policy.md section 2.2 pins IPv4-mapped IPv6 normalization on
//! the rule side too (`::ffff:1.2.3.4` loading as `1.2.3.4`, a mapped `/96`-or-longer CIDR
//! loading as the IPv4 block it covers, a shorter mapped CIDR rejected at load). until that
//! seam lands with the issue #26 implementation PR, a mapped-form rule is stored as written
//! and will not match the IPv4 form of the same destination.

use std::fmt;
use std::net::IpAddr;

/// a parsed, validated host rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRule {
    /// `*`: matches every host. the catch-all used for a blanket ask or deny.
    Any,
    /// an exact hostname, stored lowercased for case-insensitive comparison
    Exact(String),
    /// a `*.suffix` wildcard; the stored suffix is the part after `*.`, lowercased, and
    /// matches any strict subdomain of it (not the bare apex)
    Suffix(String),
    /// a literal IP address
    Ip(IpAddr),
    /// a CIDR block: a network address plus a prefix length in bits
    Cidr {
        /// the network address as written
        addr: IpAddr,
        /// the prefix length in bits (0..=32 for v4, 0..=128 for v6)
        prefix: u8,
    },
}

/// why a host string is not a valid rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    /// the host string is empty
    #[error("host is empty")]
    Empty,
    /// not a valid hostname (bad label, illegal character, or too long)
    #[error("not a valid hostname")]
    InvalidHostname,
    /// the `*.` wildcard has no valid suffix after it
    #[error("'*.' wildcard needs a valid hostname suffix")]
    InvalidWildcard,
    /// the CIDR block has a bad address or a prefix length out of range
    #[error("not a valid CIDR block")]
    InvalidCidr,
}

impl HostRule {
    /// parse and validate a host string into one of the fixed shapes. the order of checks
    /// is significant: `*` and `*.` are recognized first, then CIDR (it carries a `/`),
    /// then a bare IP, and anything left must be a valid hostname.
    pub fn parse(host: &str) -> Result<HostRule, HostError> {
        if host.is_empty() {
            return Err(HostError::Empty);
        }
        if host == "*" {
            return Ok(HostRule::Any);
        }
        if let Some(suffix) = host.strip_prefix("*.") {
            if valid_hostname(suffix) {
                return Ok(HostRule::Suffix(suffix.to_ascii_lowercase()));
            }
            return Err(HostError::InvalidWildcard);
        }
        if let Some((addr, prefix)) = host.split_once('/') {
            let addr: IpAddr = addr.parse().map_err(|_| HostError::InvalidCidr)?;
            let prefix: u8 = prefix.parse().map_err(|_| HostError::InvalidCidr)?;
            let max = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max {
                return Err(HostError::InvalidCidr);
            }
            return Ok(HostRule::Cidr { addr, prefix });
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(HostRule::Ip(ip));
        }
        if valid_hostname(host) {
            return Ok(HostRule::Exact(host.to_ascii_lowercase()));
        }
        Err(HostError::InvalidHostname)
    }

    /// does this rule match a destination IP address? this is the primitive the address
    /// families use directly; name rules resolve elsewhere and do not match an IP here.
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        match self {
            HostRule::Any => true,
            HostRule::Ip(a) => *a == ip,
            HostRule::Cidr { addr, prefix } => cidr_contains(*addr, *prefix, ip),
            HostRule::Exact(_) | HostRule::Suffix(_) => false,
        }
    }

    /// does this rule match a destination hostname? case-insensitive. a suffix rule matches
    /// strict subdomains only (`*.example.com` matches `api.example.com`, not
    /// `example.com`). address families do not match a name here.
    pub fn matches_hostname(&self, name: &str) -> bool {
        match self {
            HostRule::Any => true,
            HostRule::Exact(h) => name.eq_ignore_ascii_case(h),
            HostRule::Suffix(suffix) => {
                let name = name.to_ascii_lowercase();
                name.len() > suffix.len() + 1 && name.ends_with(suffix) && {
                    // the character just before the matched suffix must be the dot that
                    // separates the subdomain label, so "notexample.com" does not match
                    // a suffix of "example.com"
                    name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
                }
            }
            HostRule::Ip(_) | HostRule::Cidr { .. } => false,
        }
    }
}

impl fmt::Display for HostRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostRule::Any => f.write_str("*"),
            HostRule::Exact(h) => f.write_str(h),
            HostRule::Suffix(s) => write!(f, "*.{s}"),
            HostRule::Ip(ip) => write!(f, "{ip}"),
            HostRule::Cidr { addr, prefix } => write!(f, "{addr}/{prefix}"),
        }
    }
}

/// is this a syntactically valid hostname: nonempty, at most 253 characters, dot-separated
/// labels of 1..=63 characters, each label alphanumeric-or-hyphen and not hyphen-bounded.
fn valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(valid_label)
}

fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return false;
    }
    label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// does the network `addr`/`prefix` contain `ip`? false across address families. the mask
/// is built carefully because shifting an integer by its full width is undefined, so a
/// zero prefix (match everything) is handled on its own.
fn cidr_contains(addr: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (addr, ip) {
        (IpAddr::V4(net), IpAddr::V4(target)) => {
            let mask: u32 = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(net) & mask) == (u32::from(target) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(target)) => {
            let mask: u128 = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(net) & mask) == (u128::from(target) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parse_recognizes_each_shape() {
        assert_eq!(HostRule::parse("*"), Ok(HostRule::Any));
        assert_eq!(
            HostRule::parse("api.anthropic.com"),
            Ok(HostRule::Exact("api.anthropic.com".into()))
        );
        assert_eq!(
            HostRule::parse("*.anthropic.com"),
            Ok(HostRule::Suffix("anthropic.com".into()))
        );
        assert_eq!(
            HostRule::parse("203.0.113.7"),
            Ok(HostRule::Ip(ip("203.0.113.7")))
        );
        assert_eq!(HostRule::parse("::1"), Ok(HostRule::Ip(ip("::1"))));
        assert_eq!(
            HostRule::parse("10.0.0.0/8"),
            Ok(HostRule::Cidr {
                addr: ip("10.0.0.0"),
                prefix: 8
            })
        );
        assert_eq!(
            HostRule::parse("fd00::/8"),
            Ok(HostRule::Cidr {
                addr: ip("fd00::"),
                prefix: 8
            })
        );
    }

    #[test]
    fn parse_uppercases_are_lowercased() {
        assert_eq!(
            HostRule::parse("API.Anthropic.COM"),
            Ok(HostRule::Exact("api.anthropic.com".into()))
        );
    }

    #[test]
    fn parse_rejects_malformed_hosts() {
        assert_eq!(HostRule::parse(""), Err(HostError::Empty));
        assert_eq!(HostRule::parse("-bad.com"), Err(HostError::InvalidHostname));
        assert_eq!(HostRule::parse("bad-.com"), Err(HostError::InvalidHostname));
        assert_eq!(HostRule::parse("bad_host"), Err(HostError::InvalidHostname));
        assert_eq!(HostRule::parse("a..b"), Err(HostError::InvalidHostname));
        assert_eq!(HostRule::parse("*."), Err(HostError::InvalidWildcard));
        assert_eq!(HostRule::parse("*.-x.com"), Err(HostError::InvalidWildcard));
        assert_eq!(HostRule::parse("10.0.0.0/33"), Err(HostError::InvalidCidr));
        assert_eq!(HostRule::parse("fd00::/129"), Err(HostError::InvalidCidr));
        assert_eq!(HostRule::parse("999.0.0.0/8"), Err(HostError::InvalidCidr));
        assert_eq!(HostRule::parse("10.0.0.0/x"), Err(HostError::InvalidCidr));
    }

    #[test]
    fn ip_and_cidr_match_addresses() {
        let rule = HostRule::parse("10.0.0.0/8").unwrap();
        assert!(rule.matches_ip(ip("10.1.2.3")));
        assert!(rule.matches_ip(ip("10.255.255.255")));
        assert!(!rule.matches_ip(ip("11.0.0.1")));
        // a v4 rule never matches a v6 address
        assert!(!rule.matches_ip(ip("::1")));

        let exact = HostRule::parse("203.0.113.7").unwrap();
        assert!(exact.matches_ip(ip("203.0.113.7")));
        assert!(!exact.matches_ip(ip("203.0.113.8")));

        let all = HostRule::parse("0.0.0.0/0").unwrap();
        assert!(all.matches_ip(ip("8.8.8.8")));

        let v6 = HostRule::parse("fd00::/8").unwrap();
        assert!(v6.matches_ip(ip("fd12::1")));
        assert!(!v6.matches_ip(ip("fe00::1")));
    }

    #[test]
    fn any_matches_everything() {
        let any = HostRule::Any;
        assert!(any.matches_ip(ip("1.2.3.4")));
        assert!(any.matches_hostname("anything.example"));
    }

    #[test]
    fn hostname_and_suffix_match_names() {
        let exact = HostRule::parse("api.anthropic.com").unwrap();
        assert!(exact.matches_hostname("API.anthropic.com"));
        assert!(!exact.matches_hostname("evil.com"));
        // a name rule does not match a bare IP
        assert!(!exact.matches_ip(ip("1.2.3.4")));

        let suffix = HostRule::parse("*.anthropic.com").unwrap();
        assert!(suffix.matches_hostname("api.anthropic.com"));
        assert!(suffix.matches_hostname("a.b.anthropic.com"));
        // strict subdomains only: the bare apex does not match
        assert!(!suffix.matches_hostname("anthropic.com"));
        // a name that merely ends with the suffix text but not on a label boundary
        assert!(!suffix.matches_hostname("notanthropic.com"));
        assert!(!suffix.matches_hostname("evil.com"));
    }
}
