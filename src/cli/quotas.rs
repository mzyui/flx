//! Per-type output quotas for `flx find` (`TYPE=n` syntax).
//!
//! Quotas cap how many proxies of one type are emitted (e.g. `HTTP=8`
//! keeps at most 8 HTTP proxies). Enforcement lives in the output layer,
//! so validation still probes every requested type.

use flx::proxy::models::{Anonymity, Protocol, Proxy};

/// A requested type with an optional output cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeQuota {
    pub protocol: Protocol,
    pub quota: Option<usize>,
}

impl TypeQuota {
    pub fn uncapped(protocol: Protocol) -> Self {
        Self {
            protocol,
            quota: None,
        }
    }
}

/// Parse one `TYPE` or `TYPE=n` token (no `+` groups).
///
/// `=` is shell-safe (unlike parentheses), so `HTTP=8` needs no quoting.
pub fn parse_single_type(value: &str) -> Option<TypeQuota> {
    if value.contains('+') || value.contains('(') || value.contains(')') {
        return None;
    }
    if let Some((prefix, suffix)) = value.rsplit_once('=') {
        if prefix.is_empty() || suffix.is_empty() || suffix.contains('=') {
            return None;
        }
        let quota: usize = suffix.parse().ok()?;
        if quota == 0 {
            return None;
        }
        let protocol = prefix.parse::<Protocol>().ok()?;
        Some(TypeQuota {
            protocol,
            quota: Some(quota),
        })
    } else {
        value.parse::<Protocol>().ok().map(TypeQuota::uncapped)
    }
}

/// Validate a CLI `TYPES` token, including `TYPE=n` and `A+B` groups.
///
/// Quotas are rejected inside `+` groups for v1.
pub fn is_valid_type_value(value: &str) -> bool {
    if value.contains('+') {
        if value.contains('=') {
            return false;
        }
        let mut any = false;
        for part in value.split('+') {
            if part.is_empty() {
                return false;
            }
            match parse_single_type(part) {
                Some(quota) if quota.quota.is_none() => any = true,
                _ => return false,
            }
        }
        any
    } else {
        parse_single_type(value).is_some()
    }
}

/// Print a one-line error for an invalid `TYPES` token.
pub fn report_invalid_type_value(value: &str) {
    eprintln!("error: invalid value '{value}' for TYPES");
}

/// Split CLI tokens into per-type quotas and `+` AND-groups.
///
/// Quotas are only allowed on singletons; tokens mixing `+` with `=n`
/// are reported and skipped.
pub fn split_type_requests(tokens: &[String]) -> (Vec<TypeQuota>, Vec<Vec<Protocol>>) {
    let mut quotas = Vec::new();
    let mut groups: Vec<Vec<Protocol>> = Vec::new();
    for token in tokens {
        if token.contains('+') {
            if token.contains('=') {
                report_invalid_type_value(token);
                continue;
            }
            let mut parts: Vec<Protocol> = Vec::new();
            for part in token.split('+') {
                match part.parse::<Protocol>() {
                    Ok(protocol) => parts.push(protocol),
                    Err(_) => report_invalid_type_value(part),
                }
            }
            match parts.len() {
                0 => {}
                1 => quotas.push(TypeQuota::uncapped(parts[0])),
                _ => {
                    let mut seen: Vec<Protocol> = Vec::with_capacity(parts.len());
                    parts.retain(|protocol| {
                        if seen.contains(protocol) {
                            false
                        } else {
                            seen.push(*protocol);
                            true
                        }
                    });
                    groups.push(parts);
                }
            }
        } else {
            match parse_single_type(token) {
                Some(quota) => quotas.push(quota),
                None => report_invalid_type_value(token),
            }
        }
    }
    (quotas, groups)
}

/// Whether two protocols belong to one quota family.
///
/// HTTP/HTTPS match any anonymity on the same scheme; SOCKS matches its
/// own kind; CONNECT matches the exact port.
pub fn same_family(a: Protocol, b: Protocol) -> bool {
    match (a, b) {
        (Protocol::Http(_), Protocol::Http(_)) | (Protocol::Https(_), Protocol::Https(_)) => true,
        (Protocol::Connect(port), Protocol::Connect(other)) => port == other,
        (a, b) => a == b,
    }
}

/// Whether one validated/advertised protocol satisfies a request.
///
/// `Unknown` anonymity matches any level on the same family.
pub fn protocol_matches(requested: Protocol, candidate: Protocol) -> bool {
    match (requested, candidate) {
        (Protocol::Http(a), Protocol::Http(b)) | (Protocol::Https(a), Protocol::Https(b)) => {
            matches!(a, Anonymity::Unknown) || matches!(b, Anonymity::Unknown) || a == b
        }
        (Protocol::Connect(a), Protocol::Connect(b)) => a == b,
        (requested, candidate) => requested == candidate,
    }
}

/// Whether a proxy carries a type satisfying the request.
///
/// Judges validated types when present, advertised types otherwise.
#[cfg(test)]
pub fn proxy_matches(proxy: &Proxy, requested: Protocol) -> bool {
    if proxy.proxy_types.is_empty() {
        proxy
            .expected_types
            .iter()
            .any(|candidate| protocol_matches(requested, *candidate))
    } else {
        proxy
            .proxy_types
            .iter()
            .any(|typed| protocol_matches(requested, typed.protocol))
    }
}

/// Tracks per-type output caps across chained passes.
///
/// A proxy matching several quotas counts toward every matching quota
/// with remaining room. Proxies matching no quota (e.g. `+` groups) are
/// always allowed here; the global `--limit` still bounds them.
pub struct QuotaEnforcer {
    quotas: Vec<TypeQuota>,
    hits: Vec<usize>,
    has_groups: bool,
}

impl QuotaEnforcer {
    pub fn new(quotas: Vec<TypeQuota>) -> Self {
        let hits = vec![0; quotas.len()];
        Self {
            quotas,
            hits,
            has_groups: false,
        }
    }

    /// Note `+` AND-groups: their proxies may match no quota, so a filled
    /// quota set must not stop the stream while groups can still emit.
    pub fn set_has_groups(&mut self, has_groups: bool) {
        self.has_groups = has_groups;
    }

    #[cfg(test)]
    pub fn hits(&self) -> &[usize] {
        &self.hits
    }

    /// Whether any quota carries an explicit `=n` cap.
    pub fn has_any_quota(&self) -> bool {
        self.quotas.iter().any(|quota| quota.quota.is_some())
    }

    /// Whether some capped quota still has room.
    pub fn has_unfilled(&self) -> bool {
        self.quotas
            .iter()
            .enumerate()
            .any(|(i, quota)| match quota.quota {
                Some(n) => self.hits[i] < n,
                None => false,
            })
    }

    /// Whether some requested type is uncapped.
    pub fn has_uncapped(&self) -> bool {
        self.quotas.iter().any(|quota| quota.quota.is_none())
    }

    /// Whether no further proxy can be emitted: every quota is explicit,
    /// every cap is filled, and nothing uncapped (or grouped) can follow.
    pub fn is_satisfied(&self) -> bool {
        self.has_any_quota() && !self.has_unfilled() && !self.has_uncapped() && !self.has_groups
    }

    /// Decide whether to emit a proxy, recording quota hits.
    ///
    /// Strict: a proxy sharing a family with any quota must exactly match a
    /// quota with room (so `HTTPS:Elite=2` rejects anonymous HTTPS).
    /// Proxies whose families no quota names (e.g. `+` groups) stay allowed;
    /// the global `--limit` still bounds them.
    pub fn should_emit(&mut self, proxy: &Proxy) -> bool {
        let carried: Vec<Protocol> = if proxy.proxy_types.is_empty() {
            proxy.expected_types.to_vec()
        } else {
            proxy
                .proxy_types
                .iter()
                .map(|typed| typed.protocol)
                .collect()
        };
        let shares_family = self.quotas.iter().any(|quota| {
            carried
                .iter()
                .any(|candidate| same_family(quota.protocol, *candidate))
        });
        if !shares_family {
            return true;
        }
        let mut consume: Vec<usize> = Vec::new();
        for (i, quota) in self.quotas.iter().enumerate() {
            if carried
                .iter()
                .any(|candidate| protocol_matches(quota.protocol, *candidate))
            {
                match quota.quota {
                    None => consume.push(i),
                    Some(n) if self.hits[i] < n => consume.push(i),
                    Some(_) => {}
                }
            }
        }
        for i in &consume {
            if self.quotas[*i].quota.is_some() {
                self.hits[*i] += 1;
            }
        }
        !consume.is_empty()
    }

    /// Whether probing `requested` is already pointless: at least one quota
    /// names its family and every such quota is capped and filled.
    pub fn is_protocol_closed(&self, requested: Protocol) -> bool {
        let mut any = false;
        for (i, quota) in self.quotas.iter().enumerate() {
            if same_family(quota.protocol, requested) {
                any = true;
                match quota.quota {
                    Some(n) if self.hits[i] < n => return false,
                    None => return false,
                    Some(_) => {}
                }
            }
        }
        any
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flx::proxy::models::ProxyType;
    use std::net::Ipv4Addr;

    fn validated(ip: u8, protocol: Protocol) -> Proxy {
        let mut proxy = Proxy::new(Ipv4Addr::new(10, 0, 0, ip), 8080 + u16::from(ip));
        proxy.proxy_types.push(ProxyType::checked(protocol));
        proxy
    }

    #[test]
    fn parses_plain_and_quota_types() {
        assert_eq!(
            parse_single_type("HTTP"),
            Some(TypeQuota::uncapped(Protocol::Http(Anonymity::Unknown)))
        );
        assert_eq!(
            parse_single_type("HTTP=8"),
            Some(TypeQuota {
                protocol: Protocol::Http(Anonymity::Unknown),
                quota: Some(8),
            })
        );
        assert_eq!(
            parse_single_type("HTTPS:Elite=2"),
            Some(TypeQuota {
                protocol: Protocol::Https(Anonymity::Elite),
                quota: Some(2),
            })
        );
        assert_eq!(
            parse_single_type("CONNECT:80=1"),
            Some(TypeQuota {
                protocol: Protocol::Connect(80),
                quota: Some(1),
            })
        );
    }

    #[test]
    fn rejects_malformed_quotas() {
        for bad in [
            "HTTP=0",
            "HTTP=",
            "HTTP=-1",
            "HTTP=2=3",
            "=8",
            "HTTP+HTTPS",
            "HTTP(8)",
        ] {
            assert_eq!(parse_single_type(bad), None, "must reject {bad}");
        }
    }

    #[test]
    fn validates_cli_tokens_with_quotas_but_not_in_groups() {
        assert!(is_valid_type_value("HTTP=8"));
        assert!(is_valid_type_value("HTTPS:Elite=2"));
        assert!(is_valid_type_value("HTTP+HTTPS"));
        assert!(!is_valid_type_value("HTTP=2+HTTPS"));
        assert!(!is_valid_type_value("BOGUS"));
        assert!(!is_valid_type_value("HTTP=0"));
    }

    #[test]
    fn split_keeps_quotas_and_rejects_quota_groups() {
        let (quotas, groups) = split_type_requests(&[
            "HTTP=2".to_owned(),
            "SOCKS5".to_owned(),
            "HTTP+HTTPS".to_owned(),
            "HTTP=1+HTTPS".to_owned(),
        ]);
        assert_eq!(
            quotas,
            vec![
                TypeQuota {
                    protocol: Protocol::Http(Anonymity::Unknown),
                    quota: Some(2),
                },
                TypeQuota::uncapped(Protocol::Socks5),
            ]
        );
        assert_eq!(
            groups,
            vec![vec![
                Protocol::Http(Anonymity::Unknown),
                Protocol::Https(Anonymity::Unknown),
            ]]
        );
    }

    #[test]
    fn unknown_quota_matches_any_anonymity() {
        let proxy = validated(1, Protocol::Http(Anonymity::Elite));
        assert!(proxy_matches(&proxy, Protocol::Http(Anonymity::Unknown)));
        let proxy = validated(2, Protocol::Http(Anonymity::Unknown));
        assert!(proxy_matches(&proxy, Protocol::Http(Anonymity::Elite)));
        assert!(!proxy_matches(
            &validated(3, Protocol::Socks5),
            Protocol::Http(Anonymity::Unknown)
        ));
        assert!(proxy_matches(
            &validated(4, Protocol::Connect(80)),
            Protocol::Connect(80)
        ));
        assert!(!proxy_matches(
            &validated(5, Protocol::Connect(80)),
            Protocol::Connect(25)
        ));
    }

    #[test]
    fn enforcer_caps_each_type() {
        let mut enforcer = QuotaEnforcer::new(vec![TypeQuota {
            protocol: Protocol::Http(Anonymity::Unknown),
            quota: Some(2),
        }]);
        assert!(enforcer.should_emit(&validated(1, Protocol::Http(Anonymity::Elite))));
        assert!(enforcer.should_emit(&validated(2, Protocol::Http(Anonymity::Anonymous))));
        assert!(!enforcer.should_emit(&validated(3, Protocol::Http(Anonymity::Elite))));
        assert!(!enforcer.has_unfilled());
    }

    #[test]
    fn enforcer_counts_multi_type_proxies_toward_every_match() {
        let mut proxy = validated(1, Protocol::Http(Anonymity::Unknown));
        proxy
            .proxy_types
            .push(ProxyType::checked(Protocol::Https(Anonymity::Unknown)));
        let mut enforcer = QuotaEnforcer::new(vec![
            TypeQuota {
                protocol: Protocol::Http(Anonymity::Unknown),
                quota: Some(1),
            },
            TypeQuota {
                protocol: Protocol::Https(Anonymity::Unknown),
                quota: Some(1),
            },
        ]);
        assert!(enforcer.should_emit(&proxy));
        assert_eq!(enforcer.hits(), &[1, 1]);
        assert!(!enforcer.has_unfilled());
    }

    #[test]
    fn enforcer_leaves_group_proxies_to_the_global_limit() {
        let mut enforcer = QuotaEnforcer::new(vec![TypeQuota {
            protocol: Protocol::Http(Anonymity::Unknown),
            quota: Some(1),
        }]);
        assert!(enforcer.should_emit(&validated(9, Protocol::Socks5)));
        assert_eq!(enforcer.hits(), &[0]);
    }

    #[test]
    fn satisfied_needs_every_cap_filled_and_nothing_uncapped() {
        let mut enforcer = QuotaEnforcer::new(vec![
            TypeQuota {
                protocol: Protocol::Http(Anonymity::Unknown),
                quota: Some(1),
            },
            TypeQuota {
                protocol: Protocol::Https(Anonymity::Unknown),
                quota: Some(1),
            },
        ]);
        assert!(!enforcer.is_satisfied());
        assert!(enforcer.should_emit(&validated(1, Protocol::Http(Anonymity::Elite))));
        assert!(
            !enforcer.is_satisfied(),
            "one open cap keeps the stream alive"
        );
        assert!(enforcer.should_emit(&validated(2, Protocol::Https(Anonymity::Elite))));
        assert!(enforcer.is_satisfied());
    }

    #[test]
    fn satisfied_stays_false_with_uncapped_or_group_capacity() {
        let mut uncapped = QuotaEnforcer::new(vec![
            TypeQuota {
                protocol: Protocol::Http(Anonymity::Unknown),
                quota: Some(1),
            },
            TypeQuota::uncapped(Protocol::Socks5),
        ]);
        assert!(uncapped.should_emit(&validated(1, Protocol::Http(Anonymity::Elite))));
        assert!(!uncapped.is_satisfied(), "uncapped types never saturate");

        let mut grouped = QuotaEnforcer::new(vec![TypeQuota {
            protocol: Protocol::Http(Anonymity::Unknown),
            quota: Some(1),
        }]);
        grouped.set_has_groups(true);
        assert!(grouped.should_emit(&validated(1, Protocol::Http(Anonymity::Elite))));
        assert!(
            !grouped.is_satisfied(),
            "groups may still emit past filled caps"
        );
    }

    #[test]
    fn strict_rejects_same_family_mismatch() {
        let mut enforcer = QuotaEnforcer::new(vec![TypeQuota {
            protocol: Protocol::Https(Anonymity::Elite),
            quota: Some(2),
        }]);
        assert!(!enforcer.should_emit(&validated(1, Protocol::Https(Anonymity::Anonymous))));
        assert!(enforcer.should_emit(&validated(2, Protocol::Https(Anonymity::Elite))));
        assert_eq!(enforcer.hits(), &[1]);
    }

    #[test]
    fn closed_covers_filled_families_only() {
        let mut enforcer = QuotaEnforcer::new(vec![
            TypeQuota {
                protocol: Protocol::Http(Anonymity::Unknown),
                quota: Some(1),
            },
            TypeQuota::uncapped(Protocol::Socks5),
        ]);
        assert!(!enforcer.is_protocol_closed(Protocol::Http(Anonymity::Unknown)));
        assert!(enforcer.should_emit(&validated(1, Protocol::Http(Anonymity::Elite))));
        assert!(enforcer.is_protocol_closed(Protocol::Http(Anonymity::Unknown)));
        assert!(!enforcer.is_protocol_closed(Protocol::Socks5));
        assert!(!enforcer.is_protocol_closed(Protocol::Https(Anonymity::Unknown)));
    }

    #[test]
    fn closed_holds_for_filled_specific_quotas() {
        let mut enforcer = QuotaEnforcer::new(vec![TypeQuota {
            protocol: Protocol::Https(Anonymity::Elite),
            quota: Some(1),
        }]);
        assert!(enforcer.should_emit(&validated(1, Protocol::Https(Anonymity::Elite))));
        assert!(enforcer.is_protocol_closed(Protocol::Https(Anonymity::Unknown)));
    }
}
