use std::str::FromStr;

use flx::proxy::models::{Anonymity, Protocol, Proxy};

use super::argument::OutputOptions;

fn anonymity_rank_from_name(name: &str) -> u8 {
    match name {
        "transparent" => Anonymity::Transparent.rank(),
        "anonymous" => Anonymity::Anonymous.rank(),
        "elite" => Anonymity::Elite.rank(),
        _ => Anonymity::Unknown.rank(),
    }
}

fn anonymity_from_name(name: &str) -> Option<Anonymity> {
    match name {
        "transparent" => Some(Anonymity::Transparent),
        "anonymous" => Some(Anonymity::Anonymous),
        "elite" => Some(Anonymity::Elite),
        "unknown" => Some(Anonymity::Unknown),
        _ => None,
    }
}

/// Best anonymity rank across a proxy's validated types; types without an
/// anonymity level (SOCKS, CONNECT) count as `Unknown`.
pub(crate) fn proxy_anonymity_rank(proxy: &Proxy) -> u8 {
    proxy
        .proxy_types
        .iter()
        .filter_map(|proxy_type| match proxy_type.protocol {
            Protocol::Http(anonymity) | Protocol::Https(anonymity) => Some(anonymity.rank()),
            _ => None,
        })
        .max()
        .unwrap_or_else(|| Anonymity::Unknown.rank())
}

// Maps any protocol to the anonymity-agnostic form of its family, so an
// `--exclude-type HTTP` filter also drops `HTTP:Elite` results.
fn protocol_family(protocol: Protocol) -> Protocol {
    match protocol {
        Protocol::Http(_) => Protocol::Http(Anonymity::Unknown),
        Protocol::Https(_) => Protocol::Https(Anonymity::Unknown),
        other => other,
    }
}

/// Post-validation filters applied before a proxy is rendered.
pub struct ProxyFilter {
    min_anonymity_rank: Option<u8>,
    levels: Vec<Anonymity>,
    min_response_time: Option<f64>,
    max_response_time: Option<f64>,
    exclude_types: Vec<Protocol>,
}

impl ProxyFilter {
    pub fn from_options(options: &OutputOptions) -> Self {
        Self {
            min_anonymity_rank: options
                .min_anonymity
                .as_deref()
                .map(anonymity_rank_from_name),
            levels: options
                .levels
                .iter()
                .filter_map(|level| anonymity_from_name(level))
                .collect(),
            min_response_time: options.min_response_time,
            max_response_time: options.max_response_time,
            exclude_types: options
                .exclude_type
                .iter()
                .filter_map(|type_str| Protocol::from_str(type_str).ok())
                .collect(),
        }
    }

    pub fn matches(&self, proxy: &Proxy) -> bool {
        if let Some(min_rank) = self.min_anonymity_rank {
            if proxy_anonymity_rank(proxy) < min_rank {
                return false;
            }
        }
        if !self.levels.is_empty()
            && !proxy.proxy_types.iter().any(|proxy_type| {
                matches!(
                    proxy_type.protocol,
                    Protocol::Http(anonymity) | Protocol::Https(anonymity)
                        if self.levels.contains(&anonymity)
                )
            })
        {
            return false;
        }
        let response_time = proxy.avg_response_time();
        if let Some(min_time) = self.min_response_time {
            if response_time < min_time {
                return false;
            }
        }
        if let Some(max_time) = self.max_response_time {
            if response_time > max_time {
                return false;
            }
        }
        if !self.exclude_types.is_empty() {
            let advertised = proxy.proxy_types.is_empty();
            let types: Vec<Protocol> = if advertised {
                proxy.expected_types.to_vec()
            } else {
                proxy
                    .proxy_types
                    .iter()
                    .map(|proxy_type| proxy_type.protocol)
                    .collect()
            };
            if types.iter().any(|protocol| {
                self.exclude_types
                    .iter()
                    .any(|excluded| protocol_family(*excluded) == protocol_family(*protocol))
            }) {
                return false;
            }
        }
        true
    }
}
