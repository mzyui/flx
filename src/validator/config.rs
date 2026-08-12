use crate::Protocol;

/// Default online judges used to validate plain HTTP proxy forwarding.
///
/// These are third-party azenv-style echo endpoints that reflect the
/// `X-Fluxy-Token` header as `HTTP_X_FLUXY_TOKEN`. They are verified live at
/// startup (preflight) and any endpoint that fails is dropped from the pool.
pub const DEFAULT_HTTP_JUDGE_URLS: &[&str] = &[
    "http://azenv.net/",
    "http://wfuchs.de/azenv.php",
    "http://proxyjudge.us/",
    "http://shinh.org/env.cgi",
];

/// Default online judges used for HTTPS, CONNECT and SOCKS tunnels.
///
/// The same azenv contract applies, but over a verified TLS connection to port
/// 443, which proves the proxy can tunnel arbitrary HTTPS traffic.
pub const DEFAULT_HTTPS_JUDGE_URLS: &[&str] = &[
    "https://aranguren.org/azenv.php",
    "https://wfuchs.de/azenv.php",
];

/// Configuration for the proxy validating service.
pub struct Config {
    /// Maximum number of proxies validated concurrently.
    pub concurrency_limit: usize,
    /// Per-validation timeout in seconds, shared across the whole check.
    pub request_timeout: u64,
    /// Protocols to validate and match against. Empty disables the validator.
    pub types: Vec<Protocol>,
    /// AND groups of protocols. Every protocol inside a group must pass for a
    /// proxy to be emitted once, listing every passing protocol. Groups combine
    /// with OR across the singleton `types` list and with each other.
    pub groups: Vec<Vec<Protocol>>,
    /// Maximum number of attempts per advertised protocol before giving up.
    pub max_attempts: usize,
    /// Online judges used to validate plain HTTP proxy forwarding.
    ///
    /// Verified live at startup; any URL that fails preflight is dropped from
    /// the pool. Requests are spread across the surviving judges round-robin.
    pub http_judge_urls: Vec<String>,
    /// Online judges used for HTTPS, CONNECT, SOCKS4 and SOCKS5 tunnels.
    ///
    /// Same contract as [`Config::http_judge_urls`] but reached over TLS.
    pub https_judge_urls: Vec<String>,
    /// When true, TLS certificate validation is disabled for judge connections
    /// (self-hosted judges with self-signed certs). Defaults to false so real
    /// TLS judges are authenticated and MITM on the judge path is rejected.
    pub insecure: bool,
}

/// Default number of proxies validated concurrently.
///
/// Shared with the CLI (`--max-connections`) so the library facade and the
/// binary behave identically out of the box.
pub const DEFAULT_CONCURRENCY_LIMIT: usize = 500;

impl Default for Config {
    fn default() -> Self {
        Self {
            concurrency_limit: DEFAULT_CONCURRENCY_LIMIT,
            request_timeout: 3,
            types: Vec::new(),
            groups: Vec::new(),
            max_attempts: 1,
            http_judge_urls: DEFAULT_HTTP_JUDGE_URLS
                .iter()
                .map(|u| u.to_string())
                .collect(),
            https_judge_urls: DEFAULT_HTTPS_JUDGE_URLS
                .iter()
                .map(|u| u.to_string())
                .collect(),
            insecure: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use super::{DEFAULT_HTTPS_JUDGE_URLS, DEFAULT_HTTP_JUDGE_URLS};

    #[test]
    fn defaults_use_public_judge_pools() {
        let config = Config::default();

        assert_eq!(config.http_judge_urls, DEFAULT_HTTP_JUDGE_URLS.to_vec());
        assert_eq!(config.https_judge_urls, DEFAULT_HTTPS_JUDGE_URLS.to_vec());
    }

    #[test]
    fn default_max_attempts_is_positive() {
        assert!(Config::default().max_attempts > 0);
    }

    #[test]
    fn default_groups_are_empty() {
        assert!(Config::default().groups.is_empty());
    }
}
