use std::time::Duration;

use crate::Protocol;

pub const DEFAULT_HTTP_JUDGE_URLS: &[&str] = &[
    "http://azenv.net/",
    "http://wfuchs.de/azenv.php",
    "http://proxyjudge.us/",
    "http://shinh.org/env.cgi",
];

pub const DEFAULT_HTTPS_JUDGE_URLS: &[&str] = &[
    "https://aranguren.org/azenv.php",
    "https://wfuchs.de/azenv.php",
];

/// Configuration for the proxy validator.
pub struct Config {
    pub concurrency_limit: usize,
    pub request_timeout: u64,
    pub types: Vec<Protocol>,
    pub groups: Vec<Vec<Protocol>>,
    pub max_attempts: usize,
    pub http_judge_urls: Vec<String>,
    pub https_judge_urls: Vec<String>,
    pub insecure: bool,
    /// Probe requested types that the proxy's advertised set does not cover.
    pub probe_missed_types: bool,
    /// Require the judge to echo back the request's cookie header.
    pub support_cookies: bool,
    /// Require the judge to echo back the request's referer header.
    pub support_referer: bool,
    /// Pause between validation attempts of the same proxy.
    pub retry_delay: Duration,
    /// Emit a machine-readable report for every failed probe.
    pub report_failures: bool,
}

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
            probe_missed_types: false,
            support_cookies: false,
            support_referer: false,
            retry_delay: Duration::ZERO,
            report_failures: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use super::{DEFAULT_HTTPS_JUDGE_URLS, DEFAULT_HTTP_JUDGE_URLS};
    use std::time::Duration;

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

    #[test]
    fn default_probe_missed_types_is_disabled() {
        assert!(!Config::default().probe_missed_types);
    }

    #[test]
    fn default_cookie_and_referer_support_are_disabled() {
        let config = Config::default();

        assert!(!config.support_cookies);
        assert!(!config.support_referer);
    }

    #[test]
    fn retry_delay_is_zero_by_default() {
        assert_eq!(Config::default().retry_delay, Duration::ZERO);
    }

    #[test]
    fn failure_reporting_is_disabled_by_default() {
        assert!(!Config::default().report_failures);
    }
}
