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

    #[test]
    fn default_probe_missed_types_is_disabled() {
        assert!(!Config::default().probe_missed_types);
    }
}
