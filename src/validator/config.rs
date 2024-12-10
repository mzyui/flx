use crate::Protocol;

/// Options for configuring the proxy validating process.
pub struct Config {
    /// Maximum number of concurrent processes.
    pub concurrency_limit: usize,
    /// Timeout for requests in milliseconds.
    pub request_timeout: u64,
    /// Filter proxies by protocol; if empty, skip filtering (optional).
    pub types: Vec<Protocol>,
    /// Maximum number of attempts to validate a proxy.
    pub max_attempts: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            concurrency_limit: 50,
            request_timeout: 3000,
            types: Vec::new(),
            max_attempts: 1,
        }
    }
}
