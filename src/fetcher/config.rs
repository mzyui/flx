/// Options for configuring the proxy fetching process.
pub struct Config {
    /// Ensure each proxy has a unique IP; affects performance.
    pub enforce_unique_ip: bool,
    /// Maximum number of concurrent requests to process source URLs.
    pub concurrency_limit: usize,
    /// Timeout for requests in milliseconds.
    pub request_timeout: u64,
    /// Perform geo lookup for each proxy; affects performance.
    pub enable_geo_lookup: bool,
    /// Filter proxies by ISO country code; if empty, skip filtering (optional).
    pub countries: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enforce_unique_ip: true,
            concurrency_limit: 10,
            request_timeout: 3000,
            enable_geo_lookup: true,
            countries: Vec::new(),
        }
    }
}
