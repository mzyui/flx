use std::{sync::Arc, time::Duration};

/// Configuration for the proxy fetching pipeline.
pub struct Config {
    /// Deduplicate proxies that share the same endpoint (ip, port, protocol
    /// set). Bounded memory cost, so it stays on by default.
    pub enforce_unique_ip: bool,
    /// Maximum number of source URLs fetched concurrently.
    pub concurrency_limit: usize,
    /// Whether every accepted proxy receives a GeoIP lookup.
    ///
    /// The lookup is off by default because it adds per-proxy I/O.
    pub enable_geo_lookup: bool,
    /// ISO country codes to filter accepted proxies by; empty means no filter.
    pub countries: Arc<[String]>,
    /// Skip the fallback (GitHub mirror) providers when the primary providers
    /// already yielded at least this many proxies.
    ///
    /// `None` runs the fallback providers unconditionally — still only after
    /// every primary provider has finished.
    pub fallback_threshold: Option<usize>,
    /// Freshness window for the local source-body cache; `None` disables it.
    pub cache_ttl: Option<Duration>,
    /// Bypass the cache and refetch every source, repopulating it afterwards.
    pub refresh_cache: bool,
}

impl Config {
    /// Normalizes and deduplicates country filters for GeoIP matching.
    pub fn normalized_countries(&self) -> hashbrown::HashSet<String> {
        self.countries
            .iter()
            .map(|country| country.trim().to_ascii_uppercase())
            .filter(|country| !country.is_empty())
            .collect()
    }
}

/// Default number of provider sources fetched concurrently.
///
/// Shared with the CLI (`--fetch-concurrency`) so the library facade and the
/// binary behave identically out of the box.
pub const DEFAULT_CONCURRENCY_LIMIT: usize = 25;

/// Default freshness window (minutes) for the local source-body cache.
///
/// Shared with the CLI (`--cache-ttl`). `0` disables the cache.
pub const DEFAULT_CACHE_TTL_MINUTES: u64 = 15;

impl Default for Config {
    fn default() -> Self {
        Self {
            enforce_unique_ip: true,
            concurrency_limit: DEFAULT_CONCURRENCY_LIMIT,
            enable_geo_lookup: false,
            countries: Arc::from(Vec::new()),
            fallback_threshold: None,
            cache_ttl: Some(Duration::from_secs(
                DEFAULT_CACHE_TTL_MINUTES.saturating_mul(60),
            )),
            refresh_cache: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use std::sync::Arc;

    #[test]
    fn geo_lookup_is_disabled_by_default() {
        assert!(!Config::default().enable_geo_lookup);
    }

    #[test]
    fn country_filters_are_normalized_and_deduplicated() {
        let config = Config {
            countries: Arc::from(vec![
                "id".to_owned(),
                "ID".to_owned(),
                " us ".to_owned(),
                String::new(),
            ]),
            ..Config::default()
        };

        let countries = config.normalized_countries();

        assert!(countries.contains("ID"));
        assert!(countries.contains("US"));
        assert_eq!(countries.len(), 2);
    }
}
