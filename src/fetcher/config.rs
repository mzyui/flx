use std::time::Duration;

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
    pub countries: Vec<String>,
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

impl Default for Config {
    fn default() -> Self {
        Self {
            enforce_unique_ip: true,
            concurrency_limit: 10,
            enable_geo_lookup: false,
            countries: Vec::new(),
            fallback_threshold: None,
            cache_ttl: None,
            refresh_cache: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn geo_lookup_is_disabled_by_default() {
        assert!(!Config::default().enable_geo_lookup);
    }

    #[test]
    fn country_filters_are_normalized_and_deduplicated() {
        let config = Config {
            countries: vec![
                "id".to_owned(),
                "ID".to_owned(),
                " us ".to_owned(),
                String::new(),
            ],
            ..Config::default()
        };

        let countries = config.normalized_countries();

        assert!(countries.contains("ID"));
        assert!(countries.contains("US"));
        assert_eq!(countries.len(), 2);
    }
}
