use std::{sync::Arc, time::Duration};

/// Tuning knobs for provider scraping.
pub struct Config {
    /// Deduplicates candidates by endpoint and advertised protocols.
    pub enforce_unique_ip: bool,
    /// Caps concurrent provider fetches; must be non-zero.
    pub concurrency_limit: usize,
    /// Annotates candidates via GeoIP; required for country filters.
    pub enable_geo_lookup: bool,
    /// Allowlist of ISO country codes; empty means no filtering.
    pub countries: Arc<[String]>,
    /// Denylist of ISO country codes; empty means no filtering.
    pub excluded_countries: Arc<[String]>,
    /// Skips fallback providers once this many proxies exist.
    pub fallback_threshold: Option<usize>,
    /// Bounds the fallback phase; `None` waits for all sources.
    pub fallback_phase_timeout: Option<Duration>,
    /// Freshness window for cached source bodies; `None` disables the cache.
    pub cache_ttl: Option<Duration>,
    /// Re-fetches sources instead of serving cached bodies.
    pub refresh_cache: bool,
    /// Provider allowlist by name; empty selects all built-ins.
    pub providers: Arc<[String]>,
    /// Provider denylist by name.
    pub excluded_providers: Arc<[String]>,
    /// Extra raw source URLs scraped alongside built-ins.
    pub custom_sources: Arc<[String]>,
    /// Serves cached bodies only, opening no network connections.
    pub offline: bool,
    /// Minimum spacing between requests to the same host; `None` disables it.
    pub fetch_delay: Option<Duration>,
    /// Per-source fetch timeout override; `None` keeps each source default.
    pub provider_timeout: Option<Duration>,
}

impl Config {
    /// Returns the trimmed, uppercased country allowlist with empties dropped.
    pub fn normalized_countries(&self) -> hashbrown::HashSet<String> {
        self.countries
            .iter()
            .map(|country| country.trim().to_ascii_uppercase())
            .filter(|country| !country.is_empty())
            .collect()
    }

    /// Returns the trimmed, uppercased country denylist with empties dropped.
    pub fn normalized_excluded_countries(&self) -> hashbrown::HashSet<String> {
        self.excluded_countries
            .iter()
            .map(|country| country.trim().to_ascii_uppercase())
            .filter(|country| !country.is_empty())
            .collect()
    }
}

/// Default concurrent provider fetches.
pub const DEFAULT_CONCURRENCY_LIMIT: usize = 25;

/// Default concurrent provider fetches per host.
pub const DEFAULT_HOST_CONCURRENCY_LIMIT: usize = 4;

/// Default source-cache freshness in minutes.
pub const DEFAULT_CACHE_TTL_MINUTES: u64 = 15;

impl Default for Config {
    fn default() -> Self {
        Self {
            enforce_unique_ip: true,
            concurrency_limit: DEFAULT_CONCURRENCY_LIMIT,
            enable_geo_lookup: false,
            countries: Arc::from(Vec::new()),
            excluded_countries: Arc::from(Vec::new()),
            fallback_threshold: None,
            fallback_phase_timeout: None,
            cache_ttl: Some(Duration::from_secs(
                DEFAULT_CACHE_TTL_MINUTES.saturating_mul(60),
            )),
            refresh_cache: false,
            providers: Arc::from(Vec::new()),
            excluded_providers: Arc::from(Vec::new()),
            custom_sources: Arc::from(Vec::new()),
            offline: false,
            fetch_delay: None,
            provider_timeout: None,
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

    #[test]
    fn excluded_countries_are_normalized_and_deduplicated() {
        let config = Config {
            excluded_countries: Arc::from(vec![
                "cn".to_owned(),
                "CN".to_owned(),
                " ru ".to_owned(),
                String::new(),
            ]),
            ..Config::default()
        };

        let countries = config.normalized_excluded_countries();

        assert!(countries.contains("CN"));
        assert!(countries.contains("RU"));
        assert_eq!(countries.len(), 2);
    }

    #[test]
    fn excluded_countries_are_empty_by_default() {
        assert!(Config::default().normalized_excluded_countries().is_empty());
    }

    #[test]
    fn fetch_delay_is_disabled_by_default() {
        assert_eq!(Config::default().fetch_delay, None);
    }

    #[test]
    fn fallback_phase_timeout_is_disabled_by_default() {
        assert_eq!(Config::default().fallback_phase_timeout, None);
    }

    #[test]
    fn provider_timeout_is_disabled_by_default() {
        assert_eq!(Config::default().provider_timeout, None);
    }
}
