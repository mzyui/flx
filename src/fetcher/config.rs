use std::{sync::Arc, time::Duration};

/// Configuration for the proxy fetcher.
pub struct Config {
    pub enforce_unique_ip: bool,
    pub concurrency_limit: usize,
    pub enable_geo_lookup: bool,
    pub countries: Arc<[String]>,
    pub fallback_threshold: Option<usize>,
    pub cache_ttl: Option<Duration>,
    pub refresh_cache: bool,
    pub providers: Arc<[String]>,
    pub excluded_providers: Arc<[String]>,
    pub custom_sources: Arc<[String]>,
    pub offline: bool,
}

impl Config {
    pub fn normalized_countries(&self) -> hashbrown::HashSet<String> {
        self.countries
            .iter()
            .map(|country| country.trim().to_ascii_uppercase())
            .filter(|country| !country.is_empty())
            .collect()
    }
}

pub const DEFAULT_CONCURRENCY_LIMIT: usize = 25;

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
            providers: Arc::from(Vec::new()),
            excluded_providers: Arc::from(Vec::new()),
            custom_sources: Arc::from(Vec::new()),
            offline: false,
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
