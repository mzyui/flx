use std::{sync::Arc, time::Duration};

use crate::geolookup::IpType;

/// Configuration for the proxy fetcher.
pub struct Config {
    pub enforce_unique_ip: bool,
    pub concurrency_limit: usize,
    pub enable_geo_lookup: bool,
    pub enable_ip_type: bool,
    pub ip_type_filter: Option<IpType>,
    pub countries: Arc<[String]>,
    pub excluded_countries: Arc<[String]>,
    pub fallback_threshold: Option<usize>,
    pub fallback_phase_timeout: Option<Duration>,
    pub cache_ttl: Option<Duration>,
    pub refresh_cache: bool,
    pub providers: Arc<[String]>,
    pub excluded_providers: Arc<[String]>,
    pub custom_sources: Arc<[String]>,
    pub offline: bool,
    pub fetch_delay: Option<Duration>,
}

impl Config {
    pub fn normalized_countries(&self) -> hashbrown::HashSet<String> {
        self.countries
            .iter()
            .map(|country| country.trim().to_ascii_uppercase())
            .filter(|country| !country.is_empty())
            .collect()
    }

    pub fn normalized_excluded_countries(&self) -> hashbrown::HashSet<String> {
        self.excluded_countries
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
            enable_ip_type: false,
            ip_type_filter: None,
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
        assert!(!Config::default().enable_ip_type);
        assert_eq!(Config::default().ip_type_filter, None);
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
}
