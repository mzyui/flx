/// Options for configuring the proxy fetching process.
pub struct Config {
    /// Ensure each proxy has a unique IP; affects performance.
    pub enforce_unique_ip: bool,
    /// Maximum number of concurrent requests to process source URLs.
    pub concurrency_limit: usize,
    /// Perform geo lookup for each proxy; affects performance.
    pub enable_geo_lookup: bool,
    /// Filter proxies by ISO country code; if empty, skip filtering (optional).
    pub countries: Vec<String>,
    /// Skip the fallback (GitHub mirror) providers when the primary providers
    /// already yielded at least this many proxies.
    ///
    /// `None` runs the fallback providers unconditionally — still only after
    /// every primary provider has finished.
    pub fallback_threshold: Option<usize>,
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
