use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, JsonRowsConfig, ScrapeMode, Source};
use super::{ProviderTier, ProxyProvider};

/// Scrapes the Stormsia JSON proxy feed.
pub struct StormsiaProvider;

const URL: &str = "https://stormsia.github.io/proxy-list/proxies.json";

#[async_trait]
impl ProxyProvider for StormsiaProvider {
    fn name(&self) -> &'static str {
        "stormsia"
    }

    fn tier(&self) -> ProviderTier {
        ProviderTier::Fallback
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(vec![Source::all(URL).map(|source| {
            source
                .with_mode(ScrapeMode::JsonRows(
                    JsonRowsConfig::new("", "host", "port")
                        .and_then(|config| config.with_protocol_path("protocol"))
                        .expect("static Stormsia JSON schema is valid"),
                ))
                .with_timeout(Duration::from_secs(20))
        })])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stormsia_is_a_fallback_json_source() {
        let provider = StormsiaProvider;
        let sources = provider.sources();

        assert_eq!(provider.name(), "stormsia");
        assert_eq!(provider.tier(), ProviderTier::Fallback);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].url.to_string(), URL);
        assert!(matches!(sources[0].mode, ScrapeMode::JsonRows(_)));
        assert_eq!(sources[0].timeout, Duration::from_secs(20));
        assert!(sources[0].default_types.len() > 1);
    }
}
