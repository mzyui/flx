use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;

pub struct ProxyNovaProvider;

#[async_trait]
impl ProxyProvider for ProxyNovaProvider {
    fn name(&self) -> &'static str {
        "proxynova"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(vec![Source::http("https://api.proxynova.com/proxylist")
            .map(|source| {
                source
                    .with_mode(ScrapeMode::ProxyNovaJson)
                    .with_timeout(Duration::from_secs(15))
            })])
    }
}
