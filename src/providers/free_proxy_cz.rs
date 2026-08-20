use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;

pub struct FreeProxyCzProvider;

#[async_trait]
impl ProxyProvider for FreeProxyCzProvider {
    fn name(&self) -> &'static str {
        "free-proxy.cz"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(
            ["https://free-proxy.cz/en/"]
                .into_iter()
                .map(|url| {
                    Source::all(url).map(|source| {
                        source
                            .with_mode(ScrapeMode::HtmlTable)
                            .with_timeout(Duration::from_secs(20))
                    })
                })
                .collect(),
        )
    }
}
