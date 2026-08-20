use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;

pub struct GatherProxyProvider;

#[async_trait]
impl ProxyProvider for GatherProxyProvider {
    fn name(&self) -> &'static str {
        "gatherproxy"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(
            ["https://www.gatherproxy.com/"]
                .into_iter()
                .map(|url| {
                    Source::all(url).map(|source| {
                        source
                            .with_mode(ScrapeMode::GatherProxyJs)
                            .with_timeout(Duration::from_secs(10))
                    })
                })
                .collect(),
        )
    }
}
