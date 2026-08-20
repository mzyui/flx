use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;

pub struct SpysOneProvider;

#[async_trait]
impl ProxyProvider for SpysOneProvider {
    fn name(&self) -> &'static str {
        "spys.one"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(
            ["https://spys.one/en/free-proxy-list/"]
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
