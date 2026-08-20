use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;

pub struct Proxies24Provider;

#[async_trait]
impl ProxyProvider for Proxies24Provider {
    fn name(&self) -> &'static str {
        "proxies24"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(
            ["http://www.proxies24.top/"]
                .into_iter()
                .map(|url| {
                    Source::all(url).map(|source| {
                        source
                            .with_mode(ScrapeMode::HtmlTable)
                            .with_timeout(Duration::from_secs(15))
                    })
                })
                .collect(),
        )
    }
}
