use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;

pub struct ProxyDbProvider;

const PAGES: u32 = 3;
const PAGE_SIZE: u32 = 100;

#[async_trait]
impl ProxyProvider for ProxyDbProvider {
    fn name(&self) -> &'static str {
        "proxydb"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(
            (0..PAGES)
                .map(|page| {
                    let url = format!("https://proxydb.net/?offset={}", page * PAGE_SIZE);
                    Source::all(&url).map(|source| {
                        source
                            .with_mode(ScrapeMode::HtmlTable)
                            .with_timeout(Duration::from_secs(15))
                    })
                })
                .collect(),
        )
    }
}
