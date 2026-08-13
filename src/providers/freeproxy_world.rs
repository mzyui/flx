use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;

pub struct FreeProxyWorldProvider;

const MAX_PAGES: u32 = 15;

#[async_trait]
impl ProxyProvider for FreeProxyWorldProvider {
    fn name(&self) -> &'static str {
        "freeproxy-world"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(
            (1..=MAX_PAGES)
                .map(|page| {
                    let url = format!(
                        "https://freeproxy.world/?type=&anonymity=&country=&speed=&port=&page={}",
                        page
                    );
                    Source::http(&url).map(|source| {
                        source
                            .with_mode(ScrapeMode::HtmlTable)
                            .with_timeout(Duration::from_secs(15))
                    })
                })
                .collect(),
        )
    }
}
