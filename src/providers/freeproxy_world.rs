use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;
use crate::proxy::models::{Anonymity, Protocol};

/// The freeproxy.world paginated HTML table.
pub struct FreeProxyWorldProvider;

/// Pages requested per run, matching the reference implementation.
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
                    Source::typed(&url, Protocol::Http(Anonymity::Unknown)).map(|source| {
                        source
                            .with_mode(ScrapeMode::HtmlTable)
                            .with_timeout(Duration::from_secs(15))
                    })
                })
                .collect(),
        )
    }
}
