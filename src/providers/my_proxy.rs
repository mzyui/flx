use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;

/// The my-proxy.com free list, which embeds `ip:port#CC` pairs in page text.
pub struct MyProxyProvider;

#[async_trait]
impl ProxyProvider for MyProxyProvider {
    fn name(&self) -> &'static str {
        "my-proxy"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(vec![Source::http(
            "https://www.my-proxy.com/free-proxy-list.html",
        )
        .map(|source| {
            source
                .with_mode(ScrapeMode::RegexPairs)
                .with_timeout(Duration::from_secs(15))
        })])
    }
}
