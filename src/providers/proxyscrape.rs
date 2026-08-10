use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, Source};
use super::ProxyProvider;
use crate::proxy::models::Protocol;

/// A provider for fetching proxy lists from the proxyscrape.com API.
pub struct ProxyscrapeProvider;

/// Per-request timeout, ported from the `mzyui/proxy-list` engine.
const TIMEOUT: Duration = Duration::from_secs(20);

#[async_trait]
impl ProxyProvider for ProxyscrapeProvider {
    fn name(&self) -> &'static str {
        "proxyscrape"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(vec![
            Source::http("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all")
                .map(|s| s.with_timeout(TIMEOUT)),
            Source::typed(
                "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all",
                Protocol::Socks4,
            )
            .map(|s| s.with_timeout(TIMEOUT)),
            Source::typed(
                "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all",
                Protocol::Socks5,
            )
            .map(|s| s.with_timeout(TIMEOUT)),
        ])
    }
}
