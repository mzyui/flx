use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;
use crate::proxy::models::{Anonymity, Protocol};

pub struct FreeProxyListProvider;

#[async_trait]
impl ProxyProvider for FreeProxyListProvider {
    fn name(&self) -> &'static str {
        "free-proxy-list"
    }

    fn sources(&self) -> Vec<Source> {
        let sites = [
            (
                "https://free-proxy-list.net/",
                Protocol::Http(Anonymity::Unknown),
            ),
            (
                "https://www.sslproxies.org/",
                Protocol::Https(Anonymity::Unknown),
            ),
            ("https://us-proxy.org/", Protocol::Http(Anonymity::Unknown)),
            ("https://www.socks-proxy.net/", Protocol::Socks4),
        ];

        valid_sources(
            sites
                .into_iter()
                .map(|(url, protocol)| {
                    let source = match protocol {
                        Protocol::Http(_) | Protocol::Https(_) => Source::http(url),
                        _ => Source::typed(url, protocol),
                    };
                    source.map(|source| {
                        source
                            .with_mode(ScrapeMode::HtmlTable)
                            .with_timeout(Duration::from_secs(15))
                    })
                })
                .collect(),
        )
    }
}
