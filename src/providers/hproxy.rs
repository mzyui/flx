use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;
use crate::proxy::models::{Anonymity, Protocol};

pub struct HProxyProvider;

const PROTOCOLS: [(&str, Protocol); 4] = [
    ("http", Protocol::Http(Anonymity::Unknown)),
    ("https", Protocol::Https(Anonymity::Unknown)),
    ("socks4", Protocol::Socks4),
    ("socks5", Protocol::Socks5),
];

#[async_trait]
impl ProxyProvider for HProxyProvider {
    fn name(&self) -> &'static str {
        "hproxy"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(
            PROTOCOLS
                .iter()
                .map(|(param, protocol)| {
                    let url =
                        format!("https://hproxy.com/api/proxy-list?format=txt&protocol={param}");
                    Source::typed(&url, *protocol).map(|source| {
                        source
                            .with_mode(ScrapeMode::Plaintext)
                            .with_timeout(Duration::from_secs(15))
                    })
                })
                .collect(),
        )
    }
}
