use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;
use crate::proxy::models::{Anonymity, Protocol};

/// The api.proxynova.com JSON list.
///
/// The `ip` field is obfuscated as a JavaScript string expression; it is
/// decoded by the parser rather than evaluated.
pub struct ProxyNovaProvider;

#[async_trait]
impl ProxyProvider for ProxyNovaProvider {
    fn name(&self) -> &'static str {
        "proxynova"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(vec![Source::typed(
            "https://api.proxynova.com/proxylist",
            Protocol::Http(Anonymity::Unknown),
        )
        .map(|source| {
            source
                .with_mode(ScrapeMode::ProxyNovaJson)
                .with_timeout(Duration::from_secs(15))
        })])
    }
}
