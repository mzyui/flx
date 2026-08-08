use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;
use crate::proxy::models::{Anonymity, Protocol};

/// proxy-list.org, whose rows carry a base64-encoded `ip:port` blob.
pub struct ProxyListOrgProvider;

/// Pages requested per run, matching the reference implementation.
const MAX_PAGES: u32 = 10;

#[async_trait]
impl ProxyProvider for ProxyListOrgProvider {
    fn name(&self) -> &'static str {
        "proxylist-org"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(
            (1..=MAX_PAGES)
                .map(|page| {
                    let url = format!("https://proxy-list.org/english/index.php?p={}", page);
                    Source::typed(&url, Protocol::Http(Anonymity::Unknown)).map(|source| {
                        source
                            .with_mode(ScrapeMode::Base64Rows)
                            .with_timeout(Duration::from_secs(15))
                    })
                })
                .collect(),
        )
    }
}
