use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, Source};
use super::ProxyProvider;
use crate::proxy::models::{Anonymity, Protocol};

/// A provider for the api.openproxylist.xyz plaintext lists.
pub struct OpenProxyListProvider;

/// Per-request timeout, matching the reference implementation.
const TIMEOUT: Duration = Duration::from_secs(15);

#[async_trait]
impl ProxyProvider for OpenProxyListProvider {
    fn name(&self) -> &'static str {
        "openproxylist"
    }

    /// Returns a list of sources from which proxies can be fetched.
    fn sources(&self) -> Vec<Source> {
        valid_sources(vec![
            Source::typed(
                "https://api.openproxylist.xyz/http.txt",
                Protocol::Http(Anonymity::Unknown),
            )
            .map(|s| s.with_timeout(TIMEOUT)),
            Source::typed("https://api.openproxylist.xyz/socks4.txt", Protocol::Socks4)
                .map(|s| s.with_timeout(TIMEOUT)),
            Source::typed("https://api.openproxylist.xyz/socks5.txt", Protocol::Socks5)
                .map(|s| s.with_timeout(TIMEOUT)),
        ])
    }
}
