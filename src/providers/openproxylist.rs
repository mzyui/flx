use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, Source};
use super::ProxyProvider;
use crate::proxy::models::Protocol;

pub struct OpenProxyListProvider;

const TIMEOUT: Duration = Duration::from_secs(15);

#[async_trait]
impl ProxyProvider for OpenProxyListProvider {
    fn name(&self) -> &'static str {
        "openproxylist"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(vec![
            Source::http("https://api.openproxylist.xyz/http.txt").map(|s| s.with_timeout(TIMEOUT)),
            Source::typed("https://api.openproxylist.xyz/socks4.txt", Protocol::Socks4)
                .map(|s| s.with_timeout(TIMEOUT)),
            Source::typed("https://api.openproxylist.xyz/socks5.txt", Protocol::Socks5)
                .map(|s| s.with_timeout(TIMEOUT)),
        ])
    }
}
