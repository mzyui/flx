use async_trait::async_trait;

use super::{models::Source, IProxyTrait};

/// A provider for fetching proxy lists from free-proxy-list.net.
pub struct FreeProxyListProvider;

#[async_trait]
impl IProxyTrait for FreeProxyListProvider {
    /// Returns a list of sources from which proxies can be fetched.
    ///
    /// # Returns
    ///
    /// A vector of `Source` objects representing the proxy sources.
    fn sources(&self) -> Vec<Source> {
        vec![
            Source::http("https://www.sslproxies.org/"),
            Source::http("https://free-proxy-list.net/uk-proxy.html"),
            Source::http("https://www.us-proxy.org/"),
            Source::http("https://free-proxy-list.net/"),
            Source::socks("https://socks-proxy.net/"),
        ]
    }
}
