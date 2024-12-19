use async_trait::async_trait;

use super::models::Source;
use super::IProxyTrait;

/// A provider for fetching proxy lists from proxyscrape.com.
pub struct ProxyscrapeProvider;

#[async_trait]
impl IProxyTrait for ProxyscrapeProvider {
    /// Returns a list of sources from which proxies can be fetched.
    ///
    /// # Returns
    ///
    /// A vector of `Source` objects representing the proxy sources.
    fn sources(&self) -> Vec<Source> {
        vec![
            Source::all("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=ipport&format=text"),
        ]
    }
}
