use std::{borrow::Cow, collections::VecDeque, sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request};
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use models::Source;
use tokio::time;

use crate::proxy::models::{Protocol, Proxy};

mod free_proxy_list;
mod freeproxy_world;
mod geonode;
mod github;
pub mod models;
mod my_proxy;
mod openproxylist;
pub mod parsers;
mod proxylist_org;
mod proxynova;
mod proxyscrape;

pub use free_proxy_list::FreeProxyListProvider;
pub use freeproxy_world::FreeProxyWorldProvider;
pub use geonode::GeonodeProvider;
pub use github::GithubRepoProvider;
pub use my_proxy::MyProxyProvider;
pub use openproxylist::OpenProxyListProvider;
pub use proxylist_org::ProxyListOrgProvider;
pub use proxynova::ProxyNovaProvider;
pub use proxyscrape::ProxyscrapeProvider;

use models::ScrapeMode;
pub use models::ProviderTier;

/// Builds one instance of every provider fluxy knows about.
///
/// Mirrors the registry in `mzyui/proxy-list` (engine/src/providers/index.js).
/// `proxyscan` is intentionally absent: its download endpoint returns HTTP 404
/// for every protocol and it is disabled upstream too.
///
/// Ordering matters: website providers come first because they publish fresh,
/// self-maintained lists, while [`GithubRepoProvider`] is deliberately last —
/// the GitHub mirrors are aggregated copies of those same sites and serve only
/// as a fallback when the primary sources are unreachable or empty.
pub fn all_providers() -> Vec<std::sync::Arc<dyn ProxyProvider + Send + Sync>> {
    vec![
        // Primary: live websites / APIs.
        std::sync::Arc::new(ProxyscrapeProvider),
        std::sync::Arc::new(OpenProxyListProvider),
        std::sync::Arc::new(GeonodeProvider),
        std::sync::Arc::new(FreeProxyListProvider),
        std::sync::Arc::new(FreeProxyWorldProvider),
        std::sync::Arc::new(ProxyListOrgProvider),
        std::sync::Arc::new(MyProxyProvider),
        std::sync::Arc::new(ProxyNovaProvider),
        // Fallback: aggregated GitHub mirrors.
        std::sync::Arc::new(GithubRepoProvider),
    ]
}

/// Trait defining the behavior of proxy providers.
#[async_trait]
pub trait ProxyProvider {
    /// A short, stable identifier used in logs and diagnostics.
    fn name(&self) -> &'static str;

    /// Priority tier of this provider.
    ///
    /// Defaults to [`ProviderTier::Primary`]; aggregated mirrors override it
    /// with [`ProviderTier::Fallback`] so the fetcher can run them last.
    fn tier(&self) -> ProviderTier {
        ProviderTier::Primary
    }

    /// Returns a list of sources from which proxies can be fetched.
    ///
    /// # Returns
    ///
    /// A vector of `Source` objects representing the proxy sources.
    fn sources(&self) -> Vec<Source>;

    /// Fetches the HTML content from the specified URL.
    ///
    /// This method handles redirects and accumulates the HTML content from all frames.
    ///
    /// # Arguments
    ///
    /// * `client`: The HTTP client used for making requests.
    /// * `url`: The URL from which to fetch the HTML content.
    /// * `timeout`: The duration to wait before timing out the request.
    ///
    /// # Returns
    ///
    /// A result containing the parsed HTML document or an error if the fetch fails.
    async fn fetch(
        &self,
        client: Arc<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>>,
        url: &str,
        timeout: Duration,
    ) -> anyhow::Result<Cow<'static, str>> {
        let mut urls = VecDeque::new();
        urls.push_back((url.to_string(), None)); // Initialize with the first URL

        let user_agent = crate::user_agent::random_user_agent();
        let mut content = String::new(); // To accumulate HTML content

        while let Some((url, previous_url)) = urls.pop_front() {
            let mut req = Request::builder()
                .uri(&url)
                .header(hyper::header::USER_AGENT, user_agent);

            if let Some(previous_url) = previous_url {
                req = req.header(hyper::header::REFERER, previous_url); // Set the referer if available
            }

            // Send the request and await the response with a timeout
            let request = req
                .body(Empty::<Bytes>::new())
                .with_context(|| format!("failed to build request for {}", url))?;
            let mut response = time::timeout(timeout, client.request(request))
                .await
                .with_context(|| format!("request to {} timed out after {:?}", url, timeout))?
                .with_context(|| format!("request to {} failed", url))?;

            // Handle possible redirects
            if let Some(redirect) = response.headers().get(hyper::header::LOCATION) {
                let redirect = redirect
                    .to_str()
                    .with_context(|| format!("{} returned a non-utf8 Location header", url))?;
                urls.push_back((redirect.to_string(), Some(url))); // Add redirect URL to the queue
                continue;
            }

            // Read the response frames
            while let Some(next) = response.frame().await {
                let frame =
                    next.with_context(|| format!("body stream from {} was interrupted", url))?;
                if let Some(chunk) = frame.data_ref() {
                    content.push_str(&String::from_utf8_lossy(chunk)); // Append chunk to content
                }
            }
        }
        Ok(Cow::Owned(content))
    }

    /// Scrapes proxy information from the fetched HTML content.
    ///
    /// # Arguments
    ///
    /// * `html`: The HTML document containing proxy information.
    /// * `tx`: The channel to send found proxies.
    /// * `counter`: A counter to track the number of proxies found.
    /// * `default_types`: Default protocol types for the proxies.
    ///
    /// # Returns
    ///
    /// A result indicating success or failure of the scraping operation.
    async fn scrape(
        &self,
        html: Cow<'static, str>,
        tx: tokio::sync::mpsc::Sender<Proxy>,
        default_types: Vec<Protocol>,
    ) -> anyhow::Result<()> {
        self.scrape_with(html, tx, default_types, ScrapeMode::Plaintext)
            .await
    }

    /// Parses a response body according to `mode` and forwards every proxy.
    ///
    /// When the source reports a per-row protocol it replaces `default_types`
    /// for that row; otherwise the source defaults apply.
    async fn scrape_with(
        &self,
        body: Cow<'static, str>,
        tx: tokio::sync::mpsc::Sender<Proxy>,
        default_types: Vec<Protocol>,
        mode: ScrapeMode,
    ) -> anyhow::Result<()> {
        let parsed = match mode {
            ScrapeMode::Plaintext => parsers::parse_plaintext(&body),
            ScrapeMode::GeonodeJson => parsers::parse_geonode(&body)?,
            ScrapeMode::ProxyNovaJson => parsers::parse_proxynova(&body)?,
            ScrapeMode::HtmlTable => parsers::parse_html_table(&body),
            ScrapeMode::RegexPairs => parsers::parse_regex_pairs(&body),
            ScrapeMode::Base64Rows => parsers::parse_base64_rows(&body),
        };

        for (ip, port, protocol) in parsed {
            let expected_types = match protocol {
                Some(protocol) => vec![protocol],
                None => default_types.clone(),
            };
            let proxy = Proxy {
                ip,
                port,
                expected_types,
                ..Default::default()
            };
            if tx.send(proxy).await.is_err() {
                break;
            }
        }
        Ok(())
    }
}
