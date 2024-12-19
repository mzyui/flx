use std::{borrow::Cow, collections::VecDeque, net::Ipv4Addr, sync::Arc, time::Duration};

use async_trait::async_trait;
use fake::{faker::internet::en::UserAgent, Fake};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request};
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use models::Source;
use tokio::time;

use crate::proxy::models::{Proxy, ProxyType};

mod free_proxy_list;
mod github;
pub mod models;
mod proxyscrape;

pub use free_proxy_list::FreeProxyListProvider;
pub use github::GithubRepoProvider;
pub use proxyscrape::ProxyscrapeProvider;

/// Trait defining the behavior of proxy providers.
#[async_trait]
pub trait IProxyTrait {
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

        let user_agent = UserAgent().fake::<&str>(); // Generate a fake user agent
        let mut content = String::new(); // To accumulate HTML content

        while let Some((url, previous_url)) = urls.pop_front() {
            let mut req = Request::builder()
                .uri(&url)
                .header(hyper::header::USER_AGENT, user_agent);

            if let Some(previous_url) = previous_url {
                req = req.header(hyper::header::REFERER, previous_url); // Set the referer if available
            }

            // Send the request and await the response with a timeout
            let mut response =
                time::timeout(timeout, client.request(req.body(Empty::<Bytes>::new())?)).await??;

            // Handle possible redirects
            if let Some(redirect) = response.headers().get(hyper::header::LOCATION) {
                let redirect = redirect.to_str()?;
                urls.push_back((redirect.to_string(), Some(url))); // Add redirect URL to the queue
                continue;
            }

            // Read the response frames
            while let Some(next) = response.frame().await {
                let frame = next?;
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
        tx: kanal::AsyncSender<Proxy>,
        default_types: Vec<ProxyType>,
    ) -> anyhow::Result<()> {
        for line in html.lines() {
            let mut parts = line.trim().split(':');
            if let (Some(ip_str), Some(port_str)) = (parts.next(), parts.next()) {
                if let (Ok(ip), Ok(port)) = (ip_str.parse::<Ipv4Addr>(), port_str.parse::<u16>()) {
                    let proxy = Proxy {
                        ip,
                        port,
                        types: default_types.clone(),
                        ..Default::default()
                    };
                    if tx.send(proxy).await.is_err() {
                        break;
                    }
                }
            }
        }
        Ok(())
    }
}
