use std::{
    collections::VecDeque,
    sync::{atomic::AtomicUsize, Arc},
    time::Duration,
};

use async_trait::async_trait;
use fake::{faker::internet::en::UserAgent, Fake};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request};
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use scraper::Html;
use tokio::time;

use crate::models::{Proxy, Source, Type};

mod free_proxy_list;
mod github;
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
    /// This method handles redirects and accumulates the HTML content from all the frames.
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
    ) -> anyhow::Result<Html> {
        let mut urls = VecDeque::new();
        urls.push_back((url.to_string(), None)); // Initialize with the first URL

        let ua = UserAgent().fake::<&str>(); // Generate a fake user agent

        let mut content = String::new(); // To accumulate HTML content
        while let Some((url, previous_url)) = urls.pop_front() {
            let mut req = Request::builder()
                .uri(&url)
                .header(hyper::header::USER_AGENT, ua);
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
                    let chunk_str = String::from_utf8_lossy(chunk);
                    content.push_str(&chunk_str); // Append chunk to content
                }
            }
        }
        Ok(Html::parse_document(&content)) // Parse and return the accumulated HTML
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
        html: Html,
        tx: crossbeam_channel::Sender<Option<Proxy>>,
        counter: Arc<AtomicUsize>,
        default_types: Vec<Type>,
    ) -> anyhow::Result<()>;

    /// Sends a found proxy through the provided channel and updates the counter.
    ///
    /// # Arguments
    ///
    /// * `proxy`: The `Proxy` instance to be sent.
    /// * `tx`: The channel to send the proxy.
    /// * `counter`: A counter to track the number of proxies sent.
    ///
    /// # Returns
    ///
    /// `true` if the proxy was sent successfully, `false` otherwise.
    fn send(
        &self,
        proxy: Proxy,
        tx: &crossbeam_channel::Sender<Option<Proxy>>,
        counter: &Arc<AtomicUsize>,
    ) -> bool {
        if tx.send(Some(proxy)).is_ok() {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed); // Increment the counter
            return true;
        }
        false
    }
}
