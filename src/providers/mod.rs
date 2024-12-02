use std::{
    collections::VecDeque,
    sync::{atomic::AtomicUsize, mpsc, Arc},
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

use crate::models::{Protocol, Proxy, Source};

/// Module for fetching proxies from free proxy lists.
pub mod free_proxy_list;

/// Module for fetching proxies from GitHub repositories.
pub mod github;

/// Trait defining the behavior of proxy providers.
#[async_trait]
pub trait IProxyTrait {
    /// Returns a list of sources from which proxies can be fetched.
    fn sources(&self) -> Vec<Source>;

    /// Fetches the HTML content from the specified URL.
    async fn fetch(
        &self, client: Arc<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>>,
        url: &str, timeout: Duration,
    ) -> anyhow::Result<Html> {
        let mut urls = VecDeque::new();
        urls.push_back((url.to_string(), None));

        let ua = UserAgent().fake::<&str>();

        let mut content = String::new();
        while let Some((url, previous_url)) = urls.pop_front() {
            let mut req = Request::builder()
                .uri(&url)
                .header(hyper::header::USER_AGENT, ua);
            if let Some(previous_url) = previous_url {
                req = req.header(hyper::header::REFERER, previous_url);
            }

            let mut response =
                time::timeout(timeout, client.request(req.body(Empty::<Bytes>::new())?))
                    .await??;
            if let Some(redirect) = response.headers().get(hyper::header::LOCATION) {
                let redirect = redirect.to_str()?;
                urls.push_back((redirect.to_string(), Some(url)));
                continue;
            }
            while let Some(next) = response.frame().await {
                let frame = next?;
                if let Some(chunk) = frame.data_ref() {
                    let chunk_str = String::from_utf8_lossy(chunk);
                    content.push_str(&chunk_str);
                }
            }
        }
        Ok(Html::parse_document(&content))
    }

    /// Scrapes proxy information from the fetched HTML content.
    async fn scrape(
        &self, html: Html, tx: mpsc::Sender<Option<Proxy>>, counter: Arc<AtomicUsize>,
        default_types: Vec<Arc<Protocol>>,
    ) -> anyhow::Result<()>;

    /// Sends a found proxy through the provided channel and updates the counter.
    fn send(
        &self, proxy: Proxy, tx: &mpsc::Sender<Option<Proxy>>, counter: &Arc<AtomicUsize>,
    ) -> bool {
        if tx.send(Some(proxy)).is_ok() {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return true;
        }
        false
    }
}
