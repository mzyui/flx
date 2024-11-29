use std::sync::{atomic::AtomicUsize, mpsc, Arc};

use async_trait::async_trait;
use reqwest::Client;
use scraper::Html;

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

    /// Fetches the HTML content from the specified URL using the provided HTTP client.
    async fn fetch(&self, client: Client, url: &str) -> anyhow::Result<Html> {
        let response = client.get(url).send().await?;
        let text = response.text().await?;
        Ok(Html::parse_document(&text))
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
