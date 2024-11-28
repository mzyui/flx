use std::sync::{atomic::AtomicUsize, mpsc, Arc};

use async_trait::async_trait;
use reqwest::{Client, Url};
use scraper::Html;

use crate::models::{Anonymity, Protocol, Proxy, Source};

pub mod free_proxy_list;
pub mod github;

#[async_trait]
pub trait IProxyTrait {
    fn sources(&self) -> Vec<Source>;

    async fn fetch(&self, client: Client, url: &str) -> anyhow::Result<Html> {
        let response = client.get(url).send().await?;
        let text = response.text().await?;
        Ok(Html::parse_document(&text))
    }

    async fn scrape(
        &self, html: Html, tx: mpsc::SyncSender<Option<Proxy>>,
        counter: Arc<AtomicUsize>, default_protocols: Vec<Arc<Protocol>>,
    ) -> anyhow::Result<()>;

    fn send(
        &self, proxy: Proxy, tx: &mpsc::SyncSender<Option<Proxy>>,
        counter: &Arc<AtomicUsize>,
    ) -> bool {
        if tx.send(Some(proxy)).is_ok() {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return true;
        }
        false
    }
}
