use std::{
    net::Ipv4Addr,
    sync::{atomic::AtomicUsize, Arc},
};

use async_trait::async_trait;
use scraper::Html;

use super::IProxyTrait;
use crate::models::{Protocol, Proxy, Source};

/// A provider for fetching proxy lists from proxyscrape.com.
pub struct ProxyscrapeProvider;

#[async_trait]
impl IProxyTrait for ProxyscrapeProvider {
    /// Returns a list of sources from which proxies can be fetched.
    fn sources(&self) -> Vec<Source> {
        vec![
            Source::all("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=ipport&format=text")
        ]
    }

    /// Scrapes proxy information from the fetched HTML content.
    async fn scrape(
        &self, html: Html, tx: crossbeam_channel::Sender<Option<Proxy>>,
        counter: Arc<AtomicUsize>, default_types: Vec<Arc<Protocol>>,
    ) -> anyhow::Result<()> {
        for line in html.html().lines() {
            let mut splited = line.trim().split(':');
            if let Some(Ok(ip)) = splited.next().map(|f| f.parse::<Ipv4Addr>()) {
                if let Some(Ok(port)) = splited.next().map(|f| f.parse::<u16>()) {
                    let proxy = Proxy {
                        ip,
                        port,
                        types: default_types.clone(),
                        ..Default::default()
                    };
                    if !self.send(proxy, &tx, &counter) {
                        break;
                    };
                }
            }
        }

        Ok(())
    }
}
