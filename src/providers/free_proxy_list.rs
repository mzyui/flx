use std::{
    net::Ipv4Addr,
    sync::{atomic::AtomicUsize, Arc},
};

use async_trait::async_trait;
use scraper::{Html, Selector};

use super::IProxyTrait;
use crate::models::{Proxy, Source, Type};

/// A provider for fetching proxy lists from free-proxy-list.net product..
pub struct FreeProxyListProvider {
    table: Selector,
    row: Selector,
    column: Selector,
}

impl Default for FreeProxyListProvider {
    fn default() -> Self {
        Self {
            table: Selector::parse("table > tbody").unwrap(),
            row: Selector::parse("tr").unwrap(),
            column: Selector::parse("td").unwrap(),
        }
    }
}

#[async_trait]
impl IProxyTrait for FreeProxyListProvider {
    /// Returns a list of sources from which proxies can be fetched.
    fn sources(&self) -> Vec<Source> {
        vec![
            Source::http("https://www.sslproxies.org/"),
            Source::http("https://free-proxy-list.net/uk-proxy.html"),
            Source::http("https://www.us-proxy.org/"),
            Source::http("https://free-proxy-list.net/"),
            Source::socks("https://socks-proxy.net/"),
        ]
    }

    /// Scrapes proxy information from the fetched HTML content.
    async fn scrape(
        &self,
        html: Html,
        tx: crossbeam_channel::Sender<Option<Proxy>>,
        counter: Arc<AtomicUsize>,
        default_types: Vec<Type>,
    ) -> anyhow::Result<()> {
        if let Some(table) = html.select(&self.table).next() {
            for row in table.select(&self.row) {
                let mut col = row.select(&self.column).map(|i| i.inner_html());
                if let Some(Ok(ip)) = col.next().map(|f| f.parse::<Ipv4Addr>()) {
                    if let Some(Ok(port)) = col.next().map(|f| f.parse::<u16>()) {
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
        }
        Ok(())
    }
}
