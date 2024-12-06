use std::{
    net::Ipv4Addr,
    sync::{atomic::AtomicUsize, Arc},
};

use async_trait::async_trait;
use scraper::{Html, Selector};

use super::IProxyTrait;
use crate::models::{Proxy, ProxyType, Source};

/// A provider for fetching proxy lists from free-proxy-list.net.
pub struct FreeProxyListProvider {
    table: Selector,  // Selector for the main table containing proxies.
    row: Selector,    // Selector for individual rows in the table.
    column: Selector, // Selector for columns in each row.
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
        default_types: Vec<ProxyType>,
    ) -> anyhow::Result<()> {
        // Select the table containing the proxy data
        if let Some(table) = html.select(&self.table).next() {
            // Iterate over each row in the table
            for row in table.select(&self.row) {
                // Extract IP address and port from the columns
                let mut cols = row.select(&self.column).map(|col| col.inner_html());

                if let Some(Ok(ip)) = cols.next().map(|f| f.parse::<Ipv4Addr>()) {
                    if let Some(Ok(port)) = cols.next().map(|f| f.parse::<u16>()) {
                        let proxy = Proxy {
                            ip,
                            port,
                            types: default_types.clone(),
                            ..Default::default()
                        };

                        // Send the proxy through the provided channel
                        if !self.send(proxy, &tx, &counter) {
                            break; // Stop if sending fails
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
