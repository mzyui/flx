use std::{
    net::Ipv4Addr,
    sync::{atomic::AtomicUsize, Arc},
};

use async_trait::async_trait;
use scraper::Html;

use super::IProxyTrait;
use crate::models::{Proxy, ProxyType, Source};

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
        // Iterate through each line of the HTML content
        for line in html.html().lines() {
            let mut parts = line.trim().split(':');
            if let (Some(ip_str), Some(port_str)) = (parts.next(), parts.next()) {
                // Parse IP address and port number
                if let (Ok(ip), Ok(port)) = (ip_str.parse::<Ipv4Addr>(), port_str.parse::<u16>()) {
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

        Ok(())
    }
}
