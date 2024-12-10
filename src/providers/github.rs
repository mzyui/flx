use std::{
    net::Ipv4Addr,
    sync::{atomic::AtomicUsize, Arc},
};

use async_trait::async_trait;
use scraper::Html;

use super::models::Source;
use super::IProxyTrait;
use crate::proxy::models::{Proxy, ProxyType};

/// A provider for fetching proxy lists from GitHub repositories.
pub struct GithubRepoProvider;

impl GithubRepoProvider {
    /// Constructs a raw URL for accessing files in a GitHub repository.
    ///
    /// # Arguments
    ///
    /// * `path`: The path to the file in the GitHub repository.
    ///
    /// # Returns
    ///
    /// A formatted string representing the raw GitHub URL.
    fn githubusercontent(&self, path: &str) -> String {
        format!("https://raw.githubusercontent.com/{}", path)
    }
}

#[async_trait]
impl IProxyTrait for GithubRepoProvider {
    /// Returns a list of sources from which proxies can be fetched.
    ///
    /// # Returns
    ///
    /// A vector of `Source` objects representing the proxy sources.
    fn sources(&self) -> Vec<Source> {
        vec![
            Source::http(&self.githubusercontent("zevtyardt/proxy-list/main/http.txt")),
            Source::socks(&self.githubusercontent("zevtyardt/proxy-list/main/socks4.txt")),
            Source::socks(&self.githubusercontent("zevtyardt/proxy-list/main/socks5.txt")),
            Source::http(&self.githubusercontent("TheSpeedX/SOCKS-List/master/http.txt")),
            Source::socks(&self.githubusercontent("TheSpeedX/SOCKS-List/master/socks4.txt")),
            Source::socks(&self.githubusercontent("TheSpeedX/SOCKS-List/master/socks5.txt")),
            Source::http(&self.githubusercontent("monosans/proxy-list/main/proxies/http.txt")),
            Source::socks(&self.githubusercontent("monosans/proxy-list/main/proxies/socks4.txt")),
            Source::socks(&self.githubusercontent("monosans/proxy-list/main/proxies/socks5.txt")),
            Source::socks(&self.githubusercontent("hookzof/socks5_list/master/proxy.txt")),
            Source::http(&self.githubusercontent("mmpx12/proxy-list/master/http.txt")),
            Source::http(&self.githubusercontent("mmpx12/proxy-list/master/https.txt")),
            Source::socks(&self.githubusercontent("mmpx12/proxy-list/master/socks4.txt")),
            Source::socks(&self.githubusercontent("mmpx12/proxy-list/master/socks5.txt")),
            Source::all(
                &self.githubusercontent("proxifly/free-proxy-list/main/proxies/all/data.txt"),
            ),
            Source::http(&self.githubusercontent("MuRongPIG/Proxy-Master/main/http.txt")),
            Source::socks(&self.githubusercontent("MuRongPIG/Proxy-Master/main/socks4.txt")),
            Source::http(&self.githubusercontent("zloi-user/hideip.me/main/http.txt")),
            Source::http(&self.githubusercontent("zloi-user/hideip.me/main/https.txt")),
            Source::socks(&self.githubusercontent("zloi-user/hideip.me/main/socks4.txt")),
            Source::socks(&self.githubusercontent("zloi-user/hideip.me/main/socks5.txt")),
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
        for line in html.html().lines() {
            let mut parts = line.trim().split(':');
            if let (Some(ip_str), Some(port_str)) = (parts.next(), parts.next()) {
                if let (Ok(ip), Ok(port)) = (ip_str.parse::<Ipv4Addr>(), port_str.parse::<u16>()) {
                    let proxy = Proxy {
                        ip,
                        port,
                        types: default_types.clone(),
                        ..Default::default()
                    };
                    if !self.send(proxy, &tx, &counter) {
                        break; // Stop if sending fails
                    }
                }
            }
        }
        Ok(())
    }
}
