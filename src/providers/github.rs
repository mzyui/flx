use std::{
    io::BufReader,
    net::Ipv4Addr,
    sync::{atomic::AtomicUsize, mpsc, Arc},
};

use async_trait::async_trait;
use scraper::Html;

use super::IProxyTrait;
use crate::models::{Anonymity, Protocol, Proxy, Source};

pub struct GithubRepoProvider;

impl GithubRepoProvider {
    fn githubusercontent(&self, path: &str) -> String {
        format!("https://raw.githubusercontent.com/{}", path)
    }
}

#[async_trait]
impl IProxyTrait for GithubRepoProvider {
    fn sources(&self) -> Vec<Source> {
        vec![
            Source::http(&self.githubusercontent("zevtyardt/proxy-list/main/http.txt")),
            Source::socks(
                &self.githubusercontent("zevtyardt/proxy-list/main/socks4.txt"),
            ),
            Source::socks(
                &self.githubusercontent("zevtyardt/proxy-list/main/socks5.txt"),
            ),
            Source::http(&self.githubusercontent("TheSpeedX/SOCKS-List/master/http.txt")),
            Source::socks(
                &self.githubusercontent("TheSpeedX/SOCKS-List/master/socks4.txt"),
            ),
            Source::socks(
                &self.githubusercontent("TheSpeedX/SOCKS-List/master/socks5.txt"),
            ),
            Source::http(
                &self.githubusercontent("monosans/proxy-list/main/proxies/http.txt"),
            ),
            Source::socks(
                &self.githubusercontent("monosans/proxy-list/main/proxies/socks4.txt"),
            ),
            Source::socks(
                &self.githubusercontent("monosans/proxy-list/main/proxies/socks5.txt"),
            ),
            Source::socks(
                &self.githubusercontent("hookzof/socks5_list/master/proxy.txt"),
            ),
            Source::http(&self.githubusercontent("mmpx12/proxy-list/master/http.txt")),
            Source::http(&self.githubusercontent("mmpx12/proxy-list/master/https.txt")),
            Source::socks(&self.githubusercontent("mmpx12/proxy-list/master/socks4.txt")),
            Source::socks(&self.githubusercontent("mmpx12/proxy-list/master/socks5.txt")),
            Source::all(
                &self.githubusercontent(
                    "proxifly/free-proxy-list/main/proxies/all/data.txt",
                ),
            ),
            Source::http(&self.githubusercontent("MuRongPIG/Proxy-Master/main/http.txt")),
            Source::socks(
                &self.githubusercontent("MuRongPIG/Proxy-Master/main/socks4.txt"),
            ),
            Source::http(&self.githubusercontent("zloi-user/hideip.me/main/http.txt")),
            Source::http(&self.githubusercontent("zloi-user/hideip.me/main/https.txt")),
            Source::socks(&self.githubusercontent("zloi-user/hideip.me/main/socks4.txt")),
            Source::socks(&self.githubusercontent("zloi-user/hideip.me/main/socks5.txt")),
        ]
    }

    async fn scrape(
        &self, html: Html, tx: mpsc::Sender<Option<Proxy>>, counter: Arc<AtomicUsize>,
        default_types: Vec<Arc<Protocol>>,
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
