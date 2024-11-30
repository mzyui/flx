use std::{
    collections::HashSet,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};

use fake::{faker::internet::en::UserAgent, Fake};
use reqwest::{Client, ClientBuilder};
use tokio::{task::JoinHandle, time};
use tokio_task_pool::Pool;

use crate::{
    geoip::GeoIp,
    models::{Proxy, ProxyFetcherConfig, Source},
    providers::{
        free_proxy_list::FreeProxyListProvider, github::GithubRepoProvider, IProxyTrait,
    },
};

/// Responsible for fetching proxies from various sources.
pub struct ProxyFetcher {
    sender: mpsc::Sender<Option<Proxy>>,
    receiver: mpsc::Receiver<Option<Proxy>>,
    counter: Arc<AtomicUsize>,
    timer: time::Instant,
    elapsed: Option<Duration>,
    geoip: Option<GeoIp>,
    providers: Vec<Arc<dyn IProxyTrait + Send + Sync>>,
    unique_ip: HashSet<(Ipv4Addr, u16)>,
    handler: Option<JoinHandle<()>>,
    config: ProxyFetcherConfig,
}

impl ProxyFetcher {
    /// Initializes a new `ProxyFetcher` with the given config.
    pub async fn new(config: ProxyFetcherConfig) -> anyhow::Result<Self> {
        let (sender, receiver) = mpsc::channel();
        let geoip = if config.enable_geo_lookup {
            Some(GeoIp::new().await?)
        } else {
            None
        };
        let providers: Vec<Arc<dyn IProxyTrait + Send + Sync>> = vec![
            Arc::new(FreeProxyListProvider::default()),
            Arc::new(GithubRepoProvider),
        ];

        Ok(Self {
            sender,
            receiver,
            counter: Arc::new(AtomicUsize::new(0)),
            timer: time::Instant::now(),
            elapsed: None,
            geoip,
            handler: None,
            providers,
            unique_ip: HashSet::new(),
            config,
        })
    }
}

/// Executes the work of fetching proxies from a given provider.
async fn do_work(
    provider: Arc<dyn IProxyTrait + Send + Sync>, client: Client, source: Arc<Source>,
    tx: mpsc::Sender<Option<Proxy>>, counter: Arc<AtomicUsize>,
) -> anyhow::Result<()> {
    let html = provider.fetch(client, source.url.as_ref()).await?;
    let types = source.default_types.clone();
    provider.scrape(html, tx, counter, types).await
}

impl ProxyFetcher {
    /// Adds a custom proxy provider to the fetcher.
    pub fn add_provider(&mut self, provider: Arc<dyn IProxyTrait + Send + Sync>) {
        self.providers.push(provider);
    }

    /// Gathers proxies from the configured providers.
    #[allow(unused_must_use)]
    pub async fn gather(&mut self) -> anyhow::Result<()> {
        // Abort any ongoing gathering process if it exists.
        if let Some(handler) = &self.handler {
            handler.abort();
            self.handler = None;
        }

        let providers = self.providers.clone();
        let mut tasks = vec![];
        for provider in providers.iter() {
            for source in provider.sources() {
                tasks.push((Arc::new(source), Arc::clone(provider)));
            }
        }

        #[cfg(feature = "log")]
        log::debug!(
            "Proxy gather started. Collecting proxies from {} sources.",
            tasks.len(),
        );

        let ua = UserAgent().fake::<&str>();
        let client = ClientBuilder::new()
            .timeout(Duration::from_millis(self.config.request_timeout))
            .user_agent(ua)
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()?;

        let counter = self.counter.clone();
        counter.store(0, std::sync::atomic::Ordering::Relaxed);
        let sender = self.sender.clone();

        let concurrency_limit = self.config.concurrency_limit;
        let handler = tokio::spawn(async move {
            let pool = Pool::bounded(concurrency_limit);
            for (source, provider) in tasks.iter() {
                let source = Arc::clone(source);
                let provider = Arc::clone(provider);

                let tx = sender.clone();
                let client = client.clone();
                let counter = Arc::clone(&counter);
                pool.spawn(async move {
                    if let Err(e) = do_work(provider, client, source, tx, counter).await {
                        #[cfg(feature = "log")]
                        log::error!("{}.", e);
                    }
                })
                .await;
            }
            // Wait for all tasks in the pool to complete.
            while pool.busy_permits().unwrap_or(0) != 0 {
                time::sleep(Duration::from_millis(50)).await;
            }
            sender.send(None).unwrap_or_default();
        });
        self.handler = Some(handler);
        Ok(())
    }

    /// Retrieves one proxy from the receiver. Applying geo lookup is enabled.
    pub fn get_one(&mut self) -> Option<Proxy> {
        while let Some(mut proxy) = self
            .receiver
            .recv_timeout(Duration::from_millis(3000))
            .ok()?
        {
            if !self.config.filters.is_types_match(&proxy) {
                self.counter.fetch_sub(1, Ordering::Relaxed);
                continue;
            }

            if let Some(geoip) = &self.geoip {
                proxy.geo = geoip.lookup(&proxy.ip);
                if !self.config.filters.is_country_match(&proxy) {
                    self.counter.fetch_sub(1, Ordering::Relaxed);
                    continue;
                }
            }

            if self.config.enforce_unique_ip {
                if self.unique_ip.insert((proxy.ip, proxy.port)) {
                    return Some(proxy);
                } else {
                    self.counter.fetch_sub(1, Ordering::Relaxed);
                    continue;
                }
            } else {
                return Some(proxy);
            }
        }
        None
    }

    /// Creates an iterator for the fetched proxies.
    pub fn iter(&mut self) -> ProxyFetcherIter {
        ProxyFetcherIter { inner: self }
    }
}

/// Iterator for fetching proxies from the `ProxyFetcher`.
pub struct ProxyFetcherIter<'a> {
    inner: &'a mut ProxyFetcher,
}

impl ProxyFetcherIter<'_> {}

impl Iterator for ProxyFetcherIter<'_> {
    type Item = Proxy;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(proxy) = self.inner.get_one() {
            return Some(proxy);
        }
        self.inner.elapsed = Some(self.inner.timer.elapsed());
        None
    }
}

impl Drop for ProxyFetcher {
    /// Cleans up resources when `ProxyFetcher` is dropped.
    fn drop(&mut self) {
        self.sender.send(None).unwrap_or_default();
        if let Some(handler) = &self.handler {
            handler.abort();
        }

        #[cfg(feature = "log")]
        let total_proxies = self.counter.load(std::sync::atomic::Ordering::Acquire);
        #[cfg(feature = "log")]
        log::debug!(
            "Proxy gather completed in {:?}. {} proxies were found.",
            self.elapsed.unwrap_or(self.timer.elapsed()),
            total_proxies
        );
    }
}
