mod config;

use std::{borrow::Cow, sync::Arc, time::Duration};

pub use config::Config;
use hashbrown::HashSet;
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use tokio::{sync::Semaphore, task::JoinHandle, time};

use crate::{
    geolookup::GeoLookup,
    providers::{
        models::Source, FreeProxyListProvider, GithubRepoProvider, IProxyTrait, ProxyscrapeProvider,
    },
    proxy::models::{Proxy, ProxyType},
};

/// Responsible for fetching proxies from various sources.
pub struct ProxyFetcher {
    sender: kanal::AsyncSender<Proxy>, // Channel sender for passing proxies.
    receiver: kanal::Receiver<Proxy>,  // Channel receiver for receiving proxies.
    counter: usize,                    // Counter for tracking the number of fetched proxies.
    timer: time::Instant,              // Timer for measuring elapsed time.
    elapsed: Option<Duration>,         // Duration of the fetcher operation.
    geolookup: Option<GeoLookup>,      // Optional GeoIP instance for location lookups.
    providers: Vec<Arc<dyn IProxyTrait + Send + Sync>>, // List of proxy providers.
    unique_ips: HashSet<Cow<'static, str>>, // Set to track unique IPs.
    handlers: Vec<JoinHandle<()>>,     // Handle for the fetching task.
    config: Config,                    // Configuration for the proxy fetcher.
}

impl ProxyFetcher {
    /// Starts a new `ProxyFetcher` with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config`: The configuration for the proxy fetcher.
    ///
    /// # Returns
    ///
    /// A result containing the initialized `ProxyFetcher`.
    pub async fn gather(config: Config) -> anyhow::Result<Self> {
        let (sender, receiver) = kanal::unbounded();
        let geolookup = if config.enable_geo_lookup {
            Some(GeoLookup::new().await?)
        } else {
            None
        };

        let providers: Vec<Arc<dyn IProxyTrait + Send + Sync>> = vec![
            //Arc::new(GithubRepoProvider),
            Arc::new(ProxyscrapeProvider),
            //Arc::new(FreeProxyListProvider),
        ];

        let mut fetcher = Self {
            sender: sender.to_async(),
            counter: 0,
            timer: time::Instant::now(),
            elapsed: None,
            handlers: vec![],
            unique_ips: HashSet::new(),
            geolookup,
            providers,
            receiver,
            config,
        };

        fetcher.start().await?;
        Ok(fetcher)
    }
}

/// Executes the work of fetching proxies from a given provider.
async fn do_work(
    provider: Arc<dyn IProxyTrait + Send + Sync>,
    client: Arc<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>>,
    source: Arc<Source>,
    tx: kanal::AsyncSender<Proxy>,
) -> anyhow::Result<()> {
    let html = provider
        .fetch(client, &source.url.to_string(), source.timeout)
        .await?;
    let proxy_types = source
        .default_types
        .clone()
        .into_iter()
        .map(|protocol| ProxyType {
            protocol,
            checked_on: 0.0,
            checked: false,
        })
        .collect();
    provider.scrape(html, tx, proxy_types).await
}

impl ProxyFetcher {
    /// Adds a custom proxy provider to the fetcher.
    ///
    /// # Arguments
    ///
    /// * `provider`: The provider to add.
    pub fn add_provider(&mut self, provider: Arc<dyn IProxyTrait + Send + Sync>) {
        self.providers.push(provider);
    }

    /// Gathers proxies from the configured providers.
    #[allow(unused_must_use)]
    async fn start(&mut self) -> anyhow::Result<()> {
        let providers = self.providers.clone();
        let mut tasks = vec![];
        for provider in providers.iter() {
            for source in provider.sources() {
                tasks.push((Arc::new(source), Arc::clone(provider)));
            }
        }

        #[cfg(feature = "log")]
        log::debug!(
            "Proxy gathering started. Collecting proxies from {} sources",
            tasks.len(),
        );

        let client = Arc::new(
            Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(HttpsConnector::new()),
        );
        let concurrency_limit = self.config.concurrency_limit;
        let sem = Arc::new(Semaphore::new(concurrency_limit));

        for (source, provider) in tasks {
            let permit = Arc::clone(&sem);
            let client = Arc::clone(&client);
            let tx = self.sender.clone();

            self.handlers.push(tokio::spawn(async move {
                if permit.acquire().await.is_ok() {
                    let url = source.url.to_string();
                    if let Err(e) = do_work(provider, client, source, tx).await {
                        #[cfg(feature = "log")]
                        log::error!("{}: {}", url, e);
                    }
                }
            }));
        }
        Ok(())
    }

    /// Retrieves one proxy from the receiver.
    ///
    /// If geo lookup is enabled, it will apply geographic filtering.
    ///
    /// # Returns
    ///
    /// An optional `Proxy` if one is available, otherwise `None`.
    pub fn get_one(&mut self) -> Option<Proxy> {
        while !self.receiver.is_empty() || self.receiver.sender_count() - 1 != 0 {
            if let Ok(mut proxy) = self.receiver.recv_timeout(Duration::from_millis(100)) {
                if let Some(geolookup) = &self.geolookup {
                    proxy.geo = geolookup.lookup(&proxy.ip);

                    if !self.config.countries.is_empty()
                        && !proxy
                            .geo
                            .iso_code
                            .clone()
                            .map(|code| self.config.countries.contains(&code))
                            .unwrap_or(false)
                    {
                        continue;
                    }
                }

                if self.config.enforce_unique_ip {
                    if self.unique_ips.insert(proxy.as_text()) {
                        self.counter += 1;
                        return Some(proxy);
                    } else {
                        continue;
                    }
                } else {
                    self.counter += 1;
                    return Some(proxy);
                }
            }
        }
        None
    }
}

impl Iterator for ProxyFetcher {
    type Item = Proxy;

    fn next(&mut self) -> Option<Self::Item> {
        self.get_one()
    }
}

impl Drop for ProxyFetcher {
    /// Cleans up resources when `ProxyFetcher` is dropped.
    fn drop(&mut self) {
        self.receiver.close();
        while let Some(handler) = self.handlers.pop() {
            handler.abort();
        }

        #[cfg(feature = "log")]
        #[cfg(feature = "log")]
        log::debug!(
            "Proxy gathering completed in {:?}. {} proxies were found",
            self.elapsed.unwrap_or(self.timer.elapsed()),
            self.counter
        );
    }
}
