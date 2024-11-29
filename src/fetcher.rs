use std::{
    collections::HashSet,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};

use fake::{
    faker::internet::en::{IPv4, UserAgent},
    Fake,
};
use reqwest::{Client, ClientBuilder};
use tokio::{task::JoinHandle, time};
use tokio_task_pool::Pool;

use crate::{
    geoip::GeoIp,
    models::{Protocol, Proxy, Source},
    providers::{
        free_proxy_list::FreeProxyListProvider, github::GithubRepoProvider, IProxyTrait,
    },
};

pub struct ProxyFetcherOptions {
    /// Ensure each proxy has unique IP, this will affect performance (default: true)
    pub enforce_unique_ip: bool,
    /// Maximum number of concurrency to process source url (default: 25)
    pub concurrency_limit: usize,
    /// Timeout in milliseconds (default: 3000)
    pub request_timeout: u64,
}

impl Default for ProxyFetcherOptions {
    fn default() -> Self {
        Self {
            enforce_unique_ip: true,
            concurrency_limit: 25,
            request_timeout: 3000,
        }
    }
}

pub struct ProxyFetcher {
    sender: mpsc::Sender<Option<Proxy>>,
    receiver: mpsc::Receiver<Option<Proxy>>,
    counter: Arc<AtomicUsize>,
    timer: time::Instant,
    elapsed: Option<Duration>,
    geoip: GeoIp,
    providers: Vec<Arc<dyn IProxyTrait + Send + Sync>>,
    unique_ip: HashSet<(Ipv4Addr, u16)>,
    options: ProxyFetcherOptions,
}

impl ProxyFetcher {
    pub async fn new(options: ProxyFetcherOptions) -> anyhow::Result<Self> {
        let (sender, receiver) = mpsc::channel();
        Ok(Self {
            sender,
            receiver,
            counter: Arc::new(AtomicUsize::new(0)),
            timer: time::Instant::now(),
            elapsed: None,
            geoip: GeoIp::new().await?,
            providers: vec![],
            unique_ip: HashSet::new(),
            options,
        })
    }
}

async fn do_work(
    provider: Arc<dyn IProxyTrait + Send + Sync>, client: Client, source: Arc<Source>,
    tx: mpsc::Sender<Option<Proxy>>, counter: Arc<AtomicUsize>,
) -> anyhow::Result<()> {
    let html = provider.fetch(client, source.url.as_ref()).await?;
    let types = source.default_types.clone();
    provider.scrape(html, tx, counter, types).await
}

impl ProxyFetcher {
    pub fn use_default_providers(&mut self) {
        self.providers = vec![
            Arc::new(FreeProxyListProvider::default()),
            Arc::new(GithubRepoProvider),
        ];
    }

    pub fn add_provider(&mut self, provider: Arc<dyn IProxyTrait + Send + Sync>) {
        self.providers.push(provider);
    }

    #[allow(unused_must_use)]
    pub async fn gather(&self) -> anyhow::Result<JoinHandle<()>> {
        let providers = self.providers.clone();
        let mut tasks = vec![];
        for provider in providers.iter() {
            for source in provider.sources() {
                tasks.push((Arc::new(source), Arc::clone(provider)));
            }
        }

        #[cfg(feature = "log")]
        log::debug!(
            "Proxy gather started. Collecting proxies from {} sources",
            tasks.len(),
        );

        let ua = UserAgent().fake::<&str>();
        let client = ClientBuilder::new()
            .timeout(Duration::from_millis(self.options.request_timeout))
            .user_agent(ua)
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()?;
        let counter = self.counter.clone();
        counter.store(0, std::sync::atomic::Ordering::Relaxed);
        let sender = self.sender.clone();

        let concurrency_limit = self.options.concurrency_limit;
        let handle = tokio::spawn(async move {
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
                        log::error!("{}", e);
                    }
                })
                .await;
            }
            while pool.busy_permits().unwrap_or(0) != 0 {
                time::sleep(Duration::from_millis(50)).await;
            }
            sender.send(None).unwrap_or_default();
        });
        Ok(handle)
    }

    pub fn get_one(&mut self) -> Option<Proxy> {
        loop {
            if let Some(mut proxy) = self.receiver.recv().ok()? {
                if self.options.enforce_unique_ip {
                    if self.unique_ip.insert((proxy.ip, proxy.port)) {
                        proxy.geo = self.geoip.lookup(&proxy.ip);
                        return Some(proxy);
                    } else {
                        self.counter.fetch_sub(1, Ordering::Relaxed);
                    }
                } else {
                    return Some(proxy);
                }
            }
        }
    }
}

impl Iterator for ProxyFetcher {
    type Item = Proxy;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(proxy) = self.get_one() {
            return Some(proxy);
        }
        self.elapsed = Some(self.timer.elapsed());
        None
    }
}

impl Drop for ProxyFetcher {
    fn drop(&mut self) {
        self.sender.send(None).unwrap_or_default();
        #[cfg(feature = "log")]
        let total_proxies = self.counter.load(std::sync::atomic::Ordering::Acquire);
        #[cfg(feature = "log")]
        log::debug!(
            "Proxy gather completed in {:?}. {} proxies where found. ",
            self.elapsed.unwrap_or(self.timer.elapsed()),
            total_proxies
        );
    }
}
