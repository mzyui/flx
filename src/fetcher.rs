use std::{
    collections::HashSet,
    net::Ipv4Addr,
    sync::{atomic::AtomicUsize, mpsc, Arc},
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
    models::{Protocol, Proxy, Source},
    providers::{
        free_proxy_list::FreeProxyListProvider, github::GithubRepoProvider, IProxyTrait,
    },
};


pub struct ProxyFetcher {
    sender: mpsc::SyncSender<Option<Proxy>>,
    receiver: mpsc::Receiver<Option<Proxy>>,
    counter: Arc<AtomicUsize>,
    timer: time::Instant,
    elapsed: Option<Duration>,
    providers: Vec<Arc<dyn IProxyTrait + Send + Sync>>,
    unique_ip: HashSet<(Ipv4Addr, u16)>,

    // options
    enforce_unique_ip: bool,
}

impl Default for ProxyFetcher {
    fn default() -> Self {
        let (sender, receiver) = mpsc::sync_channel(1024);
        Self {
            sender,
            receiver,
            counter: Arc::new(AtomicUsize::new(0)),
            timer: time::Instant::now(),
            elapsed: None,
            providers: vec![],
            enforce_unique_ip: true,
            unique_ip: HashSet::new(),
        }
    }
}

async fn do_work(
    provider: Arc<dyn IProxyTrait + Send + Sync>, client: Client, source: Arc<Source>,
    tx: mpsc::SyncSender<Option<Proxy>>, counter: Arc<AtomicUsize>,
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

    /// Ensure each proxy has unique IP, this will affect performance (default: true)
    pub fn enforce_unique_ip(&mut self, value: bool) {
        self.enforce_unique_ip = value;
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
            .timeout(Duration::from_secs(3))
            .user_agent(ua)
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()?;
        let counter = self.counter.clone();
        counter.store(0, std::sync::atomic::Ordering::Relaxed);
        let sender = self.sender.clone();

        let handle = tokio::spawn(async move {
            let pool = Pool::bounded(25);
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

impl Iterator for ProxyFetcher {
    type Item = Proxy;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(proxy) = self.receiver.recv().unwrap_or_default() {
            if self.enforce_unique_ip {
                if !self.unique_ip.contains(&(proxy.ip, proxy.port)) {
                    self.unique_ip.insert((proxy.ip, proxy.port));
                    return Some(proxy);
                } else {
                    self.counter
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    return self.next();
                }
            }
            return Some(proxy);
        }
        self.elapsed = Some(self.timer.elapsed());
        None
    }
}
