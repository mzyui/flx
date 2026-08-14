mod cache;
mod config;

use std::{
    borrow::Cow,
    collections::{hash_map::DefaultHasher, VecDeque},
    hash::{Hash, Hasher},
    net::Ipv4Addr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::Context;
pub use config::{Config, DEFAULT_CACHE_TTL_MINUTES, DEFAULT_CONCURRENCY_LIMIT};
use futures_util::Stream;
use hashbrown::HashSet;
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use tokio::{
    sync::{mpsc, watch, Notify, Semaphore},
    task::{JoinHandle, JoinSet},
    time,
};

use crate::{
    geolookup::GeoLookup,
    providers::{
        all_providers, models::Source, select_providers, CustomUrlProvider, ProviderTier,
        ProxyProvider,
    },
    proxy::models::{Protocol, Proxy},
};

pub(crate) const FETCH_CHANNEL_CAPACITY: usize = 2_048;

const PRIMARY_PHASE_TIMEOUT: Duration = Duration::from_secs(30);

const MAX_DEDUP_ENDPOINTS: usize = 100_000;

type EndpointKey = (Ipv4Addr, u16, u64);

fn protocol_hash(protocols: &[Protocol]) -> u64 {
    let mut hasher = DefaultHasher::new();
    protocols.hash(&mut hasher);
    hasher.finish()
}

struct DedupTable {
    seen: HashSet<EndpointKey>,
    order: VecDeque<EndpointKey>,
    capacity: usize,
}

impl DedupTable {
    fn new() -> Self {
        Self::with_capacity(MAX_DEDUP_ENDPOINTS)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn insert(&mut self, endpoint: EndpointKey) -> bool {
        if self.seen.contains(&endpoint) {
            return false;
        }
        if self.seen.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(endpoint);
        self.order.push_back(endpoint);
        true
    }
}

/// Async stream of scraped proxy candidates.
pub struct ProxyFetcher {
    receiver: mpsc::Receiver<Proxy>, // Channel receiver for receiving proxies.
    counter: usize,                  // Counter for tracking the number of fetched proxies.
    timer: time::Instant,            // Timer for measuring elapsed time.
    elapsed: Option<Duration>,       // Duration of the fetcher operation.
    geolookup: Option<GeoLookup>,    // Optional GeoIP instance for location lookups.
    countries: HashSet<String>,      // Normalized ISO country filter.
    unique_ips: DedupTable,
    coordinator: JoinHandle<()>,
    config: Config, // Configuration for the proxy fetcher.
    accepted: Arc<AtomicUsize>,
    drain_notify: Arc<Notify>,
    prefetched: Option<Proxy>,
    stop_tx: watch::Sender<bool>,
    stop_signaled: AtomicBool,
}

impl ProxyFetcher {
    pub async fn gather(config: Config) -> anyhow::Result<Self> {
        if config.concurrency_limit == 0 {
            anyhow::bail!("config.concurrency_limit must be greater than zero");
        }
        // A country filter is meaningless without GeoIP lookup, so reject the
        // combination up front instead of silently dropping every proxy.
        if !config.countries.is_empty() && !config.enable_geo_lookup {
            anyhow::bail!(
                "country filter requires enable_geo_lookup=true (GeoIP lookup is currently disabled)"
            );
        }
        let (sender, receiver) = mpsc::channel(FETCH_CHANNEL_CAPACITY);
        let geolookup = if config.enable_geo_lookup {
            Some(
                GeoLookup::new()
                    .await
                    .context("failed to initialize geo lookup")?,
            )
        } else {
            None
        };

        let mut providers = select_providers(
            all_providers(),
            &config.providers,
            &config.excluded_providers,
        );
        let mut known_names: Vec<&str> = all_providers()
            .iter()
            .map(|provider| provider.name())
            .collect();
        if !config.custom_sources.is_empty() {
            known_names.push("custom");
        }
        for name in config.providers.iter() {
            if !known_names.contains(&name.as_str()) {
                anyhow::bail!(
                    "unknown provider `{name}` (available: {})",
                    known_names.join(", ")
                );
            }
        }
        for url in config.custom_sources.iter() {
            providers
                .push(Arc::new(CustomUrlProvider::new(url).with_context(
                    || format!("invalid custom source URL `{url}`"),
                )?));
        }
        if providers.is_empty() {
            #[cfg(feature = "log")]
            log::warn!("provider selection matched no providers");
        }

        let countries = config.normalized_countries();
        let accepted = Arc::new(AtomicUsize::new(0));

        let mut primary = vec![];
        let mut fallback = vec![];
        for provider in providers.iter() {
            let bucket = match provider.tier() {
                ProviderTier::Primary => &mut primary,
                ProviderTier::Fallback => &mut fallback,
            };
            for source in provider.sources() {
                bucket.push((Arc::new(source), Arc::clone(provider)));
            }
        }

        #[cfg(feature = "log")]
        log::debug!(
            "Proxy gathering started ({} primary sources, {} fallback sources)",
            primary.len(),
            fallback.len(),
        );

        let client = Arc::new(
            Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(HttpsConnector::new()),
        );
        let concurrency_limit = config.concurrency_limit;
        let fallback_threshold = config.fallback_threshold;
        let offline = config.offline;

        // The local body cache is optional and best-effort: if the cache dir
        // cannot be prepared the run simply proceeds without caching.
        let fetch_cache = match config.cache_ttl {
            Some(ttl) => match cache::Cache::new(ttl, config.refresh_cache) {
                Ok(cache) => Some(Arc::new(cache)),
                Err(error) => {
                    #[cfg(feature = "log")]
                    log::warn!("provider fetch cache disabled: {error:#}");
                    let _ = error;
                    None
                }
            },
            None => None,
        };

        // Proxies are counted by the consumer as they are accepted, so the
        // coordinator can size up the primary phase without any extra channel
        // hop or forwarding task. The tally reflects proxies that survived
        // dedup and country filtering, which is what a threshold should mean.
        let produced = Arc::clone(&accepted);

        let drain_notify = Arc::new(Notify::new());
        let drain_notify_coordinator = Arc::clone(&drain_notify);

        let (stop_tx, stop_rx) = watch::channel(false);
        let stop_rx_coordinator = stop_rx.clone();
        let stop_rx_primary = stop_rx.clone();
        let stop_rx_fallback = stop_rx;

        // Coordinator: runs the primary phase to completion (bounded by
        // PRIMARY_PHASE_TIMEOUT), then decides whether to run the fallback.
        // A `watch` stop-signal lets the consumer abort the primary phase
        // early when the threshold is already satisfied.
        let coordinator = tokio::spawn({
            let sender = sender.clone();
            async move {
                let mut stop_rx_coordinator = stop_rx_coordinator;
                let sem = Arc::new(Semaphore::new(concurrency_limit));
                let mut primary_handles = spawn_phase(
                    primary,
                    &client,
                    &sem,
                    sender.clone(),
                    stop_rx_primary,
                    fetch_cache.clone(),
                    offline,
                );

                let mut primary_aborted = false;
                tokio::select! {
                    _ = async { while primary_handles.join_next().await.is_some() {} } => {
                        // primary phase completed naturally
                    }
                    _ = stop_rx_coordinator.changed() => {
                        primary_handles.abort_all();
                        while primary_handles.join_next().await.is_some() {}
                        primary_aborted = true;
                    }
                    _ = time::sleep(PRIMARY_PHASE_TIMEOUT) => {
                        primary_handles.abort_all();
                        while primary_handles.join_next().await.is_some() {}
                        primary_aborted = true;
                    }
                }

                #[cfg(feature = "log")]
                if primary_aborted {
                    log::warn!(
                        "primary providers aborted (stop signal or timeout {:?})",
                        PRIMARY_PHASE_TIMEOUT
                    );
                }
                let _ = primary_aborted;

                if *stop_rx_coordinator.borrow() {
                    #[cfg(feature = "log")]
                    log::debug!("stopping early: consumer collected enough proxies");
                    return;
                }

                // Wait until the consumer has drained the channel so the
                // primary counter is stable before evaluating the fallback
                // threshold.  Notify is a zero-cost signal: the consumer
                // calls `notify_one` when it detects the channel is empty.
                if sender.capacity() < sender.max_capacity() {
                    drain_notify_coordinator.notified().await;
                }

                let found = produced.load(Ordering::Relaxed);
                if let Some(threshold) = fallback_threshold {
                    if found >= threshold {
                        #[cfg(feature = "log")]
                        log::debug!(
                            "skipping fallback providers: {} proxies already found (threshold {})",
                            found,
                            threshold
                        );
                        return;
                    }
                }

                #[cfg(feature = "log")]
                log::debug!(
                    "primary phase yielded {} proxies; starting {} fallback sources",
                    found,
                    fallback.len()
                );

                let mut fallback_handles = spawn_phase(
                    fallback,
                    &client,
                    &sem,
                    sender,
                    stop_rx_fallback,
                    fetch_cache,
                    offline,
                );
                while fallback_handles.join_next().await.is_some() {}
            }
        });

        Ok(Self {
            receiver,
            counter: 0,
            timer: time::Instant::now(),
            elapsed: None,
            coordinator,
            unique_ips: DedupTable::new(),
            geolookup,
            countries,
            config,
            accepted,
            drain_notify,
            prefetched: None,
            stop_tx,
            stop_signaled: AtomicBool::new(false),
        })
    }
}

#[cfg(test)]
async fn finish_phase(mut handles: JoinSet<()>, timeout: Duration) -> bool {
    let drain = async { while handles.join_next().await.is_some() {} };
    if time::timeout(timeout, drain).await.is_ok() {
        return true;
    }
    handles.abort_all();
    while handles.join_next().await.is_some() {}
    false
}

fn spawn_phase(
    tasks: Vec<(Arc<Source>, Arc<dyn ProxyProvider + Send + Sync>)>,
    client: &Arc<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>>,
    sem: &Arc<Semaphore>,
    tx: mpsc::Sender<Proxy>,
    stop_rx: watch::Receiver<bool>,
    fetch_cache: Option<Arc<cache::Cache>>,
    offline: bool,
) -> JoinSet<()> {
    let mut handles = JoinSet::new();
    for (source, provider) in tasks {
        let permit = Arc::clone(sem);
        let client = Arc::clone(client);
        let tx = tx.clone();
        let stop_rx = stop_rx.clone();
        let fetch_cache = fetch_cache.clone();

        handles.spawn(async move {
            let url = source.url.to_string();
            if let Err(e) = do_work(
                provider,
                client,
                source,
                tx,
                permit,
                stop_rx,
                FetchSettings {
                    fetch_cache,
                    offline,
                },
            )
            .await
            {
                #[cfg(feature = "log")]
                log::error!("{}: {}", url, e);
                let _ = (url, e);
            }
        });
    }
    handles
}

/// Fetch behaviour shared by every source task.
struct FetchSettings {
    fetch_cache: Option<Arc<cache::Cache>>,
    offline: bool,
}

async fn do_work(
    provider: Arc<dyn ProxyProvider + Send + Sync>,
    client: Arc<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>>,
    source: Arc<Source>,
    tx: mpsc::Sender<Proxy>,
    sem: Arc<Semaphore>,
    stop_rx: watch::Receiver<bool>,
    settings: FetchSettings,
) -> anyhow::Result<()> {
    if *stop_rx.borrow() {
        return Ok(());
    }
    let url = source.url.to_string();

    let html = match settings.fetch_cache.as_ref() {
        Some(fetch_cache) => match fetch_cache.load(&url).await {
            Some(body) => {
                #[cfg(feature = "log")]
                log::debug!("using cached body for {url}");
                Cow::Owned(body)
            }
            None => {
                if settings.offline {
                    #[cfg(feature = "log")]
                    log::warn!("offline: no cached body for {url}; skipping");
                    return Ok(());
                }
                let _permit = sem
                    .acquire()
                    .await
                    .context("fetcher semaphore closed during shutdown")?;
                let body = provider
                    .fetch(client, &url, source.timeout)
                    .await
                    .with_context(|| format!("failed to fetch proxy list from {}", source.url))?;
                // Only a real network fetch is worth persisting: a cache hit
                // that re-wrote the same body to disk every run was pure
                // write-amplification.
                fetch_cache.store(&url, body.as_ref()).await;
                body
            }
        },
        None => {
            if settings.offline {
                #[cfg(feature = "log")]
                log::warn!("offline: cache disabled; skipping {url}");
                return Ok(());
            }
            let _permit = sem
                .acquire()
                .await
                .context("fetcher semaphore closed during shutdown")?;
            provider
                .fetch(client, &url, source.timeout)
                .await
                .with_context(|| format!("failed to fetch proxy list from {}", source.url))?
        }
    };

    if *stop_rx.borrow() {
        return Ok(());
    }

    let expected_types = Arc::clone(&source.default_types);
    provider
        .scrape_with(html, tx, expected_types, source.mode.clone())
        .await
        .with_context(|| format!("failed to scrape proxies from {}", source.url))
}

impl ProxyFetcher {
    pub async fn get_one(&mut self) -> Option<Proxy> {
        loop {
            let proxy = if let Some(proxy) = self.prefetched.take() {
                proxy
            } else {
                match self.receiver.recv().await {
                    Some(proxy) => proxy,
                    None => {
                        self.elapsed = Some(self.timer.elapsed());
                        self.drain_notify.notify_one();
                        return None;
                    }
                }
            };
            if let Some(proxy) = self.accept(proxy) {
                self.check_drain();
                return Some(proxy);
            }
        }
    }

    /// Cloneable handle to the number of proxies accepted so far.
    ///
    /// The count grows as candidates survive dedup and country filtering; read
    /// it after the stream ends to report a final tally.
    pub fn accepted_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.accepted)
    }

    fn check_drain(&mut self) {
        match self.receiver.try_recv() {
            Ok(proxy) => {
                self.prefetched = Some(proxy);
            }
            Err(_) => {
                self.drain_notify.notify_one();
            }
        }
    }

    fn accept(&mut self, proxy: Proxy) -> Option<Proxy> {
        let result = accept_proxy(
            &mut self.unique_ips,
            self.config.enforce_unique_ip,
            &self.countries,
            &mut self.counter,
            &self.accepted,
            proxy,
            |ip| {
                self.geolookup
                    .as_ref()
                    .map(|geolookup| geolookup.lookup(ip))
            },
        );
        if result.is_some() {
            if let Some(threshold) = self.config.fallback_threshold {
                // Signal the stop atomically: `compare_exchange` ensures
                // only the first caller crossing the threshold sends, so the
                // watch version is bumped exactly once per run.
                if self.accepted.load(Ordering::Relaxed) >= threshold
                    && self
                        .stop_signaled
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    let _ = self.stop_tx.send(true);
                }
            }
        }
        result
    }
}

fn accept_proxy<F>(
    unique_ips: &mut DedupTable,
    enforce_unique_ip: bool,
    countries: &HashSet<String>,
    counter: &mut usize,
    accepted: &AtomicUsize,
    mut proxy: Proxy,
    lookup: F,
) -> Option<Proxy>
where
    F: FnOnce(&Ipv4Addr) -> Option<crate::geolookup::models::GeoData>,
{
    if enforce_unique_ip
        && !unique_ips.insert((proxy.ip, proxy.port, protocol_hash(&proxy.expected_types)))
    {
        return None;
    }

    if let Some(geo) = lookup(&proxy.ip) {
        proxy.geo = Arc::new(geo);

        if !countries.is_empty()
            && !proxy
                .geo
                .iso_code
                .as_ref()
                .map(|code| countries.contains(code.as_ref()))
                .unwrap_or(false)
        {
            return None;
        }
    }

    *counter += 1;
    accepted.fetch_add(1, Ordering::Relaxed);
    Some(proxy)
}

impl Stream for ProxyFetcher {
    type Item = Proxy;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(proxy) = this.prefetched.take() {
                if let Some(proxy) = this.accept(proxy) {
                    this.check_drain();
                    return Poll::Ready(Some(proxy));
                }
                continue;
            }
            match this.receiver.poll_recv(cx) {
                Poll::Ready(Some(proxy)) => {
                    if let Some(proxy) = this.accept(proxy) {
                        this.check_drain();
                        return Poll::Ready(Some(proxy));
                    }
                }
                Poll::Ready(None) => {
                    if this.elapsed.is_none() {
                        this.elapsed = Some(this.timer.elapsed());
                    }
                    this.drain_notify.notify_one();
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Drop for ProxyFetcher {
    fn drop(&mut self) {
        // Closing the receiver makes every pending `send` fail, which unwinds
        // the producing tasks on their own so they don't outlive us.
        self.receiver.close();

        self.coordinator.abort();

        #[cfg(feature = "log")]
        log::debug!(
            "Proxy gathering completed: {} proxies found ({:?})",
            self.counter,
            self.elapsed.unwrap_or(self.timer.elapsed()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{accept_proxy, do_work, finish_phase, protocol_hash, DedupTable, ProxyFetcher};
    use crate::fetcher::{cache::Cache, Config};
    use crate::geolookup::models::GeoData;
    use crate::providers::models::Source;
    use crate::providers::ProxyProvider;
    use crate::proxy::models::{Anonymity, Protocol, Proxy};
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper_tls::HttpsConnector;
    use hyper_util::{
        client::legacy::{connect::HttpConnector, Client},
        rt::TokioExecutor,
    };
    use std::{
        net::Ipv4Addr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};

    struct OfflineTestProvider;

    #[async_trait::async_trait]
    impl ProxyProvider for OfflineTestProvider {
        fn name(&self) -> &'static str {
            "offline-test"
        }

        fn sources(&self) -> Vec<Source> {
            Vec::new()
        }
    }

    fn test_client() -> Arc<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>> {
        Arc::new(
            Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(HttpsConnector::new()),
        )
    }

    fn temp_cache_dir() -> (crate::fetcher::cache::Cache, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "flx_offline_test_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir_backup = dir.clone();
        (
            Cache::new_at(dir, Duration::from_secs(60), false),
            dir_backup,
        )
    }

    #[test]
    fn duplicate_endpoint_is_rejected_before_geo_lookup() {
        let mut unique_ips = DedupTable::new();
        let config = Config::default();
        let countries = hashbrown::HashSet::new();
        let mut counter = 0;
        let accepted = AtomicUsize::new(0);
        let lookups = Arc::new(AtomicUsize::new(0));
        let proxy = Proxy::new(Ipv4Addr::new(192, 0, 2, 1), 8080);

        assert!(accept_proxy(
            &mut unique_ips,
            config.enforce_unique_ip,
            &countries,
            &mut counter,
            &accepted,
            proxy.clone(),
            |_| {
                lookups.fetch_add(1, Ordering::Relaxed);
                Some(Default::default())
            }
        )
        .is_some());
        assert!(accept_proxy(
            &mut unique_ips,
            config.enforce_unique_ip,
            &countries,
            &mut counter,
            &accepted,
            proxy,
            |_| {
                lookups.fetch_add(1, Ordering::Relaxed);
                Some(Default::default())
            }
        )
        .is_none());
        assert_eq!(lookups.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn same_endpoint_preserves_different_advertised_protocols() {
        let mut unique_ips = DedupTable::new();
        let countries = hashbrown::HashSet::new();
        let mut counter = 0;
        let accepted = AtomicUsize::new(0);
        let ip = Ipv4Addr::new(192, 0, 2, 10);
        let http =
            Proxy::with_expected_types(ip, 8080, Arc::from([Protocol::Http(Anonymity::Unknown)]));
        let socks5 = Proxy::with_expected_types(ip, 8080, Arc::from([Protocol::Socks5]));

        let first = accept_proxy(
            &mut unique_ips,
            true,
            &countries,
            &mut counter,
            &accepted,
            http,
            |_| None,
        );
        let second = accept_proxy(
            &mut unique_ips,
            true,
            &countries,
            &mut counter,
            &accepted,
            socks5,
            |_| None,
        );

        assert!(first.is_some());
        assert!(second.is_some());
        assert_eq!(counter, 2);
    }

    #[test]
    fn protocol_hash_preserves_protocol_set_equality() {
        // Regression test: the dedup key is a `u64` hash of the advertised
        // protocol set, so identical sets collide and distinct sets stay distinct.
        let http = Arc::from([Protocol::Http(Anonymity::Unknown)]);
        let socks5 = Arc::from([Protocol::Socks5]);
        let both = Arc::from([Protocol::Socks5, Protocol::Http(Anonymity::Unknown)]);
        let same = Arc::from([Protocol::Socks5, Protocol::Http(Anonymity::Unknown)]);
        let empty = Arc::from([] as [Protocol; 0]);

        assert_eq!(protocol_hash(&both), protocol_hash(&same));
        assert_eq!(protocol_hash(&empty), protocol_hash(&empty));
        assert_ne!(protocol_hash(&http), protocol_hash(&socks5));
        assert_ne!(protocol_hash(&both), protocol_hash(&socks5));
        assert_ne!(protocol_hash(&both), protocol_hash(&http));
    }

    #[test]
    fn dedup_table_is_bounded_and_evicts_oldest() {
        // Regression test: the dedup table has a fixed capacity and drops the
        // oldest entry, so an evicted endpoint can be accepted again.
        let mut table = DedupTable::with_capacity(2);
        let base = Ipv4Addr::new(192, 0, 2, 1);
        let key = |offset: u16| (base, offset, 7u64);

        assert!(table.insert(key(1)));
        assert!(table.insert(key(2)));
        assert!(
            !table.insert(key(1)),
            "duplicate within window stays filtered"
        );

        assert!(
            table.insert(key(3)),
            "new endpoint beyond capacity accepted"
        );
        assert_eq!(table.seen.len(), 2, "table stays bounded at capacity");

        assert!(table.insert(key(1)), "evicted endpoint can come back");
        assert_eq!(table.seen.len(), 2, "table stays bounded at capacity");
    }

    #[test]
    fn country_filter_is_case_insensitive() {
        let mut unique_ips = DedupTable::new();
        let countries = ["id".to_owned()]
            .into_iter()
            .map(|country| country.to_ascii_uppercase())
            .collect();
        let mut counter = 0;
        let accepted = AtomicUsize::new(0);
        let proxy = Proxy::new(Ipv4Addr::new(192, 0, 2, 2), 8080);

        let result = accept_proxy(
            &mut unique_ips,
            true,
            &countries,
            &mut counter,
            &accepted,
            proxy,
            |_| {
                Some(GeoData {
                    iso_code: Some("ID".into()),
                    ..GeoData::default()
                })
            },
        );

        assert!(result.is_some());
    }

    #[tokio::test]
    async fn timed_out_phase_aborts_tasks_and_releases_permits() {
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let mut handles = JoinSet::new();
        handles.spawn(async move {
            let _permit = permit;
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        assert!(!finish_phase(handles, Duration::from_millis(10)).await);
        assert!(semaphore.try_acquire().is_ok());
    }

    #[tokio::test]
    async fn gather_rejects_country_filter_without_geo_lookup() {
        // Regression test: requesting a country filter while GeoIP lookup
        // is disabled must fail fast instead of silently dropping every proxy.
        let config = Config {
            countries: Arc::from(vec!["ID".to_owned()]),
            enable_geo_lookup: false,
            ..Config::default()
        };
        let result = ProxyFetcher::gather(config).await;
        assert!(result.is_err());
        let err = result.err().expect("already asserted is_err");
        assert!(format!("{:#}", err).contains("enable_geo_lookup"));
    }

    #[tokio::test]
    async fn gather_allows_country_filter_with_geo_lookup() {
        // Happy path: with GeoIP on, the config check passes before
        // `GeoLookup::new()`, so a missing DB surfaces a different error and
        // never the guard error.
        let config = Config {
            countries: Arc::from(vec!["ID".to_owned()]),
            enable_geo_lookup: true,
            ..Config::default()
        };
        // Expect either success or a geo-DB error, but NOT the guard error.
        match ProxyFetcher::gather(config).await {
            Ok(_) => {}
            Err(e) => assert!(
                !format!("{:#}", e).contains("enable_geo_lookup"),
                "country-filter guard should not fire when geo lookup is enabled: {e:#}"
            ),
        }
    }

    #[tokio::test]
    async fn gather_rejects_unknown_provider_name() {
        let config = Config {
            providers: Arc::from(vec!["not-a-provider".to_owned()]),
            ..Config::default()
        };
        let result = ProxyFetcher::gather(config).await;
        assert!(result.is_err());
        let err = result.err().expect("already asserted is_err");
        assert!(format!("{:#}", err).contains("unknown provider"));
    }

    #[tokio::test]
    async fn gather_accepts_valid_provider_include() {
        let config = Config {
            providers: Arc::from(vec!["geonode".to_owned()]),
            ..Config::default()
        };
        assert!(ProxyFetcher::gather(config).await.is_ok());
    }

    #[tokio::test]
    async fn gather_fetches_custom_source_url_offline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/list");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut headers = Vec::with_capacity(512);
            let mut byte = [0u8; 1];
            while !headers.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                headers.push(byte[0]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 26\r\nConnection: close\r\n\r\n1.2.3.4:8080\n5.6.7.8:3128\n",
                )
                .await
                .unwrap();
        });

        let config = Config {
            providers: Arc::from(vec!["custom".to_owned()]),
            custom_sources: Arc::from(vec![url]),
            cache_ttl: None,
            ..Config::default()
        };
        let mut fetcher = ProxyFetcher::gather(config).await.unwrap();
        let mut proxies = Vec::new();
        while let Some(proxy) = fetcher.get_one().await {
            proxies.push(proxy);
        }
        server.await.unwrap();

        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].as_text(), "1.2.3.4:8080");
        assert_eq!(proxies[1].as_text(), "5.6.7.8:3128");
    }

    #[tokio::test]
    async fn do_work_offline_skips_source_on_cache_miss() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/list");
        let (cache, dir) = temp_cache_dir();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let (_, stop_rx) = tokio::sync::watch::channel(false);
        let semaphore = Arc::new(Semaphore::new(1));
        let source = Arc::new(Source::all(&url).unwrap());

        do_work(
            Arc::new(OfflineTestProvider),
            test_client(),
            source,
            tx.clone(),
            semaphore,
            stop_rx,
            super::FetchSettings {
                fetch_cache: Some(Arc::new(cache)),
                offline: true,
            },
        )
        .await
        .unwrap();
        drop(tx);

        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "offline mode must not open a network connection on a cache miss"
        );
        assert!(rx.recv().await.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn do_work_offline_serves_warm_cache_without_network() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/list");
        let (cache, dir) = temp_cache_dir();
        cache.store(&url, "1.2.3.4:8080\n5.6.7.8:3128\n").await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let (_, stop_rx) = tokio::sync::watch::channel(false);
        let semaphore = Arc::new(Semaphore::new(1));
        let source = Arc::new(Source::all(&url).unwrap());

        do_work(
            Arc::new(OfflineTestProvider),
            test_client(),
            source,
            tx.clone(),
            semaphore,
            stop_rx,
            super::FetchSettings {
                fetch_cache: Some(Arc::new(cache)),
                offline: true,
            },
        )
        .await
        .unwrap();
        drop(tx);

        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "offline mode must serve the cached body without opening a connection"
        );
        let mut proxies = Vec::new();
        while let Some(proxy) = rx.recv().await {
            proxies.push(proxy);
        }
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].as_text(), "1.2.3.4:8080");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn finish_phase_returns_true_when_primary_completes() {
        // Regression test: when the primary phase finishes within the
        // timeout (no stall), `finish_phase` must report success so the
        // coordinator proceeds to the fallback phase with a stable primary
        // counter rather than aborting healthy tasks.
        let mut handles = JoinSet::new();
        handles.spawn(async {});
        assert!(finish_phase(handles, Duration::from_secs(5)).await);
    }
}
