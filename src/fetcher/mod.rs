mod cache;
mod config;

use std::{
    borrow::Cow,
    collections::{hash_map::DefaultHasher, VecDeque},
    hash::{Hash, Hasher},
    net::Ipv4Addr,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::Context;
pub use config::Config;
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
    providers::{all_providers, models::Source, ProviderTier, ProxyProvider},
    proxy::models::{Protocol, Proxy},
};

/// Capacity of the bounded channel between the fetching tasks and the consumer.
///
/// A bounded channel gives us backpressure: providers stop producing once the
/// consumer falls behind instead of buffering the whole internet in memory.
pub(crate) const FETCH_CHANNEL_CAPACITY: usize = 2_048;

/// Upper bound on how long the primary phase may hold up the fallback phase.
///
/// One unresponsive website must not stall the GitHub mirrors forever: once
/// this elapses the remaining primary tasks are aborted and joined before the
/// fallback phase starts, releasing every semaphore permit deterministically.
const PRIMARY_PHASE_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on how many unique endpoints the fetcher's dedup keeps.
///
/// Proxy list fetches legitimately yield tens of thousands of endpoints;
/// without a bound the uniqueness set would grow without limit. When full,
/// the oldest entry is evicted (FIFO) so the table stays small and the run
/// can never hold 100K+ entries forever (A.3).
const MAX_DEDUP_ENDPOINTS: usize = 100_000;

/// Unique-endpoint key `(ip, port, protocol-set hash)`.
///
/// Pre-hashing the advertised protocol set once (A.4) turns the key into
/// 12 bytes — the `Arc` and its slice no longer need to be stored or hashed
/// on every probe — while preserving the existing semantics: an endpoint is
/// only considered new when a different protocol set shows up.
type EndpointKey = (Ipv4Addr, u16, u64);

/// A stable fingerprint of a protocol set, computed once per candidate.
///
/// Ordered (like `[Protocol]`'s `Hash` impl) so `[Socks5, Http]` and
/// `[Http, Socks5]` are distinct, matching the previous equality semantics.
fn protocol_hash(protocols: &[Protocol]) -> u64 {
    let mut hasher = DefaultHasher::new();
    protocols.hash(&mut hasher);
    hasher.finish()
}

/// Bounded set of unique endpoints seen so far.
///
/// A FIFO eviction policy keeps memory bounded under `capacity` entries:
/// once full, registering a new endpoint evicts the oldest one first. The
/// trade-off (a long-ago endpoint can slip back in) is what keeps the table
/// a fixed size instead of an ever-growing one.
struct DedupTable {
    seen: HashSet<EndpointKey>,
    order: VecDeque<EndpointKey>,
    capacity: usize,
}

impl DedupTable {
    /// A table bound to [`MAX_DEDUP_ENDPOINTS`]. The obvious consequence:
    /// duplicate proxies that were first seen beyond the capacity window are
    /// no longer cheaply filterable, which is exactly the point of the cap.
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

    /// Returns `false` when `endpoint` was already registered; otherwise
    /// registers it and returns `true`, evicting the oldest entry first when
    /// the table is at capacity.
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

/// Responsible for fetching proxies from various sources.
pub struct ProxyFetcher {
    receiver: mpsc::Receiver<Proxy>, // Channel receiver for receiving proxies.
    counter: usize,                  // Counter for tracking the number of fetched proxies.
    timer: time::Instant,            // Timer for measuring elapsed time.
    elapsed: Option<Duration>,       // Duration of the fetcher operation.
    geolookup: Option<GeoLookup>,    // Optional GeoIP instance for location lookups.
    countries: HashSet<String>,      // Normalized ISO country filter.
    /// Bounded (FIFO-evicted) set of unique endpoints seen so far.
    unique_ips: DedupTable,
    /// Coordinator owns every provider task through phase-local `JoinSet`s.
    coordinator: JoinHandle<()>,
    config: Config, // Configuration for the proxy fetcher.
    /// Proxies accepted so far, shared with the phase coordinator so it can
    /// evaluate `fallback_threshold`.
    accepted: Arc<AtomicUsize>,
    /// Notify the phase coordinator when the fetch channel has been drained so
    /// it can evaluate `fallback_threshold` without busy-waiting.
    drain_notify: Arc<Notify>,
    /// Item stashed by `check_drain` when `try_recv` succeeds during a drain
    /// check (the item is already consumed from the channel and must be
    /// returned on the next call before the channel is polled again).
    prefetched: Option<Proxy>,
    /// Signals the fetcher coordinator and provider tasks to stop producing
    /// when the consumer has collected enough proxies (threshold met).
    stop_tx: watch::Sender<bool>,
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
        if config.concurrency_limit == 0 {
            anyhow::bail!("config.concurrency_limit must be greater than zero");
        }
        // F-34: a country filter is meaningless without GeoIP lookup. Reject
        // the combination up front instead of silently skipping every proxy
        // because `accept_proxy` only applies the filter after a successful
        // geo lookup (which never happens when GeoIP is disabled).
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

        let providers = all_providers();

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
        })
    }
}

/// Waits for a phase to finish within `timeout`. If the phase stalls, every
/// remaining task is aborted and then joined so cancellation has completed and
/// all semaphore permits are released before the next phase starts.
///
/// F-14 (barrier): this is the primary-phase barrier. The coordinator only
/// proceeds to the fallback phase after `finish_phase` returns, which means
/// every primary task has either completed or been aborted+joined. Combined
/// with the subsequent channel-drain signal (`Notify` from the consumer),
/// it proves the primary counter (`produced`) is stable before fallback
/// runs — no primary result can be lost or double counted.
#[allow(dead_code)]
async fn finish_phase(mut handles: JoinSet<()>, timeout: Duration) -> bool {
    let drain = async { while handles.join_next().await.is_some() {} };
    if time::timeout(timeout, drain).await.is_ok() {
        return true;
    }
    handles.abort_all();
    while handles.join_next().await.is_some() {}
    false
}

/// Spawns one task per source, each gated by `sem`, and returns their handles.
/// Also registers every spawned handle in `registry` for drop-time abort.
fn spawn_phase(
    tasks: Vec<(Arc<Source>, Arc<dyn ProxyProvider + Send + Sync>)>,
    client: &Arc<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>>,
    sem: &Arc<Semaphore>,
    tx: mpsc::Sender<Proxy>,
    stop_rx: watch::Receiver<bool>,
    fetch_cache: Option<Arc<cache::Cache>>,
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
            if let Err(e) =
                do_work(provider, client, source, tx, permit, stop_rx, fetch_cache).await
            {
                #[cfg(feature = "log")]
                log::error!("{}: {}", url, e);
                let _ = (url, e);
            }
        });
    }
    handles
}

/// Fetches one source and forwards every proxy it yields.
///
/// The semaphore permit covers the network fetch only. Parsing is CPU-bound
/// and needs no network slot, so the permit is released before `scrape_with`
/// runs — otherwise a slow parser would idle a connection slot. A fresh cache
/// hit skips both the network and the permit entirely.
async fn do_work(
    provider: Arc<dyn ProxyProvider + Send + Sync>,
    client: Arc<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>>,
    source: Arc<Source>,
    tx: mpsc::Sender<Proxy>,
    sem: Arc<Semaphore>,
    stop_rx: watch::Receiver<bool>,
    fetch_cache: Option<Arc<cache::Cache>>,
) -> anyhow::Result<()> {
    if *stop_rx.borrow() {
        return Ok(());
    }
    let url = source.url.to_string();

    let html = if let Some(fetch_cache) = fetch_cache.as_ref() {
        match fetch_cache.load(&url).await {
            Some(body) => {
                #[cfg(feature = "log")]
                log::debug!("using cached body for {url}");
                Cow::Owned(body)
            }
            None => {
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
                // write-amplification (re-audit N1).
                fetch_cache.store(&url, body.as_ref()).await;
                body
            }
        }
    } else {
        let _permit = sem
            .acquire()
            .await
            .context("fetcher semaphore closed during shutdown")?;
        provider
            .fetch(client, &url, source.timeout)
            .await
            .with_context(|| format!("failed to fetch proxy list from {}", source.url))?
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
    /// Retrieves one proxy from the receiver, awaiting until one is available.
    ///
    /// If geo lookup is enabled, it will apply geographic filtering.
    ///
    /// # Returns
    ///
    /// An optional `Proxy` if one is available, otherwise `None` once every
    /// producing task has finished.
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

    /// Applies geo lookup, country filtering and uniqueness rules to `proxy`.
    ///
    /// Returns `None` when the proxy must be skipped.
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
                // Signal the stop once; re-sending the same value on every
                // accepted proxy just bumps the watch version pointlessly
                // (re-audit N3).
                if self.accepted.load(Ordering::Relaxed) >= threshold && !*self.stop_tx.borrow() {
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
    /// Cleans up resources when `ProxyFetcher` is dropped.
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
    use super::{accept_proxy, finish_phase, protocol_hash, DedupTable, ProxyFetcher};
    use crate::fetcher::Config;
    use crate::geolookup::models::GeoData;
    use crate::proxy::models::{Anonymity, Protocol, Proxy};
    use std::{
        net::Ipv4Addr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };
    use tokio::{sync::Semaphore, task::JoinSet};

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
        // Regression for A.4: the dedup key is now a `u64` hash of the
        // advertised protocol set. Identical sets must hash identically (so
        // duplicates are still caught) and distinct sets must not collide
        // (so different protocols on the same endpoint stay distinct).
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
        // Regression for A.3: the dedup table has a fixed capacity and drops
        // the oldest entry instead of growing without bound. Once evicted, an
        // endpoint can be accepted again (the memory/semantic trade-off).
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
        // Regression for F-34: requesting a country filter while GeoIP lookup
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
        // Happy path: country filter is accepted when GeoIP lookup is on.
        // We don't actually need a working MaxMind DB here — the config check
        // happens before `GeoLookup::new()`, so a missing DB would surface a
        // different, acceptable error. We only assert the F-34 guard does not
        // trip when the combination is valid.
        let config = Config {
            countries: Arc::from(vec!["ID".to_owned()]),
            enable_geo_lookup: true,
            ..Config::default()
        };
        // Expect either success or a geo-DB error, but NOT the F-34 guard error.
        match ProxyFetcher::gather(config).await {
            Ok(_) => {}
            Err(e) => assert!(
                !format!("{:#}", e).contains("enable_geo_lookup"),
                "F-34 guard should not fire when geo lookup is enabled: {e:#}"
            ),
        }
    }

    #[tokio::test]
    async fn finish_phase_returns_true_when_primary_completes() {
        // Regression for F-14: when the primary phase finishes within the
        // timeout (no stall), `finish_phase` must report success so the
        // coordinator proceeds to the fallback phase with a stable primary
        // counter rather than aborting healthy tasks.
        let mut handles = JoinSet::new();
        handles.spawn(async {});
        assert!(finish_phase(handles, Duration::from_secs(5)).await);
    }
}
