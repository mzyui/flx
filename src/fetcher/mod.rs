mod cache;
mod config;
mod dedup;
mod phase;

use std::{
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
use dedup::{protocol_hash, DedupTable};
use futures_util::Stream;
use hashbrown::HashSet;
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
pub use phase::FetchStage;
#[cfg(test)]
use phase::{do_work, source_host, FetchJob};
use phase::{spawn_phase, FetchSettings, PhaseContext, StageReporter, Throttle};
use tokio::{
    sync::{mpsc, watch, Notify, Semaphore},
    task::JoinHandle,
    time,
};

use crate::{
    geolookup::{GeoLookup, IpType},
    providers::{all_providers, select_providers, CustomUrlProvider, ProviderTier},
    proxy::models::Proxy,
};

pub(crate) const FETCH_CHANNEL_CAPACITY: usize = 2_048;

/// Hard budget for the primary provider phase before the fallback decides.
pub const PRIMARY_PHASE_TIMEOUT: Duration = Duration::from_secs(30);

/// Async stream of scraped proxy candidates.
pub struct ProxyFetcher {
    receiver: mpsc::Receiver<Proxy>, // Channel receiver for receiving proxies.
    counter: usize,                  // Counter for tracking the number of fetched proxies.
    timer: time::Instant,            // Timer for measuring elapsed time.
    elapsed: Option<Duration>,       // Duration of the fetcher operation.
    geolookup: Option<GeoLookup>,    // Optional GeoIP instance for location lookups.
    countries: HashSet<String>,      // Normalized ISO country filter.
    excluded_countries: HashSet<String>, // Normalized ISO country exclusion filter.
    ip_type_filter: Option<IpType>,  // Optional IP-type filter.
    unique_ips: DedupTable,
    coordinator: JoinHandle<()>,
    config: Config, // Configuration for the proxy fetcher.
    accepted: Arc<AtomicUsize>,
    drain_notify: Arc<Notify>,
    prefetched: Option<Proxy>,
    stop_tx: watch::Sender<bool>,
    stop_signaled: AtomicBool,
    stages: Option<mpsc::Receiver<FetchStage>>,
}

impl ProxyFetcher {
    pub async fn gather(config: Config) -> anyhow::Result<Self> {
        if config.concurrency_limit == 0 {
            anyhow::bail!("config.concurrency_limit must be greater than zero");
        }
        // A country filter is meaningless without GeoIP lookup, so reject the
        // combination up front instead of silently dropping every proxy.
        if (!config.countries.is_empty() || !config.excluded_countries.is_empty())
            && !config.enable_geo_lookup
        {
            anyhow::bail!(
                "country filter requires enable_geo_lookup=true (GeoIP lookup is currently disabled)"
            );
        }
        if (config.enable_ip_type || config.ip_type_filter.is_some()) && !config.enable_geo_lookup {
            anyhow::bail!(
                "ip-type detection requires enable_geo_lookup=true (GeoIP lookup is currently disabled)"
            );
        }
        let (sender, receiver) = mpsc::channel(FETCH_CHANNEL_CAPACITY);
        let geolookup = if config.enable_geo_lookup {
            Some(
                GeoLookup::new(config.enable_ip_type || config.ip_type_filter.is_some())
                    .await
                    .context("failed to initialize geo lookup")?,
            )
        } else {
            None
        };

        let registry = all_providers();
        let mut known_names: Vec<&str> = registry.iter().map(|provider| provider.name()).collect();
        let mut providers =
            select_providers(registry, &config.providers, &config.excluded_providers);
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
        let excluded_countries = config.normalized_excluded_countries();
        let accepted = Arc::new(AtomicUsize::new(0));

        let mut primary = vec![];
        let mut fallback = vec![];
        for provider in providers.iter() {
            let bucket = match provider.tier() {
                ProviderTier::Primary => &mut primary,
                ProviderTier::Fallback => &mut fallback,
            };
            for source in provider.sources() {
                let source = match config.provider_timeout {
                    Some(timeout) => source.with_timeout(timeout),
                    None => source,
                };
                bucket.push((Arc::new(source), Arc::clone(provider)));
            }
        }

        #[cfg(feature = "log")]
        log::debug!(
            "Proxy gathering started ({} primary sources, {} fallback sources)",
            primary.len(),
            fallback.len(),
        );

        let client = {
            let mut http = HttpConnector::new();
            // Dead hosts hang on TCP connect far longer than the per-source
            // deadline would wait; cap the connect phase so blocked providers
            // fail in seconds instead of burning their full fetch timeout.
            http.set_connect_timeout(Some(Duration::from_secs(6)));
            http.enforce_http(false);
            Arc::new(
                Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(
                    crate::proxy::client::https_connector_with_config(http, false),
                ),
            )
        };
        let concurrency_limit = config.concurrency_limit;
        let fallback_threshold = config.fallback_threshold;
        let fallback_phase_timeout = config.fallback_phase_timeout;
        let offline = config.offline;
        let fetch_delay = config.fetch_delay;

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

        let throttle = Arc::new(Throttle::new());

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

        let (stage_tx, stages) = mpsc::channel(16);

        // Coordinator: runs the primary phase to completion (bounded by
        // PRIMARY_PHASE_TIMEOUT), then decides whether to run the fallback.
        // A `watch` stop-signal lets the consumer abort the primary phase
        // early when the threshold is already satisfied.
        let coordinator = tokio::spawn({
            let sender = sender.clone();
            async move {
                let stages = StageReporter { tx: stage_tx };
                let settings = FetchSettings {
                    fetch_cache,
                    offline,
                    throttle,
                    fetch_delay,
                };
                let mut stop_rx_coordinator = stop_rx_coordinator;
                let sem = Arc::new(Semaphore::new(concurrency_limit));
                stages.send(FetchStage::Primary);
                let primary_ctx = PhaseContext {
                    client: Arc::clone(&client),
                    sem: Arc::clone(&sem),
                    tx: sender.clone(),
                    stop_rx: stop_rx_primary,
                    settings: settings.clone(),
                };
                let mut primary_handles = spawn_phase(primary, &primary_ctx);

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
                wait_for_drain(&sender, &drain_notify_coordinator).await;

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

                stages.send(FetchStage::Fallback);
                let fallback_ctx = PhaseContext {
                    client: Arc::clone(&client),
                    sem: Arc::clone(&sem),
                    tx: sender,
                    stop_rx: stop_rx_fallback,
                    settings: settings.clone(),
                };
                let mut fallback_handles = spawn_phase(fallback, &fallback_ctx);
                match fallback_phase_timeout {
                    Some(timeout) => {
                        tokio::select! {
                            _ = async { while fallback_handles.join_next().await.is_some() {} } => {}
                            _ = time::sleep(timeout) => {
                                fallback_handles.abort_all();
                                while fallback_handles.join_next().await.is_some() {}
                                #[cfg(feature = "log")]
                                log::warn!(
                                    "fallback providers aborted after timeout {:?}",
                                    timeout
                                );
                            }
                        }
                    }
                    None => while fallback_handles.join_next().await.is_some() {},
                }
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
            excluded_countries,
            ip_type_filter: config.ip_type_filter,
            config,
            accepted,
            drain_notify,
            prefetched: None,
            stop_tx,
            stop_signaled: AtomicBool::new(false),
            stages: Some(stages),
        })
    }
}

// Waits until the consumer has emptied the channel buffer so the produced
// counter is stable. A `notify_one` fired before this task registered as a
// waiter leaves a stale stored permit, so every wakeup must re-verify the
// real condition (empty buffer) instead of trusting the signal alone.
async fn wait_for_drain(tx: &mpsc::Sender<Proxy>, notify: &Notify) {
    while tx.capacity() < tx.max_capacity() {
        let drained = notify.notified();
        if tx.capacity() == tx.max_capacity() {
            break;
        }
        drained.await;
    }
}

#[cfg(test)]
async fn finish_phase(mut handles: tokio::task::JoinSet<()>, timeout: Duration) -> bool {
    let drain = async { while handles.join_next().await.is_some() {} };
    if time::timeout(timeout, drain).await.is_ok() {
        return true;
    }
    handles.abort_all();
    while handles.join_next().await.is_some() {}
    false
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

    /// Consumes this fetcher's gathering-phase events for this run.
    pub fn stage_events(&mut self) -> Option<mpsc::Receiver<FetchStage>> {
        self.stages.take()
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
        let mut ctx = AcceptContext {
            unique_ips: &mut self.unique_ips,
            enforce_unique_ip: self.config.enforce_unique_ip,
            countries: &self.countries,
            excluded_countries: &self.excluded_countries,
            ip_type_filter: self.ip_type_filter.as_ref(),
            counter: &mut self.counter,
            accepted: &self.accepted,
        };
        let result = accept_proxy(&mut ctx, proxy, |ip| {
            self.geolookup.as_ref().map(|geolookup| {
                // mmdb reads are memory-mapped binary searches (µs each, two
                // per proxy). On the multi-thread runtime move them off the
                // worker's task accounting so a cold page-cache hit does not
                // stall the executor; `block_in_place` would panic on a
                // current-thread runtime, so fall back to a direct read there.
                let do_lookup = || geolookup.lookup(ip);
                match tokio::runtime::Handle::try_current() {
                    Ok(handle)
                        if handle.runtime_flavor()
                            == tokio::runtime::RuntimeFlavor::MultiThread =>
                    {
                        tokio::task::block_in_place(do_lookup)
                    }
                    _ => do_lookup(),
                }
            })
        });
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

struct AcceptContext<'a> {
    unique_ips: &'a mut DedupTable,
    enforce_unique_ip: bool,
    countries: &'a HashSet<String>,
    excluded_countries: &'a HashSet<String>,
    ip_type_filter: Option<&'a IpType>,
    counter: &'a mut usize,
    accepted: &'a AtomicUsize,
}

fn accept_proxy<F>(ctx: &mut AcceptContext, mut proxy: Proxy, lookup: F) -> Option<Proxy>
where
    F: FnOnce(&Ipv4Addr) -> Option<crate::geolookup::models::GeoData>,
{
    if ctx.enforce_unique_ip
        && !ctx
            .unique_ips
            .insert((proxy.ip, proxy.port, protocol_hash(&proxy.expected_types)))
    {
        return None;
    }

    if let Some(geo) = lookup(&proxy.ip) {
        proxy.geo = Arc::new(geo);

        if !ctx.countries.is_empty()
            && !proxy
                .geo
                .iso_code
                .as_ref()
                .map(|code| ctx.countries.contains(code.as_ref()))
                .unwrap_or(false)
        {
            return None;
        }

        if !ctx.excluded_countries.is_empty()
            && proxy
                .geo
                .iso_code
                .as_ref()
                .map(|code| ctx.excluded_countries.contains(code.as_ref()))
                .unwrap_or(false)
        {
            return None;
        }
    }

    if let Some(want) = ctx.ip_type_filter {
        if proxy.geo.ip_type != *want {
            return None;
        }
    }

    *ctx.counter += 1;
    ctx.accepted.fetch_add(1, Ordering::Relaxed);
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
    use super::{
        accept_proxy, do_work, finish_phase, protocol_hash, source_host, wait_for_drain,
        AcceptContext, DedupTable, FetchJob, FetchStage, PhaseContext, ProxyFetcher, Throttle,
    };
    use crate::fetcher::{cache::Cache, Config};
    use crate::geolookup::models::GeoData;
    use crate::providers::models::Source;
    use crate::providers::ProxyProvider;
    use crate::proxy::models::{Anonymity, Protocol, Proxy};
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};
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

    fn test_client() -> Arc<Client<crate::proxy::client::HttpsConnector, Empty<Bytes>>> {
        Arc::new(
            Client::builder(TokioExecutor::new())
                .build::<_, Empty<Bytes>>(crate::proxy::client::https_connector()),
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
        let excluded_countries = hashbrown::HashSet::new();
        let mut counter = 0;
        let accepted = AtomicUsize::new(0);
        let lookups = Arc::new(AtomicUsize::new(0));
        let proxy = Proxy::new(Ipv4Addr::new(192, 0, 2, 1), 8080);

        assert!(accept_proxy(
            &mut AcceptContext {
                unique_ips: &mut unique_ips,
                enforce_unique_ip: config.enforce_unique_ip,
                countries: &countries,
                excluded_countries: &excluded_countries,
                ip_type_filter: None,
                counter: &mut counter,
                accepted: &accepted,
            },
            proxy.clone(),
            |_| {
                lookups.fetch_add(1, Ordering::Relaxed);
                Some(Default::default())
            }
        )
        .is_some());
        assert!(accept_proxy(
            &mut AcceptContext {
                unique_ips: &mut unique_ips,
                enforce_unique_ip: config.enforce_unique_ip,
                countries: &countries,
                excluded_countries: &excluded_countries,
                ip_type_filter: None,
                counter: &mut counter,
                accepted: &accepted,
            },
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
        let excluded_countries = hashbrown::HashSet::new();
        let mut counter = 0;
        let accepted = AtomicUsize::new(0);
        let ip = Ipv4Addr::new(192, 0, 2, 10);
        let http =
            Proxy::with_expected_types(ip, 8080, Arc::from([Protocol::Http(Anonymity::Unknown)]));
        let socks5 = Proxy::with_expected_types(ip, 8080, Arc::from([Protocol::Socks5]));

        let mut ctx = AcceptContext {
            unique_ips: &mut unique_ips,
            enforce_unique_ip: true,
            countries: &countries,
            excluded_countries: &excluded_countries,
            ip_type_filter: None,
            counter: &mut counter,
            accepted: &accepted,
        };
        let first = accept_proxy(&mut ctx, http, |_| None);
        let second = accept_proxy(&mut ctx, socks5, |_| None);

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
        let excluded_countries = hashbrown::HashSet::new();
        let mut counter = 0;
        let accepted = AtomicUsize::new(0);
        let proxy = Proxy::new(Ipv4Addr::new(192, 0, 2, 2), 8080);

        let result = accept_proxy(
            &mut AcceptContext {
                unique_ips: &mut unique_ips,
                enforce_unique_ip: true,
                countries: &countries,
                excluded_countries: &excluded_countries,
                ip_type_filter: None,
                counter: &mut counter,
                accepted: &accepted,
            },
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

    #[test]
    fn excluded_country_filter_drops_only_matching_proxies() {
        let mut unique_ips = DedupTable::new();
        let countries = hashbrown::HashSet::new();
        let excluded_countries = ["cn".to_owned()]
            .into_iter()
            .map(|country| country.to_ascii_uppercase())
            .collect();
        let mut counter = 0;
        let accepted = AtomicUsize::new(0);
        let blocked = Proxy::new(Ipv4Addr::new(192, 0, 2, 5), 8080);
        let allowed = Proxy::new(Ipv4Addr::new(192, 0, 2, 6), 8081);

        let mut ctx = AcceptContext {
            unique_ips: &mut unique_ips,
            enforce_unique_ip: true,
            countries: &countries,
            excluded_countries: &excluded_countries,
            ip_type_filter: None,
            counter: &mut counter,
            accepted: &accepted,
        };
        let rejected = accept_proxy(&mut ctx, blocked, |_| {
            Some(GeoData {
                iso_code: Some("CN".into()),
                ..GeoData::default()
            })
        });
        let kept = accept_proxy(&mut ctx, allowed, |_| {
            Some(GeoData {
                iso_code: Some("US".into()),
                ..GeoData::default()
            })
        });

        assert!(rejected.is_none());
        assert!(kept.is_some());
        assert_eq!(counter, 1);
    }

    #[test]
    fn ip_type_filter_keeps_only_matching_proxies() {
        let mut unique_ips = DedupTable::new();
        let countries = hashbrown::HashSet::new();
        let excluded_countries = hashbrown::HashSet::new();
        let mut counter = 0;
        let accepted = AtomicUsize::new(0);
        let residential = Proxy::new(Ipv4Addr::new(192, 0, 2, 3), 8080);
        let datacenter = Proxy::new(Ipv4Addr::new(192, 0, 2, 4), 8081);
        let want = crate::geolookup::IpType::Residential;

        let mut ctx = AcceptContext {
            unique_ips: &mut unique_ips,
            enforce_unique_ip: true,
            countries: &countries,
            excluded_countries: &excluded_countries,
            ip_type_filter: Some(&want),
            counter: &mut counter,
            accepted: &accepted,
        };
        let accepted_home = accept_proxy(&mut ctx, residential, |_| {
            Some(GeoData {
                ip_type: crate::geolookup::IpType::Residential,
                ..GeoData::default()
            })
        });
        let rejected_datacenter = accept_proxy(&mut ctx, datacenter, |_| {
            Some(GeoData {
                ip_type: crate::geolookup::IpType::Datacenter,
                ..GeoData::default()
            })
        });

        assert!(accepted_home.is_some());
        assert!(rejected_datacenter.is_none());
    }

    #[tokio::test]
    async fn drain_wait_survives_stale_notify_permits() {
        // Regression test: the consumer signals a drain whenever it finds
        // the channel empty; a signal fired before the coordinator
        // registered as a waiter leaves one stored permit behind. The old
        // single `notified().await` consumed it instantly and evaluated the
        // fallback threshold while items were still buffered.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Proxy>(4);
        for port in 8000u16..8003 {
            tx.send(Proxy::new(Ipv4Addr::new(192, 0, 2, 1), port))
                .await
                .unwrap();
        }
        let notify = Arc::new(tokio::sync::Notify::new());
        notify.notify_one();

        let wait = wait_for_drain(&tx, &notify);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), wait)
                .await
                .is_err(),
            "a stale permit must not end the drain wait while items are buffered"
        );

        // A real drain followed by a fresh signal must release the wait. The
        // consumer runs as a task so the waiter is woken by the signal rather
        // than by the short-circuit empty-buffer check.
        let consumer_notify = Arc::clone(&notify);
        let consumer = tokio::spawn(async move {
            // `recv` parks forever on an empty-but-open channel, so drain
            // with `try_recv`.
            while rx.try_recv().is_ok() {}
            consumer_notify.notify_one();
        });
        tokio::time::timeout(Duration::from_secs(1), wait_for_drain(&tx, &notify))
            .await
            .expect("a real drain signal must release the wait");
        consumer.await.unwrap();
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
    async fn gather_rejects_excluded_country_filter_without_geo_lookup() {
        let config = Config {
            excluded_countries: Arc::from(vec!["CN".to_owned()]),
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
    async fn stage_events_report_phases_then_done() {
        // `cache_ttl: None` keeps the run fully offline (no cached rows can
        // stall the coordinator on the drain wait the test never performs).
        let mut fetcher = ProxyFetcher::gather(Config {
            offline: true,
            cache_ttl: None,
            ..Config::default()
        })
        .await
        .unwrap();
        let mut rx = fetcher.stage_events().expect("stage stream present");
        let mut seen = Vec::new();
        while seen.last() != Some(&FetchStage::Done) {
            let stage = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("stage event timed out")
                .expect("stage channel closed before Done");
            seen.push(stage);
        }
        assert_eq!(seen.first(), Some(&FetchStage::Primary));
        assert!(seen.contains(&FetchStage::Fallback));
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

        let job = FetchJob {
            provider: Arc::new(OfflineTestProvider),
            source,
        };
        let ctx = PhaseContext {
            client: test_client(),
            sem: semaphore,
            tx: tx.clone(),
            stop_rx,
            settings: super::FetchSettings {
                fetch_cache: Some(Arc::new(cache)),
                offline: true,
                throttle: Arc::new(super::Throttle::new()),
                fetch_delay: None,
            },
        };
        do_work(job, ctx).await.unwrap();
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
        cache
            .store_rows(
                &url,
                &[
                    (Ipv4Addr::new(1, 2, 3, 4), 8080, None),
                    (Ipv4Addr::new(5, 6, 7, 8), 3128, None),
                ],
            )
            .await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let (_, stop_rx) = tokio::sync::watch::channel(false);
        let semaphore = Arc::new(Semaphore::new(1));
        let source = Arc::new(Source::all(&url).unwrap());

        let job = FetchJob {
            provider: Arc::new(OfflineTestProvider),
            source,
        };
        let ctx = PhaseContext {
            client: test_client(),
            sem: semaphore,
            tx: tx.clone(),
            stop_rx,
            settings: super::FetchSettings {
                fetch_cache: Some(Arc::new(cache)),
                offline: true,
                throttle: Arc::new(super::Throttle::new()),
                fetch_delay: None,
            },
        };
        do_work(job, ctx).await.unwrap();
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

    #[tokio::test]
    async fn throttle_spaces_same_host_requests_by_delay() {
        let throttle = Throttle::new();
        let delay = Duration::from_millis(100);

        throttle.wait("example.com", delay).await;
        let start = tokio::time::Instant::now();
        throttle.wait("example.com", delay).await;

        assert!(
            start.elapsed() >= delay - Duration::from_millis(50),
            "a second request to the same host must wait out the delay window"
        );
    }

    #[tokio::test]
    async fn throttle_does_not_delay_unseen_hosts() {
        let throttle = Throttle::new();
        let delay = Duration::from_secs(10);

        throttle.wait("example.com", delay).await;
        let start = tokio::time::Instant::now();
        throttle.wait("other.example.org", delay).await;

        assert!(
            start.elapsed() < Duration::from_secs(1),
            "a fresh host must not be held back by another host's delay"
        );
    }

    #[tokio::test]
    async fn throttle_spaces_concurrent_same_host_requests_cumulatively() {
        // Regression test: each caller used to record its own arrival time,
        // so three concurrent arrivals all woke around t0+delay together.
        // Projected slots must space them one `delay` apart instead.
        let throttle = Arc::new(Throttle::new());
        let delay = Duration::from_millis(100);
        let start = tokio::time::Instant::now();
        let handles = (0..3)
            .map(|_| {
                let throttle = Arc::clone(&throttle);
                tokio::spawn(async move { throttle.wait("example.com", delay).await })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.await.unwrap();
        }

        assert!(
            start.elapsed() >= delay * 2 - Duration::from_millis(30),
            "three concurrent requests need three distinct slots: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn source_host_comes_from_url_host() {
        let source = Arc::new(Source::all("http://lists.example.org/proxies?page=1").unwrap());
        assert_eq!(source_host(&source), "lists.example.org");
    }
}
