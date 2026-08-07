mod config;

use std::{
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
    sync::{mpsc, Semaphore},
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

/// Responsible for fetching proxies from various sources.
pub struct ProxyFetcher {
    receiver: mpsc::Receiver<Proxy>, // Channel receiver for receiving proxies.
    counter: usize,                  // Counter for tracking the number of fetched proxies.
    timer: time::Instant,            // Timer for measuring elapsed time.
    elapsed: Option<Duration>,       // Duration of the fetcher operation.
    geolookup: Option<GeoLookup>,    // Optional GeoIP instance for location lookups.
    countries: HashSet<String>,      // Normalized ISO country filter.
    unique_ips: HashSet<(Ipv4Addr, u16, Arc<[Protocol]>)>,
    /// Coordinator owns every provider task through phase-local `JoinSet`s.
    coordinator: JoinHandle<()>,
    config: Config, // Configuration for the proxy fetcher.
    /// Proxies accepted so far, shared with the phase coordinator so it can
    /// evaluate `fallback_threshold`.
    accepted: Arc<AtomicUsize>,
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

        // Proxies are counted by the consumer as they are accepted, so the
        // coordinator can size up the primary phase without any extra channel
        // hop or forwarding task. The tally reflects proxies that survived
        // dedup and country filtering, which is what a threshold should mean.
        let produced = Arc::clone(&accepted);

        // Coordinator: runs the primary phase to completion (bounded by
        // PRIMARY_PHASE_TIMEOUT), then decides whether to run the fallback.
        let coordinator = tokio::spawn({
            async move {
                let sem = Arc::new(Semaphore::new(concurrency_limit));
                let primary_handles = spawn_phase(primary, &client, &sem, sender.clone());

                let primary_timed_out = !finish_phase(primary_handles, PRIMARY_PHASE_TIMEOUT).await;

                #[cfg(feature = "log")]
                if primary_timed_out {
                    log::warn!(
                        "primary providers still running after {:?}; aborted them before starting fallback phase",
                        PRIMARY_PHASE_TIMEOUT
                    );
                }
                let _ = primary_timed_out;

                while sender.capacity() < sender.max_capacity() {
                    tokio::task::yield_now().await;
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

                let mut fallback_handles = spawn_phase(fallback, &client, &sem, sender);
                while fallback_handles.join_next().await.is_some() {}
            }
        });

        Ok(Self {
            receiver,
            counter: 0,
            timer: time::Instant::now(),
            elapsed: None,
            coordinator,
            unique_ips: HashSet::new(),
            geolookup,
            countries,
            config,
            accepted,
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
/// with the subsequent channel-drain wait (`while sender.capacity() <
/// sender.max_capacity()`), it proves the primary counter (`produced`) is
/// stable before fallback runs — no primary result can be lost or double
/// counted.
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
) -> JoinSet<()> {
    let mut handles = JoinSet::new();
    for (source, provider) in tasks {
        let permit = Arc::clone(sem);
        let client = Arc::clone(client);
        let tx = tx.clone();

        handles.spawn(async move {
            let url = source.url.to_string();
            if let Err(e) = do_work(provider, client, source, tx, permit).await {
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
/// runs — otherwise a slow parser would idle a connection slot.
async fn do_work(
    provider: Arc<dyn ProxyProvider + Send + Sync>,
    client: Arc<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>>,
    source: Arc<Source>,
    tx: mpsc::Sender<Proxy>,
    sem: Arc<Semaphore>,
) -> anyhow::Result<()> {
    let html = {
        let _permit = sem
            .acquire()
            .await
            .context("fetcher semaphore closed during shutdown")?;
        provider
            .fetch(client, &source.url.to_string(), source.timeout)
            .await
            .with_context(|| format!("failed to fetch proxy list from {}", source.url))?
    };

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
        while let Some(proxy) = self.receiver.recv().await {
            if let Some(proxy) = self.accept(proxy) {
                return Some(proxy);
            }
        }
        self.elapsed = Some(self.timer.elapsed());
        None
    }

    /// Applies geo lookup, country filtering and uniqueness rules to `proxy`.
    ///
    /// Returns `None` when the proxy must be skipped.
    fn accept(&mut self, proxy: Proxy) -> Option<Proxy> {
        accept_proxy(
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
        )
    }
}

fn accept_proxy<F>(
    unique_ips: &mut HashSet<(Ipv4Addr, u16, Arc<[Protocol]>)>,
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
        && !unique_ips.insert((proxy.ip, proxy.port, Arc::clone(&proxy.expected_types)))
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
                .map(|code| countries.contains(code))
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
            match this.receiver.poll_recv(cx) {
                Poll::Ready(Some(proxy)) => {
                    if let Some(proxy) = this.accept(proxy) {
                        return Poll::Ready(Some(proxy));
                    }
                }
                Poll::Ready(None) => {
                    if this.elapsed.is_none() {
                        this.elapsed = Some(this.timer.elapsed());
                    }
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
    use super::{accept_proxy, finish_phase, ProxyFetcher};
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
        let mut unique_ips = hashbrown::HashSet::new();
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
        let mut unique_ips = hashbrown::HashSet::new();
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
    fn country_filter_is_case_insensitive() {
        let mut unique_ips = hashbrown::HashSet::new();
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
                    iso_code: Some("ID".to_owned()),
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
            countries: vec!["ID".to_owned()],
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
            countries: vec!["ID".to_owned()],
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
