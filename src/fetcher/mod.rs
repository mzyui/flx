mod config;

use std::{
    borrow::Cow,
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
    task::JoinHandle,
    time,
};

use crate::{
    geolookup::GeoLookup,
    providers::{all_providers, models::Source, ProxyProvider, ProviderTier},
    proxy::models::Proxy,
};

/// Capacity of the bounded channel between the fetching tasks and the consumer.
///
/// A bounded channel gives us backpressure: providers stop producing once the
/// consumer falls behind instead of buffering the whole internet in memory.
pub(crate) const CHANNEL_CAPACITY: usize = 10_000;

/// Upper bound on how long the primary phase may hold up the fallback phase.
///
/// One unresponsive website must not stall the GitHub mirrors forever: once
/// this elapses the remaining primary tasks keep running in the background
/// while the fallback phase starts.
const PRIMARY_PHASE_TIMEOUT: Duration = Duration::from_secs(30);

/// Responsible for fetching proxies from various sources.
pub struct ProxyFetcher {
    receiver: mpsc::Receiver<Proxy>, // Channel receiver for receiving proxies.
    counter: usize,                  // Counter for tracking the number of fetched proxies.
    timer: time::Instant,            // Timer for measuring elapsed time.
    elapsed: Option<Duration>,       // Duration of the fetcher operation.
    geolookup: Option<GeoLookup>,    // Optional GeoIP instance for location lookups.
    unique_ips: HashSet<Cow<'static, str>>, // Set to track unique IPs.
    handlers: Vec<JoinHandle<()>>,   // Handle for the fetching task.
    config: Config,                  // Configuration for the proxy fetcher.
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
        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
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

        let mut fetcher = Self {
            receiver,
            counter: 0,
            timer: time::Instant::now(),
            elapsed: None,
            handlers: vec![],
            unique_ips: HashSet::new(),
            geolookup,
            config,
            accepted: Arc::new(AtomicUsize::new(0)),
        };

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
        let concurrency_limit = fetcher.config.concurrency_limit;
        let fallback_threshold = fetcher.config.fallback_threshold;

        // Proxies are counted by the consumer as they are accepted, so the
        // coordinator can size up the primary phase without any extra channel
        // hop or forwarding task. The tally reflects proxies that survived
        // dedup and country filtering, which is what a threshold should mean.
        let produced = Arc::clone(&fetcher.accepted);

        // Coordinator: runs the primary phase to completion (bounded by
        // PRIMARY_PHASE_TIMEOUT), then decides whether to run the fallback.
        fetcher.handlers.push(tokio::spawn(async move {
            let sem = Arc::new(Semaphore::new(concurrency_limit));
            let primary_handles = spawn_phase(
                primary,
                &client,
                &sem,
                sender.clone(),
            );

            let joined = time::timeout(
                PRIMARY_PHASE_TIMEOUT,
                futures_util::future::join_all(primary_handles),
            )
            .await;

            #[cfg(feature = "log")]
            if joined.is_err() {
                log::warn!(
                    "primary providers still running after {:?}; starting fallback phase anyway",
                    PRIMARY_PHASE_TIMEOUT
                );
            }
            let _ = joined;

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

            let fallback_handles = spawn_phase(fallback, &client, &sem, sender);
            futures_util::future::join_all(fallback_handles).await;
        }));

        Ok(fetcher)
    }
}

/// Spawns one task per source, each gated by `sem`, and returns their handles.
fn spawn_phase(
    tasks: Vec<(Arc<Source>, Arc<dyn ProxyProvider + Send + Sync>)>,
    client: &Arc<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>>,
    sem: &Arc<Semaphore>,
    tx: mpsc::Sender<Proxy>,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::with_capacity(tasks.len());
    for (source, provider) in tasks {
        let permit = Arc::clone(sem);
        let client = Arc::clone(client);
        let tx = tx.clone();

        handles.push(tokio::spawn(async move {
            let url = source.url.to_string();
            if let Err(e) = do_work(provider, client, source, tx, permit).await {
                #[cfg(feature = "log")]
                log::error!("{}: {}", url, e);
                let _ = (url, e);
            }
        }));
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

    let expected_types = source.default_types.clone();
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
    fn accept(&mut self, mut proxy: Proxy) -> Option<Proxy> {
        if let Some(geolookup) = &self.geolookup {
            proxy.geo = geolookup.lookup(&proxy.ip);

            if !self.config.countries.is_empty()
                && !proxy
                    .geo
                    .iso_code
                    .as_ref()
                    .map(|code| self.config.countries.contains(code))
                    .unwrap_or(false)
            {
                return None;
            }
        }

        if self.config.enforce_unique_ip && !self.unique_ips.insert(proxy.as_text()) {
            return None;
        }

        self.counter += 1;
        self.accepted.fetch_add(1, Ordering::Relaxed);
        Some(proxy)
    }
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
        // the producing tasks on their own instead of leaking them.
        self.receiver.close();
        while let Some(handler) = self.handlers.pop() {
            handler.abort();
        }

        #[cfg(feature = "log")]
        log::debug!(
            "Proxy gathering completed: {} proxies found ({:?})",
            self.counter,
            self.elapsed.unwrap_or(self.timer.elapsed()),
        );
    }
}
