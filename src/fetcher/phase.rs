use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

use anyhow::Context;
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use tokio::{
    sync::{mpsc, watch, Semaphore},
    task::JoinSet,
    time,
};

use super::cache::Cache;
use crate::{
    providers::{models::Source, parse_all, parsers::ParsedProxy, ProxyProvider},
    proxy::models::{Anonymity, Protocol, Proxy},
};

const MAX_FETCH_ATTEMPTS: usize = 2;
const FETCH_RETRY_BACKOFF: Duration = Duration::from_millis(250);

/// Cached single-protocol type sets, reusable across every typed row.
static HTTP_ARCS: LazyLock<[Arc<[Protocol]>; 4]> = LazyLock::new(|| {
    [
        Arc::from([Protocol::Http(Anonymity::Transparent)]),
        Arc::from([Protocol::Http(Anonymity::Anonymous)]),
        Arc::from([Protocol::Http(Anonymity::Elite)]),
        Arc::from([Protocol::Http(Anonymity::Unknown)]),
    ]
});
static HTTPS_ARCS: LazyLock<[Arc<[Protocol]>; 4]> = LazyLock::new(|| {
    [
        Arc::from([Protocol::Https(Anonymity::Transparent)]),
        Arc::from([Protocol::Https(Anonymity::Anonymous)]),
        Arc::from([Protocol::Https(Anonymity::Elite)]),
        Arc::from([Protocol::Https(Anonymity::Unknown)]),
    ]
});
static SOCKS4_ARC: LazyLock<Arc<[Protocol]>> = LazyLock::new(|| Arc::from([Protocol::Socks4]));
static SOCKS5_ARC: LazyLock<Arc<[Protocol]>> = LazyLock::new(|| Arc::from([Protocol::Socks5]));

fn anonymity_index(anonymity: Anonymity) -> usize {
    match anonymity {
        Anonymity::Transparent => 0,
        Anonymity::Anonymous => 1,
        Anonymity::Elite => 2,
        Anonymity::Unknown => 3,
    }
}

/// Returns a shared single-protocol type set, falling back to a fresh
/// allocation only for the unbounded `Connect(port)` variant.
pub(crate) fn protocol_arc(protocol: Protocol) -> Arc<[Protocol]> {
    match protocol {
        Protocol::Http(anonymity) => Arc::clone(&HTTP_ARCS[anonymity_index(anonymity)]),
        Protocol::Https(anonymity) => Arc::clone(&HTTPS_ARCS[anonymity_index(anonymity)]),
        Protocol::Socks4 => Arc::clone(&SOCKS4_ARC),
        Protocol::Socks5 => Arc::clone(&SOCKS5_ARC),
        Protocol::Connect(_) => Arc::from([protocol]),
    }
}

/// Fetch-phase transitions reported to consumers.
///
/// Primary providers run first; fallback mirrors replay only what primary
/// missed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchStage {
    /// Primary provider set is being scraped.
    Primary,
    /// Fallback mirrors are being scraped.
    Fallback,
    /// All fetch phases finished.
    Done,
}

// Always close with Done, even on early return.
pub(crate) struct StageReporter {
    pub(crate) tx: mpsc::Sender<FetchStage>,
}

impl StageReporter {
    pub(crate) fn send(&self, stage: FetchStage) {
        let _ = self.tx.try_send(stage);
    }
}

impl Drop for StageReporter {
    fn drop(&mut self) {
        let _ = self.tx.try_send(FetchStage::Done);
    }
}

pub(crate) struct FetchJob {
    pub(crate) provider: Arc<dyn ProxyProvider + Send + Sync>,
    pub(crate) source: Arc<Source>,
}

#[derive(Clone)]
pub(crate) struct PhaseContext {
    pub(crate) client: Arc<Client<crate::proxy::client::HttpsConnector, Empty<Bytes>>>,
    pub(crate) sem: Arc<Semaphore>,
    pub(crate) tx: mpsc::Sender<Proxy>,
    pub(crate) stop_rx: watch::Receiver<bool>,
    pub(crate) settings: FetchSettings,
}

pub(crate) fn spawn_phase(
    tasks: Vec<(Arc<Source>, Arc<dyn ProxyProvider + Send + Sync>)>,
    ctx: &PhaseContext,
) -> JoinSet<()> {
    let mut handles = JoinSet::new();
    for (source, provider) in tasks {
        let job = FetchJob { provider, source };
        let ctx = ctx.clone();
        handles.spawn(async move {
            // Keep the source Arc for the error path only; success never formats.
            let source = Arc::clone(&job.source);
            if let Err(e) = do_work(job, ctx).await {
                #[cfg(feature = "log")]
                log::error!("{}: {:#}", source.url, e);
                let _ = (source, e);
            }
        });
    }
    handles
}

/// Share fetch behaviour across source tasks.
#[derive(Clone)]
pub(crate) struct FetchSettings {
    pub(crate) fetch_cache: Option<Arc<Cache>>,
    pub(crate) offline: bool,
    pub(crate) throttle: Arc<Throttle>,
    pub(crate) fetch_delay: Option<Duration>,
    pub(crate) hosts: Arc<HostLimiter>,
}

/// Serializes network requests to the same host.
pub(crate) struct Throttle {
    /// Project next request slot to space concurrent callers apart.
    next_slot: Mutex<HashMap<String, time::Instant>>,
}

impl Throttle {
    pub(crate) fn new() -> Self {
        Self {
            next_slot: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn wait(&self, host: &str, delay: Duration) {
        let available_at = {
            let mut next_slot = self.next_slot.lock().unwrap_or_else(|e| e.into_inner());
            let now = time::Instant::now();
            // Reuse key allocation to avoid per-call String alloc.
            match next_slot.get_mut(host) {
                Some(previous) => {
                    let avail_at = (*previous).max(now);
                    *previous = avail_at.checked_add(delay).unwrap_or(avail_at);
                    avail_at
                }
                None => {
                    next_slot.insert(host.to_owned(), now.checked_add(delay).unwrap_or(now));
                    now
                }
            }
        };
        let remaining = available_at.saturating_duration_since(time::Instant::now());
        if !remaining.is_zero() {
            time::sleep(remaining).await;
        }
    }
}

/// Caps concurrent requests per host so bursts stay polite.
pub(crate) struct HostLimiter {
    limit: usize,
    hosts: Mutex<HashMap<String, Arc<Semaphore>>>,
}

impl HostLimiter {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            hosts: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn for_host(&self, host: &str) -> Arc<Semaphore> {
        let mut hosts = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(sem) = hosts.get(host) {
            return Arc::clone(sem);
        }
        let sem = Arc::new(Semaphore::new(self.limit));
        hosts.insert(host.to_owned(), Arc::clone(&sem));
        sem
    }
}

pub(crate) fn source_host(source: &Source) -> String {
    source
        .url
        .host()
        .map(str::to_owned)
        .unwrap_or_else(|| source.url.to_string())
}

async fn throttle_wait(settings: &FetchSettings, source: &Source) {
    if let Some(delay) = settings.fetch_delay {
        settings.throttle.wait(&source_host(source), delay).await;
    }
}

fn is_transient(error: &anyhow::Error) -> bool {
    if error.chain().any(|cause| {
        cause.is::<std::io::Error>()
            || cause.is::<hyper::Error>()
            || cause.is::<hyper_util::client::legacy::Error>()
            || cause.is::<time::error::Elapsed>()
    }) {
        return true;
    }
    let chain = format!("{error:#}");
    chain.contains("returned HTTP 5") || chain.contains("returned HTTP 429")
}

pub(crate) async fn do_work(job: FetchJob, ctx: PhaseContext) -> anyhow::Result<()> {
    let FetchJob { provider, source } = job;
    if *ctx.stop_rx.borrow() {
        return Ok(());
    }
    let url = source.url.to_string();
    let expected_types = Arc::clone(&source.default_types);

    let cached = match ctx.settings.fetch_cache.as_ref() {
        Some(fetch_cache) => fetch_cache.load_rows(&url).await,
        None => None,
    };

    let rows: Vec<ParsedProxy> = match cached {
        Some(rows) => rows,
        None => {
            if ctx.settings.offline {
                #[cfg(feature = "log")]
                log::warn!("offline: no cached rows for {url}; skipping");
                return Ok(());
            }
            // Throttle before taking a permit so a sleeping host holds no slot.
            throttle_wait(&ctx.settings, &source).await;
            // Hold the network permit only for the fetch; parsing and cache
            // writes must not occupy a fetch slot.
            #[cfg(feature = "log")]
            let fetch_started = time::Instant::now();
            let body = {
                let mut attempt = 1usize;
                loop {
                    let result = {
                        let host_sem = ctx.settings.hosts.for_host(&source_host(&source));
                        let _host_permit = host_sem
                            .acquire_owned()
                            .await
                            .context("fetcher host limiter closed during shutdown")?;
                        let _permit = ctx
                            .sem
                            .acquire()
                            .await
                            .context("fetcher semaphore closed during shutdown")?;
                        provider
                            .fetch(Arc::clone(&ctx.client), &url, source.timeout)
                            .await
                    };
                    match result {
                        Ok(body) => break body,
                        Err(error) if attempt < MAX_FETCH_ATTEMPTS && is_transient(&error) => {
                            attempt += 1;
                            time::sleep(FETCH_RETRY_BACKOFF).await;
                        }
                        Err(error) => {
                            return Err(error.context(format!(
                                "failed to fetch proxy list from {}",
                                source.url
                            )))
                        }
                    }
                }
            };
            #[cfg(feature = "log")]
            let fetch_elapsed = fetch_started.elapsed();
            #[cfg(feature = "log")]
            let body_len = body.len();
            let mode = source.mode.clone();
            #[cfg(feature = "log")]
            let parse_started = time::Instant::now();
            let rows = tokio::task::spawn_blocking(move || parse_all(&mode, body.as_ref()))
                .await
                .context("provider parser task failed")??;
            #[cfg(feature = "log")]
            log::debug!(
                "{url}: fetched {body_len} bytes in {fetch_elapsed:?}, parsed {} rows in {:?}",
                rows.len(),
                parse_started.elapsed(),
            );
            if let Some(fetch_cache) = ctx.settings.fetch_cache.as_ref() {
                fetch_cache.store_rows(&url, &rows).await;
            }
            rows
        }
    };

    if *ctx.stop_rx.borrow() {
        return Ok(());
    }

    for (ip, port, protocol) in rows {
        let proxy = match protocol {
            Some(protocol) => Proxy::with_expected_types(ip, port, protocol_arc(protocol)),
            None => Proxy::with_expected_types(ip, port, Arc::clone(&expected_types)),
        };
        if ctx.tx.send(proxy).await.is_err() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::protocol_arc;
    use crate::proxy::models::{Anonymity, Protocol};
    use std::sync::Arc;

    #[test]
    fn protocol_arc_reuses_shared_sets_and_falls_back_for_connect() {
        let first = protocol_arc(Protocol::Http(Anonymity::Elite));
        let second = protocol_arc(Protocol::Http(Anonymity::Elite));
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.as_ref(), &[Protocol::Http(Anonymity::Elite)]);

        let socks = protocol_arc(Protocol::Socks5);
        assert_eq!(socks.as_ref(), &[Protocol::Socks5]);

        let connect = protocol_arc(Protocol::Connect(8080));
        assert_eq!(connect.as_ref(), &[Protocol::Connect(8080)]);
    }

    #[test]
    fn transient_errors_are_retryable_and_permanent_ones_are_not() {
        let reset = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset",
        ));
        assert!(super::is_transient(&reset));

        assert!(super::is_transient(&anyhow::anyhow!(
            "http://example.com returned HTTP 503 Service Unavailable"
        )));
        assert!(super::is_transient(&anyhow::anyhow!(
            "http://example.com returned HTTP 429 Too Many Requests"
        )));
        assert!(!super::is_transient(&anyhow::anyhow!(
            "http://example.com returned HTTP 404 Not Found"
        )));
        assert!(!super::is_transient(&anyhow::anyhow!(
            "invalid provider URL `nope`"
        )));
    }

    #[tokio::test]
    async fn host_limiter_shares_one_semaphore_per_host() {
        let limiter = super::HostLimiter::new(1);
        let first = limiter.for_host("example.com");
        let second = limiter.for_host("example.com");
        assert!(Arc::ptr_eq(&first, &second));

        let other = limiter.for_host("other.com");
        assert!(!Arc::ptr_eq(&first, &other));

        let held = first.acquire_owned().await.unwrap();
        assert_eq!(second.available_permits(), 0);
        assert_eq!(other.available_permits(), 1);
        drop(held);
        assert_eq!(second.available_permits(), 1);
    }

    #[tokio::test]
    async fn throttle_saturates_an_oversized_delay() {
        let throttle = super::Throttle::new();
        let huge = std::time::Duration::from_secs(u64::MAX);
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            throttle.wait("example.com", huge),
        )
        .await
        .expect("an out-of-range delay must not be slept off");
    }
}
