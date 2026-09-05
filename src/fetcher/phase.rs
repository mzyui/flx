use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
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
    proxy::models::Proxy,
};

/// Report fetch-phase transitions to consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchStage {
    Primary,
    Fallback,
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
            let url = job.source.url.to_string();
            if let Err(e) = do_work(job, ctx).await {
                #[cfg(feature = "log")]
                log::error!("{}: {:#}", url, e);
                let _ = (url, e);
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
                    *previous = avail_at + delay;
                    avail_at
                }
                None => {
                    next_slot.insert(host.to_owned(), now + delay);
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
            let _permit = ctx
                .sem
                .acquire()
                .await
                .context("fetcher semaphore closed during shutdown")?;
            throttle_wait(&ctx.settings, &source).await;
            let body = provider
                .fetch(Arc::clone(&ctx.client), &url, source.timeout)
                .await
                .with_context(|| format!("failed to fetch proxy list from {}", source.url))?;
            let mode = source.mode.clone();
            let rows = tokio::task::spawn_blocking(move || parse_all(&mode, body.as_ref()))
                .await
                .context("provider parser task failed")??;
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
            Some(protocol) => Proxy::with_expected_types(ip, port, Arc::from([protocol])),
            None => Proxy::with_expected_types(ip, port, Arc::clone(&expected_types)),
        };
        if ctx.tx.send(proxy).await.is_err() {
            break;
        }
    }
    Ok(())
}
