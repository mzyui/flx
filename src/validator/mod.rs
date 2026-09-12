//! Validates proxy candidates against online judges.
//!
//! [`ProxyValidator`] streams passing proxies; [`Config`]
//! tunes concurrency, timeouts, and targets. Per-proxy failures go to the
//! optional failure channel — see [`ProxyValidator::take_failures`].
/// Online-judge probing primitives used by the validator workers.
pub mod checker;
/// Validator configuration ([`Config`], judge URL defaults, probe gates).
pub mod config;
mod progress;
mod tunnel;
mod work;

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
    vec::Vec,
};

use anyhow::Context as _;
use futures_util::{Stream, StreamExt};
#[cfg(feature = "log")]
use tokio::time::Instant;
use tokio::{
    sync::{mpsc, Notify},
    task::JoinHandle,
};

/// Validator configuration and defaults re-exported for [`ProxyValidator::validate`].
pub use config::{
    Config, ProbeGate, DEFAULT_CONCURRENCY_LIMIT, DEFAULT_HTTPS_JUDGE_URLS, DEFAULT_HTTP_JUDGE_URLS,
};
/// Judge-health and progress snapshots re-exported from the validator.
pub use progress::{JudgeHealthReport, ValidationProgress};
/// Tunnel validation milestone reached by one probe.
pub use tunnel::ValidationStatus;
/// Machine-readable record of one failed probe.
pub use work::ProxyFailure;
use work::{
    aggregate_groups, do_group_work, do_work, GroupMemberJob, GroupWorkResult, SingletonJob,
    WorkParams,
};
#[cfg(test)]
use work::{group_finish, result_satisfies_request, GroupState};

use crate::proxy::models::{Protocol, Proxy};

pub(crate) const VALIDATOR_CHANNEL_MIN: usize = 64;
pub(crate) const VALIDATOR_CHANNEL_MAX: usize = 4_096;

fn validator_channel_capacity(concurrency_limit: usize) -> usize {
    concurrency_limit
        .saturating_mul(4)
        .clamp(VALIDATOR_CHANNEL_MIN, VALIDATOR_CHANNEL_MAX)
}

/// Cooperative pause gate for validation workers.
///
/// Workers check [`PauseGate::wait_if_paused`] before starting each new
/// probe; in-flight probes always run to completion. Clone the shared
/// handle to drive pause state from elsewhere (e.g. a signal handler).
#[derive(Debug, Default)]
pub struct PauseGate {
    paused: AtomicBool,
    notify: Notify,
}

impl PauseGate {
    /// Creates an unpaused gate.
    pub fn new() -> Self {
        Self::default()
    }

    /// Holds new probes; in-flight probes finish normally.
    pub fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    /// Lets held probes start again.
    pub fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    /// Whether new probes are currently held.
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Waits while paused; returns immediately when running.
    pub async fn wait_if_paused(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // Register before re-checking: `resume` uses `notify_waiters`, which
            // is a no-op when no waiter is registered yet.
            notified.as_mut().enable();
            if !self.is_paused() {
                break;
            }
            notified.await;
        }
    }
}

struct BufferedProxyStream {
    rx: mpsc::Receiver<Proxy>,
}

impl Stream for BufferedProxyStream {
    type Item = Proxy;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().rx.poll_recv(cx)
    }
}

fn report_dropped(url: &str, reason: &str) {
    #[cfg(feature = "log")]
    log::warn!("warning: judge `{url}` failed preflight and was dropped: {reason}");
    #[cfg(not(feature = "log"))]
    let _ = (url, reason);
}

/// Validate proxy candidates against online judges.
///
/// The validator itself is a [`Stream`] of passing proxies; use
/// [`ProxyValidator::validate`] to build it.
pub struct ProxyValidator {
    receiver: mpsc::Receiver<Proxy>,
    progress: ValidationProgress,
    judge_health: JudgeHealthReport,
    pause_gate: Arc<PauseGate>,
    #[cfg(feature = "log")]
    timer: Instant,
    task_handle: JoinHandle<()>,
    group_task: JoinHandle<()>,
    failures: Option<mpsc::Receiver<work::ProxyFailure>>,
}

#[derive(Clone)]
struct JudgeTargets {
    http: Arc<checker::JudgePool>,
    tunnel: Arc<checker::JudgePool>,
}

// Reuse verified judge pool across passes within short TTL.
const JUDGE_POOL_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    urls: Vec<String>,
    insecure: bool,
}

struct CachedJudgePool {
    created: std::time::Instant,
    pool: Arc<checker::JudgePool>,
}

static POOL_CACHE: std::sync::OnceLock<Mutex<HashMap<PoolKey, CachedJudgePool>>> =
    std::sync::OnceLock::new();

fn pool_cache() -> &'static Mutex<HashMap<PoolKey, CachedJudgePool>> {
    POOL_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached_judge_pool(urls: &[String], insecure: bool) -> Option<Arc<checker::JudgePool>> {
    let mut cache = pool_cache().lock().unwrap_or_else(|e| e.into_inner());
    // Prune every expired entry, not just the requested key, so abandoned
    // configurations cannot accumulate.
    cache.retain(|_, entry| entry.created.elapsed() <= JUDGE_POOL_CACHE_TTL);
    let key = PoolKey {
        urls: urls.to_vec(),
        insecure,
    };
    cache.get(&key).map(|entry| Arc::clone(&entry.pool))
}

fn cache_judge_pool(urls: &[String], insecure: bool, pool: &Arc<checker::JudgePool>) {
    let key = PoolKey {
        urls: urls.to_vec(),
        insecure,
    };
    pool_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            key,
            CachedJudgePool {
                created: std::time::Instant::now(),
                pool: Arc::clone(pool),
            },
        );
}

// Retry preflight once so transient blips cannot abort the run.
async fn preflight_pool(
    urls: &[String],
    timeout: Duration,
    insecure: bool,
) -> anyhow::Result<(Arc<checker::JudgePool>, JudgeHealthReport)> {
    const PREFLIGHT_RETRIES: usize = 1;
    const PREFLIGHT_RETRY_DELAY: Duration = Duration::from_secs(1);
    if let Some(pool) = cached_judge_pool(urls, insecure) {
        // Report real counts for cached pools without rerunning preflight.
        let report = JudgeHealthReport {
            candidates: unique_count(urls),
            healthy: pool.len(),
            failed: Vec::new(),
        };
        return Ok((pool, report));
    }
    let mut last_error: Option<anyhow::Error> = None;
    for attempt in 0..=PREFLIGHT_RETRIES {
        if attempt > 0 {
            tokio::time::sleep(PREFLIGHT_RETRY_DELAY).await;
        }
        let failed: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let failed_cb = Arc::clone(&failed);
        match checker::JudgePool::build(urls, timeout, insecure, move |url, reason| {
            report_dropped(url, reason);
            failed_cb
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((url.to_owned(), reason.to_owned()));
        })
        .await
        {
            Ok(pool) => {
                let candidates = unique_count(urls);
                // Snapshot report once candidates resolve or short grace elapses.
                let deadline = tokio::time::Instant::now() + timeout + Duration::from_secs(1);
                let grace = tokio::time::Instant::now() + Duration::from_millis(250);
                loop {
                    let failed_len = failed.lock().unwrap_or_else(|e| e.into_inner()).len();
                    if pool.len() + failed_len >= candidates
                        || tokio::time::Instant::now() >= deadline
                        || tokio::time::Instant::now() >= grace
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                let report = JudgeHealthReport {
                    candidates,
                    healthy: pool.len(),
                    failed: failed.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                };
                cache_judge_pool(urls, insecure, &pool);
                return Ok((pool, report));
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("preflight_pool always runs at least one attempt"))
}

fn unique_count(urls: &[String]) -> usize {
    urls.iter().collect::<std::collections::HashSet<_>>().len()
}

impl ProxyValidator {
    /// Validates every proxy from the source stream against online judges.
    ///
    /// # Arguments
    ///
    /// * `proxy_source` - Candidate stream, usually from [`Flx`](crate::Flx).
    /// * `config` - Protocols, timeouts, and concurrency limits.
    ///
    /// # Errors
    ///
    /// Returns an error when the config is empty/invalid or judge preflight fails.
    pub async fn validate<S>(proxy_source: S, config: Config) -> anyhow::Result<Self>
    where
        S: Stream<Item = Proxy> + Send + 'static,
    {
        if config.types.is_empty() && config.groups.is_empty() {
            anyhow::bail!("config.types and config.groups cannot both be empty; please specify at least one type.");
        }
        if config.groups.iter().any(|group| group.is_empty()) {
            anyhow::bail!("config.groups cannot contain an empty group");
        }
        if config.concurrency_limit == 0 {
            anyhow::bail!("config.concurrency_limit must be greater than zero");
        }
        if config.request_timeout == 0 {
            anyhow::bail!("config.request_timeout must be greater than zero");
        }
        if config.max_attempts == 0 {
            anyhow::bail!("config.max_attempts must be greater than zero");
        }
        #[cfg(feature = "log")]
        log::debug!(
            "Proxy validator started ({} workers)",
            config.concurrency_limit
        );

        let (sender, receiver) =
            mpsc::channel(validator_channel_capacity(config.concurrency_limit));
        let (failure_tx, failure_rx) = if config.report_failures {
            let (tx, rx) = mpsc::channel(validator_channel_capacity(config.concurrency_limit));
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let progress = ValidationProgress::default();
        let pause_gate = Arc::new(PauseGate::new());
        let manager_pause = Arc::clone(&pause_gate);
        let manager_total = Arc::clone(&progress.total);
        let manager_done = Arc::clone(&progress.done);
        let manager_passed = Arc::clone(&progress.passed);
        let expected: Arc<[Protocol]> = Arc::from(config.types.into_boxed_slice());
        // Deduplicate group members to avoid double probes and records.
        let groups: Arc<Vec<Vec<Protocol>>> = Arc::new(
            config
                .groups
                .into_iter()
                .map(|mut group| {
                    let mut seen: Vec<Protocol> = Vec::with_capacity(group.len());
                    group.retain(|protocol| {
                        if seen.contains(protocol) {
                            false
                        } else {
                            seen.push(*protocol);
                            true
                        }
                    });
                    group
                })
                .collect(),
        );
        // Flatten groups once to avoid per-proxy allocation.
        let group_spec: Arc<Vec<(usize, usize, Protocol)>> = Arc::from(
            groups
                .iter()
                .enumerate()
                .flat_map(|(group_idx, protocols)| {
                    protocols
                        .iter()
                        .enumerate()
                        .map(move |(slot, protocol)| (group_idx, slot, *protocol))
                })
                .collect::<Vec<_>>(),
        );
        let max_attempts = config.max_attempts;
        let request_timeout = config.request_timeout;
        let concurrency_limit = config.concurrency_limit;
        let insecure = config.insecure;
        let probe_missed = config.probe_missed_types;
        let probe_gate = config.probe_gate.clone();
        let support_cookies = config.support_cookies;
        let support_referer = config.support_referer;
        let preflight_timeout = Duration::from_secs(config.request_timeout);
        let need_http = expected
            .iter()
            .chain(groups.iter().flatten())
            .any(|protocol| matches!(protocol, Protocol::Http(_)));
        let need_tunnel = expected
            .iter()
            .chain(groups.iter().flatten())
            .any(|protocol| !matches!(protocol, Protocol::Http(_)));

        // Buffer source during preflight to avoid stalling the fetcher.
        let (buf_tx, buf_rx) = mpsc::channel(validator_channel_capacity(concurrency_limit));
        let proxy_source: Pin<Box<dyn Stream<Item = Proxy> + Send>> = {
            let mut src: Pin<Box<dyn Stream<Item = Proxy> + Send>> = Box::pin(proxy_source);
            let tx = buf_tx;
            tokio::spawn(async move {
                while let Some(proxy) = src.next().await {
                    if tx.send(proxy).await.is_err() {
                        break;
                    }
                }
            });
            Box::pin(BufferedProxyStream { rx: buf_rx })
        };

        let http_preflight = async {
            if !need_http {
                return Ok::<Option<(Arc<checker::JudgePool>, JudgeHealthReport)>, anyhow::Error>(
                    None,
                );
            }
            let (pool, report) =
                preflight_pool(&config.http_judge_urls, preflight_timeout, insecure)
                    .await
                    .context("HTTP online judge pool is empty after preflight")?;
            Ok::<_, anyhow::Error>(Some((pool, report)))
        };
        let tunnel_preflight = async {
            if !need_tunnel {
                return Ok::<Option<(Arc<checker::JudgePool>, JudgeHealthReport)>, anyhow::Error>(
                    None,
                );
            }
            let (pool, report) =
                preflight_pool(&config.https_judge_urls, preflight_timeout, insecure)
                    .await
                    .context("HTTPS online judge pool is empty after preflight")?;
            Ok::<_, anyhow::Error>(Some((pool, report)))
        };
        // Warm public-IP cache in parallel with judge preflights.
        let my_ip_warmup = async {
            let _ = crate::resolver::my_ip().await;
        };
        let (http_target, tunnel_target, _) =
            tokio::join!(http_preflight, tunnel_preflight, my_ip_warmup);
        let http_target = http_target?;
        let tunnel_target = tunnel_target?;
        let mut judge_health = JudgeHealthReport::default();
        if let Some((_, report)) = http_target.as_ref() {
            judge_health.merge(report);
        }
        if let Some((_, report)) = tunnel_target.as_ref() {
            judge_health.merge(report);
        }
        #[cfg(feature = "log")]
        if let Some((pool, _)) = http_target.as_ref() {
            log::info!("using {} healthy HTTP judge(s)", pool.len());
        }
        #[cfg(feature = "log")]
        if let Some((pool, _)) = tunnel_target.as_ref() {
            log::info!("using {} healthy HTTPS judge(s)", pool.len());
        }
        let targets = JudgeTargets {
            http: http_target
                .map(|(pool, _)| pool)
                .unwrap_or_else(|| Arc::new(checker::JudgePool::from_targets(Vec::new()))),
            tunnel: tunnel_target
                .map(|(pool, _)| pool)
                .unwrap_or_else(|| Arc::new(checker::JudgePool::from_targets(Vec::new()))),
        };

        let (group_tx, group_rx): (
            mpsc::Sender<GroupWorkResult>,
            mpsc::Receiver<GroupWorkResult>,
        ) = mpsc::channel(validator_channel_capacity(concurrency_limit));

        // Forward proxies only after every group slot reports.
        let aggregate_sender = sender.clone();
        let aggregate_progress = progress.clone();
        // Share dead flags so failed members short-circuit siblings.
        let worker_group_dead: work::GroupDeadMap =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let group_aggregator = tokio::spawn(aggregate_groups(
            group_rx,
            aggregate_sender,
            aggregate_progress,
            Some(std::sync::Arc::clone(&worker_group_dead)),
        ));

        let manager = tokio::spawn(async move {
            enum Job {
                Singleton {
                    proxy: Arc<Proxy>,
                    protocol: Protocol,
                    requested: Protocol,
                },
                GroupMember {
                    proxy: Arc<Proxy>,
                    proxy_id: u64,
                    protocol: Protocol,
                    group_idx: usize,
                    slot: usize,
                    group_len: usize,
                },
            }

            // Clone counters for workers; total moves into job closure.
            let worker_counters = ValidationProgress {
                total: Arc::clone(&manager_total),
                done: Arc::clone(&manager_done),
                passed: Arc::clone(&manager_passed),
            };

            // Expand proxies into singleton plus group jobs with monotonic ids.
            let next_proxy_id = AtomicU64::new(0);
            // Count total in job units matching done/passed increments.
            let stream_total = Arc::clone(&manager_total);
            let jobs = proxy_source.flat_map(move |proxy: Proxy| {
                let proxy = Arc::new(proxy);
                let proxy_id = next_proxy_id.fetch_add(1, Ordering::Relaxed);
                let advertised = Arc::clone(&proxy.expected_types);
                let has_group = !group_spec.is_empty();

                // Collapse to unique probes; see `work::singleton_jobs`.
                let singleton_jobs =
                    work::singleton_jobs(advertised.as_ref(), expected.as_ref(), probe_missed);

                let singleton_proxy = Arc::clone(&proxy);
                let singleton: futures_util::stream::BoxStream<'static, Job> =
                    Box::pin(futures_util::stream::iter(singleton_jobs.into_iter().map(
                        move |(protocol, requested)| Job::Singleton {
                            proxy: Arc::clone(&singleton_proxy),
                            protocol,
                            requested,
                        },
                    )));

                let group: futures_util::stream::BoxStream<'static, Job> = if has_group {
                    Box::pin(futures_util::stream::unfold(
                        (
                            0usize,
                            proxy_id,
                            proxy,
                            Arc::clone(&group_spec),
                            Arc::clone(&groups),
                        ),
                        |(mut idx, proxy_id, proxy, spec, groups)| async move {
                            if idx >= spec.len() {
                                return None;
                            }
                            let (group_idx, slot, protocol) = spec[idx];
                            idx += 1;
                            let group_len = groups[group_idx].len();
                            Some((
                                Job::GroupMember {
                                    proxy: Arc::clone(&proxy),
                                    proxy_id,
                                    protocol,
                                    group_idx,
                                    slot,
                                    group_len,
                                },
                                (idx, proxy_id, proxy, spec, groups),
                            ))
                        },
                    ))
                } else {
                    Box::pin(futures_util::stream::empty())
                };

                singleton.chain(group).inspect({
                    let stream_total = Arc::clone(&stream_total);
                    move |job| match job {
                        Job::Singleton { .. } => {
                            stream_total.fetch_add(1, Ordering::Relaxed);
                        }
                        // Count each group once via its slot-0 member.
                        Job::GroupMember { slot, .. } if *slot == 0 => {
                            stream_total.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                })
            });

            let worker_group_tx = group_tx.clone();
            let worker_failures = failure_tx.clone();
            let worker_pause = Arc::clone(&manager_pause);
            let worker_gate = probe_gate.clone();
            jobs.for_each_concurrent(concurrency_limit, move |job| {
                let sender = sender.clone();
                let pause = worker_pause.clone();
                let gate = worker_gate.clone();
                let counters = worker_counters.clone();
                let targets = targets.clone();
                let group_tx = worker_group_tx.clone();
                let failures = worker_failures.clone();
                let group_dead = std::sync::Arc::clone(&worker_group_dead);
                let params = WorkParams {
                    max_attempts,
                    request_timeout: Duration::from_secs(request_timeout),
                    insecure,
                    support_cookies,
                    support_referer,
                    retry_delay: config.retry_delay,
                };
                async move {
                    // Hold new probes while paused; in-flight probes already
                    // past this gate run to completion.
                    pause.wait_if_paused().await;
                    match job {
                        Job::Singleton {
                            proxy,
                            protocol,
                            requested,
                        } => {
                            // Quota runs close filled protocols: count the job
                            // done without probing or reporting a failure.
                            if gate.as_ref().is_some_and(|gate| !gate(requested)) {
                                counters.done.fetch_add(1, Ordering::Relaxed);
                                return;
                            }
                            if let Err(_e) = do_work(
                                SingletonJob {
                                    proxy,
                                    protocol,
                                    requested,
                                },
                                sender,
                                counters,
                                targets,
                                &params,
                                failures,
                            )
                            .await
                            {
                                #[cfg(feature = "log")]
                                log::debug!("validation task failed: {:#}", _e);
                            }
                        }
                        Job::GroupMember {
                            proxy,
                            proxy_id,
                            protocol,
                            group_idx,
                            slot,
                            group_len,
                        } => {
                            if let Err(_e) = do_group_work(
                                GroupMemberJob {
                                    proxy,
                                    proxy_id,
                                    protocol,
                                    group_idx,
                                    slot,
                                    group_len,
                                },
                                group_tx,
                                targets,
                                &params,
                                failures,
                                Some(group_dead),
                            )
                            .await
                            {
                                #[cfg(feature = "log")]
                                log::debug!("group validation task failed: {:#}", _e);
                            }
                        }
                    }
                }
            })
            .await;

            // Close the group channel so the aggregator drains and stops.
            drop(group_tx);
        });

        Ok(Self {
            receiver,
            progress,
            judge_health,
            pause_gate,
            #[cfg(feature = "log")]
            timer: Instant::now(),
            task_handle: manager,
            group_task: group_aggregator,
            failures: failure_rx,
        })
    }

    /// Report judge preflight results collected at startup.
    pub fn judge_health(&self) -> &JudgeHealthReport {
        &self.judge_health
    }

    /// Returns a shared handle to the live validation counters.
    pub fn progress(&self) -> ValidationProgress {
        self.progress.clone()
    }

    /// Pauses starting new probes; in-flight probes finish normally.
    pub fn pause(&self) {
        self.pause_gate.pause();
    }

    /// Resumes starting new probes after [`ProxyValidator::pause`].
    pub fn resume(&self) {
        self.pause_gate.resume();
    }

    /// Whether new probes are currently held.
    pub fn is_paused(&self) -> bool {
        self.pause_gate.is_paused()
    }

    /// Shares the pause gate (e.g. with a signal handler task).
    pub fn pause_gate(&self) -> Arc<PauseGate> {
        Arc::clone(&self.pause_gate)
    }

    /// Takes the failure-report receiver; returns [`None`] when reporting is
    /// disabled or the receiver was already taken. Call before draining the
    /// stream so no buffered failure records are dropped.
    pub fn take_failures(&mut self) -> Option<mpsc::Receiver<work::ProxyFailure>> {
        self.failures.take()
    }

    /// Receives the next passing proxy, or [`None`] once validation is complete
    /// and all passing proxies have been consumed.
    pub async fn get_one(&mut self) -> Option<Proxy> {
        self.receiver.recv().await
    }
}

impl Stream for ProxyValidator {
    type Item = Proxy;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().receiver.poll_recv(cx)
    }
}

impl Drop for ProxyValidator {
    fn drop(&mut self) {
        self.receiver.close();
        self.task_handle.abort();
        self.group_task.abort();
        #[cfg(feature = "log")]
        log::info!(
            "Proxy validator completed: {}/{} proxies validated ({:?})",
            self.progress.passed.load(Ordering::Acquire),
            self.progress.total.load(Ordering::Acquire),
            self.timer.elapsed(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::work::advertised_matches_request;
    use super::{
        group_finish, result_satisfies_request, validator_channel_capacity, Config, GroupState,
        PauseGate, ProbeGate, ProxyValidator, VALIDATOR_CHANNEL_MAX, VALIDATOR_CHANNEL_MIN,
    };
    use crate::proxy::models::{Anonymity, Protocol, Proxy, ProxyType};

    #[test]
    fn unknown_advertised_anonymity_can_be_measured_for_specific_request() {
        assert!(advertised_matches_request(
            &Protocol::Http(Anonymity::Unknown),
            &Protocol::Http(Anonymity::Elite),
        ));
    }

    #[test]
    fn measured_anonymity_must_satisfy_specific_request() {
        assert!(result_satisfies_request(
            &Protocol::Http(Anonymity::Elite),
            &Protocol::Http(Anonymity::Elite),
        ));
        assert!(!result_satisfies_request(
            &Protocol::Http(Anonymity::Transparent),
            &Protocol::Http(Anonymity::Elite),
        ));
        assert!(result_satisfies_request(
            &Protocol::Http(Anonymity::Anonymous),
            &Protocol::Http(Anonymity::Unknown),
        ));
    }

    #[test]
    fn connect_port_must_match_request() {
        assert!(advertised_matches_request(
            &Protocol::Connect(443),
            &Protocol::Connect(443),
        ));
        assert!(!advertised_matches_request(
            &Protocol::Connect(80),
            &Protocol::Connect(443),
        ));
        assert!(!result_satisfies_request(
            &Protocol::Connect(80),
            &Protocol::Connect(443),
        ));
    }

    #[test]
    fn validator_channel_capacity_scales_with_bounded_limits() {
        assert_eq!(validator_channel_capacity(1), VALIDATOR_CHANNEL_MIN);
        assert_eq!(validator_channel_capacity(500), 2_000);
        assert_eq!(
            validator_channel_capacity(usize::MAX),
            VALIDATOR_CHANNEL_MAX
        );
    }

    #[test]
    fn group_finish_merges_passing_types_into_one_record() {
        let mut socks4 = Proxy::new("1.1.1.1".parse().unwrap(), 10006);
        socks4.runtimes.record(0.5);
        socks4
            .proxy_types
            .push(ProxyType::checked(Protocol::Socks4));
        let mut socks5 = Proxy::new("1.1.1.1".parse().unwrap(), 10006);
        socks5.runtimes.record(0.3);
        socks5
            .proxy_types
            .push(ProxyType::checked(Protocol::Socks5));

        let finished = group_finish(GroupState {
            remaining: 0,
            results: vec![Some(socks4), Some(socks5)],
        })
        .expect("group passed");

        assert_eq!(finished.ip.to_string(), "1.1.1.1");
        assert_eq!(finished.proxy_types.len(), 2);
        assert_eq!(finished.proxy_types[0].protocol, Protocol::Socks4);
        assert_eq!(finished.proxy_types[1].protocol, Protocol::Socks5);
        assert!(finished.to_string().contains("[SOCKS4, SOCKS5]"));
        // Per-protocol latencies merge into one non-zero average.
        let average = finished.avg_response_time();
        assert!(
            (average - 0.4).abs() < f64::EPSILON,
            "average was {average}"
        );
    }

    #[test]
    fn group_finish_drops_group_when_any_slot_failed() {
        let passed = Proxy::new("1.1.1.1".parse().unwrap(), 10006);
        let finished = group_finish(GroupState {
            remaining: 0,
            results: vec![Some(passed), None],
        });
        assert!(finished.is_none());
    }

    #[tokio::test]
    async fn validation_rejects_zero_max_attempts_before_startup() {
        let config = Config {
            types: vec![Protocol::Socks5],
            max_attempts: 0,
            ..Config::default()
        };

        let result = ProxyValidator::validate(futures_util::stream::empty(), config).await;
        let error = match result {
            Ok(_) => panic!("zero max_attempts must be rejected"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("max_attempts must be greater than zero"));
    }

    #[tokio::test]
    async fn validator_drop_closes_channel_without_panic() {
        // Guard synchronous panic-free drop closing receiver and manager.
        let config = Config {
            types: vec![Protocol::Socks5],
            ..Config::default()
        };
        let validator = ProxyValidator::validate(futures_util::stream::empty(), config)
            .await
            .unwrap();
        drop(validator);
    }

    #[test]
    fn progress_defaults_to_zeroed_counters() {
        let progress = super::ValidationProgress::default();
        assert_eq!(progress.total(), 0);
        assert_eq!(progress.done(), 0);
        assert_eq!(progress.passed(), 0);
        assert_eq!(progress.remaining(), 0);
        assert_eq!(progress.fraction(), 0.0);
    }

    #[tokio::test]
    async fn failure_report_emits_one_reason_per_failed_probe() {
        // Probe closed ports via echo judge so failures stay fast and offline.
        let judge = spawn_echo_judge().await;
        let config = Config {
            types: vec![Protocol::Http(Anonymity::Unknown)],
            http_judge_urls: vec![judge],
            https_judge_urls: vec![],
            report_failures: true,
            ..Config::default()
        };
        let candidates = (1u16..=3).map(|port| {
            Proxy::with_expected_types(
                std::net::Ipv4Addr::LOCALHOST,
                port,
                std::sync::Arc::from([Protocol::Http(Anonymity::Unknown)]),
            )
        });
        let mut validator =
            ProxyValidator::validate(futures_util::stream::iter(candidates), config)
                .await
                .unwrap();
        let mut failures = validator.take_failures().expect("failures enabled");

        while validator.get_one().await.is_some() {}

        let mut reasons = Vec::new();
        while let Some(failure) = failures.recv().await {
            reasons.push(failure.reason);
        }
        assert_eq!(reasons.len(), 3);
        assert!(reasons
            .iter()
            .all(|reason| reason == "unsatisfied" || reason.starts_with("error (")));
    }

    #[tokio::test]
    async fn failure_report_is_absent_when_disabled() {
        let config = Config {
            types: vec![Protocol::Socks5],
            ..Config::default()
        };
        let mut validator = ProxyValidator::validate(futures_util::stream::empty(), config)
            .await
            .unwrap();
        assert!(validator.take_failures().is_none());
    }

    #[tokio::test]
    async fn progress_advances_as_candidates_are_probed() {
        // Probe closed ports via echo judge to advance counters without passes.
        let judge = spawn_echo_judge().await;
        let config = Config {
            types: vec![Protocol::Http(Anonymity::Unknown)],
            http_judge_urls: vec![judge],
            https_judge_urls: vec![],
            ..Config::default()
        };
        let candidates = (1u16..=5).map(|port| {
            Proxy::with_expected_types(
                std::net::Ipv4Addr::LOCALHOST,
                port,
                std::sync::Arc::from([Protocol::Http(Anonymity::Unknown)]),
            )
        });
        let mut validator =
            ProxyValidator::validate(futures_util::stream::iter(candidates), config)
                .await
                .unwrap();
        let progress = validator.progress();

        while validator.get_one().await.is_some() {}

        assert_eq!(progress.total(), 5);
        assert_eq!(progress.done(), 5);
        assert_eq!(progress.passed(), 0);
        assert_eq!(progress.remaining(), 0);
        assert!((progress.fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pause_resume_never_loses_a_wakeup() {
        for _ in 0..500 {
            let gate = std::sync::Arc::new(PauseGate::new());
            gate.pause();
            let waiter = {
                let gate = std::sync::Arc::clone(&gate);
                tokio::spawn(async move { gate.wait_if_paused().await })
            };
            tokio::task::yield_now().await;
            gate.resume();
            tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
                .await
                .expect("waiter must wake after resume")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn pause_holds_new_probes_until_resume() {
        // Feed candidates through a channel so pause applies before any probe.
        let judge = spawn_echo_judge().await;
        let config = Config {
            types: vec![Protocol::Http(Anonymity::Unknown)],
            http_judge_urls: vec![judge],
            https_judge_urls: vec![],
            ..Config::default()
        };
        let (tx, rx) = tokio::sync::mpsc::channel::<Proxy>(8);
        let source = futures_util::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|proxy| (proxy, rx))
        });
        let mut validator = ProxyValidator::validate(source, config).await.unwrap();
        let progress = validator.progress();
        let gate = validator.pause_gate();
        gate.pause();
        assert!(validator.is_paused());

        for port in 1u16..=5 {
            tx.send(Proxy::with_expected_types(
                std::net::Ipv4Addr::LOCALHOST,
                port,
                std::sync::Arc::from([Protocol::Http(Anonymity::Unknown)]),
            ))
            .await
            .unwrap();
        }
        // Held jobs must not probe while paused (closed ports fail fast offline).
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(progress.done(), 0);

        gate.resume();
        assert!(!validator.is_paused());
        drop(tx);
        while validator.get_one().await.is_some() {}
        assert_eq!(progress.done(), 5);
    }

    #[tokio::test]
    async fn judge_health_reports_preflight_failures() {
        let good = spawn_echo_judge().await;
        let bad = spawn_no_echo_judge().await;
        let config = Config {
            types: vec![Protocol::Http(Anonymity::Unknown)],
            http_judge_urls: vec![good, bad],
            https_judge_urls: vec![],
            ..Config::default()
        };
        let validator =
            ProxyValidator::validate(futures_util::stream::iter(Vec::<Proxy>::new()), config)
                .await
                .unwrap();

        let report = validator.judge_health();
        assert_eq!(report.candidates, 2);
        assert_eq!(report.healthy, 1);
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].1.contains("did not echo"));
    }

    #[tokio::test]
    async fn judge_preflight_retries_after_transient_failure() {
        // Guard preflight retry passing after one transient drop.
        let judge = spawn_flaky_echo_judge().await;
        let config = Config {
            types: vec![Protocol::Http(Anonymity::Unknown)],
            http_judge_urls: vec![judge],
            https_judge_urls: vec![],
            ..Config::default()
        };
        let validator =
            ProxyValidator::validate(futures_util::stream::iter(Vec::<Proxy>::new()), config)
                .await
                .unwrap();
        assert_eq!(validator.progress().total(), 0);
    }

    #[tokio::test]
    async fn probe_missed_types_probes_only_unmatched_types() {
        // Probe unmatched types on closed ports for fast failures.
        let judge = spawn_echo_judge().await;
        let candidates = (1u16..=5)
            .map(|port| {
                Proxy::with_expected_types(
                    std::net::Ipv4Addr::LOCALHOST,
                    port,
                    std::sync::Arc::from([Protocol::Socks5]),
                )
            })
            .collect::<Vec<_>>();
        let config = Config {
            types: vec![Protocol::Http(Anonymity::Unknown)],
            http_judge_urls: vec![judge],
            https_judge_urls: vec![],
            probe_missed_types: true,
            ..Config::default()
        };
        let mut validator =
            ProxyValidator::validate(futures_util::stream::iter(candidates), config)
                .await
                .unwrap();
        let progress = validator.progress();
        while validator.get_one().await.is_some() {}
        assert_eq!(progress.total(), 5);
        assert_eq!(progress.done(), 5);
        assert_eq!(progress.passed(), 0);
    }

    #[tokio::test]
    async fn probe_missed_types_skips_already_covered_types() {
        // Skip reprobe when advertisement already covers the request.
        let judge = spawn_echo_judge().await;
        let candidate = Proxy::with_expected_types(
            std::net::Ipv4Addr::LOCALHOST,
            10_000,
            std::sync::Arc::from([Protocol::Http(Anonymity::Unknown)]),
        );
        let config = Config {
            types: vec![Protocol::Http(Anonymity::Unknown)],
            http_judge_urls: vec![judge],
            https_judge_urls: vec![],
            probe_missed_types: true,
            ..Config::default()
        };
        let mut validator =
            ProxyValidator::validate(futures_util::stream::iter([candidate]), config)
                .await
                .unwrap();
        let progress = validator.progress();
        while validator.get_one().await.is_some() {}
        assert_eq!(progress.total(), 0);
        assert_eq!(progress.done(), 0);
    }

    #[tokio::test]
    async fn total_counts_each_singleton_job_not_each_proxy() {
        // Guard job-based total matching done on multi-type runs; the two
        // advertised families are distinct, so each yields one probe.
        let http_judge = spawn_echo_judge().await;
        let tunnel_judge = spawn_echo_judge().await;
        let candidates = (1u16..=2).map(|port| {
            Proxy::with_expected_types(
                std::net::Ipv4Addr::LOCALHOST,
                port,
                std::sync::Arc::from([Protocol::Http(Anonymity::Unknown), Protocol::Socks5]),
            )
        });
        let config = Config {
            types: vec![Protocol::Http(Anonymity::Unknown), Protocol::Socks5],
            http_judge_urls: vec![http_judge],
            https_judge_urls: vec![tunnel_judge],
            ..Config::default()
        };
        let mut validator =
            ProxyValidator::validate(futures_util::stream::iter(candidates), config)
                .await
                .unwrap();
        let progress = validator.progress();
        while validator.get_one().await.is_some() {}
        assert_eq!(progress.total(), 4);
        assert_eq!(progress.done(), 4);
        assert!(progress.fraction() <= 1.0);
    }

    #[tokio::test]
    async fn duplicate_http_families_collapse_to_one_probe() {
        // Guard collapsing advertised HTTP levels that probe identically.
        let judge = spawn_echo_judge().await;
        let candidates: Vec<Proxy> = (1u16..=3)
            .map(|port| {
                Proxy::with_expected_types(
                    std::net::Ipv4Addr::LOCALHOST,
                    port,
                    std::sync::Arc::from([
                        Protocol::Http(Anonymity::Anonymous),
                        Protocol::Http(Anonymity::Unknown),
                    ]),
                )
            })
            .collect();
        let config = Config {
            types: vec![Protocol::Http(Anonymity::Unknown)],
            http_judge_urls: vec![judge],
            https_judge_urls: vec![],
            ..Config::default()
        };
        let mut validator =
            ProxyValidator::validate(futures_util::stream::iter(candidates), config)
                .await
                .unwrap();
        let progress = validator.progress();
        while validator.get_one().await.is_some() {}
        // One probe per candidate, not two.
        assert_eq!(progress.total(), 3);
        assert_eq!(progress.done(), 3);
    }

    #[tokio::test]
    async fn group_failure_does_not_leak_to_the_next_candidate() {
        // Guard monotonic ids keeping candidates independently probeable.
        let judge = spawn_echo_judge().await;
        let proxy_port = spawn_mock_http_proxy().await;
        let candidates = [
            Proxy::new(std::net::Ipv4Addr::LOCALHOST, 9),
            Proxy::new(std::net::Ipv4Addr::LOCALHOST, proxy_port),
        ];
        let config = Config {
            types: Vec::new(),
            groups: vec![vec![Protocol::Http(Anonymity::Unknown)]],
            http_judge_urls: vec![judge],
            https_judge_urls: vec![],
            ..Config::default()
        };
        let mut validator =
            ProxyValidator::validate(futures_util::stream::iter(candidates), config)
                .await
                .unwrap();
        let progress = validator.progress();
        let winner = validator
            .get_one()
            .await
            .expect("the mock candidate must pass");
        while validator.get_one().await.is_some() {}
        assert_eq!(progress.done(), 2);
        assert_eq!(progress.passed(), 1);
        assert!(winner
            .proxy_types
            .iter()
            .any(|pt| matches!(pt.protocol, Protocol::Http(_))));
    }

    #[tokio::test]
    async fn probe_gate_skips_closed_protocols_without_probing() {
        // Close HTTP from the start: advertised HTTP jobs must count done
        // without touching the judge or emitting output.
        let judge = spawn_echo_judge().await;
        let gate: ProbeGate =
            std::sync::Arc::new(|requested: Protocol| !matches!(requested, Protocol::Http(_)));
        let config = Config {
            types: vec![Protocol::Http(Anonymity::Unknown)],
            http_judge_urls: vec![judge],
            https_judge_urls: vec![],
            probe_gate: Some(gate),
            ..Config::default()
        };
        // Closed ports fail fast if anything is ever probed.
        let candidates = (1u16..=2).map(|port| {
            Proxy::with_expected_types(
                std::net::Ipv4Addr::LOCALHOST,
                port,
                std::sync::Arc::from([Protocol::Http(Anonymity::Unknown)]),
            )
        });
        let mut validator =
            ProxyValidator::validate(futures_util::stream::iter(candidates), config)
                .await
                .unwrap();
        let progress = validator.progress();
        assert!(validator.get_one().await.is_none());
        while validator.get_one().await.is_some() {}
        assert_eq!(progress.total(), 2);
        assert_eq!(progress.done(), 2);
        assert_eq!(progress.passed(), 0);
    }

    /// Spawn mock HTTP proxy echoing the judge token.
    async fn spawn_mock_http_proxy() -> u16 {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 2048];
                    loop {
                        let read = stream.read(&mut chunk).await.unwrap_or(0);
                        if read == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..read]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let text = String::from_utf8_lossy(&buf);
                    let token = text
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("x-fluxy-token")
                                .then(|| value.trim().to_owned())
                        })
                        .unwrap_or_default();
                    let body = format!("HTTP_X_FLUXY_TOKEN = {token}\n");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        port
    }

    use crate::test_support::{spawn_echo_judge, spawn_flaky_echo_judge, spawn_no_echo_judge};
}
