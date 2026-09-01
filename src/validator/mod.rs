pub mod checker;
pub mod config;
mod progress;
mod tunnel;
mod work;

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
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
use tokio::{sync::mpsc, task::JoinHandle};

pub use config::{
    Config, DEFAULT_CONCURRENCY_LIMIT, DEFAULT_HTTPS_JUDGE_URLS, DEFAULT_HTTP_JUDGE_URLS,
};
pub use progress::{JudgeHealthReport, ValidationProgress};
pub use tunnel::ValidationStatus;
pub use work::ProxyFailure;
use work::{
    advertised_matches_request, aggregate_groups, do_group_work, do_work, GroupMemberJob,
    GroupWorkResult, SingletonJob, WorkParams,
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

/// Validates proxy candidates against online judges.
pub struct ProxyValidator {
    receiver: mpsc::Receiver<Proxy>,
    progress: ValidationProgress,
    judge_health: JudgeHealthReport,
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

// Reuses a verified judge pool across passes of one run (a `find` fallback
// pass repeats `validate`, which would otherwise re-run the online preflight).
// A strong ref with a short TTL lets pass-2 reuse pass-1's pool without
// unbounded growth in long-lived processes.
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

// Builds a judge pool, retrying the whole preflight once after a short delay
// so a transient network blip cannot abort the run. Returns the pool plus a
// snapshot of which candidate judges passed or failed preflight.
async fn preflight_pool(
    urls: &[String],
    timeout: Duration,
    insecure: bool,
) -> anyhow::Result<(Arc<checker::JudgePool>, JudgeHealthReport)> {
    const PREFLIGHT_RETRIES: usize = 1;
    const PREFLIGHT_RETRY_DELAY: Duration = Duration::from_secs(1);
    if let Some(pool) = cached_judge_pool(urls, insecure) {
        // Report real numbers so pass-2 does not print a misleading empty
        // health report; no candidate failed again since none re-ran.
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
                // `build` returns as soon as the first judge passes, so the
                // remaining preflights settle in the background; snapshot the
                // report once every candidate has resolved or a short grace
                // elapses. The cap keeps one slow straggler judge from holding
                // up validation startup for the whole preflight timeout; the
                // pool (not the report) stays authoritative either way.
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
    /// Validates every proxy yielded by the source stream.
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
        let manager_total = Arc::clone(&progress.total);
        let manager_done = Arc::clone(&progress.done);
        let manager_passed = Arc::clone(&progress.passed);
        let expected: Arc<[Protocol]> = Arc::from(config.types.into_boxed_slice());
        // Deduplicate protocols inside each AND group so a duplicated member
        // can never double-probe the same slot or emit a duplicate record.
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
        // Flatten all groups once, so job expansion only clones the shared
        // spec (no per-proxy allocation).
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

        // Buffer the proxy source while judge preflights run so the fetcher
        // never stalls on a full channel. The buffer drains into the manager
        // stream as soon as preflights complete, preserving backpressure after.
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
        // Warm the public-IP cache in parallel with judge preflights so the
        // first probe does not pay a cold lookup inline on its deadline.
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

        // AND-group aggregator: correlates the per-protocol probes of each
        // proxy+group and only forwards to the public channel once every slot
        // reported. Any missing/failed slot drops the whole group. Runs
        // concurrently so multi-type results stream out as they complete.
        let aggregate_sender = sender.clone();
        let aggregate_progress = progress.clone();
        // Shared by group workers so a failed member short-circuits its
        // siblings; entries are evicted by the aggregator once a group
        // completes.
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

            // Shared by the worker tasks (`for_each_concurrent`). The `total`
            // increment happens inside the `flat_map` closure below, which moves
            // `manager_total`, so give the workers their own clone up front.
            let worker_counters = ValidationProgress {
                total: Arc::clone(&manager_total),
                done: Arc::clone(&manager_done),
                passed: Arc::clone(&manager_passed),
            };

            // Expand each proxy into its singleton jobs (advertised-gated, OR
            // semantics) plus its AND-group jobs (every member always probed).
            // Monotonic per-run proxy identity for AND-group bookkeeping; an
            // address would be unsafe because the allocator can hand a freed
            // slot to a different proxy mid-run.
            let next_proxy_id = AtomicU64::new(0);
            // `total` must use the same unit as `done`/`passed`: one per
            // singleton job and one per (proxy, group), counted as jobs are
            // emitted below.
            let stream_total = Arc::clone(&manager_total);
            let jobs = proxy_source.flat_map(move |proxy: Proxy| {
                let proxy = Arc::new(proxy);
                let proxy_id = next_proxy_id.fetch_add(1, Ordering::Relaxed);
                let advertised = Arc::clone(&proxy.expected_types);
                let has_singleton = if probe_missed {
                    // Requested types the advertised set does not cover (or
                    // every requested type when nothing is advertised).
                    expected.iter().any(|requested| {
                        advertised.is_empty()
                            || !advertised
                                .iter()
                                .any(|adv| advertised_matches_request(adv, requested))
                    })
                } else {
                    advertised.iter().any(|advertised| {
                        expected
                            .iter()
                            .any(|requested| advertised_matches_request(advertised, requested))
                    })
                };
                let has_group = !group_spec.is_empty();

                // Singleton path, allocation-free: no `Vec` is built per proxy,
                // `Protocol` is `Copy`, and both the advertised and requested
                // lists are deduplicated so a duplicated entry can never yield
                // a duplicate probe job.
                let singleton: futures_util::stream::BoxStream<'static, Job> = if has_singleton {
                    if probe_missed {
                        Box::pin(futures_util::stream::unfold(
                            (
                                proxy.clone(),
                                Arc::clone(&expected),
                                Arc::clone(&advertised),
                                0usize,
                            ),
                            |(proxy, requested, advertised, mut req_idx)| async move {
                                loop {
                                    if req_idx >= requested.len() {
                                        return None;
                                    }
                                    let req = &requested[req_idx];
                                    let is_new =
                                        !requested[..req_idx].iter().any(|seen| seen == req);
                                    req_idx += 1;
                                    let covered = advertised
                                        .iter()
                                        .any(|adv| advertised_matches_request(adv, req));
                                    if is_new && !covered {
                                        return Some((
                                            Job::Singleton {
                                                proxy: Arc::clone(&proxy),
                                                protocol: *req,
                                                requested: *req,
                                            },
                                            (proxy, requested, advertised, req_idx),
                                        ));
                                    }
                                }
                            },
                        ))
                    } else {
                        let state = (
                            proxy.clone(),
                            advertised,
                            Arc::clone(&expected),
                            0usize,
                            0usize,
                        );
                        Box::pin(futures_util::stream::unfold(
                            state,
                            |(proxy, advertised, requested, mut adv_idx, mut req_idx)| async move {
                                loop {
                                    if adv_idx >= advertised.len() {
                                        return None;
                                    }
                                    let adv = &advertised[adv_idx];
                                    if advertised[..adv_idx].iter().any(|seen| seen == adv) {
                                        adv_idx += 1;
                                        req_idx = 0;
                                        continue;
                                    }
                                    while req_idx < requested.len() {
                                        let req = &requested[req_idx];
                                        let requested_is_new =
                                            !requested[..req_idx].iter().any(|seen| seen == req);
                                        req_idx += 1;
                                        if requested_is_new && advertised_matches_request(adv, req)
                                        {
                                            return Some((
                                                Job::Singleton {
                                                    proxy: Arc::clone(&proxy),
                                                    protocol: *adv,
                                                    requested: *req,
                                                },
                                                (proxy, advertised, requested, adv_idx, req_idx),
                                            ));
                                        }
                                    }
                                    adv_idx += 1;
                                    req_idx = 0;
                                }
                            },
                        ))
                    }
                } else {
                    Box::pin(futures_util::stream::empty())
                };

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
                        // A group is one unit of work regardless of member
                        // count; slot 0 is emitted exactly once per group.
                        Job::GroupMember { slot, .. } if *slot == 0 => {
                            stream_total.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                })
            });

            let worker_group_tx = group_tx.clone();
            let worker_failures = failure_tx.clone();
            jobs.for_each_concurrent(concurrency_limit, move |job| {
                let sender = sender.clone();
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
                    match job {
                        Job::Singleton {
                            proxy,
                            protocol,
                            requested,
                        } => {
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
            #[cfg(feature = "log")]
            timer: Instant::now(),
            task_handle: manager,
            group_task: group_aggregator,
            failures: failure_rx,
        })
    }

    /// Judge preflight results collected while the validator started.
    pub fn judge_health(&self) -> &JudgeHealthReport {
        &self.judge_health
    }

    pub fn progress(&self) -> ValidationProgress {
        self.progress.clone()
    }

    /// Takes the receiver for machine-readable probe failures, when enabled.
    pub fn take_failures(&mut self) -> Option<mpsc::Receiver<work::ProxyFailure>> {
        self.failures.take()
    }

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
    use super::{
        advertised_matches_request, group_finish, result_satisfies_request,
        validator_channel_capacity, Config, GroupState, ProxyValidator, VALIDATOR_CHANNEL_MAX,
        VALIDATOR_CHANNEL_MIN,
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
        // Regression test: dropping a `ProxyValidator` closes the receiver and
        // aborts the manager task synchronously without panicking.
        let config = Config {
            types: vec![Protocol::Socks5],
            ..Config::default()
        };
        let validator = ProxyValidator::validate(futures_util::stream::empty(), config)
            .await
            .unwrap();
        drop(validator);
        // If the channel were still open, poll_next would just pending; the
        // key property is that Drop runs synchronously and never panics.
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
        // Offline-safe: the judge echoes the token during preflight, while
        // every candidate points at a closed local port, so each probe fails
        // fast with a classified reason.
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
        // Offline-safe: a local judge echoes the request token for the
        // preflight, while every candidate points at a closed local port, so
        // each probe fails fast. Done and total must still advance even when
        // nothing passes.
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
        // Offline-safe: the judge drops the first connection and echoes the
        // token on the second, so preflight must retry once to pass.
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
        // Offline-safe: candidates advertise `Socks5` while `Http(Unknown)`
        // is requested, so the missed HTTP probe runs on each candidate
        // (closed local ports make every probe fail fast).
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
        // Offline-safe: an advertised `Http` proxy is not probed again for a
        // requested `Http` type when `probe_missed_types` is on.
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
        // Offline-safe: two advertised HTTP variants each satisfy the single
        // requested type, so every candidate emits two singleton jobs. `total`
        // must count jobs (two per proxy) exactly like `done` does — counting
        // per proxy would let done/pass outrun total on multi-type runs.
        let judge = spawn_echo_judge().await;
        let candidates = (1u16..=2).map(|port| {
            Proxy::with_expected_types(
                std::net::Ipv4Addr::LOCALHOST,
                port,
                std::sync::Arc::from([
                    Protocol::Http(Anonymity::Anonymous),
                    Protocol::Http(Anonymity::Unknown),
                ]),
            )
        });
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
        assert_eq!(progress.total(), 4);
        assert_eq!(progress.done(), 4);
        assert!(progress.fraction() <= 1.0);
    }

    #[tokio::test]
    async fn group_failure_does_not_leak_to_the_next_candidate() {
        // Offline-safe: the first AND-group candidate fails fast against a
        // closed port; the second is backed by a mock HTTP proxy and must
        // still be probed. Address-derived group keys could inherit the dead
        // flag of the first candidate when the allocator reuses its slot;
        // monotonic ids keep every candidate independently probeable.
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

    /// Spawns a minimal HTTP forward proxy: it answers every request with a
    /// 200 whose body echoes the incoming `X-Fluxy-Token` header, which is
    /// exactly the marker the judge check requires.
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

    // Judge fixtures live in the shared `crate::test_support` module.
    use crate::test_support::{spawn_echo_judge, spawn_flaky_echo_judge, spawn_no_echo_judge};
}
