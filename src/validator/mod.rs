pub mod checker;
pub mod config;
mod tunnel;

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
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

pub use config::{Config, DEFAULT_CONCURRENCY_LIMIT};
pub use tunnel::ValidationStatus;

use crate::proxy::models::{Anonymity, Protocol, Proxy, ProxyType, RuntimeStats};

pub(crate) const VALIDATOR_CHANNEL_MIN: usize = 64;
pub(crate) const VALIDATOR_CHANNEL_MAX: usize = 4_096;

fn validator_channel_capacity(concurrency_limit: usize) -> usize {
    concurrency_limit
        .saturating_mul(4)
        .clamp(VALIDATOR_CHANNEL_MIN, VALIDATOR_CHANNEL_MAX)
}

fn report_dropped(url: &str, reason: &str) {
    #[cfg(feature = "log")]
    log::warn!("warning: judge `{url}` failed preflight and was dropped: {reason}");
    #[cfg(not(feature = "log"))]
    let _ = (url, reason);
}

/// Snapshot of judge preflight results at validator startup.
#[derive(Debug, Clone, Default)]
pub struct JudgeHealthReport {
    pub candidates: usize,
    pub healthy: usize,
    pub failed: Vec<(String, String)>,
}

impl JudgeHealthReport {
    fn merge(&mut self, other: &JudgeHealthReport) {
        self.candidates += other.candidates;
        self.healthy += other.healthy;
        self.failed.extend(other.failed.iter().cloned());
    }
}

/// Validation progress counters.
#[derive(Debug, Clone, Default)]
pub struct ValidationProgress {
    total: Arc<AtomicUsize>,
    done: Arc<AtomicUsize>,
    passed: Arc<AtomicUsize>,
}

impl ValidationProgress {
    pub fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    pub fn done(&self) -> usize {
        self.done.load(Ordering::Relaxed)
    }

    pub fn passed(&self) -> usize {
        self.passed.load(Ordering::Relaxed)
    }

    pub fn remaining(&self) -> usize {
        self.total().saturating_sub(self.done())
    }

    pub fn fraction(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            0.0
        } else {
            self.done() as f64 / total as f64
        }
    }
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
}

#[derive(Clone)]
struct JudgeTargets {
    http: Arc<checker::JudgePool>,
    tunnel: Arc<checker::JudgePool>,
}

struct WorkParams {
    max_attempts: usize,
    request_timeout: u64,
    insecure: bool,
    support_cookies: bool,
    support_referer: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct GroupKey {
    proxy: usize,
    group_idx: usize,
}

struct GroupWorkResult {
    key: GroupKey,
    slot: usize,
    group_len: usize,
    proxy: Option<Proxy>,
}

struct GroupState {
    remaining: usize,
    results: Vec<Option<Proxy>>,
}

fn protocol_matches<F>(a: &Protocol, b: &Protocol, on_http_https: F) -> bool
where
    F: FnOnce(&Anonymity, &Anonymity) -> bool,
{
    match (a, b) {
        (Protocol::Http(left), Protocol::Http(right))
        | (Protocol::Https(left), Protocol::Https(right)) => on_http_https(left, right),
        (Protocol::Connect(left), Protocol::Connect(right)) => left == right,
        _ => a == b,
    }
}

fn advertised_matches_request(advertised: &Protocol, requested: &Protocol) -> bool {
    protocol_matches(advertised, requested, |left, right| {
        matches!(left, Anonymity::Unknown) || matches!(right, Anonymity::Unknown) || left == right
    })
}

fn result_satisfies_request(result: &Protocol, requested: &Protocol) -> bool {
    protocol_matches(result, requested, |actual, required| {
        matches!(required, Anonymity::Unknown) || actual == required
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_probe(
    proxy: &mut Proxy,
    timeout: Duration,
    max_attempts: usize,
    insecure: bool,
    support_cookies: bool,
    support_referer: bool,
    protocol: Protocol,
    requested: Protocol,
    targets: &JudgeTargets,
) -> anyhow::Result<Option<ProxyType>> {
    if let Protocol::Http(_) = protocol {
        // The judge request performs its own connect and negotiation; avoid a
        // redundant TCP preflight for every HTTP proxy.
        let result = checker::support_http(
            proxy,
            timeout,
            max_attempts,
            &targets.http,
            insecure,
            support_cookies,
            support_referer,
        )
        .await
        .with_context(|| format!("{}: HTTP check failed", proxy.as_text()))?;
        if let Some(result) =
            result.filter(|result| result_satisfies_request(&result.inner, &requested))
        {
            result.apply(proxy);
            Ok(Some(ProxyType::checked(result.inner)))
        } else {
            Ok(None)
        }
    } else {
        let result = tunnel::support_tunnel(
            proxy,
            timeout,
            max_attempts,
            protocol,
            &targets.tunnel,
            insecure,
            support_cookies,
            support_referer,
        )
        .await
        .with_context(|| format!("{}: tunnel check failed", proxy.as_text()))?;
        if let Some(result) =
            result.filter(|result| result_satisfies_request(&result.inner, &requested))
        {
            result.apply(proxy);
            Ok(Some(ProxyType::checked(result.inner)))
        } else {
            Ok(None)
        }
    }
}

async fn do_work(
    proxy: Arc<Proxy>,
    sender: mpsc::Sender<Proxy>,
    counters: ValidationProgress,
    protocol: Protocol,
    requested: Protocol,
    targets: JudgeTargets,
    params: WorkParams,
) -> anyhow::Result<()> {
    let mut proxy = proxy.validation_probe();
    let result = run_probe(
        &mut proxy,
        Duration::from_secs(params.request_timeout),
        params.max_attempts,
        params.insecure,
        params.support_cookies,
        params.support_referer,
        protocol,
        requested,
        &targets,
    )
    .await;
    counters.done.fetch_add(1, Ordering::Relaxed);
    if let Some(proxy_type) = result? {
        proxy.proxy_types.push(proxy_type);
        counters.passed.fetch_add(1, Ordering::Relaxed);
        let _ = sender.send(proxy).await;
    }
    Ok(())
}

struct GroupMemberJob {
    proxy: Arc<Proxy>,
    protocol: Protocol,
    group_idx: usize,
    slot: usize,
    group_len: usize,
}

async fn do_group_work(
    member: GroupMemberJob,
    group_tx: mpsc::Sender<GroupWorkResult>,
    targets: JudgeTargets,
    params: WorkParams,
) -> anyhow::Result<()> {
    let GroupMemberJob {
        proxy,
        protocol,
        group_idx,
        slot,
        group_len,
    } = member;
    let mut probe = proxy.validation_probe();
    let result = match run_probe(
        &mut probe,
        Duration::from_secs(params.request_timeout),
        params.max_attempts,
        params.insecure,
        params.support_cookies,
        params.support_referer,
        protocol,
        protocol,
        &targets,
    )
    .await
    {
        Ok(Some(proxy_type)) => {
            probe.proxy_types.push(proxy_type);
            Some(probe)
        }
        Ok(None) | Err(_) => None,
    };
    let _ = group_tx
        .send(GroupWorkResult {
            key: GroupKey {
                proxy: Arc::as_ptr(&proxy) as usize,
                group_idx,
            },
            slot,
            group_len,
            proxy: result,
        })
        .await;
    Ok(())
}

fn group_finish(state: GroupState) -> Option<Proxy> {
    let slots: Vec<Proxy> = if state.results.iter().all(Option::is_some) {
        state.results.into_iter().flatten().collect()
    } else {
        return None;
    };
    let mut merged = slots[0].clone();
    merged.proxy_types = slots
        .iter()
        .filter_map(|proxy| proxy.proxy_types.first().cloned())
        .collect();
    // Combine the per-protocol latencies into one aggregate: each slot carries
    // a single aggregated sample (matching `ProxyRuntimes::apply`), so they
    // merge as one sample per passing protocol.
    merged.runtimes = RuntimeStats::default();
    for slot in &slots {
        let avg = slot.runtimes.avg();
        if avg > 0.0 {
            merged.runtimes.record(avg);
        }
    }
    Some(merged)
}

async fn aggregate_groups(
    mut group_rx: mpsc::Receiver<GroupWorkResult>,
    aggregate_sender: mpsc::Sender<Proxy>,
    aggregate_progress: ValidationProgress,
) {
    let mut states: HashMap<GroupKey, GroupState> = HashMap::new();
    while let Some(msg) = group_rx.recv().await {
        let entry = states.entry(msg.key).or_insert_with(|| GroupState {
            remaining: msg.group_len,
            results: vec![None; msg.group_len],
        });
        entry.results[msg.slot] = msg.proxy;
        entry.remaining -= 1;
        if entry.remaining == 0 {
            let finished = states
                .remove(&msg.key)
                .expect("current group state was pushed above");
            aggregate_progress.done.fetch_add(1, Ordering::Relaxed);
            if let Some(proxy) = group_finish(finished) {
                aggregate_progress.passed.fetch_add(1, Ordering::Relaxed);
                // A closed receiver simply means the consumer stopped early.
                let _ = aggregate_sender.send(proxy).await;
            }
        }
    }
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
        let (http_target, tunnel_target) = tokio::join!(http_preflight, tunnel_preflight);
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
        let group_aggregator = tokio::spawn(aggregate_groups(
            group_rx,
            aggregate_sender,
            aggregate_progress,
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
            let jobs = proxy_source.flat_map(move |proxy: Proxy| {
                let proxy = Arc::new(proxy);
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
                if has_singleton {
                    manager_total.fetch_add(1, Ordering::Relaxed);
                }
                let has_group = !group_spec.is_empty();
                if has_group {
                    manager_total.fetch_add(1, Ordering::Relaxed);
                }

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
                        (0usize, proxy, Arc::clone(&group_spec), Arc::clone(&groups)),
                        |(mut idx, proxy, spec, groups)| async move {
                            if idx >= spec.len() {
                                return None;
                            }
                            let (group_idx, slot, protocol) = spec[idx];
                            idx += 1;
                            let group_len = groups[group_idx].len();
                            Some((
                                Job::GroupMember {
                                    proxy: Arc::clone(&proxy),
                                    protocol,
                                    group_idx,
                                    slot,
                                    group_len,
                                },
                                (idx, proxy, spec, groups),
                            ))
                        },
                    ))
                } else {
                    Box::pin(futures_util::stream::empty())
                };

                singleton.chain(group)
            });

            let worker_group_tx = group_tx.clone();
            jobs.for_each_concurrent(concurrency_limit, move |job| {
                let sender = sender.clone();
                let counters = worker_counters.clone();
                let targets = targets.clone();
                let group_tx = worker_group_tx.clone();
                let params = WorkParams {
                    max_attempts,
                    request_timeout,
                    insecure,
                    support_cookies,
                    support_referer,
                };
                async move {
                    match job {
                        Job::Singleton {
                            proxy,
                            protocol,
                            requested,
                        } => {
                            if let Err(_e) = do_work(
                                proxy, sender, counters, protocol, requested, targets, params,
                            )
                            .await
                            {
                                #[cfg(feature = "log")]
                                log::debug!("validation task failed: {:#}", _e);
                            }
                        }
                        Job::GroupMember {
                            proxy,
                            protocol,
                            group_idx,
                            slot,
                            group_len,
                        } => {
                            if let Err(_e) = do_group_work(
                                GroupMemberJob {
                                    proxy,
                                    protocol,
                                    group_idx,
                                    slot,
                                    group_len,
                                },
                                group_tx,
                                targets,
                                params,
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
        })
    }

    /// Judge preflight results collected while the validator started.
    pub fn judge_health(&self) -> &JudgeHealthReport {
        &self.judge_health
    }

    pub fn progress(&self) -> ValidationProgress {
        self.progress.clone()
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

    /// Spawns a plain-HTTP judge that echoes the `X-Fluxy-Token` header, enough
    /// to pass the startup preflight without touching the network.
    async fn spawn_echo_judge() -> String {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                serve_echo_judge(stream).await;
            }
        });
        format!("http://{address}/azenv.php")
    }

    // Spawns a judge that drops the first connection and echoes the token on
    // the second, so the preflight retry is exercised without the network.
    async fn spawn_flaky_echo_judge() -> String {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
            if let Ok((stream, _)) = listener.accept().await {
                serve_echo_judge(stream).await;
            }
        });
        format!("http://{address}/azenv.php")
    }

    // Spawns a judge that answers 200 without echoing the request token, so
    // its preflight fails with a "did not echo" reason.
    async fn spawn_no_echo_judge() -> String {
        use tokio::io::AsyncReadExt as _;
        use tokio::io::AsyncWriteExt as _;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nno echo",
                    )
                    .await;
            }
        });
        format!("http://{address}/azenv.php")
    }

    async fn serve_echo_judge(mut stream: tokio::net::TcpStream) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut buf = [0u8; 4096];
        let mut received = Vec::new();
        loop {
            let n = match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            received.extend_from_slice(&buf[..n]);
            if received.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let mut token = String::new();
        for line in received.split(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(line);
            let (name, value) = line.split_once(':').unwrap_or(("", ""));
            if name.trim().eq_ignore_ascii_case("x-fluxy-token") {
                token = value.trim().to_owned();
                break;
            }
        }
        let body = format!("HTTP_X_FLUXY_TOKEN = {token}");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes()).await;
    }
}
