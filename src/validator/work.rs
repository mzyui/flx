use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use anyhow::Context as _;
use serde::Serialize;
use tokio::sync::mpsc;

use super::progress::ValidationProgress;
use super::{checker, tunnel, JudgeTargets};
use crate::proxy::models::{Anonymity, Protocol, Proxy, ProxyType, RuntimeStats};

pub(crate) struct WorkParams {
    pub(crate) max_attempts: usize,
    pub(crate) request_timeout: Duration,
    pub(crate) insecure: bool,
    pub(crate) support_cookies: bool,
    pub(crate) support_referer: bool,
    pub(crate) retry_delay: Duration,
}

/// Record proxy failing validation in machine-readable form.
///
/// Emitted on the failure channel when [`Config::report_failures`](crate::validator::Config::report_failures)
/// is enabled; the `reason` is `"unsatisfied"`, `"group-dead"`, or a classified error string.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyFailure {
    /// IPv4 address of the failed candidate.
    pub ip: std::net::Ipv4Addr,
    /// Port of the failed candidate.
    pub port: u16,
    /// Protocol that was probed when the failure occurred.
    pub protocol: Protocol,
    /// Machine-readable failure cause (e.g. `"timeout"`, `"rejected"`, `"unsatisfied"`).
    pub reason: String,
}

pub(crate) struct SingletonJob {
    pub(crate) proxy: Arc<Proxy>,
    pub(crate) protocol: Protocol,
    pub(crate) requested: Protocol,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct GroupKey {
    proxy_id: u64,
    group_idx: usize,
}

pub(crate) struct GroupWorkResult {
    key: GroupKey,
    slot: usize,
    group_len: usize,
    proxy: Option<Proxy>,
}

pub(crate) struct GroupState {
    pub(crate) remaining: usize,
    pub(crate) results: Vec<Option<Proxy>>,
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

pub(crate) fn advertised_matches_request(advertised: &Protocol, requested: &Protocol) -> bool {
    protocol_matches(advertised, requested, |left, right| {
        matches!(left, Anonymity::Unknown) || matches!(right, Anonymity::Unknown) || left == right
    })
}

/// Identity of an actual probe.
///
/// HTTP(S) anonymity is *measured* by the probe, never used to perform it, so
/// it is erased here; Socks/Connect variants keep their exact shape. Two jobs
/// with the same probe family and requested level probe identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ProbeFamily {
    Http,
    Https,
    Socks4,
    Socks5,
    Connect(u16),
}

pub(crate) fn probe_family(protocol: &Protocol) -> ProbeFamily {
    match protocol {
        Protocol::Http(_) => ProbeFamily::Http,
        Protocol::Https(_) => ProbeFamily::Https,
        Protocol::Socks4 => ProbeFamily::Socks4,
        Protocol::Socks5 => ProbeFamily::Socks5,
        Protocol::Connect(port) => ProbeFamily::Connect(*port),
    }
}

/// Builds the unique `(probe protocol, requested protocol)` pairs for one proxy.
///
/// HTTP(S) anonymity is measured by the probe, so advertised levels of the same
/// family collapse into a single probe; the requested level stays exact. With
/// `probe_missed`, only requested types the advertisement does not cover are
/// probed (every request when nothing is advertised).
pub(crate) fn singleton_jobs(
    advertised: &[Protocol],
    requested: &[Protocol],
    probe_missed: bool,
) -> Vec<(Protocol, Protocol)> {
    if probe_missed {
        let mut seen: Vec<Protocol> = Vec::with_capacity(requested.len());
        let mut jobs = Vec::new();
        for requested in requested {
            if seen.contains(requested) {
                continue;
            }
            seen.push(*requested);
            let covered = advertised
                .iter()
                .any(|adv| advertised_matches_request(adv, requested));
            if !covered {
                jobs.push((*requested, *requested));
            }
        }
        jobs
    } else {
        let mut seen_keys: HashSet<(ProbeFamily, Protocol)> = HashSet::new();
        let mut seen_adv: Vec<Protocol> = Vec::with_capacity(advertised.len());
        let mut jobs = Vec::new();
        for adv in advertised {
            if seen_adv.contains(adv) {
                continue;
            }
            seen_adv.push(*adv);
            let mut seen_req: Vec<Protocol> = Vec::with_capacity(requested.len());
            for req in requested {
                if seen_req.contains(req) {
                    continue;
                }
                seen_req.push(*req);
                if !advertised_matches_request(adv, req) {
                    continue;
                }
                if seen_keys.insert((probe_family(adv), *req)) {
                    jobs.push((*adv, *req));
                }
            }
        }
        jobs
    }
}

pub(crate) fn result_satisfies_request(result: &Protocol, requested: &Protocol) -> bool {
    protocol_matches(result, requested, |actual, required| {
        matches!(required, Anonymity::Unknown) || actual == required
    })
}

async fn run_probe(
    proxy: &mut Proxy,
    protocol: Protocol,
    requested: Protocol,
    targets: &JudgeTargets,
    params: &WorkParams,
) -> anyhow::Result<Option<ProxyType>> {
    if let Protocol::Http(_) = protocol {
        let result = checker::support_http(proxy, &targets.http, params)
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
        let result = tunnel::support_tunnel(proxy, protocol, &targets.tunnel, params)
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

fn classify_failure(error: &anyhow::Error, protocol: Protocol) -> String {
    let text = format!("{error:#}").to_ascii_lowercase();
    if text.contains("timed out") {
        "timeout".to_owned()
    } else if text.contains("did not originate")
        || text.contains("returned status")
        || text.contains("rejected request")
        || text.contains("did not accept")
        || text.contains("did not forward")
    {
        "rejected".to_owned()
    } else {
        format!("error ({protocol}): {text}")
    }
}

fn report_failure(
    sender: &Option<mpsc::Sender<ProxyFailure>>,
    proxy: &Proxy,
    protocol: Protocol,
    reason: String,
) {
    if let Some(sender) = sender {
        let _ = sender.try_send(ProxyFailure {
            ip: proxy.ip,
            port: proxy.port,
            protocol,
            reason,
        });
    }
}

pub(crate) async fn do_work(
    job: SingletonJob,
    sender: mpsc::Sender<Proxy>,
    counters: ValidationProgress,
    targets: JudgeTargets,
    params: &WorkParams,
    failures: Option<mpsc::Sender<ProxyFailure>>,
) -> anyhow::Result<()> {
    let SingletonJob {
        proxy,
        protocol,
        requested,
    } = job;
    let mut proxy = proxy.validation_probe();
    let result = run_probe(&mut proxy, protocol, requested, &targets, params).await;
    counters
        .done
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    match result {
        Ok(Some(proxy_type)) => {
            proxy.proxy_types.push(proxy_type);
            counters
                .passed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = sender.send(proxy).await;
        }
        Ok(None) => report_failure(&failures, &proxy, protocol, "unsatisfied".to_owned()),
        Err(error) => report_failure(
            &failures,
            &proxy,
            protocol,
            classify_failure(&error, protocol),
        ),
    }
    Ok(())
}

pub(crate) struct GroupMemberJob {
    pub(crate) proxy: Arc<Proxy>,
    pub(crate) proxy_id: u64,
    pub(crate) protocol: Protocol,
    pub(crate) group_idx: usize,
    pub(crate) slot: usize,
    pub(crate) group_len: usize,
}

pub(crate) type GroupDeadMap = Arc<Mutex<HashMap<GroupKey, Arc<AtomicBool>>>>;

pub(crate) async fn do_group_work(
    member: GroupMemberJob,
    group_tx: mpsc::Sender<GroupWorkResult>,
    targets: JudgeTargets,
    params: &WorkParams,
    failures: Option<mpsc::Sender<ProxyFailure>>,
    dead_map: Option<GroupDeadMap>,
) -> anyhow::Result<()> {
    let GroupMemberJob {
        proxy,
        proxy_id,
        protocol,
        group_idx,
        slot,
        group_len,
    } = member;
    let key = GroupKey {
        proxy_id,
        group_idx,
    };
    if let Some(map) = dead_map.as_ref() {
        let dead = {
            let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
            guard
                .entry(key)
                .or_insert_with(|| Arc::new(AtomicBool::new(false)))
                .clone()
        };
        if dead.load(Ordering::Relaxed) {
            let probe = proxy.validation_probe();
            report_failure(&failures, &probe, protocol, "group-dead".to_owned());
            let _ = group_tx
                .send(GroupWorkResult {
                    key,
                    slot,
                    group_len,
                    proxy: None,
                })
                .await;
            return Ok(());
        }
    }
    let mut probe = proxy.validation_probe();
    let result = match run_probe(&mut probe, protocol, protocol, &targets, params).await {
        Ok(Some(proxy_type)) => {
            probe.proxy_types.push(proxy_type);
            Some(probe)
        }
        Ok(None) => {
            report_failure(&failures, &probe, protocol, "unsatisfied".to_owned());
            None
        }
        Err(error) => {
            report_failure(
                &failures,
                &probe,
                protocol,
                classify_failure(&error, protocol),
            );
            None
        }
    };
    if result.is_none() {
        if let Some(map) = dead_map.as_ref() {
            if let Some(dead) = map.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
                dead.store(true, Ordering::Relaxed);
            }
        }
    }
    let _ = group_tx
        .send(GroupWorkResult {
            key,
            slot,
            group_len,
            proxy: result,
        })
        .await;
    Ok(())
}

pub(crate) fn group_finish(state: GroupState) -> Option<Proxy> {
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
    merged.runtimes = RuntimeStats::default();
    for slot in &slots {
        let avg = slot.runtimes.avg();
        if avg > 0.0 {
            merged.runtimes.record(avg);
        }
    }
    Some(merged)
}

pub(crate) async fn aggregate_groups(
    mut group_rx: mpsc::Receiver<GroupWorkResult>,
    aggregate_sender: mpsc::Sender<Proxy>,
    aggregate_progress: ValidationProgress,
    dead_map: Option<GroupDeadMap>,
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
            if let Some(map) = dead_map.as_ref() {
                map.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&msg.key);
            }
            aggregate_progress
                .done
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Some(proxy) = group_finish(finished) {
                aggregate_progress
                    .passed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let _ = aggregate_sender.send(proxy).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_params() -> WorkParams {
        WorkParams {
            max_attempts: 1,
            request_timeout: Duration::from_millis(50),
            insecure: true,
            support_cookies: false,
            support_referer: false,
            retry_delay: Duration::ZERO,
        }
    }

    fn group_job(proxy_id: u64) -> GroupMemberJob {
        GroupMemberJob {
            proxy: Arc::new(Proxy::new(Ipv4Addr::LOCALHOST, 9)),
            proxy_id,
            protocol: Protocol::Http(Anonymity::Unknown),
            group_idx: 0,
            slot: 0,
            group_len: 1,
        }
    }

    fn empty_targets() -> JudgeTargets {
        JudgeTargets {
            http: Arc::new(checker::JudgePool::from_targets(Vec::new())),
            tunnel: Arc::new(checker::JudgePool::from_targets(Vec::new())),
        }
    }

    #[tokio::test]
    async fn failing_member_marks_only_its_own_key_dead() {
        let dead_map: GroupDeadMap = Arc::default();
        let (group_tx, mut group_rx) = mpsc::channel(8);
        do_group_work(
            group_job(1),
            group_tx,
            empty_targets(),
            &test_params(),
            None,
            Some(Arc::clone(&dead_map)),
        )
        .await
        .unwrap();
        let result = group_rx.recv().await.unwrap();
        assert!(result.proxy.is_none());
        let guard = dead_map.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(guard.len(), 1);
        assert!(guard.values().all(|flag| flag.load(Ordering::Relaxed)));
    }

    #[tokio::test]
    async fn aggregate_groups_evicts_dead_flags_when_a_group_completes() {
        let dead_map: GroupDeadMap = Arc::default();
        let key = GroupKey {
            proxy_id: 7,
            group_idx: 0,
        };
        dead_map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, Arc::new(AtomicBool::new(true)));

        let (group_tx, group_rx) = mpsc::channel(8);
        let (pass_tx, mut pass_rx) = mpsc::channel(8);
        let aggregator = tokio::spawn(aggregate_groups(
            group_rx,
            pass_tx,
            ValidationProgress::default(),
            Some(Arc::clone(&dead_map)),
        ));
        group_tx
            .send(GroupWorkResult {
                key,
                slot: 0,
                group_len: 1,
                proxy: None,
            })
            .await
            .unwrap();
        drop(group_tx);
        assert!(pass_rx.recv().await.is_none());
        aggregator.await.unwrap();
        assert!(
            dead_map
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "a completed group's dead flag must be evicted"
        );
    }

    #[test]
    fn duplicate_http_families_collapse_to_one_probe() {
        let advertised = [
            Protocol::Http(Anonymity::Anonymous),
            Protocol::Http(Anonymity::Unknown),
        ];
        let requested = [Protocol::Http(Anonymity::Unknown)];

        let jobs = singleton_jobs(&advertised, &requested, false);

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].1, Protocol::Http(Anonymity::Unknown));
        assert_eq!(probe_family(&jobs[0].0), ProbeFamily::Http);
    }

    #[test]
    fn distinct_families_produce_one_job_each() {
        let advertised = [Protocol::Http(Anonymity::Unknown), Protocol::Socks5];
        let requested = [Protocol::Http(Anonymity::Unknown), Protocol::Socks5];

        let jobs = singleton_jobs(&advertised, &requested, false);

        assert_eq!(jobs.len(), 2);
    }

    #[test]
    fn probe_missed_skips_covered_requests() {
        let advertised = [Protocol::Http(Anonymity::Unknown)];
        let requested = [Protocol::Http(Anonymity::Unknown), Protocol::Socks5];

        let jobs = singleton_jobs(&advertised, &requested, true);

        assert_eq!(jobs, vec![(Protocol::Socks5, Protocol::Socks5)]);
    }

    #[test]
    fn probe_family_ignores_http_anonymity_but_keeps_connect_port() {
        assert_eq!(
            probe_family(&Protocol::Http(Anonymity::Elite)),
            probe_family(&Protocol::Http(Anonymity::Unknown))
        );
        assert_ne!(
            probe_family(&Protocol::Connect(80)),
            probe_family(&Protocol::Connect(443))
        );
    }
}
