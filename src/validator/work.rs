use std::{
    collections::HashMap,
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
#[derive(Debug, Clone, Serialize)]
pub struct ProxyFailure {
    pub ip: std::net::Ipv4Addr,
    pub port: u16,
    pub protocol: Protocol,
    pub reason: String,
}

pub(crate) struct SingletonJob {
    pub(crate) proxy: Arc<Proxy>,
    pub(crate) protocol: Protocol,
    pub(crate) requested: Protocol,
}

// Key groups by monotonic proxy id, never reused addresses.
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
        // Skip TCP preflight; judge request already connects and negotiates.
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
            // Skip probe; sibling failure already doomed the group.
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
    // Merge per-protocol latencies as one sample per passing slot.
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
            // Evict dead flag once every member has reported.
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
                // A closed receiver simply means the consumer stopped early.
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
        // Guard dead flag scoping to its own proxy key.
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
        // Guard dead-flag eviction on completed groups.
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
}
