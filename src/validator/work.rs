use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::Context as _;
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
}

pub(crate) struct SingletonJob {
    pub(crate) proxy: Arc<Proxy>,
    pub(crate) protocol: Protocol,
    pub(crate) requested: Protocol,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct GroupKey {
    proxy: usize,
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
        // The judge request performs its own connect and negotiation; avoid a
        // redundant TCP preflight for every HTTP proxy.
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

pub(crate) async fn do_work(
    job: SingletonJob,
    sender: mpsc::Sender<Proxy>,
    counters: ValidationProgress,
    targets: JudgeTargets,
    params: &WorkParams,
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
    if let Some(proxy_type) = result? {
        proxy.proxy_types.push(proxy_type);
        counters
            .passed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _ = sender.send(proxy).await;
    }
    Ok(())
}

pub(crate) struct GroupMemberJob {
    pub(crate) proxy: Arc<Proxy>,
    pub(crate) protocol: Protocol,
    pub(crate) group_idx: usize,
    pub(crate) slot: usize,
    pub(crate) group_len: usize,
}

pub(crate) async fn do_group_work(
    member: GroupMemberJob,
    group_tx: mpsc::Sender<GroupWorkResult>,
    targets: JudgeTargets,
    params: &WorkParams,
) -> anyhow::Result<()> {
    let GroupMemberJob {
        proxy,
        protocol,
        group_idx,
        slot,
        group_len,
    } = member;
    let mut probe = proxy.validation_probe();
    let result = match run_probe(&mut probe, protocol, protocol, &targets, params).await {
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

pub(crate) async fn aggregate_groups(
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
