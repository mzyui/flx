//! Shared pipeline plumbing for the CLI and the TUI.
//!
//! Holds the pieces that turn parsed arguments into fetcher/validator
//! configuration and drive the scrape → validate stream, so `run_grab`,
//! `run_find`, and the TUI all agree on behavior.

use std::sync::{Arc, Mutex};

use flx::proxy::models::{Anonymity, Protocol, Proxy};
use futures_util::{Stream, StreamExt};

use crate::argument::{FetcherArgs, ValidatorArgs};
use crate::quotas::QuotaEnforcer;

pub(crate) type BoxStream = std::pin::Pin<Box<dyn Stream<Item = Proxy> + Send>>;

pub(crate) async fn file_source(paths: &[std::path::PathBuf]) -> anyhow::Result<BoxStream> {
    let proxies = flx::load_proxy_files(paths.to_owned()).await?;
    Ok(Box::pin(futures_util::stream::iter(proxies)))
}

pub(crate) fn fetcher_config(options: &FetcherArgs) -> flx::fetcher::Config {
    flx::fetcher::Config {
        concurrency_limit: options.fetch_concurrency,
        enable_geo_lookup: options.with_geo
            || !options.countries.is_empty()
            || !options.exclude_country.is_empty(),
        countries: Arc::from(options.countries.as_slice()),
        excluded_countries: Arc::from(options.exclude_country.as_slice()),
        cache_ttl: (options.cache_ttl > 0)
            .then(|| std::time::Duration::from_secs(options.cache_ttl.saturating_mul(60))),
        refresh_cache: options.refresh_cache,
        enforce_unique_ip: !options.no_dedup,
        providers: Arc::from(options.provider.as_slice()),
        excluded_providers: Arc::from(options.exclude_provider.as_slice()),
        custom_sources: Arc::from(options.source_url.as_slice()),
        offline: options.offline,
        fetch_delay: (options.fetch_delay_ms > 0)
            .then(|| std::time::Duration::from_millis(options.fetch_delay_ms)),
        fallback_threshold: options.fallback_threshold,
        fallback_phase_timeout: (options.fetch_phase_timeout > 0)
            .then(|| std::time::Duration::from_secs(options.fetch_phase_timeout)),
        provider_timeout: (options.provider_timeout > 0)
            .then(|| std::time::Duration::from_secs(options.provider_timeout)),
    }
}

pub(crate) fn validator_config(
    options: &ValidatorArgs,
    protocols: Vec<Protocol>,
    groups: Vec<Vec<Protocol>>,
    probe_missed_types: bool,
) -> flx::validator::Config {
    flx::validator::Config {
        types: protocols,
        groups,
        concurrency_limit: options.max_connections,
        max_attempts: options.max_attempts,
        request_timeout: options.timeout,
        http_judge_urls: options.http_judge_urls.clone(),
        https_judge_urls: options.https_judge_urls.clone(),
        insecure: options.no_verify_tls,
        probe_missed_types,
        support_cookies: options.support_cookies,
        support_referer: options.support_referer,
        retry_delay: std::time::Duration::from_millis(options.retry_delay_ms),
        report_failures: options.report_failures.is_some(),
        probe_gate: None,
    }
}

// Match advertised types tolerating Unknown anonymity sides.
pub(crate) fn advertised_covers_request(advertised: &[Protocol], requested: Protocol) -> bool {
    advertised.iter().any(|adv| match (*adv, requested) {
        (Protocol::Http(a), Protocol::Http(b)) | (Protocol::Https(a), Protocol::Https(b)) => {
            matches!(a, Anonymity::Unknown) || matches!(b, Anonymity::Unknown) || a == b
        }
        (Protocol::Connect(a), Protocol::Connect(b)) => a == b,
        (adv, req) => adv == req,
    })
}

// Probe missed types when advertisements leave gaps.
pub(crate) fn needs_missed_probe(proxy: &Proxy, requested: &[Protocol]) -> bool {
    let advertised = proxy.expected_types.as_ref();
    advertised.is_empty()
        || requested
            .iter()
            .any(|req| !advertised_covers_request(advertised, *req))
}

// Forward candidates while recording fallbacks for replay.
pub(crate) fn tee_recorder<S>(
    inner: S,
    recordings: Arc<std::sync::Mutex<Vec<Proxy>>>,
    requested: Arc<[Protocol]>,
) -> impl Stream<Item = Proxy>
where
    S: Stream<Item = Proxy> + Unpin,
{
    futures_util::stream::unfold(inner, move |mut inner| {
        let recordings = Arc::clone(&recordings);
        let requested = Arc::clone(&requested);
        async move {
            match inner.next().await {
                // Record only fallback candidates worth a deep copy.
                Some(proxy) if needs_missed_probe(&proxy, &requested) => {
                    recordings
                        .lock()
                        .expect("candidate recorder mutex poisoned")
                        .push(proxy.clone());
                    Some((proxy, inner))
                }
                Some(proxy) => Some((proxy, inner)),
                None => None,
            }
        }
    })
}

/// Builds the probe gate that skips families whose quotas are already full.
pub(crate) fn build_probe_gate(
    quota_enforcer: &Arc<Mutex<QuotaEnforcer>>,
) -> Option<flx::ProbeGate> {
    let has_quotas = quota_enforcer
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .has_any_quota();
    has_quotas.then(|| {
        let enforcer = Arc::clone(quota_enforcer);
        Arc::new(move |requested: Protocol| {
            !enforcer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_protocol_closed(requested)
        }) as flx::ProbeGate
    })
}

/// Decides whether a fallback pass is worth running after pass 1.
///
/// Quota runs compare emitted rows (not validated probes) so capped types
/// stop at `=n`.
pub(crate) fn needs_fallback(
    has_quotas: bool,
    quota_enforcer: &Arc<Mutex<QuotaEnforcer>>,
    has_groups: bool,
    may_fallback: bool,
    limit: usize,
    emitted1: usize,
    p1_passed: usize,
) -> bool {
    if has_quotas {
        let enforcer = quota_enforcer.lock().unwrap_or_else(|e| e.into_inner());
        let room = limit == 0 || emitted1 < limit;
        let other_capacity = enforcer.has_uncapped() || has_groups;
        may_fallback && room && (emitted1 == 0 || enforcer.has_unfilled() || other_capacity)
    } else {
        may_fallback && (p1_passed == 0 || (limit > 0 && p1_passed < limit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quotas::TypeQuota;

    fn enforcer(quotas: Vec<TypeQuota>) -> Arc<Mutex<QuotaEnforcer>> {
        Arc::new(Mutex::new(QuotaEnforcer::new(quotas)))
    }

    #[test]
    fn probe_gate_absent_without_quotas() {
        let enforcer = enforcer(vec![TypeQuota::uncapped(Protocol::Socks5)]);
        assert!(build_probe_gate(&enforcer).is_none());
    }

    #[test]
    fn probe_gate_closes_only_filled_families() {
        let enforcer = enforcer(vec![TypeQuota {
            protocol: Protocol::Http(Anonymity::Unknown),
            quota: Some(1),
        }]);
        let gate = build_probe_gate(&enforcer).expect("capped quota builds a gate");
        assert!(
            gate(Protocol::Http(Anonymity::Unknown)),
            "an open cap keeps probing"
        );

        let mut proxy = Proxy::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 8080);
        proxy
            .proxy_types
            .push(flx::proxy::models::ProxyType::checked(Protocol::Http(
                Anonymity::Elite,
            )));
        assert!(enforcer.lock().unwrap().should_emit(&proxy));

        assert!(
            !gate(Protocol::Http(Anonymity::Unknown)),
            "a filled cap stops probing"
        );
        assert!(gate(Protocol::Socks5), "unrelated families still probe");
    }

    #[test]
    fn fallback_without_quotas_waits_for_empty_or_short_pass() {
        let enforcer = enforcer(Vec::new());
        assert!(needs_fallback(false, &enforcer, false, true, 5, 0, 0));
        assert!(needs_fallback(false, &enforcer, false, true, 5, 3, 3));
        assert!(!needs_fallback(false, &enforcer, false, true, 5, 5, 5));
        assert!(!needs_fallback(false, &enforcer, false, false, 0, 0, 0));
        assert!(needs_fallback(false, &enforcer, false, true, 0, 0, 0));
    }

    #[test]
    fn fallback_with_quotas_runs_while_room_remains() {
        let enforcer = enforcer(vec![TypeQuota {
            protocol: Protocol::Http(Anonymity::Unknown),
            quota: Some(2),
        }]);
        assert!(needs_fallback(true, &enforcer, false, true, 0, 0, 0));
        assert!(!needs_fallback(true, &enforcer, false, false, 0, 0, 0));
    }

    #[test]
    fn fallback_quota_run_respects_the_global_limit() {
        let enforcer = enforcer(vec![TypeQuota {
            protocol: Protocol::Http(Anonymity::Unknown),
            quota: Some(2),
        }]);
        assert!(!needs_fallback(true, &enforcer, false, true, 4, 4, 4));
        assert!(needs_fallback(true, &enforcer, false, true, 4, 3, 3));
    }

    #[test]
    fn advertised_coverage_tolerates_unknown_anonymity() {
        let advertised = [Protocol::Http(Anonymity::Unknown)];
        assert!(advertised_covers_request(
            &advertised,
            Protocol::Http(Anonymity::Elite)
        ));
        assert!(!advertised_covers_request(&advertised, Protocol::Socks5));
    }
}
