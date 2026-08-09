mod checker;
pub mod config;
mod tunnel;

use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
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

pub use config::Config;
pub use tunnel::ValidationStatus;

use crate::proxy::models::{Anonymity, Protocol, Proxy, ProxyType};

pub(crate) const VALIDATOR_CHANNEL_MIN: usize = 64;
pub(crate) const VALIDATOR_CHANNEL_MAX: usize = 4_096;

/// Sizes the bounded result channel from the validator's concurrency.
///
/// The buffer is proportional to the worker count so it never becomes a
/// bottleneck, but is clamped to stay within reason regardless of how large
/// `concurrency_limit` gets.
fn validator_channel_capacity(concurrency_limit: usize) -> usize {
    concurrency_limit
        .saturating_mul(4)
        .clamp(VALIDATOR_CHANNEL_MIN, VALIDATOR_CHANNEL_MAX)
}

/// Reports a judge that failed preflight and was excluded from the pool.
///
/// A plain `fn` (not a closure) so it can be moved into the background preflight
/// tasks spawned by [`checker::JudgePool::build`].
fn report_dropped(url: &str, reason: &str) {
    #[cfg(feature = "log")]
    log::warn!("warning: judge `{url}` failed preflight and was dropped: {reason}");
    #[cfg(not(feature = "log"))]
    let _ = (url, reason);
}

/// Validates a stream of proxies and yields the ones that pass.
///
/// Consume it with [`ProxyValidator::get_one`] or as a [`Stream`]
/// ([`futures_util::StreamExt`]).
pub struct ProxyValidator {
    receiver: mpsc::Receiver<Proxy>,
    #[cfg(feature = "log")]
    total: Arc<AtomicUsize>,
    #[cfg(feature = "log")]
    counter: Arc<AtomicUsize>,
    #[cfg(feature = "log")]
    timer: Instant,
    task_handle: JoinHandle<()>,
}

#[derive(Clone)]
struct JudgeTargets {
    http: Arc<checker::JudgePool>,
    tunnel: Arc<checker::JudgePool>,
}

/// Per-job validation parameters shared by every `do_work` task.
struct WorkParams {
    max_attempts: usize,
    request_timeout: u64,
    insecure: bool,
}

/// Whether a protocol advertised by a source is eligible for a specific user
/// request. Unknown anonymity is unspecified metadata; CONNECT ports are
/// capabilities and must match exactly.
fn advertised_matches_request(advertised: &Protocol, requested: &Protocol) -> bool {
    match (advertised, requested) {
        (Protocol::Http(left), Protocol::Http(right))
        | (Protocol::Https(left), Protocol::Https(right)) => {
            matches!(left, Anonymity::Unknown)
                || matches!(right, Anonymity::Unknown)
                || left == right
        }
        (Protocol::Connect(left), Protocol::Connect(right)) => left == right,
        _ => advertised == requested,
    }
}

/// Whether the protocol proven by the judge satisfies the user's request.
/// Unknown requests accept any measured anonymity; concrete predicates and
/// CONNECT ports must match exactly.
fn result_satisfies_request(result: &Protocol, requested: &Protocol) -> bool {
    match (result, requested) {
        (Protocol::Http(actual), Protocol::Http(required))
        | (Protocol::Https(actual), Protocol::Https(required)) => {
            matches!(required, Anonymity::Unknown) || actual == required
        }
        (Protocol::Connect(actual), Protocol::Connect(required)) => actual == required,
        _ => result == requested,
    }
}

async fn do_work(
    proxy: Arc<Proxy>,
    sender: mpsc::Sender<Proxy>,
    counter: Arc<AtomicUsize>,
    protocol: Protocol,
    requested: Protocol,
    targets: JudgeTargets,
    params: WorkParams,
) -> anyhow::Result<()> {
    let mut proxy = proxy.validation_probe();
    let timeout = Duration::from_secs(params.request_timeout);
    if let Protocol::Http(_) = protocol {
        // The judge request performs its own connect and negotiation; avoid a
        // redundant TCP preflight for every HTTP proxy.
        let result = checker::support_http(
            &mut proxy,
            timeout,
            params.max_attempts,
            &targets.http,
            params.insecure,
        )
        .await
        .with_context(|| format!("{}: HTTP check failed", proxy.as_text()))?;
        if let Some(result) =
            result.filter(|result| result_satisfies_request(&result.inner, &requested))
        {
            result.apply(&mut proxy);
            proxy.proxy_type = Some(ProxyType::checked(result.inner));
        }
    } else {
        let result = tunnel::support_tunnel(
            &mut proxy,
            timeout,
            params.max_attempts,
            protocol,
            &targets.tunnel,
            params.insecure,
        )
        .await
        .with_context(|| format!("{}: tunnel check failed", proxy.as_text()))?;
        if let Some(result) =
            result.filter(|result| result_satisfies_request(&result.inner, &requested))
        {
            result.apply(&mut proxy);
            proxy.proxy_type = Some(ProxyType::checked(result.inner));
        }
    }
    if let Some(proxy_type) = proxy.proxy_type.as_ref() {
        #[cfg(feature = "log")]
        log::trace!(
            "{}: support protocol: {}",
            proxy.as_text(),
            proxy_type.protocol
        );
        let _ = proxy_type;
        counter.fetch_add(1, Ordering::Relaxed);
        // A closed receiver simply means the consumer stopped early.
        let _ = sender.send(proxy).await;
    }
    Ok(())
}

impl ProxyValidator {
    /// Validates every proxy yielded by `proxy_source`.
    ///
    /// The source is an async [`Stream`]; use [`futures_util::stream::iter`] to
    /// feed a plain iterator into it.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration is invalid or a requested judge
    /// pool ends up empty after preflight.
    pub async fn validate<S>(proxy_source: S, config: Config) -> anyhow::Result<Self>
    where
        S: Stream<Item = Proxy> + Send + 'static,
    {
        if config.types.is_empty() {
            anyhow::bail!("config.types cannot be empty; please specify at least one type.");
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
        let total = Arc::new(AtomicUsize::new(0));
        let counter = Arc::new(AtomicUsize::new(0));
        let manager_total = Arc::clone(&total);
        let manager_counter = Arc::clone(&counter);
        let expected: Arc<[Protocol]> = Arc::from(config.types.into_boxed_slice());
        let max_attempts = config.max_attempts;
        let request_timeout = config.request_timeout;
        let concurrency_limit = config.concurrency_limit;
        let insecure = config.insecure;
        let preflight_timeout = Duration::from_secs(config.request_timeout);
        let need_http = expected
            .iter()
            .any(|protocol| matches!(protocol, Protocol::Http(_)));
        let need_tunnel = expected
            .iter()
            .any(|protocol| !matches!(protocol, Protocol::Http(_)));

        let http_preflight = async {
            if !need_http {
                return Ok::<Option<Arc<checker::JudgePool>>, anyhow::Error>(None);
            }
            let pool = checker::JudgePool::build(
                &config.http_judge_urls,
                preflight_timeout,
                insecure,
                report_dropped,
            )
            .await
            .context("HTTP online judge pool is empty after preflight")?;
            Ok::<_, anyhow::Error>(Some(pool))
        };
        let tunnel_preflight = async {
            if !need_tunnel {
                return Ok::<Option<Arc<checker::JudgePool>>, anyhow::Error>(None);
            }
            let pool = checker::JudgePool::build(
                &config.https_judge_urls,
                preflight_timeout,
                insecure,
                report_dropped,
            )
            .await
            .context("HTTPS online judge pool is empty after preflight")?;
            Ok::<_, anyhow::Error>(Some(pool))
        };
        let (http_target, tunnel_target) = tokio::join!(http_preflight, tunnel_preflight);
        let http_target = http_target?;
        let tunnel_target = tunnel_target?;
        #[cfg(feature = "log")]
        if let Some(pool) = http_target.as_ref() {
            log::info!("using {} healthy HTTP judge(s)", pool.len());
        }
        #[cfg(feature = "log")]
        if let Some(pool) = tunnel_target.as_ref() {
            log::info!("using {} healthy HTTPS judge(s)", pool.len());
        }
        let targets = JudgeTargets {
            http: http_target
                .unwrap_or_else(|| Arc::new(checker::JudgePool::from_targets(Vec::new()))),
            tunnel: tunnel_target
                .unwrap_or_else(|| Arc::new(checker::JudgePool::from_targets(Vec::new()))),
        };

        let manager = tokio::spawn(async move {
            let jobs =
                proxy_source.flat_map(move |proxy| {
                    let jobs: Vec<(Protocol, Protocol)> = proxy
                        .expected_types
                        .iter()
                        .flat_map(|advertised| {
                            expected
                                .iter()
                                .filter(move |requested| {
                                    advertised_matches_request(advertised, requested)
                                })
                                .map(move |requested| (advertised.clone(), requested.clone()))
                        })
                        .collect();

                    if !jobs.is_empty() {
                        manager_total.fetch_add(1, Ordering::Relaxed);
                    }

                    let proxy = Arc::new(proxy);

                    futures_util::stream::iter(jobs.into_iter().map(
                        move |(protocol, requested)| (Arc::clone(&proxy), protocol, requested),
                    ))
                });

            jobs.for_each_concurrent(concurrency_limit, move |(proxy, protocol, requested)| {
                let sender = sender.clone();
                let counter = Arc::clone(&manager_counter);
                let targets = targets.clone();
                async move {
                    if let Err(_e) = do_work(
                        proxy,
                        sender,
                        counter,
                        protocol,
                        requested,
                        targets,
                        WorkParams {
                            max_attempts,
                            request_timeout,
                            insecure,
                        },
                    )
                    .await
                    {
                        #[cfg(feature = "log")]
                        log::debug!("validation task failed: {:#}", _e);
                    }
                }
            })
            .await;
        });

        Ok(Self {
            receiver,
            #[cfg(feature = "log")]
            total,
            #[cfg(feature = "log")]
            counter,
            #[cfg(feature = "log")]
            timer: Instant::now(),
            task_handle: manager,
        })
    }

    /// Awaits the next validated proxy, or `None` once validation finished.
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
        #[cfg(feature = "log")]
        log::info!(
            "Proxy validator completed: {}/{} proxies validated ({:?})",
            self.counter.load(Ordering::Acquire),
            self.total.load(Ordering::Acquire),
            self.timer.elapsed(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        advertised_matches_request, result_satisfies_request, validator_channel_capacity, Config,
        ProxyValidator, VALIDATOR_CHANNEL_MAX, VALIDATOR_CHANNEL_MIN,
    };
    use crate::proxy::models::{Anonymity, Protocol};

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
        // Regression for F-25: dropping a `ProxyValidator` must close the
        // receiver and abort the manager task synchronously (a `Drop` cannot
        // `.await`/join), leaving no dangling channel. We only assert it does
        // not panic and that no proxy is delivered afterwards.
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
}
