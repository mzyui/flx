mod checker;
mod config;

use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::Context as _;
use futures_util::{Stream, StreamExt};
use tokio::{
    sync::{mpsc, Semaphore},
    time::Instant,
};

pub use config::Config;

use crate::{
    fetcher::CHANNEL_CAPACITY,
    proxy::{
        client::ProxyClient,
        models::{Protocol, Proxy, ProxyType},
    },
    resolver::my_ip,
};

pub struct ProxyValidator {
    receiver: mpsc::Receiver<Proxy>,
    total: Arc<AtomicUsize>,
    counter: Arc<AtomicUsize>,
    timer: Instant,
    is_finished: Arc<AtomicBool>,
}

async fn do_work(
    mut proxy: Proxy,
    sender: mpsc::Sender<Proxy>,
    counter: Arc<AtomicUsize>,
    protocol: Protocol,
    max_attempts: usize,
    timeout: u64,
) -> anyhow::Result<()> {
    let timeout = Duration::from_secs(timeout);
    let tcp = match proxy.connect_timeout(timeout).await {
        Ok(tcp) => tcp,
        Err(_e) => {
            // Unreachable proxies are the common case, not a program error.
            #[cfg(feature = "log")]
            log::trace!("{}: tcp connect failed: {:#}", proxy.as_text(), _e);
            return Ok(());
        }
    };
    tcp.apply(&mut proxy);

    if let Protocol::Http(_) = protocol {
        let result = checker::support_http(&mut proxy, timeout, max_attempts)
            .await
            .with_context(|| format!("{}: HTTP check failed", proxy.as_text()))?;
        if let Some(result) = result {
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
    pub async fn validate<S>(proxy_source: S, config: Config) -> anyhow::Result<Self>
    where
        S: Stream<Item = Proxy> + Send + 'static,
    {
        if config.types.is_empty() {
            anyhow::bail!("config.types cannot be empty; please specify at least one type.");
        }

        #[cfg(feature = "log")]
        log::debug!(
            "Proxy validator started ({} workers)",
            config.concurrency_limit
        );

        my_ip().await.context(
            "failed to determine our public IP; validation requires it to grade proxy anonymity",
        )?;

        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
        let validator = Self {
            receiver,
            total: Arc::new(AtomicUsize::new(0)),
            counter: Arc::new(AtomicUsize::new(0)),
            timer: Instant::now(),
            is_finished: Arc::new(AtomicBool::new(false)),
        };

        let counter = Arc::clone(&validator.counter);
        let total = Arc::clone(&validator.total);
        let is_finished = Arc::clone(&validator.is_finished);
        tokio::spawn(async move {
            let sem = Arc::new(Semaphore::new(config.concurrency_limit));
            let expected: Arc<[Protocol]> = Arc::from(config.types.into_boxed_slice());
            tokio::pin!(proxy_source);

            while let Some(mut proxy) = proxy_source.next().await {
                if is_finished.load(Ordering::Relaxed) {
                    break;
                }

                let mut added = false;
                while let Some(protocol) = proxy.expected_types.pop() {
                    if expected
                        .iter()
                        .any(|right_proto| match (&protocol, right_proto) {
                            (Protocol::Http(_), Protocol::Http(_))
                            | (Protocol::Connect(_), Protocol::Connect(_)) => true,
                            _ => protocol == *right_proto,
                        })
                    {
                        if !added {
                            total.fetch_add(1, Ordering::Relaxed);
                            added = true;
                        }

                        // Acquire the permit *before* spawning so the number of
                        // in-flight tasks stays bounded (backpressure).
                        let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
                            // Semaphore closed: validator is shutting down.
                            return;
                        };

                        let sender = sender.clone();
                        let counter = Arc::clone(&counter);
                        let max_attempts = config.max_attempts;
                        let timeout = config.request_timeout;
                        let proxy = proxy.clone();

                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(_e) =
                                do_work(proxy, sender, counter, protocol, max_attempts, timeout)
                                    .await
                            {
                                #[cfg(feature = "log")]
                                log::debug!("validation task failed: {:#}", _e);
                            }
                        });
                    }
                }
            }
        });
        Ok(validator)
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
        self.is_finished.store(true, Ordering::SeqCst);
        self.receiver.close();
        #[cfg(feature = "log")]
        log::debug!(
            "Proxy validator completed: {}/{} proxies validated ({:?})",
            self.counter.load(Ordering::Acquire),
            self.total.load(Ordering::Acquire),
            self.timer.elapsed(),
        );
    }
}
