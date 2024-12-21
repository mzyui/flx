#![allow(unused, dead_code)]
mod checker;
mod config;

use core::arch;
use std::{
    borrow::Cow,
    sync::{
        atomic::{AtomicBool, AtomicUsize},
        Arc, Mutex,
    },
    time::Duration,
};

use hashbrown::HashSet;
use tokio::{sync::Semaphore, task::JoinHandle, time::Instant};

pub use config::Config;

use crate::{
    proxy::{
        client::ProxyClient,
        models::{Protocol, Proxy, ProxyType},
    },
    resolver::my_ip,
};

pub struct ProxyValidator {
    receiver: kanal::Receiver<Proxy>,
    total: Arc<AtomicUsize>,
    counter: Arc<AtomicUsize>,
    timer: Instant,
    is_finished: Arc<AtomicBool>,
}

#[allow(unused_must_use)]
async fn do_work(
    mut proxy: Proxy,
    sender: kanal::AsyncSender<Proxy>,
    counter: Arc<AtomicUsize>,
    protocol: Protocol,
    max_attempts: usize,
    timeout: u64,
) {
    let timeout = Duration::from_secs(timeout);
    if let Ok(tcp) = proxy.connect_timeout(timeout).await {
        tcp.apply(&mut proxy);

        if let Protocol::Http(_) = protocol {
            if let Some(result) = checker::support_http(&mut proxy, timeout, max_attempts).await {
                result.apply(&mut proxy);
                proxy.proxy_type = Some(ProxyType::checked(result.inner));
            }
        }

        if proxy.proxy_type.is_some() {
            #[cfg(feature = "log")]
            log::trace!(
                "{}: support protocol: {}",
                proxy.as_text(),
                proxy.proxy_type.as_ref().unwrap().protocol
            );
            sender.send(proxy).await.unwrap_or_default();
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

impl ProxyValidator {
    #[allow(unused_must_use)]
    pub async fn validate<I>(proxy_source: I, config: Config) -> anyhow::Result<Self>
    where
        I: Iterator<Item = Proxy> + Send + 'static,
    {
        if config.types.is_empty() {
            anyhow::bail!("config.types cannot be empty; please specify at least one type.");
        }

        #[cfg(feature = "log")]
        log::debug!(
            "Proxy validator started ({} workers)",
            config.concurrency_limit
        );

        my_ip().await;

        let (sender, receiver) = kanal::unbounded_async();
        let validator = Self {
            receiver: receiver.to_sync(),
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
            for mut proxy in proxy_source {
                if is_finished.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }

                let mut added = false;
                while let Some(protocol) = proxy.expected_types.pop() {
                    if config
                        .types
                        .iter()
                        .any(|right_proto| match (&protocol, right_proto) {
                            (Protocol::Http(_), Protocol::Http(_))
                            | (Protocol::Connect(_), Protocol::Connect(_)) => true,
                            _ => protocol == *right_proto,
                        })
                    {
                        if !added {
                            total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            added = true;
                        }
                        let permit = Arc::clone(&sem);
                        let sender = sender.clone();
                        let counter = Arc::clone(&counter);
                        let max_attempts = config.max_attempts;
                        let timeout = config.request_timeout;
                        let proxy = proxy.clone();

                        tokio::spawn(async move {
                            let _ = permit.acquire().await.unwrap();
                            do_work(proxy, sender, counter, protocol, max_attempts, timeout).await
                        });
                    }
                }
            }
        });
        Ok(validator)
    }

    pub fn get_one(&mut self) -> Option<Proxy> {
        while !self.receiver.is_empty() || self.receiver.sender_count() != 0 {
            if let Ok(proxy) = self.receiver.recv_timeout(Duration::from_millis(100)) {
                return Some(proxy);
            }
        }
        None
    }
}

impl Iterator for ProxyValidator {
    type Item = Proxy;

    fn next(&mut self) -> Option<Self::Item> {
        self.get_one()
    }
}

impl Drop for ProxyValidator {
    fn drop(&mut self) {
        self.is_finished
            .store(true, std::sync::atomic::Ordering::SeqCst);
        #[cfg(feature = "log")]
        log::debug!(
            "Proxy validator completed: {}/{} proxies validated ({:?})",
            self.counter.load(std::sync::atomic::Ordering::Acquire),
            self.total.load(std::sync::atomic::Ordering::Acquire),
            self.timer.elapsed(),
        );
    }
}
