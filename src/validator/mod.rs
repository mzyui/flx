#![allow(unused, dead_code)]
mod checker;
mod config;

use core::arch;
use std::{
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::Duration,
};

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
    is_finished: Arc<AtomicBool>,
}

#[allow(unused_must_use)]
async fn do_work(
    mut proxy: Proxy,
    sender: kanal::AsyncSender<Proxy>,
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

        my_ip().await;

        let (sender, receiver) = kanal::unbounded_async();
        let validator = Self {
            receiver: receiver.to_sync(),
            is_finished: Arc::new(AtomicBool::new(false)),
        };

        let is_finished = Arc::clone(&validator.is_finished);
        tokio::spawn(async move {
            let sem = Arc::new(Semaphore::new(config.concurrency_limit));
            for mut proxy in proxy_source {
                if is_finished.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
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
                        let permit = Arc::clone(&sem);
                        let sender = sender.clone();
                        let max_attempts = config.max_attempts;
                        let timeout = config.request_timeout;
                        let proxy = proxy.clone();

                        tokio::spawn(async move {
                            let _ = permit.acquire().await.unwrap();
                            do_work(proxy, sender, protocol, max_attempts, timeout).await
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
    }
}
