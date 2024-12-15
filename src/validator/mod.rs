mod checker;
mod config;

use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use checker::ProxyCheck;
use tokio::task::JoinHandle;
use tokio_task_pool::Pool;

pub use config::Config;

use crate::{
    proxy::{
        client::ProxyClient,
        models::{Protocol, Proxy},
    },
    utils::my_ip,
};

pub struct ProxyValidator {
    sender: crossbeam_channel::Sender<Option<Proxy>>,
    receiver: crossbeam_channel::Receiver<Option<Proxy>>,
    handler: JoinHandle<anyhow::Result<()>>,
}
async fn do_work(mut proxy: Proxy, max_attempts: usize, timeout: u64) -> anyhow::Result<Proxy> {
    let timeout = Duration::from_secs(timeout);
    let tcp = proxy.connect_timeout(timeout).await?;
    tcp.apply(&mut proxy);

    proxy.support_http(timeout, max_attempts).await;

    if !proxy.runtimes.is_empty() {
        return Ok(proxy);
    }
    anyhow::bail!("")
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

        let (sender, receiver) = crossbeam_channel::unbounded();

        let tx = sender.clone();
        let handler = tokio::spawn(async move {
            let pool = Pool::bounded(config.concurrency_limit);
            let process_done = Arc::new(AtomicBool::new(false));
            for mut proxy in proxy_source {
                if process_done.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }

                proxy.types.retain(|type_| {
                    let left_proto = &type_.protocol;
                    config
                        .types
                        .iter()
                        .any(|right_proto| match (left_proto, right_proto) {
                            (Protocol::Http(_), Protocol::Http(_))
                            | (Protocol::Connect(_), Protocol::Connect(_)) => true,
                            _ => left_proto == right_proto,
                        })
                });

                if !proxy.types.is_empty() {
                    let tx = tx.clone();
                    let max_attempts = config.max_attempts;
                    let timeout = config.request_timeout;
                    let process_done = Arc::clone(&process_done);

                    pool.spawn(async move {
                        if let Ok(proxy) = do_work(proxy, max_attempts, timeout).await {
                            if tx.send(Some(proxy)).is_err() {
                                process_done.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    })
                    .await;
                }
            }
            while pool.busy_permits().unwrap_or(0) != 0 {}
            tx.try_send(None)?;
            Ok::<(), anyhow::Error>(())
        });
        Ok(Self {
            receiver,
            handler,
            sender,
        })
    }
}

impl Drop for ProxyValidator {
    fn drop(&mut self) {
        self.sender.send(None).unwrap_or_default();
        self.handler.abort();
    }
}

impl Iterator for ProxyValidator {
    type Item = Proxy;

    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(proxy) = self.receiver.recv() {
            return proxy;
        }
        None
    }
}
