mod config;

use std::time::Duration;

use tokio::{task::JoinHandle, time::Timeout};
use tokio_task_pool::Pool;

pub use config::Config;

use crate::{
    proxy::client::ProxyClient,
    proxy::models::{Anonymity, Protocol, Proxy},
    utils::my_ip,
};

pub struct ProxyValidator {
    sender: crossbeam_channel::Sender<Option<Proxy>>,
    receiver: crossbeam_channel::Receiver<Option<Proxy>>,
    handler: JoinHandle<()>,
}
async fn do_work(
    proxy: Proxy,
    sender: crossbeam_channel::Sender<Option<Proxy>>,
    max_attempts: usize,
) {
    let mut proxy_client = ProxyClient::new(proxy);
    proxy_client.check_all().await;
    sender.send(Some(proxy_client.proxy)).unwrap_or_default();
}

impl ProxyValidator {
    #[allow(unused_must_use)]
    pub async fn validate<I>(proxy_source: I, config: Config) -> anyhow::Result<Self>
    where
        I: Iterator<Item = Proxy> + Send + 'static,
    {
        if config.types.is_empty() {
            anyhow::bail!("config.types cannot be empty")
        }

        if config.types.contains(&Protocol::Http(Anonymity::Unknown)) {
            anyhow::bail!("can't use Protocol::Http(Anonymity::Unknown) for proxy filtering")
        }

        let (sender, receiver) = crossbeam_channel::unbounded();

        let tx = sender.clone();
        let handler = tokio::spawn(async move {
            let pool = Pool::bounded(config.concurrency_limit);
            pool.spawn(my_ip()).await;

            for mut proxy in proxy_source {
                let sender = tx.clone();
                let max_attempts = config.max_attempts;
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
                    pool.spawn(async move {
                        do_work(proxy, sender, max_attempts).await;
                    })
                    .await;
                }
            }

            // Wait for all tasks in the pool to complete.
            while pool.busy_permits().unwrap_or(0) != 0 {
                // do nothing
            }
            tx.send(None).unwrap_or_default();
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
