use std::time::Duration;

use tokio::{task::JoinHandle, time};
use tokio_task_pool::Pool;

use crate::models::{Anonymity, Protocol, Proxy, ProxyValidatorConfig};

pub struct ProxyValidator {
    receiver: crossbeam_channel::Receiver<Option<Proxy>>,
    handler: JoinHandle<()>,
}

impl ProxyValidator {
    pub async fn validate<I>(proxy_source: I, config: ProxyValidatorConfig) -> anyhow::Result<Self>
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
        let handler = tokio::spawn(async move {
            let pool = Pool::bounded(config.concurrency_limit);
            for mut proxy in proxy_source {
                proxy.types.retain(|type_| {
                    let left_proto = &*type_.protocol;
                    config
                        .types
                        .iter()
                        .any(|right_proto| match (left_proto, right_proto) {
                            (Protocol::Http(_), Protocol::Http(_))
                            | (Protocol::Connect(_), Protocol::Connect(_)) => true,
                            _ => left_proto == right_proto,
                        })
                });
                if proxy.types.is_empty() {
                    continue;
                }

                let _ = sender.send(Some(proxy));
            }

            // Wait for all tasks in the pool to complete.
            while pool.busy_permits().unwrap_or(0) != 0 {
                time::sleep(Duration::from_millis(50)).await;
            }
            sender.send(None).unwrap_or_default();
        });
        Ok(Self { receiver, handler })
    }
}

impl Drop for ProxyValidator {
    fn drop(&mut self) {
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
