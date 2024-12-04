use std::{sync::Arc, time::Duration};

use fake::{faker::internet::en::UserAgent, Fake};
#[cfg(feature = "log")]
use fluxy::setup_log;
use fluxy::{
    client::ProxyClient,
    models::{Proxy, ProxyConfig},
    negotiators::Socks4Negotiator,
    ProxyFetcher, ProxyValidator,
};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Bytes, Incoming},
    Request, Response,
};
use tokio::{runtime, time::timeout};
use tokio_task_pool::Pool;

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "log")]
    setup_log(log::LevelFilter::Info)?;

    let runtime = runtime::Builder::new_multi_thread().enable_all().build()?;

    runtime.block_on(async {
        let config = ProxyConfig {
            concurrency_limit: 10,
            ..Default::default()
        };

        let mut fetcher = ProxyFetcher::gather(config).await?;
        let mut validator = ProxyValidator::from(fetcher.iter());

        let (sender, receiver) = crossbeam_channel::bounded(0);
        tokio::spawn(async move {
            let (proxy, res): (Proxy, Response<Incoming>) = receiver.recv().unwrap();

            println!("{}", proxy);
            let status = res.status();
            println!("Response: {}", status);
            println!("Headers: {:#?}", res.headers());
            let c = res.into_body().collect().await.unwrap();
            let d = c.to_bytes();
            let v = serde_json::from_slice::<serde_json::Value>(&d.clone())
                .map(|v| serde_json::to_string_pretty(&v).unwrap_or("Empty".into()))
                .unwrap_or(String::from_utf8_lossy(&d).to_string());
            println!("Body: {}", v);

            std::process::exit(0);
        });

        let pool = Pool::bounded(500);
        for proxy in validator.iter() {
            let sender = sender.clone();
            let _ = pool
                .spawn(async move {
                    let mut client = ProxyClient::new(proxy);
                    let req = Request::builder()
                        .uri("/json")
                        .header(hyper::header::HOST, "ip-api.com")
                        .header(hyper::header::USER_AGENT, UserAgent().fake::<&str>())
                        .body(Full::<Bytes>::from(""))?;
                    match timeout(
                        Duration::from_secs(5),
                        client.send_request(req.clone(), Arc::new(Socks4Negotiator)),
                    )
                    .await
                    {
                        Ok(Ok(res)) => {
                            if res.status().is_success() {
                                sender.send((client.proxy.clone(), res))?;
                            }
                        }
                        Ok(Err(e)) => {
                            client.log_error(e);
                        }

                        Err(e) => {
                            client.log_error(e);
                        }
                    }
                    Ok::<(), anyhow::Error>(())
                })
                .await;
        }

            while pool.busy_permits().unwrap_or(0) != 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

        Ok(())
    })
}
