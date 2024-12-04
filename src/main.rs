use std::{sync::Arc, time::Duration};

#[cfg(feature = "log")]
use fluxy::setup_log;
use fluxy::{
    client::ProxyClient,
    fetcher::ProxyFetcher,
    models::{Protocol, ProxyConfig},
    negotiators::https::HttpsNegotiator,
    validator::ProxyValidator,
};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request};
use hyper_tls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tokio::{runtime, time::timeout};

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "log")]
    setup_log(log::LevelFilter::Trace)?;

    let runtime = runtime::Builder::new_multi_thread().enable_all().build()?;

    runtime.block_on(async {
        let config = ProxyConfig {
            filters: fluxy::models::ProxyFilter {
                types: vec![Protocol::Http(fluxy::models::Anonymity::Unknown)],
                ..Default::default()
            },
            concurrency_limit: 10,
            ..Default::default()
        };

        let mut fetcher = ProxyFetcher::gather(config).await?;
        let mut validator = ProxyValidator::from(fetcher.iter());

        for proxy in validator.iter() {
            let mut client = ProxyClient::new(proxy);
            let req = Request::builder()
                .uri("https://myip.wtf/text")
                .header(hyper::header::HOST, "myip.wtf")
                .body(Full::<Bytes>::from(""))?;
            match timeout(
                Duration::from_secs(3),
                client.send_request(req.clone(), Arc::new(HttpsNegotiator)),
            )
            .await
            {
                Ok(Ok(res)) => {
                    let status = res.status();
                    println!("Response: {}", status);
                    println!("Headers: {:#?}", res.headers());
                    let c = res.into_body().collect().await?;
                    let d = c.to_bytes();
                    let v = serde_json::from_slice::<serde_json::Value>(&d.clone())
                        .map(|v| {
                            serde_json::to_string_pretty(&v).unwrap_or("Empty".into())
                        })
                        .unwrap_or(String::from_utf8_lossy(&d).to_string());
                    println!("Body: {}", v);
                    println!("{}", client.proxy);
                    if status.is_success() {
                        let https = HttpsConnector::new();
                        let c = Client::builder(TokioExecutor::new()).build(https);
                        let res2 = c.request(req).await?;
                        println!("Response: {}", res2.status());
                        println!("Headers: {:#?}", res2.headers());
                        let c = res2.into_body().collect().await?;
                        let d = c.to_bytes();
                        let v = serde_json::from_slice::<serde_json::Value>(&d.clone())
                            .map(|v| {
                                serde_json::to_string_pretty(&v).unwrap_or("Empty".into())
                            })
                            .unwrap_or(String::from_utf8_lossy(&d).to_string());
                        println!("Body: {}", v);

                        break;
                    }
                }
                Ok(Err(e)) => {
                    client.log_error(e);
                }

                Err(e) => {
                    client.log_error(e);
                }
            }
        }

        Ok(())
    })
}
