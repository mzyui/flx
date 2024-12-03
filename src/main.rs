use std::time::Duration;

use fake::{faker::internet::en::UserAgent, Fake};
#[cfg(feature = "log")]
use fluxy::setup_log;
use fluxy::{
    client::ProxyClient,
    fetcher::ProxyFetcher,
    models::{Protocol, ProxyConfig},
    validator::ProxyValidator,
};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request};
use tokio::runtime;

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "log")]
    setup_log(log::LevelFilter::Trace)?;

    let runtime = runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()?;

    runtime.block_on(async {
        let config = ProxyConfig {
            filters: fluxy::models::ProxyFilter {
                types: vec![Protocol::Https],
                ..Default::default()
            },
            ..Default::default()
        };

        let mut fetcher = ProxyFetcher::gather(config).await?;
        let mut validator = ProxyValidator::from(fetcher.iter());

        for proxy in validator.iter().take(500) {
            let mut client = ProxyClient::new(proxy, Duration::from_secs(5));
            let req = Request::builder()
                .uri("https://httpbin.org/get?show_env")
                .header(hyper::header::USER_AGENT, UserAgent().fake::<&str>())
                .body(Empty::<Bytes>::new())?;
            match client.send_request(req).await {
                Ok(res) => {
                    println!("Response: {}", res.status());
                    println!("Headers: {:#?}\n", res.headers());
                    let c = res.into_body().collect().await?;
                    println!("Body: {}", String::from_utf8_lossy(&c.to_bytes()));
	            println!("{}", client.proxy);

                    break;
                }
                Err(e) => {
                    client.log_error(e);
                }
            }
        }
        Ok(())
    })
}
