use std::time::Duration;

#[cfg(feature = "log")]
use fluxy::setup_log;
use fluxy::{
    client::ProxyClient,
    fetcher::ProxyFetcher,
    models::{Protocol, ProxyFetcherConfig, ProxyFilter},
};
use http_body_util::Empty;
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
        let config = ProxyFetcherConfig {
            filters: ProxyFilter {
                types: vec![Protocol::Http(fluxy::models::Anonymity::Unknown)],
                ..Default::default()
            },
            ..Default::default()
        };

        let mut f = ProxyFetcher::new(config).await?;
        f.gather().await?;

        for proxy in f.iter() {
            let mut client = ProxyClient::new(proxy, Duration::from_secs(5));
            let req = Request::builder()
                .uri("https://google.com")
                .header(hyper::header::HOST, "google.com")
                .body(Empty::<Bytes>::new())?;
            if let Err(e) = client.send_request(req).await {
                client.log_error(e);
                continue;
            }
            println!("{}", client.proxy);
            break;
        }
        Ok(())
    })
}
