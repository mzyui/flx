#[cfg(feature = "log")]
use fluxy::setup_log;
use fluxy::{
    fetcher::ProxyFetcher,
    models::{Protocol, ProxyFetcherConfig, ProxyFilter},
};
use tokio::runtime;

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "log")]
    setup_log(log::LevelFilter::Debug)?;

    let runtime = runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()?;

    runtime.block_on(async {
        let config = ProxyFetcherConfig {
            filters: ProxyFilter {
                countries: vec!["ID".into()],
                types: vec![Protocol::Https],
            },
            ..Default::default()
        };

        let mut f = ProxyFetcher::new(config).await?;
        f.gather().await?;

        for p in f.iter().take(50) {
            println!("{}", p);
        }
        Ok(())
    })
}
