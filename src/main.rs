use fluxy::fetcher::{ProxyFetcher, ProxyFetcherOptions};
#[cfg(feature = "log")]
use fluxy::setup_log;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(feature = "log")]
    setup_log(log::LevelFilter::Debug)?;

    let opts = ProxyFetcherOptions::default();
    let mut f = ProxyFetcher::new(opts).await?;
    f.use_default_providers();
    f.gather().await?;

    for p in f.take(1) {
        println!("{:#?}", p);
    }

    Ok(())
}
