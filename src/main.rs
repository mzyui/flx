use fluxy::fetcher::ProxyFetcher;
#[cfg(feature = "log")]
use fluxy::setup_log;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(feature = "log")]
    setup_log(log::LevelFilter::Debug)?;

    let mut f = ProxyFetcher::default();
    f.use_default_providers();
    f.gather().await?;

    #[cfg(feature = "log")]
    log::info!("{:#?}", f.next());
    Ok(())
}
