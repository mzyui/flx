use fluxy::fetcher::{ProxyFetcher, ProxyFetcherOptions};
#[cfg(feature = "log")]
use fluxy::setup_log;
use tokio::runtime;

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "log")]
    setup_log(log::LevelFilter::Debug)?;

    let runtime = runtime::Builder::new_multi_thread().enable_all().build()?;

    runtime.block_on(async {
        let opts = ProxyFetcherOptions::default();
        let mut f = ProxyFetcher::new(opts).await?;
        f.use_default_providers();
        f.gather().await?;

        println!("{:#?}", f.iter().take(56).count());
        Ok(())
    })
}
