use argument::Cli;
use clap::Parser;
#[cfg(feature = "log")]
use fluxy::setup_log;
use fluxy::{
    models::{Protocol, ProxyFetcherConfig, ProxyValidatorConfig},
    ProxyFetcher, ProxyValidator,
};
use tokio::runtime;

mod argument;

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "log")]
    setup_log(log::LevelFilter::Off)?;

    let opt = Cli::parse();

    let runtime = runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        let proxy_source = ProxyFetcher::gather(ProxyFetcherConfig::default()).await?;
        let validated_proxy = ProxyValidator::validate(
            proxy_source,
            ProxyValidatorConfig {
                types: vec![Protocol::Http(fluxy::models::Anonymity::Elite)],
                ..Default::default()
            },
        )
        .await?;

        for proxy in validated_proxy {
            println!("{}", proxy);
        }

        Ok(())
    })
}
