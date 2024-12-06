#[cfg(feature = "log")]
use fluxy::initialize_logging;
use fluxy::{
    models::{Protocol, ProxyFetcherConfig},
    ProxySource, ProxyValidator, ProxyValidatorConfig,
};
use tokio::runtime;

mod argument;

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "log")]
    initialize_logging(log::LevelFilter::Off)?;

    let runtime = runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        let proxy_source = ProxySource::from_fetcher(ProxyFetcherConfig::default()).await?;
        let validated_proxy = ProxyValidator::validate(
            proxy_source,
            ProxyValidatorConfig {
                types: vec![
                    Protocol::Https,
                    Protocol::Http(fluxy::models::Anonymity::Elite),
                ],
                ..Default::default()
            },
        )
        .await?;

        for proxy in validated_proxy {
            println!("{}", proxy.as_json()?);
        }
        Ok(())
    })
}
