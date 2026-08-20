use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;

pub struct HideMyNameProvider;

#[async_trait]
impl ProxyProvider for HideMyNameProvider {
    fn name(&self) -> &'static str {
        "hidemy.name"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(
            ["https://hidemy.name/en/proxy-list/"]
                .into_iter()
                .map(|url| {
                    Source::all(url).map(|source| {
                        source
                            .with_mode(ScrapeMode::HtmlTable)
                            .with_timeout(Duration::from_secs(15))
                    })
                })
                .collect(),
        )
    }
}
