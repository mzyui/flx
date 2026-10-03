use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, JsonRowsConfig, ScrapeMode, Source};
use super::ProxyProvider;

/// Scrapes the Geonode API proxy list.
pub struct GeonodeProvider;

const PAGES: u32 = 3;
const LIMIT: u32 = 500;

#[async_trait]
impl ProxyProvider for GeonodeProvider {
    fn name(&self) -> &'static str {
        "geonode"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(
            (1..=PAGES)
                .map(|page| {
                    let url = format!(
                        "https://proxylist.geonode.com/api/proxy-list?limit={}&page={}&sort_by=lastChecked&sort_type=desc",
                        LIMIT, page
                    );
                    Source::all(&url).map(|source| {
                        source
                            .with_mode(ScrapeMode::JsonRows(
                                JsonRowsConfig::new("data", "ip", "port")
                                    .and_then(|config| config.with_protocols_path("protocols"))
                                    .expect("static Geonode JSON schema is valid"),
                            ))
                            .with_timeout(Duration::from_secs(8))
                    })
                })
                .collect(),
        )
    }
}
