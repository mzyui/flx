use std::time::Duration;

use async_trait::async_trait;

use super::models::{valid_sources, ScrapeMode, Source};
use super::ProxyProvider;

/// The proxylist.geonode.com public JSON API.
///
/// Unlike the plaintext sources this endpoint reports the protocol per entry,
/// and a single entry may advertise several. No API key is required.
pub struct GeonodeProvider;

/// Number of pages requested, matching the reference implementation.
const PAGES: u32 = 3;
/// Entries per page.
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
                    // Protocols come from the payload, so the defaults are only
                    // a fallback for rows that omit them.
                    Source::all(&url).map(|source| {
                        source
                            .with_mode(ScrapeMode::GeonodeJson)
                            .with_timeout(Duration::from_secs(20))
                    })
                })
                .collect(),
        )
    }
}
