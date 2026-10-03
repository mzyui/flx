use std::time::Duration;

use async_trait::async_trait;

use super::models::{
    valid_sources, JsonFixedProtocol, JsonIpTransform, JsonRowsConfig, ScrapeMode, Source,
};
use super::ProxyProvider;

/// Scrapes the ProxyNova API proxy list.
pub struct ProxyNovaProvider;

#[async_trait]
impl ProxyProvider for ProxyNovaProvider {
    fn name(&self) -> &'static str {
        "proxynova"
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(vec![Source::all("https://api.proxynova.com/proxylist")
            .map(|source| {
                source
                    .with_mode(ScrapeMode::JsonRows(
                        JsonRowsConfig::new("data", "ip", "port")
                            .map(|config| {
                                config
                                    .with_ip_transform(JsonIpTransform::JsObfuscated)
                                    .with_fixed_protocol(JsonFixedProtocol::Http)
                            })
                            .expect("static ProxyNova JSON schema is valid"),
                    ))
                    .with_timeout(Duration::from_secs(15))
            })])
    }
}
