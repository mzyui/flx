use std::{
    str::FromStr,
    sync::{Arc, LazyLock},
    time::Duration,
};

use anyhow::Context;
use hyper::Uri;

use crate::proxy::models::{Anonymity, Protocol};

/// Bundle default protocols with the scrape mode for a provider body.
pub struct ScrapeContext {
    /// Protocols assigned to rows advertising none.
    pub default_types: Arc<[Protocol]>,
    /// Parser used for the provider body.
    pub mode: ScrapeMode,
}

/// Parser selected for a provider response body.
#[derive(Debug, Clone, PartialEq)]
pub enum ScrapeMode {
    /// One `ip:port` candidate per line.
    Plaintext,
    /// Geonode `{ data: [...] }` JSON payload.
    GeonodeJson,
    /// ProxyNova `{ data: [...] }` JSON payload with obfuscated IPs.
    ProxyNovaJson,
    /// Generic HTML table with IP/port columns.
    HtmlTable,
    /// Free-form `ip:port` pairs found by regex.
    RegexPairs,
    /// Base64-encoded `Proxy('...')` rows.
    Base64Rows,
    /// JSON array of `ip:port` strings.
    JsonStringArray,
    /// Stormsia JSON array of `{ protocol, host, port }` rows.
    StormsiaJson,
    /// GatherProxy `gp.insertPrx({...})` script rows.
    GatherProxyJs,
}

/// Scheduling tier ordering provider fetches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProviderTier {
    /// Fetched in the primary phase.
    Primary,
    /// Fetched only after primary providers complete.
    Fallback,
}

/// One scrapable provider URL with its parse mode and protocols.
#[derive(Clone)]
pub struct Source {
    /// Source URL to download.
    pub url: Uri,
    /// Protocols assigned to rows advertising none.
    pub default_types: Arc<[Protocol]>,
    /// Per-source fetch timeout.
    pub timeout: Duration,
    /// Parser used for this source body.
    pub mode: ScrapeMode,
}

/// Supply fallback protocols for sources advertising none.
static COMMON_SOURCE_PROTOCOLS: LazyLock<Arc<[Protocol]>> = LazyLock::new(|| {
    Arc::from([
        Protocol::Http(Anonymity::Unknown),
        Protocol::Https(Anonymity::Unknown),
        Protocol::Socks4,
        Protocol::Socks5,
        Protocol::Connect(25),
        Protocol::Connect(80),
        Protocol::Connect(443),
    ])
});

impl Source {
    /// Builds a source with explicit fallback `types` for untyped rows.
    ///
    /// An empty `types` list falls back to the common protocol set.
    ///
    /// # Errors
    ///
    /// Returns an error when `url` is not a valid URI.
    pub fn new(url: &str, types: Vec<Protocol>) -> anyhow::Result<Self> {
        let default_types = if types.is_empty() {
            Arc::clone(&COMMON_SOURCE_PROTOCOLS)
        } else {
            Arc::from(types)
        };

        Ok(Self {
            url: Uri::from_str(url).with_context(|| format!("invalid provider url: {}", url))?,
            default_types,
            timeout: Duration::from_secs(3),
            mode: ScrapeMode::Plaintext,
        })
    }

    /// Sets the parser used for this source body.
    pub fn with_mode(mut self, mode: ScrapeMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the per-source fetch timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Builds a source advertising a single `protocol`.
    ///
    /// # Errors
    ///
    /// Returns an error when `url` is not a valid URI.
    pub fn typed(url: &str, protocol: Protocol) -> anyhow::Result<Self> {
        Self::new(url, vec![protocol])
    }

    /// Builds a source accepting every common protocol for untyped rows.
    ///
    /// # Errors
    ///
    /// Returns an error when `url` is not a valid URI.
    pub fn all(url: &str) -> anyhow::Result<Self> {
        Self::new(url, vec![])
    }

    /// Builds a source with HTTP-family fallback protocols.
    ///
    /// # Errors
    ///
    /// Returns an error when `url` is not a valid URI.
    pub fn http(url: &str) -> anyhow::Result<Self> {
        Self::new(
            url,
            vec![
                Protocol::Http(Anonymity::Unknown),
                Protocol::Https(Anonymity::Unknown),
                Protocol::Connect(80),
                Protocol::Connect(25),
                Protocol::Connect(443),
            ],
        )
    }

    /// Builds a source with SOCKS4/SOCKS5 fallback protocols.
    ///
    /// # Errors
    ///
    /// Returns an error when `url` is not a valid URI.
    pub fn socks(url: &str) -> anyhow::Result<Self> {
        Self::new(url, vec![Protocol::Socks4, Protocol::Socks5])
    }
}

/// Filter sources to those whose URL parsed successfully.
pub fn valid_sources(sources: Vec<anyhow::Result<Source>>) -> Vec<Source> {
    sources
        .into_iter()
        .filter_map(|source| {
            #[cfg(feature = "log")]
            if let Err(error) = &source {
                log::warn!("skipping provider source: {error:#}");
            }
            source.ok()
        })
        .collect()
}
