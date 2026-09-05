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
    pub default_types: Arc<[Protocol]>,
    pub mode: ScrapeMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScrapeMode {
    Plaintext,
    GeonodeJson,
    ProxyNovaJson,
    HtmlTable,
    RegexPairs,
    Base64Rows,
    JsonStringArray,
    GatherProxyJs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProviderTier {
    Primary,
    Fallback,
}

#[derive(Clone)]
pub struct Source {
    pub url: Uri,
    pub default_types: Arc<[Protocol]>,
    pub timeout: Duration,
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

    pub fn with_mode(mut self, mode: ScrapeMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn typed(url: &str, protocol: Protocol) -> anyhow::Result<Self> {
        Self::new(url, vec![protocol])
    }

    pub fn all(url: &str) -> anyhow::Result<Self> {
        Self::new(url, vec![])
    }

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
