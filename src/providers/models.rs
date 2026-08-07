use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::Context;
use hyper::Uri;

use crate::proxy::models::{Anonymity, Protocol};

/// How the body returned by a source must be parsed into proxies.
#[derive(Debug, Clone, PartialEq)]
pub enum ScrapeMode {
    /// One `ip:port` per line, optionally followed by extra fields.
    Plaintext,
    /// GeoNode JSON API (`{"data":[{ip,port,protocols,...}]}`).
    GeonodeJson,
    /// ProxyNova JSON API, whose `ip` field is a JS string expression.
    ProxyNovaJson,
    /// HTML `<table>` markup shared by the free-proxy-list family of sites.
    HtmlTable,
    /// Free-form HTML containing `ip:port#CC` pairs.
    RegexPairs,
    /// proxy-list.org rows carrying a base64-encoded `ip:port` blob.
    Base64Rows,
}

/// Priority tier of a provider within [`crate::providers::all_providers`].
///
/// The fetcher runs every [`ProviderTier::Primary`] provider first and only
/// then the [`ProviderTier::Fallback`] ones, so ordering is deterministic
/// instead of depending on how the async scheduler happens to hand out
/// semaphore permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProviderTier {
    /// Live websites and APIs that publish their own lists.
    Primary,
    /// Aggregated mirrors, used after the primary sources have been exhausted.
    Fallback,
}

/// Represents a source of proxy information, such as a URL and default protocol types.
pub struct Source {
    pub url: Uri,                       // URL of the proxy source.
    pub default_types: Arc<[Protocol]>, // Default protocol types, shared across proxies.
    pub timeout: Duration,              // Time before giving up on a request.
    pub mode: ScrapeMode,               // How to parse the response body.
}

impl Source {
    /// Creates a new `Source` with a specified URL and protocol types.
    ///
    /// # Arguments
    ///
    /// * `url`: The URL of the proxy source.
    /// * `types`: A vector of `Protocol` types.
    ///
    /// # Errors
    ///
    /// Returns an error if `url` is not a valid URI.
    pub fn new(url: &str, types: Vec<Protocol>) -> anyhow::Result<Self> {
        let types = if types.is_empty() {
            vec![
                Protocol::Http(Anonymity::Unknown),
                Protocol::Https(Anonymity::Unknown),
                Protocol::Socks4,
                Protocol::Socks5,
                Protocol::Connect(25),
                Protocol::Connect(80),
            ]
        } else {
            types
        };

        Ok(Self {
            url: Uri::from_str(url).with_context(|| format!("invalid provider url: {}", url))?,
            default_types: Arc::from(types.into_boxed_slice()),
            timeout: Duration::from_secs(3),
            mode: ScrapeMode::Plaintext,
        })
    }

    /// Overrides how this source's response body is parsed.
    pub fn with_mode(mut self, mode: ScrapeMode) -> Self {
        self.mode = mode;
        self
    }

    /// Overrides the per-request timeout.
    ///
    /// HTML scrapes and paginated APIs are much slower than raw text lists.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Creates a `Source` for a single well-known protocol.
    ///
    /// # Errors
    ///
    /// Returns an error if `url` is not a valid URI.
    pub fn typed(url: &str, protocol: Protocol) -> anyhow::Result<Self> {
        Self::new(url, vec![protocol])
    }

    /// Creates a `Source` with default common protocols.
    ///
    /// # Errors
    ///
    /// Returns an error if `url` is not a valid URI.
    pub fn all(url: &str) -> anyhow::Result<Self> {
        Self::new(url, vec![])
    }

    /// Creates a `Source` with default types for HTTP protocols.
    ///
    /// # Errors
    ///
    /// Returns an error if `url` is not a valid URI.
    pub fn http(url: &str) -> anyhow::Result<Self> {
        Self::new(
            url,
            vec![
                Protocol::Http(Anonymity::Unknown),
                Protocol::Https(Anonymity::Unknown),
                Protocol::Connect(80),
                Protocol::Connect(25),
            ],
        )
    }

    /// Creates a `Source` with default types for SOCKS protocols.
    ///
    /// # Errors
    ///
    /// Returns an error if `url` is not a valid URI.
    pub fn socks(url: &str) -> anyhow::Result<Self> {
        Self::new(url, vec![Protocol::Socks4, Protocol::Socks5])
    }
}

/// Keeps only the sources whose URL parsed successfully, logging the rest.
///
/// Providers build their source list from static strings, so a malformed URL is
/// a bug rather than a user error — but it must never abort the whole run.
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
