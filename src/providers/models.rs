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

/// Dot-separated path to an object key in a JSON row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JsonPath(String);

impl JsonPath {
    /// Returns the path segments after validating dot syntax.
    pub fn parse(path: impl Into<String>) -> anyhow::Result<Self> {
        let path = path.into();
        if path.is_empty() {
            return Ok(Self(path));
        }
        if path.split('.').any(str::is_empty) {
            anyhow::bail!("JSON path contains an empty segment: `{path}`");
        }
        Ok(Self(path))
    }

    /// Returns the original dot-separated path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Protocol attached to every row when the JSON feed carries none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonFixedProtocol {
    /// Plain HTTP proxy with unknown anonymity.
    Http,
    /// HTTPS proxy with unknown anonymity.
    Https,
    /// SOCKS4 proxy.
    Socks4,
    /// SOCKS5 proxy.
    Socks5,
}

impl JsonFixedProtocol {
    /// Converts the fixed protocol into a [`Protocol`].
    pub fn as_protocol(self) -> Protocol {
        match self {
            Self::Http => Protocol::Http(Anonymity::Unknown),
            Self::Https => Protocol::Https(Anonymity::Unknown),
            Self::Socks4 => Protocol::Socks4,
            Self::Socks5 => Protocol::Socks5,
        }
    }
}
/// How the IP field of a JSON row is decoded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum JsonIpTransform {
    /// Plain dotted-quad string.
    #[default]
    Plain,
    /// Charcode-array plus base64 tail (e.g. ProxyNova feeds).
    JsObfuscated,
}

/// Schema for streaming JSON rows into proxy candidates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRowsConfig {
    /// Path to the rows array; empty means the JSON root is the array.
    pub rows_path: JsonPath,
    /// Path to the IPv4 host field within each row.
    pub ip_path: JsonPath,
    /// Path to the port field within each row.
    pub port_path: JsonPath,
    /// Optional path to one protocol string within each row.
    pub protocol_path: Option<JsonPath>,
    /// Optional path to an array of protocol strings within each row.
    pub protocols_path: Option<JsonPath>,
    /// How the IP field is decoded.
    pub ip_transform: JsonIpTransform,
    /// Protocol attached to rows carrying no protocol field.
    pub fixed_protocol: Option<JsonFixedProtocol>,
}
impl JsonRowsConfig {
    /// Creates a JSON row schema with no protocol field.
    pub fn new(
        rows_path: impl Into<String>,
        ip_path: impl Into<String>,
        port_path: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let ip_path = JsonPath::parse(ip_path)?;
        let port_path = JsonPath::parse(port_path)?;
        if ip_path.as_str().is_empty() || port_path.as_str().is_empty() {
            anyhow::bail!("JSON row field paths cannot be empty");
        }
        Ok(Self {
            rows_path: JsonPath::parse(rows_path)?,
            ip_path,
            port_path,
            protocol_path: None,
            protocols_path: None,
            ip_transform: JsonIpTransform::default(),
            fixed_protocol: None,
        })
    }

    /// Sets a single protocol field path.
    pub fn with_protocol_path(mut self, path: impl Into<String>) -> anyhow::Result<Self> {
        if self.protocols_path.is_some() {
            anyhow::bail!("JSON schema cannot use protocol and protocols paths together");
        }
        self.protocol_path = Some(JsonPath::parse(path)?);
        Ok(self)
    }

    /// Sets a protocol array field path.
    pub fn with_protocols_path(mut self, path: impl Into<String>) -> anyhow::Result<Self> {
        if self.protocol_path.is_some() {
            anyhow::bail!("JSON schema cannot use protocol and protocols paths together");
        }
        self.protocols_path = Some(JsonPath::parse(path)?);
        Ok(self)
    }

    /// Sets how the IP field is decoded.
    pub fn with_ip_transform(mut self, transform: JsonIpTransform) -> Self {
        self.ip_transform = transform;
        self
    }

    /// Attaches a fixed protocol to rows carrying no protocol field.
    pub fn with_fixed_protocol(mut self, protocol: JsonFixedProtocol) -> Self {
        self.fixed_protocol = Some(protocol);
        self
    }
}

/// Parser selected for a provider response body.
#[derive(Debug, Clone, PartialEq)]
pub enum ScrapeMode {
    /// One `ip:port` candidate per line.
    Plaintext,
    /// Generic HTML table with IP/port columns.
    HtmlTable,
    /// Free-form `ip:port` pairs found by regex.
    RegexPairs,
    /// Base64-encoded `Proxy('...')` rows.
    Base64Rows,
    /// JSON array of `ip:port` strings.
    JsonStringArray,
    /// Schema-driven JSON rows with nested object paths.
    JsonRows(JsonRowsConfig),
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

#[cfg(test)]
mod tests {
    use super::{JsonFixedProtocol, JsonIpTransform, JsonPath, JsonRowsConfig};
    use crate::proxy::models::{Anonymity, Protocol};

    #[test]
    fn json_rows_config_accepts_nested_paths_and_protocol_field() {
        let config = JsonRowsConfig::new("payload.proxies", "endpoint.host", "endpoint.port")
            .unwrap()
            .with_protocol_path("kind")
            .unwrap();

        assert_eq!(config.rows_path.as_str(), "payload.proxies");
        assert_eq!(config.ip_path.as_str(), "endpoint.host");
        assert_eq!(config.port_path.as_str(), "endpoint.port");
        assert_eq!(config.protocol_path.unwrap().as_str(), "kind");
    }

    #[test]
    fn json_path_rejects_empty_segments_but_allows_root_path() {
        assert!(JsonPath::parse("payload..proxies").is_err());
        assert!(JsonPath::parse("").is_ok());
    }

    #[test]
    fn json_rows_config_rejects_empty_fields_and_protocol_conflicts() {
        assert!(JsonRowsConfig::new("", "", "port").is_err());
        let config = JsonRowsConfig::new("", "host", "port")
            .unwrap()
            .with_protocol_path("protocol")
            .unwrap();
        assert!(config.with_protocols_path("protocols").is_err());
    }

    #[test]
    fn json_rows_config_decodes_plain_ips_by_default() {
        let config = JsonRowsConfig::new("data", "ip", "port").unwrap();
        assert_eq!(config.ip_transform, JsonIpTransform::Plain);
        assert_eq!(config.fixed_protocol, None);
        let config = config
            .with_ip_transform(JsonIpTransform::JsObfuscated)
            .with_fixed_protocol(JsonFixedProtocol::Http);
        assert_eq!(config.ip_transform, JsonIpTransform::JsObfuscated);
        assert_eq!(config.fixed_protocol, Some(JsonFixedProtocol::Http));
        assert_eq!(
            config.fixed_protocol.unwrap().as_protocol(),
            Protocol::Http(Anonymity::Unknown)
        );
    }
}
