use std::{
    fmt::Display,
    net::Ipv4Addr,
    str::FromStr,
    sync::{Arc, LazyLock},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Serialize, Serializer};

use crate::{error::ProtocolParseError, error::ProxyParseError, geolookup::models::GeoData};

// ── RuntimeStats ──────────────────────────────────────────────────────

/// Running statistics for response-time tracking.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuntimeStats {
    pub count: u32,
    pub total: f64,
    pub min: f64,
    pub max: f64,
}

impl RuntimeStats {
    /// Records a timing sample.
    pub fn record(&mut self, secs: f64) {
        self.count += 1;
        self.total += secs;
        if self.count == 1 || secs < self.min {
            self.min = secs;
        }
        if secs > self.max {
            self.max = secs;
        }
    }

    /// Average response time in seconds.
    pub fn avg(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.total / self.count as f64
        }
    }
}

// ── Anonymity ─────────────────────────────────────────────────────────

/// Anonymity level of a proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Anonymity {
    Elite,
    Transparent,
    Anonymous,
    Unknown,
}

impl Anonymity {
    /// Numeric rank from least to most anonymous.
    pub fn rank(self) -> u8 {
        match self {
            Anonymity::Transparent => 0,
            Anonymity::Anonymous => 1,
            Anonymity::Elite => 2,
            Anonymity::Unknown => 3,
        }
    }
}

// ── Protocol ─────────────────────────────────────────────────────────

/// Protocol that a proxy supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Protocol {
    Http(Anonymity),
    Https(Anonymity),
    Socks4,
    Socks5,
    Connect(u16),
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(anon) => match anon {
                Anonymity::Unknown => write!(f, "HTTP"),
                Anonymity::Elite => write!(f, "HTTP: Elite"),
                Anonymity::Transparent => write!(f, "HTTP: Transparent"),
                Anonymity::Anonymous => write!(f, "HTTP: Anonymous"),
            },
            Self::Https(anon) => match anon {
                Anonymity::Unknown => write!(f, "HTTPS"),
                Anonymity::Elite => write!(f, "HTTPS: Elite"),
                Anonymity::Transparent => write!(f, "HTTPS: Transparent"),
                Anonymity::Anonymous => write!(f, "HTTPS: Anonymous"),
            },
            Self::Socks4 => write!(f, "SOCKS4"),
            Self::Socks5 => write!(f, "SOCKS5"),
            Self::Connect(port) => write!(f, "CONNECT:{}", port),
        }
    }
}

impl FromStr for Protocol {
    type Err = ProtocolParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(':');
        let head = parts.next().unwrap_or_default();
        match head {
            "HTTP" => Ok(Protocol::Http(match parts.next() {
                Some("Transparent") => Anonymity::Transparent,
                Some("Anonymous") => Anonymity::Anonymous,
                Some("Elite") => Anonymity::Elite,
                _ => Anonymity::Unknown,
            })),
            "HTTPS" => Ok(Protocol::Https(match parts.next() {
                Some("Transparent") => Anonymity::Transparent,
                Some("Anonymous") => Anonymity::Anonymous,
                Some("Elite") => Anonymity::Elite,
                _ => Anonymity::Unknown,
            })),
            "SOCKS4" => Ok(Protocol::Socks4),
            "SOCKS5" => Ok(Protocol::Socks5),
            "CONNECT" => parts
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .map(Protocol::Connect)
                .ok_or_else(|| ProtocolParseError::InvalidConnectPort(s.to_string())),
            _ => Err(ProtocolParseError::Unknown(s.to_string())),
        }
    }
}

// ── ProxyType ─────────────────────────────────────────────────────────

/// A proxy type with protocol and checked status.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyType {
    pub protocol: Protocol,
    #[serde(skip)]
    pub checked: bool,
    pub checked_on: f64,
}

impl ProxyType {
    /// Creates a new ProxyType with the specified protocol.
    pub fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            checked: false,
            checked_on: 0.0,
        }
    }
    /// Creates a checked ProxyType with the current timestamp.
    pub fn checked(protocol: Protocol) -> Self {
        Self {
            protocol,
            checked: true,
            checked_on: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0),
        }
    }
}

// ── Serialization helpers ─────────────────────────────────────────────

// Newtype so the `type` key can be serialized from a borrowed field inside
// the manual `Proxy` serializer.
struct TypesRef<'a>(&'a [ProxyType]);

impl serde::Serialize for TypesRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            [] => serializer.serialize_none(),
            [single] => single.serialize(serializer),
            many => many.serialize(serializer),
        }
    }
}

// ── Proxy ─────────────────────────────────────────────────────────────

/// A validated proxy endpoint with metadata.
#[derive(Debug, Clone)]
pub struct Proxy {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub geo: Arc<GeoData>,
    pub runtimes: RuntimeStats,
    pub expected_types: Arc<[Protocol]>,
    pub proxy_types: Vec<ProxyType>,
    pub(crate) text: Arc<str>,
}

// Hand-written instead of derived so the latency statistics split out of the
// single `runtimes` field while keeping every historical JSON key intact.
impl serde::Serialize for Proxy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("Proxy", 8)?;
        state.serialize_field("ip", &self.ip)?;
        state.serialize_field("port", &self.port)?;
        state.serialize_field("geo", &self.geo)?;
        state.serialize_field("average_response_time", &self.runtimes.avg())?;
        state.serialize_field("min_response_time", &self.runtimes.min)?;
        state.serialize_field("max_response_time", &self.runtimes.max)?;
        state.serialize_field("response_time_samples", &self.runtimes.count)?;
        state.serialize_field("type", &TypesRef(&self.proxy_types))?;
        state.end()
    }
}

static DEFAULT_GEO: LazyLock<Arc<GeoData>> = LazyLock::new(|| Arc::new(GeoData::default()));

impl Proxy {
    pub fn new(ip: Ipv4Addr, port: u16) -> Self {
        let mut buf = [0u8; 32];
        let text = crate::write_to_buffer(&mut buf, format_args!("{ip}:{port}"));
        Self {
            ip,
            port,
            geo: Arc::clone(&DEFAULT_GEO),
            runtimes: RuntimeStats::default(),
            expected_types: Arc::from([]),
            proxy_types: Vec::new(),
            text: Arc::from(text.as_ref()),
        }
    }

    pub fn with_expected_types(ip: Ipv4Addr, port: u16, expected_types: Arc<[Protocol]>) -> Self {
        let mut proxy = Self::new(ip, port);
        proxy.expected_types = expected_types;
        proxy
    }

    /// Fastest recorded end-to-end response time in seconds (0 when unsampled).
    pub fn min_response_time(&self) -> f64 {
        if self.runtimes.count == 0 {
            0.0
        } else {
            self.runtimes.min
        }
    }

    /// Slowest recorded end-to-end response time in seconds (0 when unsampled).
    pub fn max_response_time(&self) -> f64 {
        self.runtimes.max
    }

    /// Number of recorded response-time samples.
    pub fn sample_count(&self) -> u32 {
        self.runtimes.count
    }

    pub(crate) fn validation_probe(&self) -> Self {
        Self {
            ip: self.ip,
            port: self.port,
            geo: Arc::clone(&self.geo),
            runtimes: self.runtimes,
            expected_types: Arc::from([]),
            proxy_types: Vec::new(),
            text: Arc::clone(&self.text),
        }
    }
}

impl Default for Proxy {
    fn default() -> Self {
        Self::new(Ipv4Addr::new(0, 0, 0, 0), 0)
    }
}

impl Proxy {
    /// Average response time in seconds.
    pub fn avg_response_time(&self) -> f64 {
        self.runtimes.avg()
    }

    /// Returns the proxy in ip:port format.
    pub fn as_text(&self) -> &str {
        &self.text
    }

    /// Serializes the proxy as compact JSON.
    pub fn as_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|error| {
            #[cfg(feature = "log")]
            log::error!("failed to serialize proxy to JSON: {error}");
            #[cfg(not(feature = "log"))]
            let _ = error;
            String::new()
        })
    }

    /// Serializes the proxy as pretty-printed JSON.
    pub fn as_pretty_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|error| {
            #[cfg(feature = "log")]
            log::error!("failed to serialize proxy to pretty JSON: {error}");
            #[cfg(not(feature = "log"))]
            let _ = error;
            String::new()
        })
    }
}

impl Display for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(iso_code) = &self.geo.iso_code {
            write!(f, "<Proxy {}", iso_code)?;
        } else {
            write!(f, "<Proxy --")?;
        }

        write!(f, " {:.2}s [", self.avg_response_time())?;
        match self.proxy_types.as_slice() {
            [] => write!(f, "--")?,
            proxy_types => {
                for (i, proxy_type) in proxy_types.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", proxy_type.protocol)?;
                }
            }
        }
        write!(f, "] {}:{}>", self.ip, self.port)
    }
}

impl FromStr for Proxy {
    type Err = ProxyParseError;

    /// Parses a proxy from text like "1.2.3.4:8080" or "http://1.2.3.4:8080".
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        // Detect a scheme prefix so the protocol can be extracted, then strip
        // it so the parse_pair helper sees a clean `ip:port` head.
        let (scheme, rest) = if let Some(rest) = s.strip_prefix("http://") {
            (Some("http"), rest)
        } else if let Some(rest) = s.strip_prefix("https://") {
            (Some("https"), rest)
        } else if let Some(rest) = s.strip_prefix("socks4://") {
            (Some("socks4"), rest)
        } else if let Some(rest) = s.strip_prefix("socks5://") {
            (Some("socks5"), rest)
        } else {
            (None, s)
        };

        let (ip, port) = crate::providers::parsers::parse_pair(rest)
            .ok_or_else(|| ProxyParseError::MissingSeparator(s.to_string()))?;

        let expected_types: Arc<[Protocol]> =
            match scheme.and_then(crate::providers::parsers::protocol_from_str) {
                Some(protocol) => Arc::from([protocol]),
                None => Arc::from([]),
            };

        Ok(Proxy::with_expected_types(ip, port, expected_types))
    }
}

#[cfg(test)]
mod tests {
    use super::{Anonymity, Protocol, Proxy, ProxyType};
    use std::{net::Ipv4Addr, sync::Arc};

    #[test]
    fn constructor_keeps_cached_host_in_sync() {
        let proxy = Proxy::with_expected_types(
            Ipv4Addr::new(192, 0, 2, 10),
            8080,
            Arc::from([Protocol::Https(Anonymity::Unknown)]),
        );

        assert_eq!(proxy.as_text(), "192.0.2.10:8080");
        assert_eq!(
            proxy.expected_types,
            Arc::from([Protocol::Https(Anonymity::Unknown)])
        );
    }

    #[test]
    fn validation_probe_does_not_copy_advertised_protocols() {
        let proxy = Proxy::with_expected_types(
            Ipv4Addr::new(192, 0, 2, 20),
            3128,
            Arc::from([Protocol::Http(Anonymity::Unknown), Protocol::Socks5]),
        );

        let probe = proxy.validation_probe();

        assert!(probe.expected_types.is_empty());
        assert!(std::sync::Arc::ptr_eq(&probe.geo, &proxy.geo));
        assert_eq!(probe.as_text(), proxy.as_text());
    }

    #[test]
    fn proxies_share_advertised_protocols_and_cached_endpoint() {
        let expected: std::sync::Arc<[Protocol]> =
            std::sync::Arc::from([Protocol::Http(Anonymity::Unknown), Protocol::Socks5]);
        let proxy = Proxy::with_expected_types(
            Ipv4Addr::new(192, 0, 2, 30),
            8080,
            std::sync::Arc::clone(&expected),
        );
        let probe = proxy.validation_probe();

        assert!(std::sync::Arc::ptr_eq(&proxy.expected_types, &expected));
        assert!(std::sync::Arc::ptr_eq(&proxy.text, &probe.text));
    }

    #[test]
    fn json_keeps_historical_keys_and_adds_latency_statistics() {
        let mut proxy = Proxy::new(Ipv4Addr::new(192, 0, 2, 50), 8080);
        proxy.runtimes.record(0.2);
        proxy.runtimes.record(0.8);

        let value = serde_json::to_value(&proxy).unwrap();
        assert_eq!(value["average_response_time"], serde_json::json!(0.5));
        assert_eq!(value["min_response_time"], serde_json::json!(0.2));
        assert_eq!(value["max_response_time"], serde_json::json!(0.8));
        assert_eq!(value["response_time_samples"], serde_json::json!(2));
        // Historical shape is untouched for existing consumers.
        assert!(value["type"].is_null());
        assert_eq!(value["ip"], serde_json::json!("192.0.2.50"));
        assert_eq!(value["port"], serde_json::json!(8080));
        assert!(proxy.min_response_time() > 0.0);
        assert_eq!(proxy.sample_count(), 2);
    }

    #[test]
    fn multi_type_proxy_renders_combined_display_and_json() {
        let mut proxy = Proxy::new(Ipv4Addr::new(192, 0, 2, 40), 10006);
        proxy.proxy_types.push(ProxyType::checked(Protocol::Socks4));
        proxy.proxy_types.push(ProxyType::checked(Protocol::Socks5));

        let rendered = proxy.to_string();
        assert!(rendered.contains("[SOCKS4, SOCKS5]"), "got: {rendered}");

        let value: serde_json::Value = serde_json::from_str(&proxy.as_json()).unwrap();
        let types = value["type"]
            .as_array()
            .expect("multi-type serializes as array");
        assert_eq!(types.len(), 2);
        assert_eq!(types[0]["protocol"], "Socks4");
        assert_eq!(types[1]["protocol"], "Socks5");
    }

    #[test]
    fn single_type_proxy_keeps_object_json_shape() {
        let mut proxy = Proxy::new(Ipv4Addr::new(192, 0, 2, 41), 8080);
        proxy
            .proxy_types
            .push(ProxyType::checked(Protocol::Http(Anonymity::Transparent)));

        let value: serde_json::Value = serde_json::from_str(&proxy.as_json()).unwrap();
        assert!(value["type"].is_object());
        assert_eq!(value["type"]["protocol"]["Http"], "Transparent");
    }

    #[test]
    fn typo_qualifier_falls_back_to_unknown_wildcard() {
        // Regression test: a misspelled anonymity qualifier falls back to
        // `Unknown` instead of inventing a concrete anonymity.
        assert_eq!(
            "HTTP:Elit".parse::<Protocol>().unwrap(),
            Protocol::Http(Anonymity::Unknown)
        );
        assert_eq!(
            "HTTPS:Anonimous".parse::<Protocol>().unwrap(),
            Protocol::Https(Anonymity::Unknown)
        );
        // A well-formed qualifier still parses to a concrete anonymity.
        assert_eq!(
            "HTTP:Elite".parse::<Protocol>().unwrap(),
            Protocol::Http(Anonymity::Elite)
        );
        // A missing qualifier defaults to Unknown wildcard.
        assert_eq!(
            "HTTP".parse::<Protocol>().unwrap(),
            Protocol::Http(Anonymity::Unknown)
        );
    }

    #[test]
    fn anonymity_ranks_lowest_to_highest() {
        assert!(Anonymity::Transparent.rank() < Anonymity::Anonymous.rank());
        assert!(Anonymity::Anonymous.rank() < Anonymity::Elite.rank());
        assert!(Anonymity::Elite.rank() < Anonymity::Unknown.rank());
        assert_eq!(Anonymity::Transparent.rank(), 0);
        assert_eq!(Anonymity::Unknown.rank(), 3);
    }

    #[test]
    fn geo_is_serialized_into_json_output() {
        // Regression test: `Proxy.geo` must appear in `as_json()` output.
        let mut proxy = Proxy::new(Ipv4Addr::new(192, 0, 2, 40), 8080);
        proxy.geo = Arc::new(crate::geolookup::models::GeoData {
            iso_code: Some("ID".into()),
            name: Some("Indonesia".into()),
            region_iso_code: None,
            region_name: None,
            city_name: None,
            ip_type: crate::geolookup::IpType::Residential,
        });

        let json = proxy.as_json();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["geo"]["iso_code"], "ID");
        assert_eq!(value["geo"]["name"], "Indonesia");
        assert_eq!(value["geo"]["ip_type"], "residential");
    }

    #[test]
    fn from_str_parses_bare_ip_port() {
        let proxy: Proxy = "1.2.3.4:8080".parse().unwrap();
        assert_eq!(proxy.ip, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(proxy.port, 8080);
        assert!(proxy.expected_types.is_empty());
    }

    #[test]
    fn from_str_parses_http_prefix() {
        let proxy: Proxy = "http://1.2.3.4:8080".parse().unwrap();
        assert_eq!(proxy.ip, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(proxy.port, 8080);
        assert_eq!(
            proxy.expected_types.as_ref(),
            &[Protocol::Http(Anonymity::Unknown)]
        );
    }

    #[test]
    fn from_str_parses_https_prefix() {
        let proxy: Proxy = "https://5.6.7.8:3128".parse().unwrap();
        assert_eq!(
            proxy.expected_types.as_ref(),
            &[Protocol::Https(Anonymity::Unknown)]
        );
    }

    #[test]
    fn from_str_parses_socks5_prefix() {
        let proxy: Proxy = "socks5://10.0.0.1:1080".parse().unwrap();
        assert_eq!(proxy.expected_types.as_ref(), &[Protocol::Socks5]);
    }

    #[test]
    fn from_str_parses_socks4_prefix() {
        let proxy: Proxy = "socks4://10.0.0.2:1080".parse().unwrap();
        assert_eq!(proxy.expected_types.as_ref(), &[Protocol::Socks4]);
    }

    #[test]
    fn from_str_fails_on_garbage() {
        assert!("garbage".parse::<Proxy>().is_err());
    }

    #[test]
    fn from_str_fails_on_missing_port() {
        assert!("1.2.3.4".parse::<Proxy>().is_err());
    }

    #[test]
    fn from_str_fails_on_invalid_ip() {
        assert!("999.999.999.999:8080".parse::<Proxy>().is_err());
    }
}
