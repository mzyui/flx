//! Validated proxy endpoint models.
//!
//! [`Proxy`](crate::Proxy) is the unit passed through fetch → validate → filter.
//! [`Protocol`](crate::Protocol) selects the validation path, [`Anonymity`](crate::Anonymity) ranks HTTP(S)
//! privacy, and [`RuntimeStats`](crate::RuntimeStats) tracks response-time samples.

use std::{
    fmt::Display,
    net::Ipv4Addr,
    str::FromStr,
    sync::{Arc, LazyLock},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::{error::ProtocolParseError, error::ProxyParseError, geolookup::models::GeoData};

/// Running response-time statistics for one proxy.
///
/// # Examples
///
/// ```
/// use flx::proxy::models::RuntimeStats;
///
/// let mut stats = RuntimeStats::default();
/// stats.record(0.5);
/// assert_eq!(stats.avg(), 0.5);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct RuntimeStats {
    /// Number of recorded samples.
    pub count: u32,
    /// Sum of all samples, in seconds.
    pub total: f64,
    /// Fastest sample, in seconds.
    pub min: f64,
    /// Slowest sample, in seconds.
    pub max: f64,
}

impl RuntimeStats {
    /// Records one timing sample, in seconds.
    ///
    /// # Examples
    ///
    /// ```
    /// use flx::proxy::models::RuntimeStats;
    ///
    /// let mut stats = RuntimeStats::default();
    /// stats.record(0.2);
    /// assert_eq!(stats.count, 1);
    /// ```
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

    /// Returns the mean sample, or `0.0` when unsampled.
    ///
    /// # Examples
    ///
    /// ```
    /// use flx::proxy::models::RuntimeStats;
    ///
    /// assert_eq!(RuntimeStats::default().avg(), 0.0);
    /// ```
    pub fn avg(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.total / self.count as f64
        }
    }
}

/// HTTP(S) anonymity level, ordered by [`Anonymity::rank`].
///
/// Unknown levels match any requested level on the same family.
///
/// # Examples
///
/// ```
/// use flx::{Anonymity, Protocol};
///
/// let elite = Protocol::Http(Anonymity::Elite);
/// assert!(matches!(elite, Protocol::Http(Anonymity::Elite)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Anonymity {
    /// Server sees neither client IP nor proxy usage.
    Elite,
    /// Server sees the request came via a proxy.
    Transparent,
    /// Server sees a proxy was used but not the client IP.
    Anonymous,
    /// Anonymity was not advertised or not yet probed.
    Unknown,
}

impl Anonymity {
    /// Ranks anonymity from least to most anonymous.
    ///
    /// Transparent (0) < Anonymous (1) < Elite (2); Unknown (3) sorts last
    /// so unclassified candidates are not silently preferred.
    ///
    /// # Examples
    ///
    /// ```
    /// use flx::Anonymity;
    ///
    /// assert!(Anonymity::Elite.rank() > Anonymity::Transparent.rank());
    /// ```
    pub fn rank(self) -> u8 {
        match self {
            Anonymity::Transparent => 0,
            Anonymity::Anonymous => 1,
            Anonymity::Elite => 2,
            Anonymity::Unknown => 3,
        }
    }
}

/// Proxy protocol under test; selects the validation path.
///
/// `+` groups in type syntax (e.g. `HTTP+HTTPS`) combine variants; `:`
/// suffixes pin [`Anonymity`] (e.g. `HTTP:Elite`).
///
/// # Examples
///
/// ```
/// use flx::Protocol;
///
/// let protocol: Protocol = "SOCKS5".parse().unwrap();
/// assert_eq!(protocol, Protocol::Socks5);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// Plain HTTP proxy with an anonymity level.
    Http(Anonymity),
    /// HTTP CONNECT tunnel with an anonymity level.
    Https(Anonymity),
    /// SOCKS4 proxy.
    Socks4,
    /// SOCKS5 proxy.
    Socks5,
    /// Raw CONNECT tunnel to `port`.
    Connect(u16),
}

// Serialize every variant as an object so consumers never branch on
// string-vs-object: Http/Https carry anonymity, Connect carries port,
// SOCKS carries family only.
impl Serialize for Protocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        match self {
            Self::Http(anonymity) => {
                let mut state = serializer.serialize_struct("Protocol", 2)?;
                state.serialize_field("family", "Http")?;
                state.serialize_field("anonymity", anonymity)?;
                state.end()
            }
            Self::Https(anonymity) => {
                let mut state = serializer.serialize_struct("Protocol", 2)?;
                state.serialize_field("family", "Https")?;
                state.serialize_field("anonymity", anonymity)?;
                state.end()
            }
            Self::Socks4 => {
                let mut state = serializer.serialize_struct("Protocol", 1)?;
                state.serialize_field("family", "Socks4")?;
                state.end()
            }
            Self::Socks5 => {
                let mut state = serializer.serialize_struct("Protocol", 1)?;
                state.serialize_field("family", "Socks5")?;
                state.end()
            }
            Self::Connect(port) => {
                let mut state = serializer.serialize_struct("Protocol", 2)?;
                state.serialize_field("family", "Connect")?;
                state.serialize_field("port", port)?;
                state.end()
            }
        }
    }
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

fn parse_anonymity(qualifier: Option<&str>) -> Result<Anonymity, ProtocolParseError> {
    match qualifier.map(str::trim) {
        None | Some("") => Ok(Anonymity::Unknown),
        Some(level) if level.eq_ignore_ascii_case("transparent") => Ok(Anonymity::Transparent),
        Some(level) if level.eq_ignore_ascii_case("anonymous") => Ok(Anonymity::Anonymous),
        Some(level) if level.eq_ignore_ascii_case("elite") => Ok(Anonymity::Elite),
        Some(level) => Err(ProtocolParseError::UnknownAnonymity(level.to_string())),
    }
}

impl FromStr for Protocol {
    type Err = ProtocolParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(':');
        let head = parts.next().unwrap_or_default();
        match head {
            "HTTP" => Ok(Protocol::Http(parse_anonymity(parts.next())?)),
            "HTTPS" => Ok(Protocol::Https(parse_anonymity(parts.next())?)),
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

/// One validated protocol on a [`Proxy`].
#[derive(Debug, Clone, Serialize)]
pub struct ProxyType {
    /// Protocol that passed validation.
    pub protocol: Protocol,
    /// Whether this protocol was checked.
    #[serde(skip)]
    pub checked: bool,
    /// Unix timestamp of the check, in seconds.
    pub checked_on: f64,
}

impl ProxyType {
    /// Creates an unchecked protocol entry.
    ///
    /// # Examples
    ///
    /// ```
    /// use flx::{Protocol, ProxyType};
    ///
    /// let entry = ProxyType::new(Protocol::Socks5);
    /// assert!(!entry.checked);
    /// ```
    pub fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            checked: false,
            checked_on: 0.0,
        }
    }
    /// Mark protocol checked with current timestamp.
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

/// Validated proxy endpoint with geo and timing metadata.
///
/// Parse from `ip:port` or scheme-prefixed text; bare lines leave
/// `expected_types` empty until the caller assigns defaults.
///
/// # Examples
///
/// ```
/// use flx::Proxy;
///
/// let proxy: Proxy = "1.2.3.4:8080".parse().unwrap();
/// assert_eq!(proxy.as_text(), "1.2.3.4:8080");
/// ```
#[derive(Debug, Clone)]
pub struct Proxy {
    /// Proxy IPv4 address.
    pub ip: Ipv4Addr,
    /// Proxy TCP port.
    pub port: u16,
    /// GeoIP record; empty when lookup is disabled.
    pub geo: Arc<GeoData>,
    /// Response-time samples across validations.
    pub runtimes: RuntimeStats,
    /// Protocols to probe; empty means "assign caller defaults".
    pub expected_types: Arc<[Protocol]>,
    /// Protocols that passed validation.
    pub proxy_types: Vec<ProxyType>,
    pub(crate) text: Arc<str>,
}

// Split latency stats while keeping historical JSON keys intact.
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
        state.serialize_field("type", &self.proxy_types)?;
        state.end()
    }
}

static DEFAULT_GEO: LazyLock<Arc<GeoData>> = LazyLock::new(|| Arc::new(GeoData::default()));

impl Proxy {
    /// Creates an endpoint with empty geo, timings, and type sets.
    ///
    /// # Examples
    ///
    /// ```
    /// use flx::Proxy;
    ///
    /// let proxy = Proxy::new("1.2.3.4".parse().unwrap(), 8080);
    /// assert_eq!(proxy.as_text(), "1.2.3.4:8080");
    /// ```
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

    /// Attaches the protocols to probe for this endpoint.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use flx::{Protocol, Proxy};
    ///
    /// let proxy = Proxy::with_expected_types(
    ///     "1.2.3.4".parse().unwrap(),
    ///     8080,
    ///     Arc::from([Protocol::Socks5]),
    /// );
    /// assert_eq!(proxy.expected_types.as_ref(), &[Protocol::Socks5]);
    /// ```
    pub fn with_expected_types(ip: Ipv4Addr, port: u16, expected_types: Arc<[Protocol]>) -> Self {
        let mut proxy = Self::new(ip, port);
        proxy.expected_types = expected_types;
        proxy
    }

    /// Report fastest response time, or 0 when unsampled.
    pub fn min_response_time(&self) -> f64 {
        if self.runtimes.count == 0 {
            0.0
        } else {
            self.runtimes.min
        }
    }

    /// Report slowest response time, or 0 when unsampled.
    pub fn max_response_time(&self) -> f64 {
        self.runtimes.max
    }

    /// Count recorded response-time samples.
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
    /// Returns the mean response time, or `0.0` when unsampled.
    ///
    /// # Examples
    ///
    /// ```
    /// use flx::Proxy;
    ///
    /// let proxy: Proxy = "1.2.3.4:8080".parse().unwrap();
    /// assert_eq!(proxy.avg_response_time(), 0.0);
    /// ```
    pub fn avg_response_time(&self) -> f64 {
        self.runtimes.avg()
    }

    /// Format proxy as ip:port text.
    pub fn as_text(&self) -> &str {
        &self.text
    }

    /// Serialize proxy as compact JSON.
    pub fn as_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|error| {
            #[cfg(feature = "log")]
            log::error!("failed to serialize proxy to JSON: {error}");
            #[cfg(not(feature = "log"))]
            let _ = error;
            String::new()
        })
    }

    /// Serialize proxy as pretty-printed JSON.
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

    /// Parse proxy from "1.2.3.4:8080" or scheme-prefixed text.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        // Strip scheme prefix so helper sees clean ip:port head.
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
        // `type` is always an array, even when empty.
        assert_eq!(value["type"], serde_json::json!([]));
        assert_eq!(value["ip"], serde_json::json!("192.0.2.50"));
        assert_eq!(value["port"], serde_json::json!(8080));
        assert!(proxy.min_response_time() > 0.0);
        assert_eq!(proxy.sample_count(), 2);
    }

    #[test]
    fn proxy_without_geo_lookup_serializes_empty_geo_object() {
        // `Proxy::new` carries the shared default geo (no lookup ran).
        let proxy = Proxy::new(Ipv4Addr::new(192, 0, 2, 60), 8080);
        let value: serde_json::Value = serde_json::from_str(&proxy.as_json()).unwrap();
        assert_eq!(value["geo"], serde_json::json!({}));
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
        assert_eq!(types[0]["protocol"]["family"], "Socks4");
        assert_eq!(types[1]["protocol"]["family"], "Socks5");
    }

    #[test]
    fn single_type_proxy_serializes_as_single_element_array() {
        let mut proxy = Proxy::new(Ipv4Addr::new(192, 0, 2, 41), 8080);
        proxy
            .proxy_types
            .push(ProxyType::checked(Protocol::Http(Anonymity::Transparent)));

        let value: serde_json::Value = serde_json::from_str(&proxy.as_json()).unwrap();
        let types = value["type"]
            .as_array()
            .expect("single type serializes as array");
        assert_eq!(types.len(), 1);
        assert_eq!(types[0]["protocol"]["family"], "Http");
        assert_eq!(types[0]["protocol"]["anonymity"], "Transparent");
    }

    #[test]
    fn every_protocol_family_serializes_as_object() {
        let cases = [
            (
                Protocol::Https(Anonymity::Elite),
                serde_json::json!({"family": "Https", "anonymity": "Elite"}),
            ),
            (Protocol::Socks5, serde_json::json!({"family": "Socks5"})),
            (
                Protocol::Connect(80),
                serde_json::json!({"family": "Connect", "port": 80}),
            ),
        ];
        for (protocol, expected) in cases {
            assert_eq!(serde_json::to_value(protocol).unwrap(), expected);
        }
    }

    #[test]
    fn unknown_qualifier_rejects_typos_but_accepts_any_case() {
        assert!("HTTP:Elit".parse::<Protocol>().is_err());
        assert!("HTTPS:Anonimous".parse::<Protocol>().is_err());
        assert_eq!(
            "HTTP:elite".parse::<Protocol>().unwrap(),
            Protocol::Http(Anonymity::Elite)
        );
        assert_eq!(
            "HTTPS:ANONYMOUS".parse::<Protocol>().unwrap(),
            Protocol::Https(Anonymity::Anonymous)
        );
    }

    #[test]
    fn missing_or_empty_qualifier_stays_an_unknown_wildcard() {
        assert_eq!(
            "HTTP".parse::<Protocol>().unwrap(),
            Protocol::Http(Anonymity::Unknown)
        );
        assert_eq!(
            "HTTP:".parse::<Protocol>().unwrap(),
            Protocol::Http(Anonymity::Unknown)
        );
        assert_eq!(
            "HTTP:Elite".parse::<Protocol>().unwrap(),
            Protocol::Http(Anonymity::Elite)
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
            asn: Some(17995),
            aso: Some("PT Telekomunikasi Indonesia".into()),
            ip_type: crate::geolookup::IpType::Residential,
            continent_code: Some("AS".into()),
            continent_name: Some("Asia".into()),
            latitude: Some(-6.2),
            longitude: Some(106.8),
            timezone: Some("Asia/Jakarta".into()),
            zip: Some("10110".into()),
        });

        let json = proxy.as_json();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["geo"]["iso_code"], "ID");
        assert_eq!(value["geo"]["name"], "Indonesia");
        assert_eq!(value["geo"]["asn"], 17995);
        assert_eq!(value["geo"]["aso"], "PT Telekomunikasi Indonesia");
        assert_eq!(value["geo"]["ip_type"], "residential");
        assert_eq!(value["geo"]["continent_code"], "AS");
        assert_eq!(value["geo"]["latitude"], -6.2);
        assert_eq!(value["geo"]["timezone"], "Asia/Jakarta");
        assert_eq!(value["geo"]["zip"], "10110");
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
