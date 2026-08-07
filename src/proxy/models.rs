use std::{
    fmt::Display,
    net::Ipv4Addr,
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Serialize, Serializer};

use crate::{error::ProtocolParseError, geolookup::models::GeoData};

// ── RuntimeStats ──────────────────────────────────────────────────────

/// Online running statistics for response-time tracking.
///
/// Stores count, total, min and max so the average can be computed at any
/// point without keeping every individual sample in memory.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuntimeStats {
    pub count: u32,
    pub total: f64,
    pub min: f64,
    pub max: f64,
}

impl RuntimeStats {
    /// Records a single timing sample (in seconds).
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

    /// Average response time in seconds, or 0.0 when no samples exist.
    pub fn avg(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.total / self.count as f64
        }
    }
}

// ── Anonymity ─────────────────────────────────────────────────────────

/// Represents the level of anonymity of a proxy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum Anonymity {
    /// Elite anonymity: No IP address or headers are leaked.
    Elite,
    /// Transparent anonymity: Original IP address is visible.
    Transparent,
    /// Anonymous anonymity: Some headers may be leaked, but IP is hidden.
    Anonymous,
    /// Anonymity is unknown.
    Unknown,
}

// ── Protocol ─────────────────────────────────────────────────────────

/// Represents different protocols that a proxy can support.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
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

    /// Parses a protocol token such as `HTTP`, `HTTP:Elite`, `HTTPS`,
    /// `HTTPS:Anonymous`, `SOCKS5` or `CONNECT:8080`.
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

/// Represents a type of proxy with its protocol and checked status.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyType {
    /// The protocol of the proxy.
    pub protocol: Protocol,
    /// Indicates if the proxy has been checked
    #[serde(skip)]
    pub checked: bool,
    /// Time when this proxy type was checked
    pub checked_on: f64,
}

impl ProxyType {
    /// Creates a new `ProxyType` with the specified protocol.
    pub fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            checked: false,
            checked_on: 0.0,
        }
    }
    /// Creates a new `ProxyType` with the specified protocol. marked as checked
    ///
    /// If the system clock is set before the unix epoch the timestamp falls
    /// back to `0.0` rather than panicking.
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

fn serialize_runtimes<S>(runtimes: &RuntimeStats, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_f64(runtimes.avg())
}

// ── Proxy ─────────────────────────────────────────────────────────────

/// Represents a proxy with its details.
#[derive(Debug, Clone, Serialize)]
pub struct Proxy {
    /// IP address of the proxy.
    pub ip: Ipv4Addr,
    /// Port number of the proxy.
    pub port: u16,
    /// Geographical data associated with the proxy.
    pub geo: Arc<GeoData>,
    /// Running response-time statistics (replaces unbounded Vec<f64>).
    #[serde(
        rename = "average_response_time",
        serialize_with = "serialize_runtimes"
    )]
    pub runtimes: RuntimeStats,
    #[serde(skip)]
    pub expected_types: Arc<[Protocol]>,
    #[serde(rename = "type")]
    pub proxy_type: Option<ProxyType>,
    /// Precomputed `ip:port` text, cached to avoid re-formatting on every hot-path call.
    #[serde(skip)]
    pub(crate) text: Arc<str>,
}

impl Proxy {
    /// Builds a proxy, precomputing its `ip:port` text representation.
    pub fn new(ip: Ipv4Addr, port: u16) -> Self {
        Self {
            ip,
            port,
            geo: Arc::new(GeoData::default()),
            runtimes: RuntimeStats::default(),
            expected_types: Arc::from([]),
            proxy_type: None,
            text: Arc::from(format!("{}:{}", ip, port)),
        }
    }

    /// Builds a proxy and assigns the protocols advertised by its source.
    pub fn with_expected_types(ip: Ipv4Addr, port: u16, expected_types: Arc<[Protocol]>) -> Self {
        let mut proxy = Self::new(ip, port);
        proxy.expected_types = expected_types;
        proxy
    }

    /// Creates the minimal mutable state needed by one validation job.
    pub(crate) fn validation_probe(&self) -> Self {
        Self {
            ip: self.ip,
            port: self.port,
            geo: Arc::clone(&self.geo),
            runtimes: self.runtimes,
            expected_types: Arc::from([]),
            proxy_type: None,
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
    /// Calculates the average proxy response time.
    ///
    /// # Returns
    ///
    /// The average response time as a `f64`. Returns 0.0 if no runtimes are recorded.
    pub fn avg_response_time(&self) -> f64 {
        self.runtimes.avg()
    }

    /// Returns the proxy in `<ip>:<port>` format (precomputed, zero-allocation).
    pub fn as_text(&self) -> &str {
        &self.text
    }

    /// Converts the proxy details to JSON format.
    ///
    /// # Returns
    ///
    /// A result containing the JSON string or an error.
    pub fn as_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

impl Display for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(iso_code) = &self.geo.iso_code {
            write!(f, "<Proxy {}", iso_code)?;
        } else {
            write!(f, "<Proxy --")?;
        }

        write!(
            f,
            " {:.2}s [{}] {}:{}>",
            self.avg_response_time(),
            self.proxy_type
                .as_ref()
                .map(|v| format!("{}", v.protocol))
                .unwrap_or("--".into()),
            self.ip,
            self.port
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Anonymity, Protocol, Proxy};
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
    fn typo_qualifier_falls_back_to_unknown_wildcard() {
        // Regression for F-28: a misspelled anonymity qualifier (e.g.
        // `HTTP:Elit` or `HTTPS:Anonimous`) must not invent a concrete
        // anonymity; it falls back to `Unknown` so matching stays a wildcard.
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
    fn geo_is_serialized_into_json_output() {
        // Regression for F-35: `Proxy.geo` must appear in `as_json()` output
        // (README documents the `geo` field). Previously `#[serde(skip)]`
        // omitted it.
        let mut proxy = Proxy::new(Ipv4Addr::new(192, 0, 2, 40), 8080);
        proxy.geo = Arc::new(crate::geolookup::models::GeoData {
            iso_code: Some("ID".to_owned()),
            name: Some("Indonesia".to_owned()),
            region_iso_code: None,
            region_name: None,
            city_name: None,
        });

        let json = proxy.as_json();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["geo"]["iso_code"], "ID");
        assert_eq!(value["geo"]["name"], "Indonesia");
    }
}
