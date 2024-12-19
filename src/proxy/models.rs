use std::{
    borrow::Cow,
    fmt::Display,
    net::Ipv4Addr,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Serialize, Serializer};

use crate::geolookup::models::GeoData;

/// Represents the level of anonymity of a proxy.
#[derive(Debug, Clone, PartialEq, Serialize)]
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

/// Represents different protocols that a proxy can support.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Protocol {
    Http(Anonymity),
    Https,
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
            Self::Https => write!(f, "HTTPS"),
            Self::Socks4 => write!(f, "SOCKS4"),
            Self::Socks5 => write!(f, "SOCKS5"),
            Self::Connect(port) => write!(f, "CONNECT:{}", port),
        }
    }
}

/// Represents a type of proxy with its protocol and checked status.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyType {
    /// The protocol of the proxy.
    pub protocol: Protocol,
    /// Indicates if the proxy has been checked
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
    pub fn checked(protocol: Protocol) -> Self {
        Self {
            protocol,
            checked: true,
            checked_on: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
        }
    }
}

fn serialize_runtimes<S>(runtimes: &[f64], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if runtimes.is_empty() {
        return serializer.serialize_f64(0.0);
    }
    let sum: f64 = runtimes.iter().sum();
    serializer.serialize_f64(sum / runtimes.len() as f64)
}

/// Represents a proxy with its details.
#[derive(Debug, Clone, Serialize)]
pub struct Proxy {
    /// IP address of the proxy.
    pub ip: Ipv4Addr,
    /// Port number of the proxy.
    pub port: u16,
    /// Geographical data associated with the proxy.
    pub geo: GeoData,
    /// Response times for the proxy.
    #[serde(
        rename = "average_response_time",
        serialize_with = "serialize_runtimes"
    )]
    pub runtimes: Vec<f64>,
    /// Supported protocols for the proxy.
    pub types: Vec<ProxyType>,
}

impl Proxy {
    /// Calculates the average proxy response time.
    ///
    /// # Returns
    ///
    /// The average response time as a `f64`. Returns 0.0 if no runtimes are recorded.
    pub fn avg_response_time(&self) -> f64 {
        if self.runtimes.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.runtimes.iter().sum();
        sum / self.runtimes.len() as f64
    }

    /// Returns the proxy in `<ip>:<port>` format.
    ///
    /// # Returns
    ///
    /// A `Cow<'static, str>` representing the proxy address.
    pub fn as_text(&self) -> Cow<'static, str> {
        Cow::Owned(format!("{}:{}", self.ip, self.port))
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

impl Default for Proxy {
    fn default() -> Self {
        Self {
            ip: Ipv4Addr::new(0, 0, 0, 0),
            port: 0,
            geo: GeoData::default(),
            runtimes: vec![],
            types: vec![],
        }
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
            self.types
                .iter()
                .filter_map(|proxy_type| {
                    if proxy_type.checked {
                        Some(proxy_type.protocol.to_string())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join(", "),
            self.ip,
            self.port
        )
    }
}
