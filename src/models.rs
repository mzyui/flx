use std::{fmt::Display, net::Ipv4Addr, sync::Arc};

use reqwest::Url;

#[derive(Debug, PartialEq)]
pub enum Anonymity {
    Elite,
    Transparent,
    Anonymous,
    Unknown,
}

#[derive(Debug, PartialEq)]
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
            Self::Http(anonimity) => match anonimity {
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

#[derive(Debug)]
pub enum Country {
    Unknown,
    Id(String),
}

impl Display for Country {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "--"),
            Self::Id(id) => write!(f, "{}", id),
        }
    }
}

#[derive(Debug)]
pub struct Proxy {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub country: Country,
    pub avg_response_time: f64,
    pub types: Vec<Arc<Protocol>>,
}

impl Default for Proxy {
    fn default() -> Self {
        Self {
            ip: Ipv4Addr::new(0, 0, 0, 0),
            port: 0,
            country: Country::Unknown,
            avg_response_time: 0.0,
            types: vec![],
        }
    }
}

impl Display for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<Proxy {} {:.2}s [{}] {}:{}>",
            self.country,
            self.avg_response_time,
            self.types
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            self.ip,
            self.port
        )
    }
}

pub struct Source {
    pub url: Url,
    pub default_types: Vec<Arc<Protocol>>,
}

impl Source {
    pub fn new(url: &str, types: Vec<Protocol>) -> Self {
        let types = if types.is_empty() {
            vec![
                Arc::new(Protocol::Http(Anonymity::Unknown)),
                Arc::new(Protocol::Https),
                Arc::new(Protocol::Socks4),
                Arc::new(Protocol::Socks5),
                Arc::new(Protocol::Connect(25)),
                Arc::new(Protocol::Connect(80)),
            ]
        } else {
            types.into_iter().map(Arc::new).collect()
        };

        Self {
            url: Url::parse(url).unwrap(),
            default_types: types,
        }
    }

    pub fn all(url: &str) -> Self {
        Self::new(url, vec![])
    }

    pub fn http(url: &str) -> Self {
        Self::new(
            url,
            vec![
                Protocol::Http(Anonymity::Unknown),
                Protocol::Https,
                Protocol::Connect(80),
                Protocol::Connect(25),
            ],
        )
    }

    pub fn socks(url: &str) -> Self {
        Self::new(url, vec![Protocol::Socks4, Protocol::Socks5])
    }
}
