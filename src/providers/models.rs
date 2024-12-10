use std::{str::FromStr, time::Duration};

use hyper::Uri;

use crate::proxy::models::{Anonymity, Protocol};

/// Represents a source of proxy information, such as a URL and default protocol types.
pub struct Source {
    pub url: Uri,                     // URL of the proxy source.
    pub default_types: Vec<Protocol>, // Default protocol types for the source.
    pub timeout: Duration,            // Time before giving up on a request.
}

impl Source {
    /// Creates a new `Source` with a specified URL and protocol types.
    ///
    /// # Arguments
    ///
    /// * `url`: The URL of the proxy source.
    /// * `types`: A vector of `Protocol` types.
    ///
    /// # Returns
    ///
    /// A new instance of `Source`.
    pub fn new(url: &str, types: Vec<Protocol>) -> Self {
        let types = if types.is_empty() {
            vec![
                Protocol::Http(Anonymity::Unknown),
                Protocol::Https,
                Protocol::Socks4,
                Protocol::Socks5,
                Protocol::Connect(25),
                Protocol::Connect(80),
            ]
        } else {
            types
        };

        Self {
            url: Uri::from_str(url).unwrap(),
            default_types: types,
            timeout: Duration::from_secs(3),
        }
    }

    /// Creates a `Source` with default common protocols.
    ///
    /// # Arguments
    ///
    /// * `url`: The URL of the proxy source.
    ///
    /// # Returns
    ///
    /// A new instance of `Source` with common protocols.
    pub fn all(url: &str) -> Self {
        Self::new(url, vec![])
    }

    /// Creates a `Source` with default types for HTTP protocols.
    ///
    /// # Arguments
    ///
    /// * `url`: The URL of the proxy source.
    ///
    /// # Returns
    ///
    /// A new instance of `Source` with HTTP protocol types.
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

    /// Creates a `Source` with default types for SOCKS protocols.
    ///
    /// # Arguments
    ///
    /// * `url`: The URL of the proxy source.
    ///
    /// # Returns
    ///
    /// A new instance of `Source` with SOCKS protocol types.
    pub fn socks(url: &str) -> Self {
        Self::new(url, vec![Protocol::Socks4, Protocol::Socks5])
    }
}
