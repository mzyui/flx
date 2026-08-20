//! Proxy handshake negotiators.

mod http;
mod https;
mod socks4;
mod socks5;

use std::fmt::Display;

use async_trait::async_trait;
pub use http::HttpNegotiator;
pub use https::HttpsNegotiator;
use hyper::Uri;
pub use socks4::Socks4Negotiator;
pub use socks5::Socks5Negotiator;
use tokio::net::TcpStream;

/// Handshake behaviour for a proxy protocol.
#[async_trait]
pub trait NegotiatorTrait {
    async fn negotiate(
        &self,
        _stream: &mut TcpStream,
        _proxy_host: &str,
        _uri: &Uri,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Whether the connection must be upgraded to TLS after negotiation.
    fn with_tls(&self) -> bool {
        false
    }

    /// Emits a `trace`-level log line prefixed with `proxy_host`.
    fn log_trace<S>(&self, _proxy_host: &str, _msg: S)
    where
        S: Display,
    {
        #[cfg(feature = "log")]
        log::trace!("{}: {}", _proxy_host, _msg);
    }

    /// Emits an `error`-level log line prefixed with `proxy_host`.
    ///
    /// Only forwarded when the configured level is `Trace`, so a noisy error
    /// cannot drown out genuinely higher-priority messages.
    fn log_error<S>(&self, _proxy_host: &str, _msg: S)
    where
        S: Display,
    {
        #[cfg(feature = "log")]
        if log::max_level().eq(&log::LevelFilter::Trace) {
            log::error!("{}: {}", _proxy_host, _msg);
        }
    }
}
