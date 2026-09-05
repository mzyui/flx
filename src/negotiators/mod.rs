//! Negotiate proxy handshakes per protocol.

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

/// Negotiate handshake for a proxy protocol.
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

    /// Report whether negotiation requires TLS upgrade.
    fn with_tls(&self) -> bool {
        false
    }

    /// Log trace line prefixed with proxy_host.
    fn log_trace<S>(&self, _proxy_host: &str, _msg: S)
    where
        S: Display,
    {
        #[cfg(feature = "log")]
        log::trace!("{}: {}", _proxy_host, _msg);
    }

    /// Log error line prefixed with proxy_host.
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
