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

use crate::proxy::models::ProxyAuth;

/// Negotiate handshake for a proxy protocol.
#[async_trait]
pub trait NegotiatorTrait {
    /// Runs the protocol handshake over the connected socket.
    ///
    /// The default impl is a no-op for direct connections; overrides speak
    /// the proxy protocol before the request is sent.
    ///
    /// # Errors
    ///
    /// Returns an error when the handshake fails.
    async fn negotiate(
        &self,
        _stream: &mut TcpStream,
        _proxy_host: &str,
        _uri: &Uri,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Runs the handshake with `auth` when the proxy requires it.
    ///
    /// The default impl ignores `auth` and runs the anonymous [`negotiate`](Self::negotiate).
    /// Overrides speak the per-protocol auth exchange: `Basic` on `CONNECT`
    /// for HTTPS, RFC 1929 username/password for SOCKS5, `USERID` for SOCKS4.
    /// Plain HTTP carries auth as a request header instead, so [`HttpNegotiator`](crate::negotiators::HttpNegotiator)
    /// keeps the default.
    ///
    /// # Errors
    ///
    /// Returns an error when the handshake or the auth exchange fails.
    async fn negotiate_with_auth(
        &self,
        stream: &mut TcpStream,
        proxy_host: &str,
        uri: &Uri,
        auth: Option<&ProxyAuth>,
    ) -> anyhow::Result<()> {
        let _ = auth;
        self.negotiate(stream, proxy_host, uri).await
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
