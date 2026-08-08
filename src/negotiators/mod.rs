//! Proxy handshake negotiators.
//!
//! Each negotiator implements the transport handshake a given proxy protocol
//! requires ([`HttpsNegotiator`] and the SOCKS family establish a tunnel or
//! relay, while plain HTTP needs none). Validation and sending reuse these via
//! the [`NegotiatorTrait`] bound.

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

use crate::proxy::models::RuntimeStats;

/// Handshake behaviour for a proxy protocol class.
#[async_trait]
pub trait NegotiatorTrait {
    /// Establishes the protocol handshake over the connected `stream`.
    ///
    /// # Parameters
    ///
    /// * `stream`: open TCP connection to the proxy.
    /// * `runtimes`: per-phase latency accumulator updated by the handshake.
    /// * `proxy_host`: the proxy's `ip:port`, used in diagnostic messages.
    /// * `uri`: target the caller plans to reach through the proxy.
    ///
    /// # Errors
    ///
    /// Returns an error when the proxy rejects the handshake, times out, or
    /// answers with an unexpected protocol.
    async fn negotiate(
        &self,
        _stream: &mut TcpStream,
        _runtimes: &mut RuntimeStats,
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
