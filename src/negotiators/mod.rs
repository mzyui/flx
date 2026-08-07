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

/// Trait defining the negotiation behavior for different proxy types.
#[async_trait]
pub trait NegotiatorTrait {
    /// Negotiates a connection with the proxy.
    ///
    /// # Arguments
    ///
    /// * `stream`: The TCP stream to negotiate.
    /// * `runtimes`: Running timing statistics, updated with each phase.
    /// * `proxy_host`: The proxy address (ip:port).
    /// * `uri`: The URI to be accessed through the proxy.
    ///
    /// # Returns
    ///
    /// A result indicating success or failure of the negotiation.
    async fn negotiate(
        &self,
        _stream: &mut TcpStream,
        _runtimes: &mut RuntimeStats,
        _proxy_host: &str,
        _uri: &Uri,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Determines if the negotiator requires TLS.
    fn with_tls(&self) -> bool {
        false
    }

    /// Logs a trace message.
    fn log_trace<S>(&self, _proxy_host: &str, _msg: S)
    where
        S: Display,
    {
        #[cfg(feature = "log")]
        log::trace!("{}: {}", _proxy_host, _msg);
    }

    /// Logs an error message.
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
