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

use crate::models::Proxy;

/// Trait defining the negotiation behavior for different proxy types.
#[async_trait]
pub trait NegotiatorTrait {
    /// Negotiates a connection with the proxy.
    ///
    /// # Arguments
    ///
    /// * `stream`: The TCP stream to negotiate.
    /// * `proxy`: The proxy being used for the negotiation.
    /// * `uri`: The URI to be accessed through the proxy.
    ///
    /// # Returns
    ///
    /// A result indicating success or failure of the negotiation.
    #[allow(unused_variables)] // Allows unused variables for trait methods.
    async fn negotiate(
        &self,
        stream: &mut TcpStream,
        proxy: &mut Proxy,
        uri: &Uri,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Determines if the negotiator requires TLS.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether TLS is required.
    fn with_tls(&self) -> bool {
        false
    }

    /// Logs a trace message.
    ///
    /// # Arguments
    ///
    /// * `proxy`: The proxy associated with the log message.
    /// * `msg`: The message to log.
    fn log_trace<S>(&self, proxy: &Proxy, msg: S)
    where
        S: Display,
    {
        #[cfg(feature = "log")]
        log::trace!("{}: {}", proxy.as_text(), msg);
    }

    /// Logs an error message.
    ///
    /// # Arguments
    ///
    /// * `proxy`: The proxy associated with the error message.
    /// * `msg`: The message to log as an error.
    fn log_error<S>(&self, proxy: &Proxy, msg: S)
    where
        S: Display,
    {
        #[cfg(feature = "log")]
        if log::max_level().eq(&log::LevelFilter::Trace) {
            log::error!("{}: {}", proxy.as_text(), msg);
        }
    }
}
