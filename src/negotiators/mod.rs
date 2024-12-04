mod http;
mod https;
mod socks4;

use std::fmt::Display;

use async_trait::async_trait;
pub use http::HttpNegotiator;
pub use https::HttpsNegotiator;
use hyper::Uri;
pub use socks4::Socks4Negotiator;
use tokio::net::TcpStream;

use crate::models::Proxy;

#[async_trait]
pub trait NegotiatorTrait {
    #[allow(unused_variables)]
    async fn negotiate(
        &self,
        stream: &mut TcpStream,
        proxy: &mut Proxy,
        uri: &Uri,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn with_tls(&self) -> bool {
        false
    }

    /// Logs a trace message.
    ///
    /// # Arguments
    ///
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
