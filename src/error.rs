//! Library-level error types.
//!
//! The library surface uses these typed errors (`thiserror`) so callers can
//! match on failure kinds. The CLI binary keeps using `anyhow` for its
//! top-level, human-facing error reporting.

use std::net::AddrParseError;
use std::num::ParseIntError;

use thiserror::Error;

/// Errors produced while parsing a proxy from text.
#[derive(Debug, Error)]
pub enum ProxyParseError {
    /// The line did not contain an `ip:port` pair.
    #[error("missing `:` separator in proxy `{0}`")]
    MissingSeparator(String),
    /// The host part was not a valid IP address.
    #[error("invalid IP address `{0}`")]
    InvalidIp(String, #[source] AddrParseError),
    /// The port part was not a valid u16.
    #[error("invalid port `{0}`")]
    InvalidPort(String, #[source] ParseIntError),
}

/// Errors produced while parsing a [`crate::proxy::models::Protocol`] from text.
#[derive(Debug, Error)]
pub enum ProtocolParseError {
    /// The protocol token was not recognised.
    #[error("unknown protocol `{0}`")]
    Unknown(String),
    /// A `CONNECT:<port>` value carried an invalid port.
    #[error("invalid CONNECT port `{0}`")]
    InvalidConnectPort(String),
}
