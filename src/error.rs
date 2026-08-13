//! Library error types.

use std::net::AddrParseError;
use std::num::ParseIntError;

use thiserror::Error;

/// Error parsing a proxy from text.
#[derive(Debug, Error)]
pub enum ProxyParseError {
    #[error("missing `:` separator in proxy `{0}`")]
    MissingSeparator(String),
    #[error("invalid IP address `{0}`")]
    InvalidIp(String, #[source] AddrParseError),
    #[error("invalid port `{0}`")]
    InvalidPort(String, #[source] ParseIntError),
}

/// Error parsing a protocol from text.
#[derive(Debug, Error)]
pub enum ProtocolParseError {
    #[error("unknown protocol `{0}`")]
    Unknown(String),
    #[error("invalid CONNECT port `{0}`")]
    InvalidConnectPort(String),
}
