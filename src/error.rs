//! Library error types.

use std::net::AddrParseError;
use std::num::ParseIntError;

use thiserror::Error;
/// Top-level library error.
#[derive(Debug, Error)]
pub enum FlxError {
    #[error("fetch error: {0:#}")]
    Fetch(#[source] anyhow::Error),
    #[error("validation error: {0:#}")]
    Validate(#[source] anyhow::Error),
    #[error("geo lookup error: {0:#}")]
    Geo(#[source] anyhow::Error),
    #[error("io error: {0}")]
    Io(#[source] std::io::Error),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("parse error: {0:#}")]
    Parse(#[source] anyhow::Error),
}

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
