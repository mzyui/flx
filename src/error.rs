//! Library error types.

use std::error::Error as StdError;
use std::fmt;
use std::net::AddrParseError;
use std::num::ParseIntError;

/// Top-level library error.
#[derive(Debug)]
pub enum FlxError {
    Fetch(anyhow::Error),
    Validate(anyhow::Error),
    Geo(anyhow::Error),
    Io(std::io::Error),
    Config(String),
    Parse(anyhow::Error),
}

impl fmt::Display for FlxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlxError::Fetch(error) => write!(f, "fetch error: {error:#}"),
            FlxError::Validate(error) => write!(f, "validation error: {error:#}"),
            FlxError::Geo(error) => write!(f, "geo lookup error: {error:#}"),
            FlxError::Io(error) => write!(f, "io error: {error}"),
            FlxError::Config(message) => write!(f, "configuration error: {message}"),
            FlxError::Parse(error) => write!(f, "parse error: {error:#}"),
        }
    }
}

impl StdError for FlxError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            // `anyhow::Error` derefs to `dyn StdError + Send + Sync`, which
            // coerces to the plain trait object `#[source]` produced before.
            FlxError::Fetch(error) => Some(&**error),
            FlxError::Validate(error) => Some(&**error),
            FlxError::Geo(error) => Some(&**error),
            FlxError::Io(error) => Some(error),
            FlxError::Config(_) => None,
            FlxError::Parse(error) => Some(&**error),
        }
    }
}

/// Error parsing a proxy from text.
#[derive(Debug)]
pub enum ProxyParseError {
    MissingSeparator(String),
    InvalidIp(String, AddrParseError),
    InvalidPort(String, ParseIntError),
}

impl fmt::Display for ProxyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyParseError::MissingSeparator(pair) => {
                write!(f, "missing `:` separator in proxy `{pair}`")
            }
            ProxyParseError::InvalidIp(value, _) => write!(f, "invalid IP address `{value}`"),
            ProxyParseError::InvalidPort(value, _) => write!(f, "invalid port `{value}`"),
        }
    }
}

impl StdError for ProxyParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ProxyParseError::MissingSeparator(_) => None,
            ProxyParseError::InvalidIp(_, error) => Some(error),
            ProxyParseError::InvalidPort(_, error) => Some(error),
        }
    }
}

/// Error parsing a protocol from text.
#[derive(Debug)]
pub enum ProtocolParseError {
    Unknown(String),
    InvalidConnectPort(String),
}

impl fmt::Display for ProtocolParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolParseError::Unknown(value) => write!(f, "unknown protocol `{value}`"),
            ProtocolParseError::InvalidConnectPort(value) => {
                write!(f, "invalid CONNECT port `{value}`")
            }
        }
    }
}

impl StdError for ProtocolParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
}
