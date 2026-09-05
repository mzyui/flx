//! Defines library error types.

use std::error::Error as StdError;
use std::fmt;
use std::net::AddrParseError;
use std::num::ParseIntError;

/// Top-level library error.
///
/// Each variant preserves its source; match on it to decide retry vs abort.
#[derive(Debug)]
pub enum FlxError {
    /// Fetching from providers failed; safe to retry with backoff.
    Fetch(anyhow::Error),
    /// Validation startup failed (bad config or dead judges).
    Validate(anyhow::Error),
    /// GeoIP lookup or database sync failed; results may lack country data.
    Geo(anyhow::Error),
    /// File or cache I/O failed.
    Io(std::io::Error),
    /// Invalid builder combination (e.g. no validation target selected).
    Config(String),
    /// Proxy text could not be parsed.
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
            // Derefs anyhow errors to plain std errors.
            FlxError::Fetch(error) => Some(&**error),
            FlxError::Validate(error) => Some(&**error),
            FlxError::Geo(error) => Some(&**error),
            FlxError::Io(error) => Some(error),
            FlxError::Config(_) => None,
            FlxError::Parse(error) => Some(&**error),
        }
    }
}

/// Rejects malformed proxy text.
#[derive(Debug)]
pub enum ProxyParseError {
    /// Reports a missing separator.
    MissingSeparator(String),
    /// Reports an invalid IP address.
    InvalidIp(String, AddrParseError),
    /// Reports an invalid port.
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

/// Rejects malformed protocol text.
#[derive(Debug)]
pub enum ProtocolParseError {
    /// Reports an unknown protocol.
    Unknown(String),
    /// Reports an invalid CONNECT port.
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
