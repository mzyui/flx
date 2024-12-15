pub mod fetcher;
pub mod geolookup;
pub mod negotiators;
pub mod providers;
pub mod proxy;
pub mod validator;

mod utils;

use fetcher::{Config, ProxyFetcher};
use proxy::models::{Anonymity, Protocol, Proxy, ProxyType};
use std::{
    fs::File,
    io::{BufReader, Lines},
};
use std::{io::BufRead, net::Ipv4Addr, path::PathBuf};
pub use validator::ProxyValidator;

/// Initializes the logging system for the application.
///
/// This function configures the logging system with the specified verbosity level.
///
/// # Arguments
///
/// * `log_level`: The desired verbosity level for logging. Determines which log messages will be displayed.
///
/// # Returns
///
/// A result indicating the success or failure of the logging setup.
#[cfg(feature = "log")]
pub fn initialize_logging(log_level: log::LevelFilter) -> anyhow::Result<()> {
    #[cfg(feature = "log")]
    stderrlog::new()
        .module(module_path!()) // Configures the module path for log messages.
        .show_module_names(true) // Enables module names in log output.
        .verbosity(log_level) // Sets the specified log verbosity level.
        .init()?; // Initializes the logger.
    Ok(())
}

/// Represents a source of proxy servers, either from a file or a network fetcher.
pub struct ProxySource {
    lines: Lines<BufReader<File>>,
    default_proxy_types: Vec<ProxyType>,
}

impl ProxySource {
    /// Creates a new `ProxyFetcher` from the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config`: The configuration to use for fetching proxies.
    ///
    /// # Returns
    ///
    /// A result containing the `ProxyFetcher` or an error if the operation fails.
    pub async fn from_fetcher(config: Config) -> anyhow::Result<ProxyFetcher> {
        ProxyFetcher::gather(config).await
    }

    /// Creates a `ProxySource` from a specified file path.
    ///
    /// # Arguments
    ///
    /// * `filepath`: The path to the file containing proxy server information.
    ///
    /// # Returns
    ///
    /// A result containing the `ProxySource` or an error if the operation fails.
    pub fn from_file(filepath: PathBuf) -> anyhow::Result<Self> {
        let file = File::open(filepath)?;
        let buffered_reader = BufReader::new(file);
        let lines = buffered_reader.lines();

        let default_proxy_types = vec![
            ProxyType::new(Protocol::Http(Anonymity::Unknown)),
            ProxyType::new(Protocol::Https),
            ProxyType::new(Protocol::Socks4),
            ProxyType::new(Protocol::Socks5),
        ];

        Ok(Self {
            lines,
            default_proxy_types,
        })
    }
}

impl Iterator for ProxySource {
    type Item = Proxy;

    /// Retrieves the next proxy from the source.
    ///
    /// This method attempts to parse the next line into a `Proxy` object.
    ///
    /// # Returns
    ///
    /// An optional `Proxy` if one was successfully parsed, otherwise `None`.
    fn next(&mut self) -> Option<Self::Item> {
        for line in self.lines.by_ref().flatten() {
            let mut parts = line.split(':');
            if let Some(Ok(ip_address)) = parts.next().map(|part| part.parse::<Ipv4Addr>()) {
                if let Some(Ok(port_number)) = parts.next().map(|part| part.parse::<u16>()) {
                    let proxy = Proxy {
                        ip: ip_address,
                        port: port_number,
                        types: self.default_proxy_types.clone(),
                        ..Default::default()
                    };

                    return Some(proxy);
                }
            }
        }
        None
    }
}
