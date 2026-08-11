pub mod error;
pub mod fetcher;
pub mod geolookup;

pub mod negotiators;
pub mod providers;
pub mod proxy;
pub mod validator;

mod resolver;
mod user_agent;

use fetcher::{Config, ProxyFetcher};
use proxy::models::{Anonymity, Protocol, Proxy};
use std::{
    borrow::Cow,
    fs::File,
    io::{BufRead, BufReader, Cursor, Lines, Write as _},
    net::Ipv4Addr,
    path::PathBuf,
    sync::{Arc, LazyLock},
};
pub use validator::ProxyValidator;

/// Initializes the logging system with the requested verbosity.
///
/// # Errors
///
/// Returns an error if the `stderrlog` logger cannot be initialized.
#[cfg(feature = "log")]
pub fn initialize_logging(log_level: log::LevelFilter) -> anyhow::Result<()> {
    #[cfg(feature = "log")]
    stderrlog::new()
        .module(module_path!())
        .show_module_names(true)
        .verbosity(log_level)
        .init()?;
    Ok(())
}

/// Source of proxies to be validated.
///
/// Wraps a plaintext file of `ip:port` lines, yielding one [`Proxy`] at a
/// time. For provider-fetched proxies use [`ProxySource::from_fetcher`], which
/// returns an asynchronous [`ProxyFetcher`] stream directly instead of a
/// `ProxySource`.
pub struct ProxySource {
    lines: Lines<BufReader<File>>,
    default_proxy_types: Arc<[Protocol]>,
}

/// Default protocol set inherited by proxies read from a file.
///
/// Built once and shared via `Arc::clone` instead of allocating a fresh
/// `Vec<Protocol>` + `Arc` per `ProxySource` (audit A.11).
static FILE_DEFAULT_PROTOCOLS: LazyLock<Arc<[Protocol]>> = LazyLock::new(|| {
    Arc::from([
        Protocol::Http(Anonymity::Unknown),
        Protocol::Https(Anonymity::Unknown),
        Protocol::Socks4,
        Protocol::Socks5,
    ])
});

/// Writes `args` into `buf` using `Cursor`, returning a borrowed view of the
/// written region when possible and an owned `String` only for overlong output.
///
/// The return value is always ASCII (the callers only format ASCII content), so
/// a panic on invalid UTF-8 is a bug.
pub(crate) fn write_to_buffer<'a>(
    buf: &'a mut [u8],
    args: std::fmt::Arguments<'_>,
) -> Cow<'a, str> {
    let mut writer = Cursor::new(buf);
    match writer.write_fmt(args) {
        Ok(()) => {
            let len = writer.position() as usize;
            Cow::Borrowed(std::str::from_utf8(&writer.into_inner()[..len]).expect("ASCII"))
        }
        Err(_) => Cow::Owned(args.to_string()),
    }
}

impl ProxySource {
    /// Starts a [`ProxyFetcher`] fed by every configured provider.
    ///
    /// # Errors
    ///
    /// Returns an error when provider fetching cannot be started
    /// (e.g. invalid configuration or a failed GeoIP setup).
    pub async fn from_fetcher(config: Config) -> anyhow::Result<ProxyFetcher> {
        ProxyFetcher::gather(config).await
    }

    /// Builds a `ProxySource` that reads `ip:port` lines from `filepath`.
    ///
    /// Each parsed proxy inherits the source-wide default protocol set.
    ///
    /// # Errors
    ///
    /// Returns an error if `filepath` cannot be opened.
    pub fn from_file(filepath: PathBuf) -> anyhow::Result<Self> {
        let file = anyhow::Context::with_context(File::open(&filepath), || {
            format!("failed to open proxy file {}", filepath.display())
        })?;
        let buffered_reader = BufReader::new(file);
        let lines = buffered_reader.lines();

        let default_proxy_types = Arc::clone(&FILE_DEFAULT_PROTOCOLS);

        Ok(Self {
            lines,
            default_proxy_types,
        })
    }
}

impl Iterator for ProxySource {
    type Item = Proxy;

    /// Parses the next line into a [`Proxy`], inheriting the source-wide
    /// default protocol set.
    ///
    /// Returns `None` once no parseable `ip:port` line remains.
    fn next(&mut self) -> Option<Self::Item> {
        for line in self.lines.by_ref() {
            let line = match line {
                Ok(line) => line,
                Err(error) => {
                    #[cfg(feature = "log")]
                    log::warn!("failed to read a line from the proxy file: {error}");
                    #[cfg(not(feature = "log"))]
                    let _ = error;
                    continue;
                }
            };
            let mut parts = line.split(':');
            if let Some(Ok(ip_address)) = parts.next().map(|part| part.parse::<Ipv4Addr>()) {
                if let Some(Ok(port_number)) = parts.next().map(|part| part.parse::<u16>()) {
                    let proxy = Proxy::with_expected_types(
                        ip_address,
                        port_number,
                        Arc::clone(&self.default_proxy_types),
                    );

                    return Some(proxy);
                }
            }
        }
        None
    }
}
