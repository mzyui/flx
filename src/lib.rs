//! Proxy scraper and validator library.
//!
//! # Example
//!
//! ```no_run
//! use fluxy::{Anonymity, Fluxy, Protocol};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let proxies = Fluxy::fetch()
//!         .types([Protocol::Http(Anonymity::Elite)])
//!         .limit(20)
//!         .collect()
//!         .await?;
//!
//!     for proxy in &proxies {
//!         println!("{}", proxy.as_text());
//!     }
//!     Ok(())
//! }
//! ```

pub mod error;
pub mod fetcher;
pub mod geolookup;

mod api;
pub mod negotiators;
pub mod providers;
pub mod proxy;
pub mod validator;

mod resolver;
mod user_agent;

use std::{
    borrow::Cow,
    fs::File,
    io::{BufRead, BufReader, Cursor, Lines, Write as _},
    path::PathBuf,
    sync::{Arc, LazyLock},
};

// ── Root re-exports ───────────────────────────────────────────────────

pub use api::Fluxy;
pub use error::{ProtocolParseError, ProxyParseError};
pub use fetcher::{Config as FetcherConfig, ProxyFetcher};
pub use geolookup::models::GeoData;
pub use geolookup::{sync_database, GeoLookup, SyncOutcome};
pub use providers::all_providers;
pub use providers::models::{ProviderTier, ScrapeMode, Source};
pub use providers::ProxyProvider;
pub use proxy::models::{Anonymity, Protocol, Proxy, ProxyType, RuntimeStats};
pub use validator::{
    Config as ValidatorConfig, ProxyValidator, ValidationProgress, ValidationStatus,
};

/// Convenience glob for common types.
pub mod prelude {
    pub use crate::{
        all_providers, sync_database, Anonymity, FetcherConfig, Fluxy, GeoData, GeoLookup,
        Protocol, Proxy, ProxyFetcher, ProxyParseError, ProxySource, ProxyType, ProxyValidator,
        RuntimeStats, ScrapeMode, Source, SyncOutcome, ValidationProgress, ValidatorConfig,
    };
}

/// Initializes the logging system.
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

/// File-backed proxy source. Scheme-prefixed lines pin their own protocol;
/// bare `ip:port` lines inherit the file's default protocol set.
pub struct ProxySource {
    lines: Lines<BufReader<File>>,
    default_proxy_types: Arc<[Protocol]>,
}

/// Default protocol set inherited by proxies read from a file.
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
    pub async fn from_fetcher(config: FetcherConfig) -> anyhow::Result<ProxyFetcher> {
        ProxyFetcher::gather(config).await
    }

    /// Opens an ip:port file for reading.
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
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut proxy = match line.parse::<Proxy>() {
                Ok(proxy) => proxy,
                Err(error) => {
                    #[cfg(feature = "log")]
                    log::warn!("skipped unparseable proxy file line '{line}': {error}");
                    #[cfg(not(feature = "log"))]
                    let _ = error;
                    continue;
                }
            };
            // A scheme prefixed line pins its protocol (`http://...` → HTTP);
            // a bare `ip:port` line carries no scheme, so it inherits the
            // file-wide default protocol set.
            if proxy.expected_types.is_empty() {
                proxy.expected_types = Arc::clone(&self.default_proxy_types);
            }
            return Some(proxy);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{ProxySource, FILE_DEFAULT_PROTOCOLS};
    use crate::proxy::models::{Anonymity, Protocol, Proxy};

    fn proxy_source(content: &str) -> (ProxySource, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "fluxy_proxy_source_test_{}_{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, content).unwrap();
        let source = ProxySource::from_file(path.clone()).unwrap();
        (source, path)
    }

    #[test]
    fn bare_lines_inherit_file_default_protocols() {
        let (source, path) = proxy_source("1.2.3.4:8080\n5.6.7.8:3128\n\n1.2.3.4:80:Country\n");
        let proxies: Vec<Proxy> = source.collect();
        let _ = std::fs::remove_file(&path);

        assert_eq!(proxies.len(), 3);
        for proxy in &proxies {
            assert_eq!(
                proxy.expected_types, *FILE_DEFAULT_PROTOCOLS,
                "bare lines must inherit the file default protocol set"
            );
        }
    }

    #[test]
    fn scheme_lines_pin_their_own_protocol() {
        let (source, path) = proxy_source(
            "http://1.2.3.4:8080\nhttps://5.6.7.8:3128\nsocks4://9.10.11.12:1080\nsocks5://13.14.15.16:1080\n",
        );
        let proxies: Vec<Proxy> = source.collect();
        let _ = std::fs::remove_file(&path);

        assert_eq!(proxies.len(), 4);
        assert_eq!(
            proxies[0].expected_types.as_ref(),
            &[Protocol::Http(Anonymity::Unknown)]
        );
        assert_eq!(
            proxies[1].expected_types.as_ref(),
            &[Protocol::Https(Anonymity::Unknown)]
        );
        assert_eq!(proxies[2].expected_types.as_ref(), &[Protocol::Socks4]);
        assert_eq!(proxies[3].expected_types.as_ref(), &[Protocol::Socks5]);
    }

    #[test]
    fn mixed_lines_keep_each_lines_semantics() {
        let (source, path) = proxy_source("socks5://1.2.3.4:1080\n5.6.7.8:8080\ngarbage\n");
        let proxies: Vec<Proxy> = source.collect();
        let _ = std::fs::remove_file(&path);

        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].expected_types.as_ref(), &[Protocol::Socks5]);
        assert_eq!(proxies[1].expected_types, *FILE_DEFAULT_PROTOCOLS);
    }
}
