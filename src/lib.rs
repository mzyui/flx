//! Fast proxy scraper and validator.
//!
//! The [`Flx`] builder mirrors the CLI defaults.
//!
//! # Examples
//!
//! ```no_run
//! use flx::{Anonymity, Flx, Protocol};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let proxies = Flx::fetch()
//!     .types([Protocol::Http(Anonymity::Elite)])
//!     .limit(20)
//!     .collect()
//!     .await?;
//! # Ok(())
//! # }
//! ```

pub mod base_dirs;
pub mod error;
pub mod fetcher;
pub mod filters;
pub mod geolookup;

#[cfg(test)]
mod test_support;

mod api;
pub mod negotiators;
pub mod providers;
pub mod proxy;
pub mod rotator;
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

pub use api::{load_proxy_files, Flx, ValidationRun};
pub use error::{FlxError, ProtocolParseError, ProxyParseError};
pub use fetcher::{Config as FetcherConfig, FetchStage, ProxyFetcher};
pub use filters::{
    protocol_family, proxy_anonymity_rank, shuffle_proxies, sort_proxies, ProxyStreamExt, SortKey,
    SortOrder,
};
pub use geolookup::models::GeoData;
pub use geolookup::{
    install_download_observer, sync_database, DownloadProgress, GeoLookup, IpType, SyncOutcome,
};
pub use providers::all_providers;
pub use providers::models::{ProviderTier, ScrapeMode, Source};
pub use providers::ProxyProvider;
pub use proxy::models::{Anonymity, Protocol, Proxy, ProxyType, RuntimeStats};
pub use rotator::{Rotator, RotatorPool, ServeOptions, Strategy};
pub use validator::{
    Config as ValidatorConfig, JudgeHealthReport, ProxyFailure, ProxyValidator, ValidationProgress,
    ValidationStatus,
};

/// Re-exports common types.
pub mod prelude {
    pub use crate::{
        all_providers, load_proxy_files, sync_database, Anonymity, FetcherConfig, Flx, FlxError,
        GeoData, GeoLookup, IpType, JudgeHealthReport, Protocol, Proxy, ProxyFailure, ProxyFetcher,
        ProxyParseError, ProxySource, ProxyStreamExt, ProxyType, ProxyValidator, RuntimeStats,
        ScrapeMode, SortKey, SortOrder, Source, SyncOutcome, ValidationProgress, ValidationRun,
        ValidatorConfig,
    };
}

/// Initializes logging.
#[cfg(feature = "log")]
pub fn initialize_logging(log_level: log::LevelFilter) -> anyhow::Result<()> {
    log::set_boxed_logger(Box::new(FlxLogger))?;
    log::set_max_level(log_level);
    Ok(())
}

/// Writes flx records to stderr with tty-gated colors.
#[cfg(feature = "log")]
struct FlxLogger;

#[cfg(feature = "log")]
const LOG_MODULE_ROOT: &str = "flx";

#[cfg(feature = "log")]
fn log_module_allowed(target: &str) -> bool {
    match target.strip_prefix(LOG_MODULE_ROOT) {
        // Matches Rust module paths split by `::`.
        Some(rest) => rest.is_empty() || rest.starts_with("::"),
        None => false,
    }
}

#[cfg(feature = "log")]
fn log_prefix_color(level: log::Level) -> &'static str {
    match level {
        log::Level::Error => "\x1b[31m",
        log::Level::Warn => "\x1b[33m",
        log::Level::Info => "\x1b[34m",
        log::Level::Debug => "\x1b[36m",
        log::Level::Trace => "\x1b[35m",
    }
}

#[cfg(feature = "log")]
impl FlxLogger {
    fn color_enabled() -> bool {
        use std::io::IsTerminal as _;
        match std::env::var_os("TERM") {
            None => return false,
            Some(term) => {
                if term == "dumb" {
                    return false;
                }
            }
        }
        if std::env::var_os("NO_COLOR").is_some() {
            return false;
        }
        std::io::stderr().is_terminal()
    }
}

#[cfg(feature = "log")]
impl log::Log for FlxLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level() && log_module_allowed(metadata.target())
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut stderr = std::io::stderr().lock();
        if Self::color_enabled() {
            // Keeps prefix bytes identical to the previous logger.
            let _ = write!(
                stderr,
                "\x1b[0m{}{}: {} ",
                log_prefix_color(record.level()),
                record.target(),
                record.level()
            );
            let _ = write!(stderr, "\x1b[0m");
        } else {
            let _ = write!(stderr, "{}: {} ", record.target(), record.level());
        }
        let _ = writeln!(stderr, "{}", record.args());
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}

/// Reads proxies from files with per-line protocol pinning.
pub struct ProxySource {
    lines: Lines<Box<dyn BufRead + Send>>,
    default_proxy_types: Arc<[Protocol]>,
}

/// Defines fallback protocols for bare ip:port lines.
static FILE_DEFAULT_PROTOCOLS: LazyLock<Arc<[Protocol]>> = LazyLock::new(|| {
    Arc::from([
        Protocol::Http(Anonymity::Unknown),
        Protocol::Https(Anonymity::Unknown),
        Protocol::Socks4,
        Protocol::Socks5,
    ])
});

/// Formats args into buf, borrowing when it fits.
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

    pub fn from_file(filepath: PathBuf) -> anyhow::Result<Self> {
        let file = anyhow::Context::with_context(File::open(&filepath), || {
            format!("failed to open proxy file {}", filepath.display())
        })?;
        Self::from_reader(BufReader::new(file))
    }

    pub fn from_reader<R: BufRead + Send + 'static>(reader: R) -> anyhow::Result<Self> {
        let lines = (Box::new(reader) as Box<dyn BufRead + Send>).lines();

        let default_proxy_types = Arc::clone(&FILE_DEFAULT_PROTOCOLS);

        Ok(Self {
            lines,
            default_proxy_types,
        })
    }

    pub fn from_stdin() -> anyhow::Result<Self> {
        Self::from_reader(std::io::BufReader::new(std::io::stdin()))
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
            // Pins scheme-prefixed lines; bare lines inherit defaults.
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
            "flx_proxy_source_test_{}_{}.txt",
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

    #[test]
    fn from_reader_parses_like_from_file() {
        let source = ProxySource::from_reader(std::io::Cursor::new(
            "socks4://1.2.3.4:1080\n5.6.7.8:8080\n",
        ))
        .unwrap();
        let proxies: Vec<Proxy> = source.collect();

        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].expected_types.as_ref(), &[Protocol::Socks4]);
        assert_eq!(proxies[1].expected_types, *FILE_DEFAULT_PROTOCOLS);
    }

    #[cfg(feature = "log")]
    #[test]
    fn log_module_gate_accepts_only_crate_targets() {
        use super::log_module_allowed;

        assert!(log_module_allowed("flx"));
        assert!(log_module_allowed("flx::validator::work"));
        assert!(!log_module_allowed("other_crate"));
        assert!(!log_module_allowed("flx2"));
        assert!(!log_module_allowed("fl"));
    }

    #[cfg(feature = "log")]
    #[test]
    fn log_prefix_colors_match_the_documented_palette() {
        use super::log_prefix_color;
        use log::Level;

        assert_eq!(log_prefix_color(Level::Error), "\x1b[31m");
        assert_eq!(log_prefix_color(Level::Warn), "\x1b[33m");
        assert_eq!(log_prefix_color(Level::Info), "\x1b[34m");
        assert_eq!(log_prefix_color(Level::Debug), "\x1b[36m");
        assert_eq!(log_prefix_color(Level::Trace), "\x1b[35m");
    }
}
