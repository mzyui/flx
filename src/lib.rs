#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]
//! Fast proxy scraper and validator.
//!
//! The [`Flx`] builder mirrors the CLI defaults: scrape the built-in
//! providers or load candidates from files, validate them against online
//! judges, then filter, sort, and export the survivors.
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
//!
//! See [`Flx`] for the full builder contract, `examples/` for runnable
//! workflows, and the README for CLI usage.
//!
//! ## Features
//!
//! - `log` (default): emit `flx::*` records via the `log` crate.
//! - `progress_bar` (default): CLI progress rendering.
//! - `clap` (default): enables the `flx` binary.
//! - `serve` (optional): rotating proxy endpoint (`flx serve`);
//!   off by default while experimental.
//!
//! ## Minimum Supported Rust Version
//!
//! Requires a recent stable toolchain (tested on 1.89+). No `rust-version`
//! floor is declared in `Cargo.toml`; MSRV bumps are treated as a minor
//! breaking change and noted in release notes.
//!
//! ## License
//!
//! Licensed under the MIT license (`LICENSE`).

pub mod base_dirs;
pub mod error;
pub mod fetcher;
pub mod filters;
pub mod geolookup;

#[cfg(test)]
mod bench;
#[cfg(test)]
mod test_support;

mod api;
pub mod negotiators;
pub mod providers;
pub mod proxy;
#[cfg(feature = "serve")]
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
#[cfg(feature = "serve")]
pub use rotator::{Rotator, RotatorPool, ServeEvent, ServeOptions, Strategy};
pub use validator::{
    Config as ValidatorConfig, JudgeHealthReport, PauseGate, ProbeGate, ProxyFailure,
    ProxyValidator, ValidationProgress, ValidationStatus,
};

/// Re-exports common types.
pub mod prelude {
    pub use crate::{
        all_providers, load_proxy_files, sync_database, Anonymity, FetcherConfig, Flx, FlxError,
        GeoData, GeoLookup, IpType, JudgeHealthReport, PauseGate, ProbeGate, Protocol, Proxy,
        ProxyFailure, ProxyFetcher, ProxyParseError, ProxySource, ProxyStreamExt, ProxyType,
        ProxyValidator, RuntimeStats, ScrapeMode, SortKey, SortOrder, Source, SyncOutcome,
        ValidationProgress, ValidationRun, ValidatorConfig,
    };
}

/// Initializes logging.
#[cfg(feature = "log")]
pub fn initialize_logging(log_level: log::LevelFilter) -> anyhow::Result<()> {
    log::set_boxed_logger(Box::new(FlxLogger::to_stderr()))?;
    log::set_max_level(log_level);
    Ok(())
}

/// Sends log records to `path` instead of stderr, for runs that own the screen.
///
/// ANSI is always off: the destination is a file to be paged through later, and
/// anything written to stderr while a full-screen UI is up would corrupt it.
#[cfg(feature = "log")]
pub fn initialize_file_logging(
    log_level: log::LevelFilter,
    path: &std::path::Path,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("cannot open the log file {}", path.display()))?;
    log::set_boxed_logger(Box::new(FlxLogger::to_file(file)))?;
    log::set_max_level(log_level);
    Ok(())
}

/// Where a run that owns the screen writes its log.
#[cfg(feature = "log")]
pub fn screen_log_path() -> anyhow::Result<std::path::PathBuf> {
    // Reuses the database directory: the one flx path already created on demand.
    Ok(geolookup::data_dir()?.join(TUI_LOG_FILE))
}

/// File name a full-screen run logs to, inside the flx data directory.
#[cfg(feature = "log")]
pub const TUI_LOG_FILE: &str = "tui.log";

/// Where flx records go: the terminal, or a file for a full-screen run.
#[cfg(feature = "log")]
enum LogSink {
    Stderr,
    /// Appended to, behind a lock: many tasks log from many threads.
    File(std::sync::Mutex<std::fs::File>),
}

/// Writes flx records with tty-gated colors.
#[cfg(feature = "log")]
struct FlxLogger {
    sink: LogSink,
}

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
    fn to_stderr() -> Self {
        Self {
            sink: LogSink::Stderr,
        }
    }

    fn to_file(file: std::fs::File) -> Self {
        Self {
            sink: LogSink::File(std::sync::Mutex::new(file)),
        }
    }

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

    /// One record, as a single line: the color is only added for a terminal.
    fn write_record(&self, record: &log::Record, color: bool) -> std::io::Result<()> {
        match &self.sink {
            LogSink::Stderr => {
                let mut stderr = std::io::stderr().lock();
                write_record_to(&mut stderr, record, color)
            }
            LogSink::File(file) => {
                let mut file = file.lock().unwrap_or_else(|e| e.into_inner());
                write_record_to(&mut *file, record, color)
            }
        }
    }
}

#[cfg(feature = "log")]
fn write_record_to(
    target: &mut impl std::io::Write,
    record: &log::Record,
    color: bool,
) -> std::io::Result<()> {
    if color {
        // Keeps prefix bytes identical to the previous logger.
        write!(
            target,
            "\x1b[0m{}{}: {} ",
            log_prefix_color(record.level()),
            record.target(),
            record.level()
        )?;
        write!(target, "\x1b[0m")?;
    } else {
        write!(target, "{}: {} ", record.target(), record.level())?;
    }
    writeln!(target, "{}", record.args())
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
        let color = matches!(self.sink, LogSink::Stderr) && Self::color_enabled();
        let _ = self.write_record(record, color);
    }

    fn flush(&self) {
        match &self.sink {
            LogSink::Stderr => {
                let _ = std::io::stderr().flush();
            }
            LogSink::File(file) => {
                if let Ok(mut file) = file.lock() {
                    let _ = file.flush();
                }
            }
        }
    }
}

/// Reads proxies from files with per-line protocol pinning.
///
/// Bare `ip:port` lines inherit all requested protocols; scheme-prefixed
/// lines (`socks5://…`) pin their own type. `-` means stdin.
/// See [`load_proxy_files`] for the file-loading helper.
///
/// # Examples
///
/// ```no_run
/// use flx::ProxySource;
///
/// # fn example() -> anyhow::Result<()> {
/// let source = ProxySource::from_reader(std::io::Cursor::new("1.2.3.4:8080\n"))?;
/// let proxies: Vec<_> = source.collect();
/// # Ok(())
/// # }
/// ```
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
    /// Builds a fetcher-backed source from `config` without blocking.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider set cannot be assembled.
    pub async fn from_fetcher(config: FetcherConfig) -> anyhow::Result<ProxyFetcher> {
        ProxyFetcher::gather(config).await
    }

    /// Opens `filepath` for lazy line-by-line parsing.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the file cannot be opened.
    pub fn from_file(filepath: PathBuf) -> anyhow::Result<Self> {
        let file = anyhow::Context::with_context(File::open(&filepath), || {
            format!("failed to open proxy file {}", filepath.display())
        })?;
        Self::from_reader(BufReader::new(file))
    }

    /// Wraps any buffered reader as a proxy source.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns `Ok` for API symmetry with [`ProxySource::from_file`].
    pub fn from_reader<R: BufRead + Send + 'static>(reader: R) -> anyhow::Result<Self> {
        let lines = (Box::new(reader) as Box<dyn BufRead + Send>).lines();

        let default_proxy_types = Arc::clone(&FILE_DEFAULT_PROTOCOLS);

        Ok(Self {
            lines,
            default_proxy_types,
        })
    }

    /// Reads candidates from stdin without blocking.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns `Ok` for API symmetry with [`ProxySource::from_file`].
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

    #[cfg(feature = "log")]
    #[test]
    fn a_file_sink_writes_uncolored_lines() {
        use super::{FlxLogger, TUI_LOG_FILE};

        let path = std::env::temp_dir().join(format!(
            "flx_file_sink_{}_{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let logger = FlxLogger::to_file(std::fs::File::create(&path).unwrap());
        logger
            .write_record(
                &log::Record::builder()
                    .target("flx::test")
                    .level(log::Level::Warn)
                    .args(format_args!("noise"))
                    .build(),
                // Color is only ever requested for a terminal.
                false,
            )
            .unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(written, "flx::test: WARN noise\n");
        assert!(
            !written.contains('\u{1b}'),
            "a log file is paged through later, never painted"
        );
        assert!(TUI_LOG_FILE.ends_with(".log"));
    }

    #[cfg(feature = "log")]
    #[test]
    fn the_screen_log_lives_beside_the_database() {
        use super::screen_log_path;
        use std::ffi::OsStr;

        let path = screen_log_path().expect("a data directory resolves");
        assert_eq!(path.file_name(), Some(OsStr::new(super::TUI_LOG_FILE)));
        assert_eq!(
            path.parent().and_then(|dir| dir.file_name()),
            Some(OsStr::new(env!("CARGO_PKG_NAME"))),
            "the log belongs in flx's own data directory, got {}",
            path.display()
        );
    }
}
