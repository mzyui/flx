//! GeoIP lookup backed by a locally cached GeoLite2-City database.
//!
//! The database is downloaded from the P3TERX mirror on first use into the
//! platform data directory, locked against concurrent processes, and cached for
//! the rest of the run.

pub mod models;

use std::{
    env::current_dir,
    fs::{self, remove_file},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::OnceLock,
};

#[cfg(feature = "progress_bar")]
use std::{
    fmt::{Display, Formatter},
    sync::atomic::{AtomicUsize, Ordering},
};

use anyhow::Context;
#[cfg(feature = "progress_bar")]
use colored::Colorize;
use futures_util::{Stream, StreamExt};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request};
use hyper_tls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use maxminddb::{geoip2::City, Reader};
use models::GeoData;
#[cfg(feature = "progress_bar")]
use status_line::StatusLine;
use tokio::io::AsyncWriteExt;
#[cfg(feature = "progress_bar")]
use tokio::time;

const GEOLITE_ENDPOINT_URL: &str =
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb";
const MAX_DATABASE_SIZE: usize = 128 * 1024 * 1024;
const DATABASE_DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

static DOWNLOAD_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn download_lock() -> &'static tokio::sync::Mutex<()> {
    DOWNLOAD_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Derives the path of the `.part` scratch file used while downloading.
fn temporary_path(path: &Path) -> PathBuf {
    let mut temporary = path.to_path_buf();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("geolite2-city.mmdb");
    temporary.set_file_name(format!(".{file_name}.part"));
    temporary
}

/// Derives the path of the cross-process lock file guarding a download.
fn lock_path(path: &Path) -> PathBuf {
    let mut lock = path.to_path_buf();
    lock.set_file_name(format!(
        ".{}.lock",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("geolite2-city.mmdb")
    ));
    lock
}

/// Acquires an exclusive advisory lock on the database's lock file.
///
/// The lock keeps two concurrent processes from downloading the database at
/// the same time. It is released when the returned [`std::fs::File`] drops.
async fn acquire_download_lock(path: &Path) -> anyhow::Result<std::fs::File> {
    let lock = lock_path(path);
    tokio::task::spawn_blocking(move || {
        use fs2::FileExt;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock)
            .with_context(|| format!("failed to create {}", lock.display()))?;
        file.lock_exclusive()
            .with_context(|| format!("failed to lock {}", lock.display()))?;
        Ok(file)
    })
    .await
    .context("GeoLite2 lock task failed")?
}

/// Streams a downloaded database into a scratch file, validates it, and
/// atomically renames it into place.
///
/// The body is bounded by `max_size` and `deadline`, and every progress update
/// is reported through `progress`. On any failure the partial file is removed
/// so a corrupt half-written database never shadows the real one.
async fn write_database_chunks<S, E, P>(
    mmdb_path: &Path,
    chunks: S,
    max_size: usize,
    deadline: tokio::time::Instant,
    mut progress: P,
) -> anyhow::Result<()>
where
    S: Stream<Item = Result<Bytes, E>>,
    E: std::error::Error + Send + Sync + 'static,
    P: FnMut(usize),
{
    let temporary_path = temporary_path(mmdb_path);
    let _lock = acquire_download_lock(mmdb_path).await?;
    let result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary_path)
            .await
            .with_context(|| format!("failed to create {}", temporary_path.display()))?;
        let mut downloaded = 0usize;
        let mut chunks = std::pin::pin!(chunks);

        while let Some(next) = tokio::time::timeout_at(deadline, chunks.next())
            .await
            .context("GeoLite2 download body timed out")?
        {
            let chunk = next.context("GeoLite2 download stream interrupted")?;
            downloaded = downloaded
                .checked_add(chunk.len())
                .context("GeoLite2 database size overflow")?;
            if downloaded > max_size {
                anyhow::bail!(
                    "GeoLite2 database exceeds maximum size of {} bytes",
                    max_size
                );
            }
            progress(chunk.len());
            file.write_all(&chunk)
                .await
                .with_context(|| format!("failed to write to {}", temporary_path.display()))?;
        }

        file.sync_all()
            .await
            .with_context(|| format!("failed to flush {}", temporary_path.display()))?;
        drop(file);
        tokio::task::spawn_blocking({
            let temporary_path = temporary_path.clone();
            move || Reader::open_readfile(&temporary_path).map(|_| ())
        })
        .await
        .context("GeoLite2 validation task failed")?
        .context("downloaded GeoLite2 file is not a valid MMDB database")?;
        tokio::fs::rename(&temporary_path, mmdb_path)
            .await
            .with_context(|| {
                format!(
                    "failed to atomically install {} as {}",
                    temporary_path.display(),
                    mmdb_path.display()
                )
            })
    }
    .await;

    if result.is_err() {
        match tokio::fs::remove_file(&temporary_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to remove partial file {}", temporary_path.display())
                });
            }
        }
    }

    result
}

/// Renders the GeoLite2 download progress on the terminal.
#[cfg(feature = "progress_bar")]
struct Progress {
    progress: AtomicUsize, // Bytes downloaded so far.
    max: f64,              // Expected total size of the download.
    timer: time::Instant,  // When the download started.
}

#[cfg(feature = "progress_bar")]
impl Display for Progress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} Downloading GeoLite2-City.mmdb: {:.2}%",
            format!("{}:", module_path!()).bright_blue(),
            "INFO".bright_blue(),
            (self.progress.load(Ordering::Relaxed) as f64 / self.max) * 100.0
        )
    }
}

#[cfg(all(feature = "progress_bar", feature = "log"))]
impl Drop for Progress {
    fn drop(&mut self) {
        log::debug!(
            "Finished downloading GeoLite2-City.mmdb in {:?}",
            self.timer.elapsed()
        );
    }
}

/// Retrieves the data directory path for the application.
///
/// # Returns
///
/// A `PathBuf` representing the path to the data directory.
pub(crate) fn data_dir() -> anyhow::Result<PathBuf> {
    if let Some(base_dirs) = directories::BaseDirs::new() {
        let mut dir = base_dirs.data_dir().to_path_buf();
        dir.push(env!("CARGO_PKG_NAME"));

        if !dir.is_dir() {
            fs::create_dir_all(&dir)
                .with_context(|| format!("failed to create data directory {}", dir.display()))?;
        }
        Ok(dir)
    } else {
        #[cfg(feature = "log")]
        log::warn!("Failed to get local data directory, using current directory instead");
        let mut dir = current_dir().context("failed to determine current working directory")?;
        dir.push(env!("CARGO_PKG_NAME"));
        if !dir.is_dir() {
            fs::create_dir_all(&dir).with_context(|| {
                format!(
                    "failed to create data directory {} under the current working directory (no platform data directory available); choose a writable working directory or set XDG_DATA_HOME",
                    dir.display()
                )
            })?;
        }
        Ok(dir)
    }
}

/// Downloads the GeoLite2 city database from the P3TERX mirror into
/// `mmdb_path`, enforcing a 120s deadline and a 128MB size cap.
///
/// # Errors
///
/// Returns an error when the download fails, times out, exceeds the size cap,
/// or produces a file that cannot be opened as an MMDB database.
pub async fn download_database(mmdb_path: &Path) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + DATABASE_DOWNLOAD_TIMEOUT;
    let https_connector = HttpsConnector::new();
    let client = Client::builder(TokioExecutor::new()).build(https_connector);

    let req = Request::builder()
        .uri(GEOLITE_ENDPOINT_URL)
        .header(
            hyper::header::USER_AGENT,
            crate::user_agent::next_user_agent(),
        )
        .body(Empty::<Bytes>::new())
        .context("failed to build GeoLite2 download request")?;

    let response = tokio::time::timeout_at(deadline, client.request(req))
        .await
        .context("GeoLite2 download request timed out")?
        .with_context(|| {
            format!(
                "failed to download GeoLite2 database from {}",
                GEOLITE_ENDPOINT_URL
            )
        })?;

    if !response.status().is_success() {
        anyhow::bail!(
            "GeoLite2 download from {} returned status {}",
            GEOLITE_ENDPOINT_URL,
            response.status()
        );
    }

    let content_length = response
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if content_length.is_some_and(|length| length > MAX_DATABASE_SIZE) {
        anyhow::bail!(
            "GeoLite2 database exceeds maximum size of {} bytes",
            MAX_DATABASE_SIZE
        );
    }

    #[cfg(feature = "progress_bar")]
    let max_size = if let Some(length) = response.headers().get(hyper::header::CONTENT_LENGTH) {
        length.to_str().map(|v| v.parse::<f64>().unwrap_or(0.0))?
    } else {
        0.0
    };

    #[cfg(feature = "progress_bar")]
    let status = StatusLine::new(Progress {
        progress: AtomicUsize::new(0),
        timer: time::Instant::now(),
        max: max_size,
    });

    let chunks = futures_util::stream::unfold(response, |mut response| async move {
        loop {
            match response.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(chunk) = frame.into_data() {
                        return Some((Ok(chunk), response));
                    }
                }
                Some(Err(error)) => return Some((Err(error), response)),
                None => return None,
            }
        }
    });
    write_database_chunks(
        mmdb_path,
        chunks,
        MAX_DATABASE_SIZE,
        deadline,
        |chunk_size| {
            #[cfg(feature = "progress_bar")]
            status.progress.fetch_add(chunk_size, Ordering::Relaxed);
            #[cfg(not(feature = "progress_bar"))]
            let _ = chunk_size;
        },
    )
    .await
}

/// Geographically resolves proxy IP addresses against the GeoLite2 database.
pub struct GeoLookup {
    reader: Reader<Vec<u8>>,
}

impl GeoLookup {
    /// Creates a new instance of `GeoLookup`, downloading the GeoLite2 database if necessary.
    ///
    /// # Returns
    ///
    /// A result containing the initialized `GeoLookup` instance.
    pub async fn new() -> anyhow::Result<Self> {
        let mut mmdb_path = data_dir()?;
        mmdb_path.set_file_name("geolite2-city.mmdb");

        let _download_guard = download_lock().lock().await;
        if !mmdb_path.exists() {
            #[cfg(feature = "log")]
            log::debug!("Geolite2-city.mmdb does not exist, downloading");
            download_database(&mmdb_path)
                .await
                .context("failed to download the GeoLite2 city database")?;
        }

        match Reader::open_readfile(&mmdb_path) {
            Ok(reader) => Ok(Self { reader }),
            Err(e) => {
                // The file is corrupt or truncated; drop it so the next run re-downloads.
                if let Err(_remove_err) = remove_file(&mmdb_path) {
                    #[cfg(feature = "log")]
                    log::warn!(
                        "failed to remove corrupt database {}: {}",
                        mmdb_path.display(),
                        _remove_err
                    );
                }
                Err(anyhow::Error::new(e).context(format!(
                    "failed to open GeoLite2 database {}",
                    mmdb_path.display()
                )))
            }
        }
    }

    /// Looks up the geographical data for `ip`.
    ///
    /// Returns a blank [`GeoData`] when the database has no record for the
    /// address.
    pub fn lookup(&self, ip: &Ipv4Addr) -> GeoData {
        let mut geodata = GeoData::default();
        if let Ok(lookup) = self.reader.lookup::<City>(std::net::IpAddr::V4(*ip)) {
            self.extract_country_data(&lookup, &mut geodata);
            self.extract_region_data(&lookup, &mut geodata);
            self.extract_city_data(&lookup, &mut geodata);
        }
        geodata
    }

    /// Fills `geodata` with the country (or continent when no country is
    /// reported) resolved for the address.
    fn extract_country_data(&self, lookup: &City, geodata: &mut GeoData) {
        if let Some(country) = &lookup.country {
            geodata.iso_code = country.iso_code.map(Box::from);
            if let Some(country_names) = &country.names {
                geodata.name = country_names.get("en").map(|name| Box::from(*name));
            }
        } else if let Some(continent) = &lookup.continent {
            geodata.iso_code = continent.code.map(Box::from);
            if let Some(continent_names) = &continent.names {
                geodata.name = continent_names.get("en").map(|name| Box::from(*name));
            }
        }
    }

    /// Fills `geodata` with the first subdivision's region identifiers.
    fn extract_region_data(&self, lookup: &City, geodata: &mut GeoData) {
        if let Some(subdivisions) = &lookup.subdivisions {
            if let Some(division) = subdivisions.first() {
                geodata.region_iso_code = division.iso_code.map(Box::from);
                if let Some(division_names) = &division.names {
                    geodata.region_name = division_names.get("en").map(|name| Box::from(*name));
                }
            }
        }
    }

    /// Fills `geodata` with the resolved city name.
    fn extract_city_data(&self, lookup: &City, geodata: &mut GeoData) {
        if let Some(city) = &lookup.city {
            if let Some(city_names) = &city.names {
                geodata.city_name = city_names.get("en").map(|name| Box::from(*name));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{temporary_path, write_database_chunks};
    use futures_util::stream;
    use hyper::body::Bytes;

    fn test_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "fluxy_geoip_{name}_{}_{}.mmdb",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    #[tokio::test]
    async fn oversized_database_is_rejected_and_partial_file_is_removed() {
        let path = test_path("oversized");
        let partial = temporary_path(&path);
        let chunks = stream::iter([
            Ok::<_, std::io::Error>(Bytes::from_static(b"1234")),
            Ok(Bytes::from_static(b"5678")),
        ]);

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        let result = write_database_chunks(&path, chunks, 6, deadline, |_| {}).await;

        assert!(result.is_err());
        assert!(!path.exists());
        assert!(!partial.exists());
    }

    #[tokio::test]
    async fn interrupted_database_download_removes_partial_file() {
        let path = test_path("interrupted");
        let partial = temporary_path(&path);
        let chunks = stream::iter([
            Ok(Bytes::from_static(b"1234")),
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "interrupted",
            )),
        ]);

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        let result = write_database_chunks(&path, chunks, 64, deadline, |_| {}).await;

        assert!(result.is_err());
        assert!(!path.exists());
        assert!(!partial.exists());
    }

    #[tokio::test]
    async fn invalid_database_is_rejected_before_atomic_install() {
        let path = test_path("invalid");
        let partial = temporary_path(&path);
        let chunks = stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(
            b"not a maxmind database",
        ))]);

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        let result = write_database_chunks(&path, chunks, 64, deadline, |_| {}).await;

        assert!(result.is_err());
        assert!(!path.exists());
        assert!(!partial.exists());
    }

    #[tokio::test]
    async fn stalled_database_body_times_out_and_removes_partial_file() {
        let path = test_path("stalled");
        let partial = temporary_path(&path);
        let chunks = stream::pending::<Result<Bytes, std::io::Error>>();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(25);

        let result = write_database_chunks(&path, chunks, 64, deadline, |_| {}).await;

        assert!(format!("{:#}", result.unwrap_err()).contains("body timed out"));
        assert!(!path.exists());
        assert!(!partial.exists());
    }
}
