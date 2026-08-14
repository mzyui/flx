//! GeoIP lookup via cached GeoLite2-City database.

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

fn temporary_path(path: &Path) -> PathBuf {
    let mut temporary = path.to_path_buf();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("geolite2-city.mmdb");
    temporary.set_file_name(format!(".{file_name}.part"));
    temporary
}

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

fn database_path() -> anyhow::Result<PathBuf> {
    let mut mmdb_path = data_dir()?;
    mmdb_path.set_file_name("geolite2-city.mmdb");
    Ok(mmdb_path)
}

fn local_build_epoch(mmdb_path: &Path) -> Option<u64> {
    Reader::open_readfile(mmdb_path)
        .ok()
        .map(|reader| reader.metadata.build_epoch)
}

fn sync_marker_path(mmdb_path: &Path) -> PathBuf {
    let file_name = mmdb_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("geolite2-city.mmdb");
    let mut marker = mmdb_path.to_path_buf();
    marker.set_file_name(format!("{file_name}.etag"));
    marker
}

fn read_synced_etag(mmdb_path: &Path) -> Option<String> {
    let content = fs::read(sync_marker_path(mmdb_path)).ok()?;
    let etag = std::str::from_utf8(&content).ok()?.trim();
    (!etag.is_empty()).then(|| etag.to_owned())
}

async fn write_synced_etag(mmdb_path: &Path, etag: &str) -> anyhow::Result<()> {
    let marker = sync_marker_path(mmdb_path);
    let temporary = temporary_path(&marker);
    tokio::fs::write(&temporary, etag.as_bytes())
        .await
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    tokio::fs::rename(&temporary, &marker)
        .await
        .with_context(|| format!("failed to install {}", marker.display()))
}

async fn fetch_database(
    if_none_match: Option<&str>,
    deadline: tokio::time::Instant,
) -> anyhow::Result<(hyper::Response<hyper::body::Incoming>, Option<String>)> {
    let https_connector = HttpsConnector::new();
    let client = Client::builder(TokioExecutor::new()).build(https_connector);

    let mut builder = Request::builder().uri(GEOLITE_ENDPOINT_URL).header(
        hyper::header::USER_AGENT,
        crate::user_agent::next_user_agent(),
    );
    if let Some(etag) = if_none_match {
        builder = builder.header(hyper::header::IF_NONE_MATCH, etag);
    }
    let req = builder
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
    let etag = response
        .headers()
        .get(hyper::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    Ok((response, etag))
}

async fn install_response(
    response: hyper::Response<hyper::body::Incoming>,
    mmdb_path: &Path,
    deadline: tokio::time::Instant,
) -> anyhow::Result<()> {
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

/// Result of a GeoLite2 database sync against the mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The local database is up to date.
    UpToDate,
    /// A newer database was downloaded.
    Synced,
}

/// Ensures the local GeoLite2 database matches the latest mirror revision.
pub async fn sync_database() -> anyhow::Result<SyncOutcome> {
    let mmdb_path = database_path()?;
    let db_valid = local_build_epoch(&mmdb_path).is_some();
    let stored_etag = read_synced_etag(&mmdb_path);
    let deadline = tokio::time::Instant::now() + DATABASE_DOWNLOAD_TIMEOUT;

    // A valid local copy with a recorded ETag can be checked with `If-None-
    // Match`; a missing or corrupt copy always needs the full body.
    let conditional = db_valid && stored_etag.is_some();
    let (response, remote_etag) = if conditional {
        fetch_database(stored_etag.as_deref(), deadline).await?
    } else {
        fetch_database(None, deadline).await?
    };

    if response.status() == hyper::StatusCode::NOT_MODIFIED {
        return Ok(SyncOutcome::UpToDate);
    }

    install_response(response, &mmdb_path, deadline).await?;
    if let Some(etag) = remote_etag {
        write_synced_etag(&mmdb_path, &etag).await?;
    }
    Ok(SyncOutcome::Synced)
}

/// Downloads the GeoLite2 database from the mirror.
pub async fn download_database(mmdb_path: &Path) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + DATABASE_DOWNLOAD_TIMEOUT;
    let (response, _etag) = fetch_database(None, deadline).await?;
    install_response(response, mmdb_path, deadline).await
}

/// GeoLite2-based IP geolocation resolver.
pub struct GeoLookup {
    reader: Reader<Vec<u8>>,
}

impl GeoLookup {
    pub async fn new() -> anyhow::Result<Self> {
        let mmdb_path = database_path()?;

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

    /// Looks up geographical data for an IP address.
    pub fn lookup(&self, ip: &Ipv4Addr) -> GeoData {
        let mut geodata = GeoData::default();
        if let Ok(lookup) = self.reader.lookup::<City>(std::net::IpAddr::V4(*ip)) {
            self.extract_country_data(&lookup, &mut geodata);
            self.extract_region_data(&lookup, &mut geodata);
            self.extract_city_data(&lookup, &mut geodata);
        }
        geodata
    }

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
    use super::{
        read_synced_etag, sync_marker_path, temporary_path, write_database_chunks,
        write_synced_etag,
    };
    use futures_util::stream;
    use hyper::body::Bytes;

    #[tokio::test]
    async fn etag_marker_round_trips_through_sidecar() {
        let path = test_path("etag");
        let marker = sync_marker_path(&path);
        assert!(read_synced_etag(&path).is_none());

        write_synced_etag(&path, "\"1c87b8b3c4670be9\"")
            .await
            .unwrap();
        assert_eq!(
            read_synced_etag(&path).as_deref(),
            Some("\"1c87b8b3c4670be9\"")
        );
        // the scratch file must not linger next to the marker
        assert!(!temporary_path(&marker).exists());

        let _ = std::fs::remove_file(&marker);
    }

    fn test_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "flx_geoip_{name}_{}_{}.mmdb",
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
