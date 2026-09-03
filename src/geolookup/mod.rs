//! GeoIP lookup via cached GeoLite2-City database.

mod ip_type;
pub mod models;
pub use ip_type::IpType;

use std::{
    env::current_dir,
    fs::{self, remove_file},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};

use anyhow::Context;
use futures_util::{Stream, StreamExt};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use maxminddb::{
    geoip2::{Asn, City},
    Reader,
};
use models::GeoData;
use tokio::{io::AsyncWriteExt, sync::watch};

const GEOLITE_ENDPOINT_URL: &str =
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb";
const GEOLITE_ASN_ENDPOINT_URL: &str =
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb";
const MAX_DATABASE_SIZE: usize = 128 * 1024 * 1024;
const DATABASE_DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const GEOLITE_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

static DOWNLOAD_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn download_lock() -> &'static tokio::sync::Mutex<()> {
    DOWNLOAD_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Snapshot of an in-flight GeoLite2 database download.
#[derive(Debug, Clone, Copy)]
pub struct DownloadProgress {
    pub name: &'static str,
    pub downloaded: usize,
    pub total: usize,
}

static DOWNLOAD_EVENTS: OnceLock<watch::Sender<Option<DownloadProgress>>> = OnceLock::new();

/// Installs the download observer and returns a receiver for its events.
pub fn install_download_observer() -> Option<watch::Receiver<Option<DownloadProgress>>> {
    let (tx, rx) = watch::channel(None);
    match DOWNLOAD_EVENTS.set(tx) {
        Ok(()) => Some(rx),
        Err(tx) => {
            let _ = tx.send(None);
            None
        }
    }
}

fn report_download(event: Option<DownloadProgress>) {
    if let Some(tx) = DOWNLOAD_EVENTS.get() {
        let _ = tx.send_replace(event);
    }
}

// Ends the active download event on every exit path of the install function.
struct DownloadNotifier;

impl Drop for DownloadNotifier {
    fn drop(&mut self) {
        report_download(None);
    }
}

// Announces a download before the network request starts so observers see
// progress (even just 0.0 MB) during the connect/request phase, not only once
// body chunks arrive.
fn begin_download(name: &'static str) -> DownloadNotifier {
    report_download(Some(DownloadProgress {
        name,
        downloaded: 0,
        total: 0,
    }));
    DownloadNotifier
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
    // A stopped or wedged process holding the exclusive file lock would
    // otherwise block this forever; give up after a short wait instead.
    let acquire = tokio::task::spawn_blocking({
        let lock = lock.clone();
        move || {
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
        }
    });
    tokio::time::timeout(Duration::from_secs(5), acquire)
        .await
        .context("timed out waiting for the GeoLite2 database lock (held by another flx instance)")?
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

pub fn data_dir() -> anyhow::Result<PathBuf> {
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
    Ok(database_in(data_dir()?, "geolite2-city.mmdb"))
}

fn asn_database_path() -> anyhow::Result<PathBuf> {
    Ok(database_in(data_dir()?, "geolite2-asn.mmdb"))
}

fn database_in(mut dir: PathBuf, file_name: &str) -> PathBuf {
    dir.push(file_name);
    migrate_legacy_database(&dir);
    dir
}

/// Older releases built the database path with `set_file_name` on the data
/// directory itself, storing `<data>/geolite2-*.mmdb` beside (not inside) the
/// `flx/` folder. Move such a leftover into the real location so an existing
/// install does not re-download, carrying the ETag marker along.
fn migrate_legacy_database(new_path: &Path) {
    let Some(file_name) = new_path.file_name() else {
        return;
    };
    let Some(legacy) = new_path
        .parent()
        .and_then(Path::parent)
        .map(|dir| dir.join(file_name))
    else {
        return;
    };
    if new_path.exists() || !legacy.exists() {
        return;
    }
    if let Err(error) = fs::rename(legacy, new_path) {
        #[cfg(feature = "log")]
        log::warn!(
            "failed to move legacy database to {}: {error}",
            new_path.display()
        );
        #[cfg(not(feature = "log"))]
        let _ = error;
        return;
    }
    // The ETag sidecar moves too, otherwise the next sync would treat the
    // migrated copy as unverified and download the full body again.
    let marker = sync_marker_path(new_path);
    if let Some(legacy_marker) = marker
        .parent()
        .and_then(Path::parent)
        .map(|dir| dir.join(marker.file_name().unwrap_or_default()))
    {
        if !marker.exists() && legacy_marker.exists() {
            let _ = fs::rename(legacy_marker, &marker);
        }
    }
}

fn local_build_epoch(mmdb_path: &Path) -> Option<u64> {
    Reader::open_readfile(mmdb_path)
        .ok()
        .map(|reader| reader.metadata().build_epoch)
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
    url: &str,
    if_none_match: Option<&str>,
    deadline: tokio::time::Instant,
) -> anyhow::Result<(hyper::Response<hyper::body::Incoming>, Option<String>)> {
    let https_connector = crate::proxy::client::https_connector();
    let client = Client::builder(TokioExecutor::new()).build(https_connector);

    let mut builder = Request::builder().uri(url).header(
        hyper::header::USER_AGENT,
        crate::user_agent::next_user_agent(),
    );
    if let Some(etag) = if_none_match {
        builder = builder.header(hyper::header::IF_NONE_MATCH, etag);
    }
    let req = builder
        .body(Empty::<Bytes>::new())
        .context("failed to build GeoLite2 download request")?;

    // Reaching the mirror (TCP/TLS connect + response headers) is bounded
    // separately from the body download so an unreachable mirror fails fast
    // instead of sitting silent for the whole 120s download deadline.
    let request_deadline = deadline.min(tokio::time::Instant::now() + GEOLITE_CONNECT_TIMEOUT);
    let response = tokio::time::timeout_at(request_deadline, client.request(req))
        .await
        .context("cannot reach the GeoLite2 mirror")?
        .with_context(|| format!("failed to download GeoLite2 database from {url}"))?;
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
    url: &str,
    deadline: tokio::time::Instant,
) -> anyhow::Result<()> {
    if !response.status().is_success() {
        anyhow::bail!(
            "GeoLite2 download from {} returned status {}",
            url,
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

    let name = database_name(url);
    let total = content_length.unwrap_or(0);
    let mut downloaded = 0usize;

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
            downloaded = downloaded.saturating_add(chunk_size);
            report_download(Some(DownloadProgress {
                name,
                downloaded,
                total,
            }));
        },
    )
    .await
}

fn database_name(url: &str) -> &'static str {
    if url.contains("ASN") {
        "GeoLite2-ASN.mmdb"
    } else {
        "GeoLite2-City.mmdb"
    }
}

/// Result of a GeoLite2 database sync against the mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The local database is up to date.
    UpToDate,
    /// A newer database was downloaded.
    Synced,
}

/// Ensures the local GeoLite2 databases match the latest mirror revision.
pub async fn sync_database() -> anyhow::Result<SyncOutcome> {
    let city = sync_one(GEOLITE_ENDPOINT_URL, &database_path()?).await?;
    let asn = sync_one(GEOLITE_ASN_ENDPOINT_URL, &asn_database_path()?).await?;
    Ok(match (city, asn) {
        (SyncOutcome::Synced, _) | (_, SyncOutcome::Synced) => SyncOutcome::Synced,
        _ => SyncOutcome::UpToDate,
    })
}

async fn sync_one(url: &str, mmdb_path: &Path) -> anyhow::Result<SyncOutcome> {
    let db_valid = local_build_epoch(mmdb_path).is_some();
    let stored_etag = read_synced_etag(mmdb_path);
    let deadline = tokio::time::Instant::now() + DATABASE_DOWNLOAD_TIMEOUT;

    // A valid local copy with a recorded ETag can be checked with `If-None-
    // Match`; a missing or corrupt copy always needs the full body.
    let conditional = db_valid && stored_etag.is_some();
    let (response, remote_etag) = if conditional {
        fetch_database(url, stored_etag.as_deref(), deadline).await?
    } else {
        fetch_database(url, None, deadline).await?
    };

    if response.status() == hyper::StatusCode::NOT_MODIFIED {
        return Ok(SyncOutcome::UpToDate);
    }

    let _notifier = begin_download(database_name(url));
    install_response(response, mmdb_path, url, deadline).await?;
    if let Some(etag) = remote_etag {
        write_synced_etag(mmdb_path, &etag).await?;
    }
    Ok(SyncOutcome::Synced)
}

/// Downloads a GeoLite2 database from the mirror into `mmdb_path`.
pub async fn download_database(mmdb_path: &Path, url: &str) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + DATABASE_DOWNLOAD_TIMEOUT;
    let _notifier = begin_download(database_name(url));
    let (response, _etag) = fetch_database(url, None, deadline).await?;
    install_response(response, mmdb_path, url, deadline).await
}

async fn ensure_database(
    mmdb_path: &Path,
    url: &str,
    display_name: &str,
) -> anyhow::Result<Reader<Vec<u8>>> {
    if !mmdb_path.exists() {
        #[cfg(feature = "log")]
        log::debug!("{} does not exist, downloading", mmdb_path.display());
        download_database(mmdb_path, url)
            .await
            .with_context(|| format!("failed to download {display_name}"))?;
    }

    match Reader::open_readfile(mmdb_path) {
        Ok(reader) => Ok(reader),
        Err(e) => {
            // The file is corrupt or truncated; drop it so the next run re-downloads.
            if let Err(_remove_err) = remove_file(mmdb_path) {
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

/// GeoLite2-based IP geolocation resolver.
pub struct GeoLookup {
    reader: Reader<Vec<u8>>,
    asn_reader: Option<Reader<Vec<u8>>>,
}

impl GeoLookup {
    pub async fn new(need_asn: bool) -> anyhow::Result<Self> {
        let mmdb_path = database_path()?;

        let _download_guard = download_lock().lock().await;
        let reader = ensure_database(
            &mmdb_path,
            GEOLITE_ENDPOINT_URL,
            "the GeoLite2 city database",
        )
        .await?;
        let asn_reader = if need_asn {
            Some(
                ensure_database(
                    &asn_database_path()?,
                    GEOLITE_ASN_ENDPOINT_URL,
                    "the GeoLite2 ASN database",
                )
                .await?,
            )
        } else {
            None
        };

        Ok(Self { reader, asn_reader })
    }

    /// Looks up geographical data for an IP address.
    pub fn lookup(&self, ip: &Ipv4Addr) -> GeoData {
        let mut geodata = GeoData::default();
        let Ok(result) = self.reader.lookup(std::net::IpAddr::V4(*ip)) else {
            return geodata;
        };
        if let Ok(Some(city)) = result.decode::<City>() {
            self.extract_country_data(&city, &mut geodata);
            self.extract_region_data(&city, &mut geodata);
            self.extract_city_data(&city, &mut geodata);
        }
        self.extract_ip_type(ip, &mut geodata);
        geodata
    }

    fn extract_ip_type(&self, ip: &Ipv4Addr, geodata: &mut GeoData) {
        let (asn, aso) = match self.asn_reader.as_ref().and_then(|reader| {
            reader
                .lookup(std::net::IpAddr::V4(*ip))
                .ok()
                .and_then(|result| result.decode::<Asn>().ok())
                .flatten()
        }) {
            Some(record) => (
                record.autonomous_system_number,
                record.autonomous_system_organization,
            ),
            None => (None, None),
        };
        geodata.ip_type = IpType::classify(asn, aso, None, None);
    }

    fn extract_country_data(&self, lookup: &City, geodata: &mut GeoData) {
        let country = &lookup.country;
        if !country.is_empty() {
            geodata.iso_code = country.iso_code.map(Box::from);
            geodata.name = country.names.english.map(Box::from);
        } else {
            let continent = &lookup.continent;
            geodata.iso_code = continent.code.map(Box::from);
            geodata.name = continent.names.english.map(Box::from);
        }
    }

    fn extract_region_data(&self, lookup: &City, geodata: &mut GeoData) {
        if let Some(division) = lookup.subdivisions.first() {
            geodata.region_iso_code = division.iso_code.map(Box::from);
            geodata.region_name = division.names.english.map(Box::from);
        }
    }

    fn extract_city_data(&self, lookup: &City, geodata: &mut GeoData) {
        geodata.city_name = lookup.city.names.english.map(Box::from);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        begin_download, install_download_observer, read_synced_etag, sync_marker_path,
        temporary_path, write_database_chunks, write_synced_etag,
    };
    use futures_util::stream;
    use hyper::body::Bytes;

    #[test]
    fn download_start_event_is_announced_then_cleared() {
        let Some(rx) = install_download_observer() else {
            return; // another test already owns the process-wide observer
        };
        let mut rx = rx;
        {
            let _notifier = begin_download("GeoLite2-City.mmdb");
            let event = rx.borrow_and_update().expect("observer alive");
            assert_eq!(event.name, "GeoLite2-City.mmdb");
            assert_eq!(event.downloaded, 0);
            assert_eq!(event.total, 0);
        }
        assert!(rx.borrow().is_none());
    }

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

    // Builds a `<root>/data/flx/…` tree mirroring the data-dir layout so the
    // legacy sibling location is `<root>/data/<file>`.
    fn migration_dir(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "flx_geoip_migrate_{tag}_{}_{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let dir = root.join("data").join("flx");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&dir).unwrap();
        let new_path = dir.join("geolite2-city.mmdb");
        let legacy = root.join("data").join("geolite2-city.mmdb");
        (new_path, legacy, root)
    }

    #[test]
    fn legacy_database_is_migrated_into_data_dir() {
        let (new_path, legacy, root) = migration_dir("moves");
        std::fs::write(&legacy, b"mmdb").unwrap();
        std::fs::write(legacy.with_file_name("geolite2-city.mmdb.etag"), b"etag").unwrap();

        super::migrate_legacy_database(&new_path);

        assert!(new_path.exists());
        assert!(!legacy.exists());
        assert_eq!(std::fs::read(&new_path).unwrap(), b"mmdb");
        // the ETag sidecar moves along so the copy stays verifiable
        assert_eq!(std::fs::read(sync_marker_path(&new_path)).unwrap(), b"etag");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn migration_never_touches_fresh_installs() {
        let (new_path, legacy, root) = migration_dir("fresh");

        // nothing anywhere: no panic, no files created
        super::migrate_legacy_database(&new_path);
        assert!(!new_path.exists());

        // an existing up-to-date database is left alone
        std::fs::write(&new_path, b"current").unwrap();
        std::fs::write(&legacy, b"stale").unwrap();
        super::migrate_legacy_database(&new_path);
        assert_eq!(std::fs::read(&new_path).unwrap(), b"current");
        assert!(legacy.exists());

        let _ = std::fs::remove_dir_all(&root);
    }
}
