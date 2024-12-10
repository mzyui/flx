pub mod models;

use std::{
    env::current_dir,
    fmt::{Display, Formatter},
    fs::{self, remove_file, OpenOptions},
    io::Write,
    net::Ipv4Addr,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

#[cfg(feature = "progress_bar")]
use colored::Colorize;
use fake::{faker::internet::en::UserAgent, Fake};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request};
use hyper_tls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use maxminddb::{geoip2::City, Reader};
use models::GeoData;
#[cfg(feature = "progress_bar")]
use status_line::StatusLine;
use tokio::time;

const GEOLITE_ENDPOINT_URL: &str =
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb";

#[cfg(feature = "progress_bar")]
/// Struct to manage and display progress for downloading the GeoLite2 database.
struct Progress {
    progress: AtomicUsize, // Tracks the current progress.
    max: f64,              // Maximum size of the download.
    timer: time::Instant,  // Timer to measure download duration.
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
fn data_dir() -> anyhow::Result<PathBuf> {
    if let Some(base_dirs) = directories::BaseDirs::new() {
        let mut dir = base_dirs.data_dir().to_path_buf();
        dir.push(env!("CARGO_PKG_NAME"));

        if !dir.is_dir() {
            fs::create_dir(&dir)?;
        }
        Ok(dir)
    } else {
        #[cfg(feature = "log")]
        log::warn!("Failed to get local data directory, using current directory instead");
        Ok(current_dir().unwrap_or_default())
    }
}

/// Downloads the GeoLite2 database from the specified endpoint if it does not exist.
///
/// # Arguments
///
/// * `mmdb_path`: The path where the database file will be saved.
///
/// # Returns
///
/// A result indicating success or failure.
pub async fn download_database(mmdb_path: &PathBuf) -> anyhow::Result<()> {
    let https_connector = HttpsConnector::new();
    let client = Client::builder(TokioExecutor::new()).build(https_connector);

    let req = Request::builder()
        .uri(GEOLITE_ENDPOINT_URL)
        .header(hyper::header::USER_AGENT, UserAgent().fake::<&str>())
        .body(Empty::<Bytes>::new())?;

    let mut response = client.request(req).await?;

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
    #[cfg(feature = "progress_bar")]
    status.progress.fetch_add(0, Ordering::Relaxed);

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(mmdb_path)?;

    while let Some(next) = response.frame().await {
        let frame = next?;
        if let Some(chunk) = frame.data_ref() {
            #[cfg(feature = "progress_bar")]
            status.progress.fetch_add(chunk.len(), Ordering::Relaxed);
            file.write_all(chunk)?;
        }
    }
    Ok(())
}

/// Manages the GeoIP database and provides lookup functionality.
pub struct GeoLookup {
    reader: Reader<Vec<u8>>, // Reader for the GeoLite2 database.
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

        if !mmdb_path.exists() {
            #[cfg(feature = "log")]
            log::debug!("Geolite2-city.mmdb does not exist, downloading");
            download_database(&mmdb_path).await?;
        }

        match Reader::open_readfile(&mmdb_path) {
            Ok(reader) => Ok(Self { reader }),
            Err(e) => {
                remove_file(mmdb_path)?;
                anyhow::bail!(e);
            }
        }
    }

    /// Looks up geographical data for a given IPv4 address.
    ///
    /// # Arguments
    ///
    /// * `ip`: The IPv4 address to look up.
    ///
    /// # Returns
    ///
    /// A `GeoData` instance containing the geographic information.
    pub fn lookup(&self, ip: &Ipv4Addr) -> GeoData {
        let mut geodata = GeoData::default();
        if let Ok(lookup) = self.reader.lookup::<City>(std::net::IpAddr::V4(*ip)) {
            self.extract_country_data(&lookup, &mut geodata);
            self.extract_region_data(&lookup, &mut geodata);
            self.extract_city_data(&lookup, &mut geodata);
        }
        geodata
    }

    /// Extracts country data from the lookup result and populates the `GeoData`.
    ///
    /// # Arguments
    ///
    /// * `lookup`: The lookup result containing geographic information.
    /// * `geodata`: The `GeoData` instance to populate with country information.
    fn extract_country_data(&self, lookup: &City, geodata: &mut GeoData) {
        if let Some(country) = &lookup.country {
            geodata.iso_code = country.iso_code.map(ToString::to_string);
            if let Some(country_names) = &country.names {
                geodata.name = country_names.get("en").map(ToString::to_string);
            }
        } else if let Some(continent) = &lookup.continent {
            geodata.iso_code = continent.code.map(ToString::to_string);
            if let Some(continent_names) = &continent.names {
                geodata.name = continent_names.get("en").map(ToString::to_string);
            }
        }
    }

    /// Extracts region data from the lookup result and populates the `GeoData`.
    ///
    /// # Arguments
    ///
    /// * `lookup`: The lookup result containing geographic information.
    /// * `geodata`: The `GeoData` instance to populate with region information.
    fn extract_region_data(&self, lookup: &City, geodata: &mut GeoData) {
        if let Some(subdivisions) = &lookup.subdivisions {
            if let Some(division) = subdivisions.first() {
                geodata.region_iso_code = division.iso_code.map(ToString::to_string);
                if let Some(division_names) = &division.names {
                    geodata.region_name = division_names.get("en").map(ToString::to_string);
                }
            }
        }
    }

    /// Extracts city data from the lookup result and populates the `GeoData`.
    ///
    /// # Arguments
    ///
    /// * `lookup`: The lookup result containing geographic information.
    /// * `geodata`: The `GeoData` instance to populate with city information.
    fn extract_city_data(&self, lookup: &City, geodata: &mut GeoData) {
        if let Some(city) = &lookup.city {
            if let Some(city_names) = &city.names {
                geodata.city_name = city_names.get("en").map(ToString::to_string);
            }
        }
    }
}
