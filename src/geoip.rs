use std::{
    env::current_dir,
    fmt::{Display, Formatter},
    fs::{self, remove_file, File, OpenOptions},
    io::Write,
    net::Ipv4Addr,
    path::PathBuf,
    process::exit,
    sync::atomic::{AtomicUsize, Ordering},
};

#[cfg(feature = "progress_bar")]
use colored::Colorize;
use fake::{faker::internet::en::UserAgent, Fake};
use futures_util::StreamExt;
use maxminddb::{geoip2::City, Reader};
use reqwest::ClientBuilder;
#[cfg(feature = "progress_bar")]
use status_line::StatusLine;
use tokio::time;

use crate::models::GeoData;

const GEOLITE_ENDPOINT_URL: &str = "https://git.io/GeoLite2-City.mmdb";

#[cfg(feature = "progress_bar")]
struct Progress {
    progress: AtomicUsize,
    max: f64,
    timer: time::Instant,
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
        log::warn!("Failed to get local data directory, use current directory instead");
        Ok(current_dir().unwrap_or_default())
    }
}
pub async fn download_database(mmdb_path: &PathBuf) -> anyhow::Result<()> {
    let client = ClientBuilder::new()
        .user_agent(UserAgent().fake::<&str>())
        .build()?;

    let response = client.get(GEOLITE_ENDPOINT_URL).send().await?;
    #[cfg(feature = "progress_bar")]
    let max = if let Some(length) = response.headers().get("content-length") {
        length.to_str().map(|v| v.parse::<f64>().unwrap_or(0.0))?
    } else {
        0.0
    };

    #[cfg(feature = "progress_bar")]
    let status = StatusLine::new(Progress {
        progress: AtomicUsize::new(0),
        timer: time::Instant::now(),
        max,
    });
    #[cfg(feature = "progress_bar")]
    status.progress.fetch_add(0, Ordering::Relaxed);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(mmdb_path)?;

    let mut stream = response.bytes_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result?;
        #[cfg(feature = "progress_bar")]
        status.progress.fetch_add(chunk.len(), Ordering::Relaxed);
        file.write_all(&chunk);
    }
    Ok(())
}

pub struct GeoIp {
    reader: Reader<Vec<u8>>,
}

impl GeoIp {
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
                remove_file(mmdb_path);
                anyhow::bail!(e);
            }
        }
    }

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

    fn extract_region_data(&self, lookup: &City, geodata: &mut GeoData) {
        if let Some(subdivisions) = &lookup.subdivisions {
            if let Some(division) = subdivisions.first() {
                geodata.region_iso_code = division.iso_code.map(ToString::to_string);
                if let Some(division_names) = &division.names {
                    geodata.region_name =
                        division_names.get("en").map(ToString::to_string);
                }
            }
        }
    }

    fn extract_city_data(&self, lookup: &City, geodata: &mut GeoData) {
        if let Some(city) = &lookup.city {
            if let Some(city_names) = &city.names {
                geodata.city_name = city_names.get("en").map(ToString::to_string);
            }
        }
    }
}
