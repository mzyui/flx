#[cfg(feature = "progress_bar")]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    fmt::{Display, Formatter},
    time::Duration,
};

#[cfg(feature = "progress_bar")]
use colored::Colorize;
use fake::{faker::internet::en::UserAgent, Fake};
use futures_util::StreamExt;
use reqwest::ClientBuilder;
#[cfg(feature = "progress_bar")]
use status_line::StatusLine;
use tokio::time;

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
            module_path!().bright_blue(),
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

pub async fn download_geolite() -> anyhow::Result<()> {
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

    let mut stream = response.bytes_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result?;
        #[cfg(feature = "progress_bar")]
        status.progress.fetch_add(chunk.len(), Ordering::Relaxed);
    }
    Ok(())
}
