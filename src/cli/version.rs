use anyhow::Context;
use std::time::Duration;

const VERSION_CHECK_URL: &str = "https://raw.githubusercontent.com/mzyui/flx/main/Cargo.toml";
const VERSION_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Returns true when `latest` is a newer release than `current`.
pub fn check_version(current: &str, latest: &str) -> bool {
    fn parse(version: &str) -> Vec<u64> {
        version
            .trim()
            .trim_start_matches('v')
            .split('.')
            .filter_map(|part| {
                part.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse::<u64>()
                    .ok()
            })
            .collect()
    }
    let current = parse(current);
    let latest = parse(latest);
    for (ours, theirs) in current.iter().zip(latest.iter()) {
        if ours != theirs {
            return theirs > ours;
        }
    }
    latest.len() > current.len()
}

pub async fn fetch_latest_version() -> anyhow::Result<String> {
    use http_body_util::{BodyExt, Empty};
    use hyper::body::Bytes;
    use hyper_tls::HttpsConnector;
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};

    let client = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(VERSION_CHECK_TIMEOUT)
        .build::<_, Empty<Bytes>>(HttpsConnector::new());
    let request = hyper::Request::builder()
        .uri(VERSION_CHECK_URL)
        .header("User-Agent", format!("flx/{}", env!("CARGO_PKG_VERSION")))
        .body(Empty::<Bytes>::new())
        .context("failed to build version check request")?;
    let response = tokio::time::timeout(VERSION_CHECK_TIMEOUT, client.request(request))
        .await
        .context("version check timed out")?
        .context("version check request failed")?;
    if !response.status().is_success() {
        anyhow::bail!("version check returned {}", response.status());
    }
    let body = tokio::time::timeout(VERSION_CHECK_TIMEOUT, response.into_body().collect())
        .await
        .context("version check body timed out")?
        .context("version check body failed")?
        .to_bytes();
    let body = String::from_utf8_lossy(&body);
    let version = body
        .lines()
        .find(|line| line.trim_start().starts_with("version"))
        .and_then(|line| line.split('=').nth(1))
        .map(|value| value.trim().trim_matches('"').trim_matches('\'').to_owned())
        .context("version not found in Cargo.toml")?;
    Ok(version)
}
