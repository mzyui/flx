use std::{
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant, SystemTime},
};

use anyhow::Context;
use futures_util::{stream::FuturesUnordered, StreamExt};
use hickory_resolver::{
    config::{LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
    TokioResolver,
};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_tls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tokio::sync::OnceCell;
use tokio::time;

static HTTP_IP_ENDPOINTS: [&str; 3] = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
];

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IP_BODY_BYTES: usize = 64;

// DNS discovery (LOOKUP_TIMEOUT) is followed by the HTTPS fallback
// (LOOKUP_TIMEOUT again) end-to-end, so the whole lookup is bounded to give
// it a fixed budget independent of any probe deadline.
const MY_IP_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

const PUBLIC_IP_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

fn public_ip_cache_path() -> Option<PathBuf> {
    let mut path = crate::geolookup::data_dir().ok()?;
    path.push("public-ip");
    Some(path)
}

async fn load_cached_public_ip(path: &Path) -> Option<String> {
    let modified = tokio::fs::metadata(path).await.ok()?.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?;
    if age > PUBLIC_IP_CACHE_TTL {
        return None;
    }
    let body = tokio::fs::read_to_string(path).await.ok()?;
    let ip = body.trim();
    if ip.parse::<IpAddr>().is_ok() {
        Some(ip.to_string())
    } else {
        None
    }
}

async fn store_public_ip(path: &Path, ip: &str) {
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("public-ip");
    let tmp = path.with_file_name(format!(".{name}.tmp-{}", std::process::id()));
    if tokio::fs::write(&tmp, format!("{ip}\n")).await.is_err() {
        return;
    }
    if tokio::fs::rename(&tmp, path).await.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
}

fn parse_ip_body(body: &[u8]) -> anyhow::Result<String> {
    if body.len() > MAX_IP_BODY_BYTES {
        anyhow::bail!("public-IP response exceeds {MAX_IP_BODY_BYTES} bytes");
    }
    let text = std::str::from_utf8(body).context("public-IP response is not valid UTF-8")?;
    let ip: IpAddr = text
        .trim()
        .parse()
        .with_context(|| format!("endpoint did not return a valid IP: {text:?}"))?;
    Ok(ip.to_string())
}

async fn fetch_ip_endpoint(
    client: Client<
        HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Empty<Bytes>,
    >,
    endpoint: &'static str,
    deadline: time::Instant,
) -> anyhow::Result<String> {
    let response = time::timeout_at(deadline, client.get(endpoint.parse()?))
        .await
        .with_context(|| format!("request to {endpoint} timed out"))?
        .with_context(|| format!("request to {endpoint} failed"))?;
    if !response.status().is_success() {
        anyhow::bail!("{endpoint} returned status {}", response.status());
    }

    let mut body = response.into_body();
    let mut bytes = Vec::with_capacity(32);
    while let Some(frame) = time::timeout_at(deadline, body.frame())
        .await
        .with_context(|| format!("body from {endpoint} timed out"))?
    {
        let chunk = frame
            .with_context(|| format!("body from {endpoint} was interrupted"))?
            .into_data()
            .unwrap_or_default();
        if bytes.len().saturating_add(chunk.len()) > MAX_IP_BODY_BYTES {
            anyhow::bail!("{endpoint} response exceeds {MAX_IP_BODY_BYTES} bytes");
        }
        bytes.extend_from_slice(&chunk);
    }
    parse_ip_body(&bytes).with_context(|| format!("invalid response from {endpoint}"))
}

static DNS_UNAVAILABLE: AtomicBool = AtomicBool::new(false);

async fn my_ip_via_dns() -> anyhow::Result<String> {
    if DNS_UNAVAILABLE.load(Ordering::Relaxed) {
        anyhow::bail!("OpenDNS lookup previously failed; DNS discovery disabled");
    }
    let response = match DNS_RESOLVER
        .get_or_init(|| async { build_dns_resolver() })
        .await
        .lookup_ip("myip.opendns.com")
        .await
    {
        Ok(response) => response,
        Err(error) => {
            DNS_UNAVAILABLE.store(true, Ordering::Relaxed);
            return Err(anyhow::anyhow!(
                "failed to resolve public IP via OpenDNS (myip.opendns.com): {error}"
            ));
        }
    };

    let ip = response
        .iter()
        .next()
        .context("OpenDNS returned no address record for myip.opendns.com")?;

    Ok(ip.to_string())
}

static DNS_RESOLVER: OnceCell<TokioResolver> = OnceCell::const_new();

fn build_dns_resolver() -> TokioResolver {
    // `myip.opendns.com` only publishes an A record; the default strategy also
    // queries AAAA and would fail the whole lookup with "no record found".
    let mut opts = ResolverOpts::default();
    opts.ip_strategy = LookupIpStrategy::Ipv4Only;
    opts.timeout = LOOKUP_TIMEOUT;
    opts.attempts = 1;

    let config = ResolverConfig::from_parts(
        None,
        vec![],
        vec![NameServerConfig::udp(IpAddr::V4(Ipv4Addr::new(
            208, 67, 222, 222,
        )))], // OpenDNS server
    );

    TokioResolver::builder_with_config(config, TokioRuntimeProvider::new())
        .with_options(opts)
        .build()
        .expect("failed to build OpenDNS resolver")
}

async fn my_ip_via_https() -> anyhow::Result<String> {
    let client =
        Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(HttpsConnector::new());
    let deadline = time::Instant::now() + LOOKUP_TIMEOUT;
    let mut requests = HTTP_IP_ENDPOINTS
        .into_iter()
        .map(|endpoint| fetch_ip_endpoint(client.clone(), endpoint, deadline))
        .collect::<FuturesUnordered<_>>();
    let mut errors = Vec::new();
    while let Some(result) = requests.next().await {
        match result {
            Ok(ip) => return Ok(ip),
            Err(error) => errors.push(format!("{error:#}")),
        }
    }
    anyhow::bail!("all HTTPS IP endpoints failed: {}", errors.join("; "))
}

pub async fn my_ip() -> anyhow::Result<String> {
    // Cache the first successful resolution for the lifetime of the process.
    // Failures are not stored, so a transient outage can be retried. Replaces
    // the `cached` crate with a single `OnceCell`.
    static CACHE: OnceCell<String> = OnceCell::const_new();
    CACHE
        .get_or_try_init(|| async {
            time::timeout(MY_IP_LOOKUP_TIMEOUT, resolve_public_ip())
                .await
                .context("public-IP lookup timed out")?
        })
        .await
        .cloned()
}

async fn resolve_public_ip() -> anyhow::Result<String> {
    let start_time = Instant::now();

    if let Some(path) = public_ip_cache_path() {
        if let Some(ip) = load_cached_public_ip(&path).await {
            #[cfg(feature = "log")]
            log::debug!("My IP: {ip} (loaded from cache)");
            return Ok(ip);
        }
    }

    let ip = match my_ip_via_dns().await {
        Ok(ip) => {
            #[cfg(feature = "log")]
            log::debug!(
                "My IP: {} (resolved via DNS in {:?})",
                ip,
                start_time.elapsed()
            );
            ip
        }
        Err(dns_error) => {
            #[cfg(feature = "log")]
            log::debug!("DNS lookup failed ({:#}), falling back to HTTPS", dns_error);

            match my_ip_via_https().await {
                Ok(ip) => {
                    #[cfg(feature = "log")]
                    log::debug!(
                        "My IP: {} (resolved via HTTPS in {:?})",
                        ip,
                        start_time.elapsed()
                    );
                    ip
                }
                Err(https_error) => {
                    return Err(https_error.context(format!(
                        "could not determine public IP; DNS also failed: {:#}",
                        dns_error
                    )));
                }
            }
        }
    };

    if let Some(path) = public_ip_cache_path() {
        store_public_ip(&path, &ip).await;
    }
    let _ = start_time;
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::{load_cached_public_ip, parse_ip_body, store_public_ip, MAX_IP_BODY_BYTES};
    use std::{
        fs::File,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, SystemTime},
    };

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn temp_cache_path() -> PathBuf {
        let unique = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "flx_public_ip_test_{}_{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn public_ip_body_is_bounded_and_validated() {
        assert_eq!(parse_ip_body(b"203.0.113.7\n").unwrap(), "203.0.113.7");
        assert!(parse_ip_body(&[b'x'; MAX_IP_BODY_BYTES + 1]).is_err());
        assert!(parse_ip_body(b"not-an-ip").is_err());
    }

    #[tokio::test]
    async fn public_ip_cache_round_trips_fresh_ip() {
        let path = temp_cache_path();
        store_public_ip(&path, "203.0.113.7").await;
        assert_eq!(
            load_cached_public_ip(&path).await.as_deref(),
            Some("203.0.113.7")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn expired_public_ip_cache_is_ignored() {
        let path = temp_cache_path();
        store_public_ip(&path, "203.0.113.7").await;
        let file = File::open(&path).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(25 * 60 * 60))
            .unwrap();
        drop(file);
        assert!(load_cached_public_ip(&path).await.is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn corrupt_public_ip_cache_is_ignored() {
        let path = temp_cache_path();
        tokio::fs::write(&path, "not-an-ip").await.unwrap();
        assert!(load_cached_public_ip(&path).await.is_none());
        let _ = std::fs::remove_file(&path);
    }
}
