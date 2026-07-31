use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
    time::Instant,
};

use anyhow::Context;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_tls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tokio::time;
use tokio::sync::OnceCell;
use hickory_resolver::{
    config::{LookupIpStrategy, NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

/// HTTPS endpoints used when DNS-based discovery is unavailable.
///
/// Each must answer with the caller's IP address as plain text and nothing else.
static HTTP_IP_ENDPOINTS: [&str; 3] = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
];

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolves our public IP over DNS using OpenDNS.
async fn my_ip_via_dns() -> anyhow::Result<String> {
    // `myip.opendns.com` only publishes an A record; the default strategy also
    // queries AAAA and would fail the whole lookup with "no record found".
    let mut opts = ResolverOpts::default();
    opts.ip_strategy = LookupIpStrategy::Ipv4Only;
    opts.timeout = LOOKUP_TIMEOUT;
    opts.attempts = 1;

    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(
                &[IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222))], // OpenDNS server
                53,
                false,
            ),
        ),
        opts,
    );

    let response = resolver
        .lookup_ip("myip.opendns.com")
        .await
        .context("failed to resolve public IP via OpenDNS (myip.opendns.com)")?;

    let ip = response
        .iter()
        .next()
        .context("OpenDNS returned no address record for myip.opendns.com")?;

    Ok(ip.to_string())
}

/// Resolves our public IP over HTTPS.
///
/// Used when outbound UDP:53 is filtered, which is common on container hosts
/// and corporate networks.
async fn my_ip_via_https() -> anyhow::Result<String> {
    let client =
        Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(HttpsConnector::new());

    let mut last_error = None;
    for endpoint in HTTP_IP_ENDPOINTS {
        let result = time::timeout(LOOKUP_TIMEOUT, async {
            let response = client
                .get(endpoint.parse()?)
                .await
                .with_context(|| format!("request to {} failed", endpoint))?;

            if !response.status().is_success() {
                anyhow::bail!("{} returned status {}", endpoint, response.status());
            }

            let body = response
                .into_body()
                .collect()
                .await
                .with_context(|| format!("failed to read body from {}", endpoint))?
                .to_bytes();

            let text = String::from_utf8_lossy(&body);
            let ip: IpAddr = text
                .trim()
                .parse()
                .with_context(|| format!("{} did not return a valid IP: {:?}", endpoint, text))?;
            Ok::<_, anyhow::Error>(ip.to_string())
        })
        .await;

        match result {
            Ok(Ok(ip)) => return Ok(ip),
            Ok(Err(e)) => last_error = Some(e),
            Err(_) => {
                last_error = Some(anyhow::anyhow!(
                    "{} timed out after {:?}",
                    endpoint,
                    LOOKUP_TIMEOUT
                ))
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no HTTPS IP endpoint configured")))
}

/// Determines the public IP address of the current host.
///
/// Tries OpenDNS first, then falls back to HTTPS echo services when DNS is
/// unavailable (e.g. outbound UDP:53 is blocked). Successful lookups are
/// cached; failures are not, so a transient outage can be retried.
///
/// # Errors
///
/// Returns an error only when every discovery method fails.
pub async fn my_ip() -> anyhow::Result<String> {
    // Cache the first successful resolution for the lifetime of the process.
    // Failures are not stored, so a transient outage can be retried. Replaces
    // the `cached` crate with a single `OnceCell`.
    static CACHE: OnceCell<String> = OnceCell::const_new();
    CACHE
        .get_or_try_init(resolve_public_ip)
        .await
        .cloned()
}

/// Performs the actual public-IP discovery, uncached.
async fn resolve_public_ip() -> anyhow::Result<String> {
    let start_time = Instant::now();

    let dns_error = match my_ip_via_dns().await {
        Ok(ip) => {
            #[cfg(feature = "log")]
            log::debug!(
                "My IP: {} (resolved via DNS in {:?})",
                ip,
                start_time.elapsed()
            );
            let _ = start_time;
            return Ok(ip);
        }
        Err(e) => e,
    };

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
            let _ = start_time;
            Ok(ip)
        }
        Err(https_error) => Err(https_error.context(format!(
            "could not determine public IP; DNS also failed: {:#}",
            dns_error
        ))),
    }
}
