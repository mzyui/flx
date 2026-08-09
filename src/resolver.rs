use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
    time::Instant,
};

use anyhow::Context;
use futures_util::{stream::FuturesUnordered, StreamExt};
use hickory_resolver::{
    config::{LookupIpStrategy, NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_tls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tokio::sync::OnceCell;
use tokio::time;

/// HTTPS endpoints used when DNS-based discovery is unavailable.
///
/// Each must answer with the caller's IP address as plain text and nothing else.
static HTTP_IP_ENDPOINTS: [&str; 3] = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
];

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IP_BODY_BYTES: usize = 64;

/// Validates and normalizes a public-IP response body.
///
/// Rejects bodies that are too large, not UTF-8, or not a parseable [`IpAddr`].
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

/// Fetches one HTTPS IP-echo endpoint and validates its body.
///
/// Applies a shared absolute `deadline` so a stalled peer cannot run past the
/// overall lookup budget.
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

/// Set once the OpenDNS lookup fails, so a known-broken DNS path is not
/// retried on every subsequent `my_ip()` call.
///
/// `my_ip` is called once per accepted HTTPS proxy; the public IP is constant
/// for the process lifetime, so re-attempting a deterministic DNS failure per
/// proxy only burns part of each per-validation deadline (and spams logs).
static DNS_UNAVAILABLE: AtomicBool = AtomicBool::new(false);

/// Resolves our public IP over DNS using OpenDNS.
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

/// Lazily-built resolver for `my_ip_via_dns`, constructed once per process.
///
/// Building a `TokioAsyncResolver` is comparatively heavy, so it must not be
/// recreated on every DNS lookup (`my_ip` is called once per accepted HTTPS
/// proxy).
static DNS_RESOLVER: OnceCell<TokioAsyncResolver> = OnceCell::const_new();

/// Builds the cached DNS resolver targeting OpenDNS's A-record-only server.
fn build_dns_resolver() -> TokioAsyncResolver {
    // `myip.opendns.com` only publishes an A record; the default strategy also
    // queries AAAA and would fail the whole lookup with "no record found".
    let mut opts = ResolverOpts::default();
    opts.ip_strategy = LookupIpStrategy::Ipv4Only;
    opts.timeout = LOOKUP_TIMEOUT;
    opts.attempts = 1;

    TokioAsyncResolver::tokio(
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
    )
}

/// Resolves our public IP over HTTPS.
///
/// Used when outbound UDP:53 is filtered, which is common on container hosts
/// and corporate networks.
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

/// Determines the public IP address of the current host.
///
/// Tries OpenDNS first, then falls back to HTTPS echo services when DNS is
/// unavailable (e.g. outbound UDP:53 is blocked). A failed DNS lookup is
/// remembered for the rest of the process so subsequent calls skip straight to
/// HTTPS instead of repeating the doomed DNS attempt.
///
/// # Errors
///
/// Returns an error only when every discovery method fails.
pub async fn my_ip() -> anyhow::Result<String> {
    // Cache the first successful resolution for the lifetime of the process.
    // Failures are not stored, so a transient outage can be retried. Replaces
    // the `cached` crate with a single `OnceCell`.
    static CACHE: OnceCell<String> = OnceCell::const_new();
    CACHE.get_or_try_init(resolve_public_ip).await.cloned()
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

#[cfg(test)]
mod tests {
    use super::{parse_ip_body, MAX_IP_BODY_BYTES};

    #[test]
    fn public_ip_body_is_bounded_and_validated() {
        assert_eq!(parse_ip_body(b"203.0.113.7\n").unwrap(), "203.0.113.7");
        assert!(parse_ip_body(&[b'x'; MAX_IP_BODY_BYTES + 1]).is_err());
        assert!(parse_ip_body(b"not-an-ip").is_err());
    }
}
