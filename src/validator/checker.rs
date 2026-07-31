use std::time::Duration;

use anyhow::Context;

use http_body_util::{BodyExt, Empty};
use hyper::{
    body::{Bytes, Incoming},
    header::USER_AGENT,
    Request, Response,
};

use crate::{
    negotiators::HttpNegotiator,
    proxy::{
        client::{ProxyClient, ProxyRuntimes},
        models::{Anonymity, Protocol, Proxy},
    },
    resolver::my_ip,
};

static ANON_INTEREST: [&str; 15] = [
    "X-REAL-IP",
    "X-FORWARDED-FOR",
    "X-PROXY-ID",
    "VIA",
    "FORWARDED-FOR",
    "X-FORWARDED",
    "HTTP-FORWARDED",
    "CLIENT-IP",
    "FORWARDED-FOR-IP",
    "FORWARDED_FOR",
    "X_FORWARDED FORWARDED",
    "CLIENT_IP",
    "PROXY-CONNECTION",
    "X-PROXY-CONNECTION",
    "X-IMFORWARDS",
];

static HTTP_JUDGES: [&str; 10] = [
    "http://azenv.net/",
    "http://httpheader.net/azenv.php",
    "http://httpbin.org/get?show_env",
    "http://mojeip.net.pl/asdfa/azenv.php",
    "http://proxyjudge.us",
    "http://pascal.hoez.free.fr/azenv.php",
    "http://www.9ravens.com/env.cgi",
    "http://www3.wind.ne.jp/hassii/env.cgi",
    "http://shinh.org/env.cgi",
    "http://www2t.biglobe.ne.jp/~take52/test/env.cgi",
];

/// Maximum simultaneous requests aimed at a single judge.
///
/// With `--max-connections 500` every worker could otherwise hammer the same
/// judge at once, which gets our IP throttled or banned and turns healthy
/// proxies into false negatives.
const MAX_CONCURRENT_PER_JUDGE: usize = 25;

/// One semaphore per entry of [`HTTP_JUDGES`], indexed identically.
static JUDGE_LIMITS: std::sync::LazyLock<Vec<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| {
        HTTP_JUDGES
            .iter()
            .map(|_| tokio::sync::Semaphore::new(MAX_CONCURRENT_PER_JUDGE))
            .collect()
    });

async fn to_raw_response(response: Response<Incoming>) -> anyhow::Result<String> {
    let mut content = String::new();
    for (k, v) in response.headers() {
        content.push_str(&k.as_str().to_uppercase());
        content.push_str(": ");
        content.push_str(
            v.to_str()
                .with_context(|| format!("response header `{}` is not valid utf-8", k))?,
        );
        content.push('\n');
    }
    content.push_str("\n\n");
    if let Ok(bytes) = response.collect().await.map(|body| body.to_bytes()) {
        let body = String::from_utf8_lossy(&bytes);
        content.push_str(&body);
    }
    Ok(content)
}

/// Checks whether the proxy supports plain HTTP by querying public proxy judges.
///
/// # Errors
///
/// Returns an error only for non-recoverable problems (e.g. the public IP of
/// this host could not be determined). Per-attempt failures such as connection
/// refused, timeouts or malformed judge responses are logged and retried, and
/// exhausting all attempts yields `Ok(None)` instead of an error.
pub async fn support_http(
    proxy: &mut Proxy,
    timeout: Duration,
    max_attempts: usize,
) -> anyhow::Result<Option<ProxyRuntimes<Protocol>>> {
    let useragent = crate::user_agent::random_user_agent();
    let my_ip = my_ip()
        .await
        .context("cannot determine anonymity level without knowing our own public IP")?;

    for (index, judge_url) in HTTP_JUDGES.iter().enumerate().cycle().take(max_attempts) {
        // Rate-limit per judge so one host is never overwhelmed.
        let Ok(_judge_permit) = JUDGE_LIMITS[index].acquire().await else {
            continue;
        };

        let req = match Request::get(*judge_url)
            .header(USER_AGENT, useragent)
            .body(Empty::<Bytes>::new())
        {
            Ok(req) => req,
            Err(_e) => {
                #[cfg(feature = "log")]
                log::trace!("{}: invalid judge request for {}: {}", proxy, judge_url, _e);
                continue;
            }
        };

        let response = match proxy.send_request(req, Some(HttpNegotiator), timeout).await {
            Ok(response) => response,
            Err(_e) => {
                #[cfg(feature = "log")]
                log::trace!("{}: judge {} unreachable: {:#}", proxy, judge_url, _e);
                continue;
            }
        };

        if !response.inner.status().is_success() {
            #[cfg(feature = "log")]
            log::trace!(
                "{}: judge {} returned status {}",
                proxy,
                judge_url,
                response.inner.status()
            );
            return Ok(None);
        }

        let body = match to_raw_response(response.inner).await {
            Ok(body) => body,
            Err(_e) => {
                #[cfg(feature = "log")]
                log::trace!(
                    "{}: failed to read judge {} response: {:#}",
                    proxy,
                    judge_url,
                    _e
                );
                continue;
            }
        };

        let anonymity = if body.contains(&my_ip) {
            Anonymity::Transparent
        } else if ANON_INTEREST.iter().any(|&v| body.contains(v))
            || body.contains(&proxy.ip.to_string())
        {
            Anonymity::Anonymous
        } else {
            Anonymity::Elite
        };

        return Ok(Some(ProxyRuntimes {
            inner: Protocol::Http(anonymity),
            runtimes: response.runtimes,
        }));
    }
    Ok(None)
}
