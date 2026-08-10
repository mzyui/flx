use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::{task::JoinSet, time};

use anyhow::Context;

use http_body_util::Empty;
use hyper::{
    body::{Bytes, Incoming},
    header::USER_AGENT,
    Request, Response,
};

use crate::{
    negotiators::{HttpNegotiator, HttpsNegotiator},
    proxy::{
        client::{ProxyClient, ProxyRuntimes},
        models::{Anonymity, Protocol, Proxy, RuntimeStats},
    },
    resolver::my_ip,
};

/// Header tokens whose appearance in a judge's echoed environment is taken as
/// evidence that a proxy forwards client- or proxy-internal metadata. Kept as
/// a small sorted slice (not a `HashSet`) because classification only iterates
/// it: a fixed-size contiguous array is cheaper than hashing 15 members.
static ANON_INTEREST: &[&str] = &[
    "CLIENT-IP",
    "CLIENT_IP",
    "FORWARDED-FOR",
    "FORWARDED-FOR-IP",
    "FORWARDED_FOR",
    "HTTP-FORWARDED",
    "PROXY-CONNECTION",
    "VIA",
    "X-FORWARDED",
    "X-FORWARDED-FOR",
    "X-IMFORWARDS",
    "X-PROXY-CONNECTION",
    "X-PROXY-ID",
    "X-REAL-IP",
    "X_FORWARDED FORWARDED",
];

const MAX_JUDGE_BODY_BYTES: usize = 512 * 1024;
const JUDGE_FAILURE_COOLDOWN: Duration = Duration::from_secs(30);

fn end_to_end_runtime(elapsed: Duration) -> RuntimeStats {
    let mut runtimes = RuntimeStats::default();
    runtimes.record(elapsed.as_secs_f64());
    runtimes
}

/// Reads an HTTP body incrementally, enforcing `limit` *before* appending each
/// chunk so a malicious/sloppy judge cannot make us buffer an unbounded amount
/// of memory before the size check fires. Replaces the previous
/// `response.collect().await?.to_bytes()` pattern which accumulated the whole
/// body first and only then compared against the limit.
pub(crate) async fn read_bounded_body(
    mut body: hyper::body::Incoming,
    limit: usize,
) -> anyhow::Result<Bytes> {
    use http_body_util::BodyExt;
    let mut collected: Vec<u8> = Vec::with_capacity(8192);
    while let Some(chunk) = body.frame().await {
        let chunk = chunk
            .map_err(|e| anyhow::anyhow!("judge body stream error: {e}"))?
            .into_data()
            .unwrap_or_default();
        if collected.len().saturating_add(chunk.len()) > limit {
            anyhow::bail!("judge response body exceeds {limit} bytes");
        }
        collected.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(collected))
}

/// Classifies the anonymity level of a proxy from the judge response body.
///
/// `my_ip` is this host's public IP; if it appears in the echoed environment the
/// proxy is `Transparent`. Presence of any header that typically leaks client or
/// proxy metadata marks it `Anonymous`, otherwise `Elite`.
pub(crate) fn classify_anonymity(body: &str, my_ip: &str) -> Anonymity {
    if body.contains(my_ip) {
        Anonymity::Transparent
    } else if ANON_INTEREST.iter().any(|token| body.contains(token)) {
        Anonymity::Anonymous
    } else {
        Anonymity::Elite
    }
}

#[derive(Debug, Clone)]
pub struct ValidationTarget {
    pub(crate) url: String,
    pub(crate) response_marker: String,
    pub(crate) request_token: String,
}

impl ValidationTarget {
    /// Builds a target from a judge URL, minting a fresh request token for it.
    ///
    /// The token is bound to this target, so a response cannot be reused
    /// against a different target (token-replay resistance).
    pub fn online(url: &str) -> anyhow::Result<Self> {
        let uri: hyper::Uri = url
            .parse()
            .with_context(|| format!("invalid online judge URL `{url}`"))?;
        match uri.scheme_str() {
            Some("http") | Some("https") => {}
            _ => anyhow::bail!("online judge URL must use http or https"),
        }
        if uri.host().is_none() {
            anyhow::bail!("online judge URL must contain a host");
        }
        let token = format!(
            "fluxy-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        Ok(Self {
            url: url.to_owned(),
            response_marker: format!("HTTP_X_FLUXY_TOKEN = {token}"),
            request_token: token,
        })
    }

    /// Sends the request token and checks that the judge echoes it back.
    ///
    /// # Errors
    ///
    /// Returns an error when the judge is unreachable or times out, returns a
    /// non-success status, or fails to echo the token.
    pub async fn verify_online(&self, timeout: Duration, insecure: bool) -> anyhow::Result<()> {
        use hyper_tls::HttpsConnector;
        use hyper_util::{
            client::legacy::{connect::HttpConnector, Client},
            rt::TokioExecutor,
        };

        let tls = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(insecure)
            .build()
            .context("failed to build online judge TLS connector")?;
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let connector = HttpsConnector::from((http, tokio_native_tls::TlsConnector::from(tls)));
        let client = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(connector);
        let request = Request::get(&self.url)
            .header("X-Fluxy-Token", &self.request_token)
            .body(Empty::<Bytes>::new())?;
        let deadline = time::Instant::now() + timeout;
        let response = time::timeout_at(deadline, client.request(request))
            .await
            .context("online judge preflight timed out")??;
        if !response.status().is_success() {
            anyhow::bail!(
                "online judge preflight returned status {}",
                response.status()
            );
        }
        let body = time::timeout_at(
            deadline,
            read_bounded_body(response.into_body(), MAX_JUDGE_BODY_BYTES),
        )
        .await
        .context("online judge preflight body timed out")??;
        if body.len() > MAX_JUDGE_BODY_BYTES {
            anyhow::bail!("online judge preflight body exceeds limit");
        }
        if !body
            .windows(self.response_marker.len())
            .any(|window| window.eq_ignore_ascii_case(self.response_marker.as_bytes()))
        {
            anyhow::bail!("online judge did not echo X-Fluxy-Token");
        }
        Ok(())
    }
}

/// A verified pool of judges for a single protocol class (HTTP or tunnel).
///
/// Each judge is independently preflighted at startup; only those that echo the
/// unique token within the deadline enter the pool. Preflight is streaming: the
/// pool starts empty and judges are appended as soon as they pass, so
/// validation can begin with the first verified judge instead of waiting for
/// the slowest candidate. Live requests pick the next healthy judge
/// round-robin, so a single dead endpoint degrades gracefully instead of
/// failing every probe or silently swapping to an unverified one.
pub struct JudgePool {
    inner: Mutex<PoolInner>,
    cursor: AtomicUsize,
    epoch: time::Instant,
}

/// The append-only judge list plus per-judge cooldown timestamps.
struct PoolInner {
    judges: Vec<Arc<ValidationTarget>>,
    cooldown_until_ms: Vec<PaddedCooldown>,
}

/// A cooldown timestamp padded to its own cache line so judges probed by
/// different workers never bounce one shared line when one of them is written
/// during a failure while the others are being read.
#[repr(align(64))]
struct PaddedCooldown(AtomicU64);

impl JudgePool {
    /// Builds a pool from the candidate `urls`, preflighting each one.
    ///
    /// Judges that fail preflight are reported via `on_dropped` and excluded.
    /// If no judge survives, this returns an error so the caller can fail fast
    /// with a message telling the user to supply a working `--*judge-url`.
    ///
    /// Returns as soon as the first candidate passes; the remaining candidates
    /// keep preflighting in the background and are appended when they pass.
    pub async fn build<F>(
        urls: &[String],
        timeout: Duration,
        insecure: bool,
        mut on_dropped: F,
    ) -> anyhow::Result<Arc<Self>>
    where
        F: FnMut(&str, &str) + Send + 'static,
    {
        if urls.is_empty() {
            anyhow::bail!("judge pool must contain at least one candidate URL");
        }
        let mut seen = HashSet::with_capacity(urls.len());
        let mut candidates = Vec::with_capacity(urls.len());
        for url in urls {
            if !seen.insert(url.clone()) {
                continue; // de-duplicate without a redundant preflight
            }
            match ValidationTarget::online(url) {
                Ok(target) => candidates.push((url.clone(), target)),
                Err(error) => on_dropped(url, &format!("{error:#}")),
            }
        }

        // Preflight every candidate concurrently; a passing judge is appended
        // to the shared pool the moment it verifies, so validation never waits
        // for the slowest candidate.
        let pool = Arc::new(Self::empty());
        let mut tasks = JoinSet::new();
        for (url, target) in candidates {
            let pool = Arc::clone(&pool);
            tasks.spawn(async move {
                let result = target.verify_online(timeout, insecure).await;
                if result.is_ok() {
                    pool.append(Arc::new(target));
                }
                (url, result)
            });
        }

        // Wait until the first judge has passed (appended) or every candidate
        // has finished. Failures that land first are still reported.
        loop {
            if pool.len() > 0 {
                break;
            }
            match tasks.join_next().await {
                Some(Ok((_url, Ok(())))) => {} // already appended by the task
                Some(Ok((url, Err(error)))) => on_dropped(&url, &format!("{error:#}")),
                Some(Err(error)) => {
                    return Err(error).context("online judge preflight task failed");
                }
                None => break,
            }
        }
        if pool.len() == 0 {
            anyhow::bail!(
                "no online judge passed preflight; all {} candidate URL(s) failed",
                urls.len()
            );
        }

        // The remaining candidates finish in the background: survivors are
        // appended as they verify, failures are reported.
        tokio::spawn(async move {
            while let Some(joined) = tasks.join_next().await {
                match joined {
                    Ok((_url, Ok(()))) => {}
                    Ok((url, Err(error))) => on_dropped(&url, &format!("{error:#}")),
                    Err(error) => on_dropped("<judge>", &format!("{error:#}")),
                }
            }
        });

        Ok(pool)
    }

    /// Returns the next healthy judge using a round-robin cursor.
    ///
    /// Production probing goes through [`Self::candidates`] (which snapshots
    /// the healthy judges once per proxy); this single-pick primitive is only
    /// exercised by the round-robin/cooldown tests now.
    #[cfg(test)]
    pub fn next(&self) -> Arc<ValidationTarget> {
        let start = self.cursor.fetch_add(1, Ordering::Relaxed);
        let now_ms = self.epoch.elapsed().as_millis() as u64;
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for offset in 0..inner.judges.len() {
            let index = (start + offset) % inner.judges.len();
            if inner.cooldown_until_ms[index].0.load(Ordering::Relaxed) <= now_ms {
                return Arc::clone(&inner.judges[index]);
            }
        }
        Arc::clone(&inner.judges[start % inner.judges.len()])
    }

    /// Healthy judges to try for the next attempt: the round-robin rotation
    /// minus any judges currently in cooldown. Falls back to a single judge
    /// when all are cooling down.
    pub(crate) fn candidates(&self) -> Vec<Arc<ValidationTarget>> {
        let start = self.cursor.fetch_add(1, Ordering::Relaxed);
        let now_ms = self.epoch.elapsed().as_millis() as u64;
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut candidates = Vec::with_capacity(inner.judges.len());
        for offset in 0..inner.judges.len() {
            let index = (start + offset) % inner.judges.len();
            if inner.cooldown_until_ms[index].0.load(Ordering::Relaxed) <= now_ms {
                candidates.push(Arc::clone(&inner.judges[index]));
            }
        }
        if candidates.is_empty() {
            candidates.push(Arc::clone(&inner.judges[start % inner.judges.len()]));
        }
        candidates
    }

    pub fn report_failure(&self, target: &ValidationTarget) {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(index) = inner
            .judges
            .iter()
            .position(|judge| judge.url == target.url)
        {
            let until = self
                .epoch
                .elapsed()
                .saturating_add(JUDGE_FAILURE_COOLDOWN)
                .as_millis() as u64;
            inner.cooldown_until_ms[index]
                .0
                .store(until, Ordering::Relaxed);
        }
    }

    /// Number of healthy judges currently in the pool.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .judges
            .len()
    }

    /// Creates an empty pool that preflight tasks append to as they pass.
    pub(crate) fn empty() -> Self {
        Self {
            inner: Mutex::new(PoolInner {
                judges: Vec::new(),
                cooldown_until_ms: Vec::new(),
            }),
            cursor: AtomicUsize::new(0),
            epoch: time::Instant::now(),
        }
    }

    /// Adds a verified judge to the pool.
    pub(crate) fn append(&self, target: Arc<ValidationTarget>) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.judges.push(target);
        inner
            .cooldown_until_ms
            .push(PaddedCooldown(AtomicU64::new(0)));
    }

    /// Builds a pool from already-constructed targets (used by tests and the
    /// validator's placeholder pools for unrequested protocol classes).
    pub(crate) fn from_targets(targets: Vec<Arc<ValidationTarget>>) -> Self {
        let cooldown_until_ms = (0..targets.len())
            .map(|_| PaddedCooldown(AtomicU64::new(0)))
            .collect();
        Self {
            inner: Mutex::new(PoolInner {
                judges: targets,
                cooldown_until_ms,
            }),
            cursor: AtomicUsize::new(0),
            epoch: time::Instant::now(),
        }
    }
}

/// Serializes a judge response for marker and anonymity matching: upper-cased
/// headers followed by the bounded raw body.
///
/// Header names are upper-cased byte-by-byte into a reusable `Vec<u8>` and the
/// body is appended directly, so no intermediate `String` is allocated per
/// header or per response body (a lossy decode only happens later, when
/// anonymity classification actually needs text).
async fn to_raw_response(
    response: Response<Incoming>,
    deadline: time::Instant,
) -> anyhow::Result<Vec<u8>> {
    let mut content: Vec<u8> = Vec::with_capacity(2048);
    for (k, v) in response.headers() {
        for &b in k.as_str().as_bytes() {
            content.push(b.to_ascii_uppercase());
        }
        content.extend_from_slice(b": ");
        content.extend_from_slice(
            v.to_str()
                .with_context(|| format!("response header `{}` is not valid utf-8", k))?
                .as_bytes(),
        );
        content.push(b'\n');
    }
    content.extend_from_slice(b"\n\n");
    let bytes = time::timeout_at(
        deadline,
        read_bounded_body(response.into_body(), MAX_JUDGE_BODY_BYTES),
    )
    .await
    .context("judge response body timed out")??;
    content.extend_from_slice(&bytes);
    Ok(content)
}

/// Checks whether the proxy supports plain HTTP through the local judge.
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
    pool: &JudgePool,
    insecure: bool,
) -> anyhow::Result<Option<ProxyRuntimes<Protocol>>> {
    let useragent = crate::user_agent::random_user_agent();

    for _ in 0..max_attempts {
        for target in pool.candidates() {
            let started = time::Instant::now();
            let deadline = time::Instant::now() + timeout;
            let req = match Request::get(&target.url)
                .header(USER_AGENT, useragent)
                .header("X-Fluxy-Token", &target.request_token)
                .body(Empty::<Bytes>::new())
            {
                Ok(req) => req,
                Err(_e) => {
                    #[cfg(feature = "log")]
                    log::trace!("{}: invalid local judge request: {}", proxy, _e);
                    continue;
                }
            };

            let response = match if target.url.starts_with("https://") {
                proxy
                    .send_request(req, Some(HttpsNegotiator), timeout, insecure)
                    .await
            } else {
                proxy
                    .send_request(req, Some(HttpNegotiator), timeout, insecure)
                    .await
            } {
                Ok(response) => response,
                Err(_e) => {
                    #[cfg(feature = "log")]
                    log::trace!("{}: local judge unreachable: {:#}", proxy, _e);
                    // A judge that cannot be reached once is likely still down;
                    // cool it down so the round-robin (and every other proxy)
                    // stops wasting an attempt and a TCP connect on it. Mirrors
                    // the tunnel path (re-audit N2).
                    pool.report_failure(&target);
                    continue;
                }
            };

            if !response.inner.status().is_success() {
                #[cfg(feature = "log")]
                log::trace!(
                    "{}: local judge returned status {}",
                    proxy,
                    response.inner.status()
                );
                pool.report_failure(&target);
                continue;
            }

            let body = match to_raw_response(response.inner, deadline).await {
                Ok(body) => body,
                Err(_e) => {
                    #[cfg(feature = "log")]
                    log::trace!("{}: failed to read local judge response: {:#}", proxy, _e);
                    continue;
                }
            };

            if memchr::memmem::find(&body, target.response_marker.as_bytes()).is_none() {
                #[cfg(feature = "log")]
                log::trace!("{}: response did not originate from the local judge", proxy);
                pool.report_failure(&target);
                continue;
            }

            let remaining = deadline
                .checked_duration_since(time::Instant::now())
                .context("public-IP lookup timed out during HTTP validation")?;
            let my_ip = time::timeout(remaining, my_ip())
                .await
                .context("public-IP lookup timed out during HTTP validation")?
                .context("cannot determine anonymity level without knowing our own public IP")?;
            let body = String::from_utf8_lossy(&body);
            let anonymity = classify_anonymity(&body, &my_ip);

            return Ok(Some(ProxyRuntimes {
                inner: Protocol::Http(anonymity),
                runtimes: end_to_end_runtime(started.elapsed()),
                driver: None,
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{end_to_end_runtime, JudgePool, ValidationTarget};
    use std::time::{Duration, Instant};
    use std::vec::Vec;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn http_latency_is_one_end_to_end_sample() {
        let runtimes = end_to_end_runtime(Duration::from_millis(125));

        assert_eq!(runtimes.count, 1);
        assert!((runtimes.avg() - 0.125).abs() < f64::EPSILON);
        assert!((runtimes.min - 0.125).abs() < f64::EPSILON);
        assert!((runtimes.max - 0.125).abs() < f64::EPSILON);
    }

    #[test]
    fn online_target_requires_its_echoed_request_token() {
        let target = ValidationTarget::online("https://example.com/azenv.php").unwrap();

        assert!(target.url.starts_with("https://example.com/azenv.php"));
        assert!(target.request_token.starts_with("fluxy-"));
        assert_eq!(
            target.response_marker,
            format!("HTTP_X_FLUXY_TOKEN = {}", target.request_token)
        );
    }

    #[tokio::test]
    async fn pool_rejects_judge_that_does_not_echo_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nno echo",
                )
                .await
                .unwrap();
        });
        let urls = Vec::from([format!("http://{address}/judge")]);
        let dropped = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let dropped_for_report = std::sync::Arc::clone(&dropped);

        let result = JudgePool::build(&urls, Duration::from_secs(1), false, move |url, reason| {
            dropped_for_report
                .lock()
                .unwrap()
                .push((url.to_owned(), reason.to_owned()));
        })
        .await;

        assert!(result.is_err());
        {
            let dropped = dropped.lock().unwrap();
            assert_eq!(dropped.len(), 1);
            assert!(dropped[0].1.contains("did not echo"));
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pool_round_robin_cycles_through_all_judges() {
        let urls = Vec::from([
            "http://a.example.com/azenv.php".to_owned(),
            "http://b.example.com/azenv.php".to_owned(),
            "http://c.example.com/azenv.php".to_owned(),
        ]);
        let targets: Vec<_> = urls
            .iter()
            .map(|u| std::sync::Arc::new(ValidationTarget::online(u).unwrap()))
            .collect();
        let pool = JudgePool::from_targets(targets);
        assert_eq!(pool.len(), 3);

        let first = pool.next();
        let second = pool.next();
        let third = pool.next();
        let fourth = pool.next();

        assert_eq!(first.url, urls[0]);
        assert_eq!(second.url, urls[1]);
        assert_eq!(third.url, urls[2]);
        // wraps back to the start
        assert_eq!(fourth.url, urls[0]);
    }

    #[tokio::test]
    async fn build_returns_once_first_judge_passes() {
        // Regression for B.49: a judge that accepts but never responds must not
        // hold up startup — `build` returns as soon as the first candidate
        // passes, and the straggler is left preflighting in the background.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hanging_url = format!("http://{}/judge", listener.local_addr().unwrap());
        let _server = tokio::spawn(async move {
            let _ = listener.accept().await;
            std::future::pending::<()>().await; // never reply
        });

        let fast_url = spawn_plain_echo_judge().await;
        let started = Instant::now();

        let pool = JudgePool::build(
            &[hanging_url, fast_url],
            Duration::from_secs(5),
            /* insecure = */ false,
            |_, _| {},
        )
        .await
        .unwrap();

        assert!(
            started.elapsed() < Duration::from_secs(3),
            "build must not wait for the hanging judge's timeout"
        );
        assert_eq!(pool.len(), 1);
    }

    #[tokio::test]
    async fn pool_appends_judges_after_empty_start() {
        let pool = JudgePool::empty();
        assert_eq!(pool.len(), 0);

        let url = "http://a.example.com/azenv.php".to_owned();
        pool.append(std::sync::Arc::new(ValidationTarget::online(&url).unwrap()));
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.next().url, url);
        assert_eq!(pool.next().url, url, "round-robin wraps on a single judge");
    }

    #[test]
    fn pool_skips_judge_in_runtime_cooldown() {
        let first = std::sync::Arc::new(
            ValidationTarget::online("http://first.example.com/judge").unwrap(),
        );
        let second = std::sync::Arc::new(
            ValidationTarget::online("http://second.example.com/judge").unwrap(),
        );
        let pool = JudgePool::from_targets(Vec::from([
            std::sync::Arc::clone(&first),
            std::sync::Arc::clone(&second),
        ]));

        pool.report_failure(&first);

        assert_eq!(pool.next().url, second.url);
        assert_eq!(pool.next().url, second.url);
    }

    #[test]
    fn candidate_round_contains_each_healthy_judge_once() {
        let first = std::sync::Arc::new(
            ValidationTarget::online("http://first.example.com/judge").unwrap(),
        );
        let second = std::sync::Arc::new(
            ValidationTarget::online("http://second.example.com/judge").unwrap(),
        );
        let third = std::sync::Arc::new(
            ValidationTarget::online("http://third.example.com/judge").unwrap(),
        );
        let pool = JudgePool::from_targets(Vec::from([
            std::sync::Arc::clone(&first),
            std::sync::Arc::clone(&second),
            std::sync::Arc::clone(&third),
        ]));
        pool.report_failure(&first);

        let candidates = pool.candidates();

        assert_eq!(candidates.len(), 2);
        assert!(candidates
            .iter()
            .any(|candidate| candidate.url == second.url));
        assert!(candidates
            .iter()
            .any(|candidate| candidate.url == third.url));
        assert!(!candidates
            .iter()
            .any(|candidate| candidate.url == first.url));
    }

    #[test]
    fn pool_deduplicates_repeated_urls() {
        let url = "http://a.example.com/azenv.php".to_owned();
        let target = ValidationTarget::online(&url).unwrap();
        // Two clones of the same target: from_targets keeps both unless deduped
        // upstream. The build() path dedupes by URL, but the unit constructor
        // honours exactly what it is given.
        let pool = JudgePool::from_targets(Vec::from([
            std::sync::Arc::new(target),
            std::sync::Arc::new(ValidationTarget::online(&url).unwrap()),
        ]));
        assert_eq!(pool.len(), 2);
    }

    /// Spawns a plain-HTTP judge that echoes the `X-Fluxy-Token` header.
    ///
    /// The header match is case-insensitive, mirroring `spawn_self_signed_judge`
    /// (F-32), and is safe to rely on for the streaming-preflight tests.
    async fn spawn_plain_echo_judge() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let mut received = Vec::new();
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    received.extend_from_slice(&buf[..n]);
                    if received.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let mut token = String::new();
                for line in received.split(|&b| b == b'\n') {
                    let line = String::from_utf8_lossy(line);
                    let (name, value) = line.split_once(':').unwrap_or(("", ""));
                    if name.trim().eq_ignore_ascii_case("x-fluxy-token") {
                        token = value.trim().to_owned();
                        break;
                    }
                }
                let body = format!("HTTP_X_FLUXY_TOKEN = {token}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        format!("http://{address}/azenv.php")
    }

    // Self-signed certificate + key for the F-32 end-to-end preflight test.
    // Stored as fixtures (generated for CN=127.0.0.1 / SAN IP:127.0.0.1) and
    // embedded at compile time. NOT a CA-signed cert, so a strict TLS client
    // must reject it unless `--insecure` is honoured.
    const SELF_SIGNED_CERT_PEM: &str = include_str!("../../tests/fixtures/self_signed_cert.pem");
    const SELF_SIGNED_KEY_PEM: &str = include_str!("../../tests/fixtures/self_signed_key.pem");

    async fn spawn_self_signed_judge(echo_token: bool) -> String {
        use native_tls::Identity;
        use tokio_native_tls::TlsAcceptor;
        let identity = Identity::from_pkcs8(
            SELF_SIGNED_CERT_PEM.as_bytes(),
            SELF_SIGNED_KEY_PEM.as_bytes(),
        )
        .expect("build self-signed identity");
        let acceptor = TlsAcceptor::from(native_tls::TlsAcceptor::new(identity).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    // Read the HTTP request so we can echo the per-target token.
                    let mut buf = [0u8; 2048];
                    let mut received = Vec::new();
                    let mut token = String::new();
                    loop {
                        let n = match tls.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        received.extend_from_slice(&buf[..n]);
                        if received.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    for line in received.split(|&b| b == b'\n') {
                        let line = String::from_utf8_lossy(line).to_string();
                        if let Some((name, value)) = line.split_once(':') {
                            if name.trim().eq_ignore_ascii_case("x-fluxy-token") {
                                token = value.trim().to_owned();
                                break;
                            }
                        }
                    }
                    let body = if echo_token {
                        format!("HTTP_X_FLUXY_TOKEN = {token}")
                    } else {
                        "no token here".to_owned()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tls.write_all(response.as_bytes()).await;
                }
            }
        });
        format!("https://{address}/azenv.php")
    }

    #[tokio::test]
    async fn self_signed_judge_passes_preflight_with_insecure() {
        // Regression for F-32: `--insecure` must let a self-signed judge pass
        // preflight (it echoes the token over a TLS connection we trust).
        let url = spawn_self_signed_judge(true).await;
        let target = ValidationTarget::online(&url).unwrap();
        let err = target
            .verify_online(Duration::from_secs(2), /* insecure = */ true)
            .await;
        match &err {
            Ok(()) => {}
            #[cfg(feature = "log")]
            Err(e) => log::error!("VERIFY_ERR insecure=true: {e:#}"),
            #[cfg(not(feature = "log"))]
            Err(_) => {}
        }
        assert!(err.is_ok(), "self-signed judge must pass with --insecure");
    }

    #[tokio::test]
    async fn self_signed_judge_is_rejected_without_insecure() {
        // Regression for F-32: without `--insecure` the self-signed cert must
        // be rejected during preflight.
        let url = spawn_self_signed_judge(true).await;
        let result = JudgePool::build(
            &[url],
            Duration::from_secs(2),
            /* insecure = */ false,
            |_, _| {},
        )
        .await;
        assert!(
            result.is_err(),
            "self-signed judge must fail without --insecure"
        );
    }

    #[tokio::test]
    async fn verify_online_rejects_judge_without_token_echo() {
        // Regression for F-30 (token replay resistance): a judge that serves a
        // 200 but does NOT echo the per-target token must be rejected. This is
        // the property that stops a MITM from replaying a previous judge
        // response, since the token is bound to the `ValidationTarget`.
        let url = spawn_self_signed_judge(false).await;
        let target = ValidationTarget::online(&url).unwrap();
        let err = target
            .verify_online(Duration::from_secs(2), /* insecure = */ true)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("did not echo"));
    }
}
