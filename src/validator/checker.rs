use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, LazyLock, Mutex,
    },
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use aho_corasick::AhoCorasick;
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
        client::{tls_connector, ProxyClient, ProxyRuntimes},
        models::{Anonymity, Protocol, Proxy, RuntimeStats},
    },
    resolver::my_ip,
};

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

static ANON_MATCHER: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(ANON_INTEREST).expect("static anonymity tokens are valid"));

const MAX_JUDGE_BODY_BYTES: usize = 512 * 1024;
const JUDGE_FAILURE_COOLDOWN: Duration = Duration::from_secs(30);

fn end_to_end_runtime(elapsed: Duration) -> RuntimeStats {
    let mut runtimes = RuntimeStats::default();
    runtimes.record(elapsed.as_secs_f64());
    runtimes
}

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

pub fn classify_anonymity(body: &str, my_ip: &str) -> Anonymity {
    if body.contains(my_ip) {
        Anonymity::Transparent
    } else if ANON_MATCHER.find(body.as_bytes()).is_some() {
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

    pub async fn verify_online(&self, timeout: Duration, insecure: bool) -> anyhow::Result<()> {
        use hyper_tls::HttpsConnector;
        use hyper_util::{
            client::legacy::{connect::HttpConnector, Client},
            rt::TokioExecutor,
        };

        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let connector = HttpsConnector::from((http, tls_connector(insecure)));
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
        if memchr::memmem::find(&body, self.response_marker.as_bytes()).is_none() {
            anyhow::bail!("online judge did not echo X-Fluxy-Token");
        }
        Ok(())
    }
}

pub struct JudgePool {
    inner: Mutex<PoolInner>,
    cursor: AtomicUsize,
    epoch: time::Instant,
}

struct PoolInner {
    judges: Vec<Arc<ValidationTarget>>,
    cooldown_until_ms: Vec<PaddedCooldown>,
}

#[repr(align(64))]
struct PaddedCooldown(AtomicU64);

impl JudgePool {
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
            if !pool.is_empty() {
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
        if pool.is_empty() {
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

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .judges
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

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

    pub(crate) fn append(&self, target: Arc<ValidationTarget>) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.judges.push(target);
        inner
            .cooldown_until_ms
            .push(PaddedCooldown(AtomicU64::new(0)));
    }

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

pub async fn support_http(
    proxy: &mut Proxy,
    timeout: Duration,
    max_attempts: usize,
    pool: &JudgePool,
    insecure: bool,
) -> anyhow::Result<Option<ProxyRuntimes<Protocol>>> {
    let useragent = crate::user_agent::next_user_agent();
    // One shared end-to-end budget across every attempt and judge so a proxy
    // that accepts TCP but never replies is bounded once instead of paying a
    // full `timeout` per judge/attempt.
    let budget_started = time::Instant::now();
    let budget = timeout.saturating_mul(max_attempts as u32);

    for _ in 0..max_attempts {
        for target in pool.candidates() {
            let remaining = budget
                .checked_sub(budget_started.elapsed())
                .unwrap_or_default();
            if remaining.is_zero() {
                return Ok(None);
            }
            let started = time::Instant::now();
            let per_request = remaining.min(timeout);
            let deadline = started + per_request;
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
                    .send_request(req, Some(HttpsNegotiator), per_request, insecure)
                    .await
            } else {
                proxy
                    .send_request(req, Some(HttpNegotiator), per_request, insecure)
                    .await
            } {
                Ok(response) => response,
                Err(_e) => {
                    #[cfg(feature = "log")]
                    log::trace!("{}: local judge unreachable: {:#}", proxy, _e);
                    // Cool the judge down so the round-robin stops wasting attempts on a
                    // judge that just failed.
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
    use super::{
        classify_anonymity, end_to_end_runtime, support_http, JudgePool, ValidationTarget,
    };
    use crate::proxy::models::{Anonymity, Proxy};
    use std::time::{Duration, Instant};
    use std::vec::Vec;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn anonymity_classification_uses_single_pass_token_matching() {
        let ip = "203.0.113.7";
        let body = "HTTP/1.1 200 OK\nX-CLIENT-IP: 10.0.0.1\n...";

        assert_eq!(
            classify_anonymity(&format!("REMOTE_ADDR = {ip}\n..."), ip),
            Anonymity::Transparent
        );
        assert_eq!(classify_anonymity(body, ip), Anonymity::Anonymous);
        assert_eq!(
            classify_anonymity("no leak tokens here", ip),
            Anonymity::Elite
        );
    }

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
        // Regression test: `build` returns as soon as the first candidate passes,
        // leaving a hanging judge preflighting in the background.
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

    // Self-signed fixtures (CN=127.0.0.1, SAN IP:127.0.0.1) that a strict TLS
    // client must reject unless `--insecure` is honoured.
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
        // Regression test: `--insecure` must let a self-signed judge pass preflight.
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
        // Regression test: without `--insecure` the self-signed cert must be
        // rejected during preflight.
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
        // Regression test: a judge serving 200 without echoing the per-target
        // token must be rejected (token replay resistance).
        let url = spawn_self_signed_judge(false).await;
        let target = ValidationTarget::online(&url).unwrap();
        let err = target
            .verify_online(Duration::from_secs(2), /* insecure = */ true)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("did not echo"));
    }

    async fn spawn_stalled_clients() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            for _ in 0..16 {
                match listener.accept().await {
                    Ok((stream, _)) => held.push(stream),
                    Err(_) => break,
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        address
    }

    #[tokio::test]
    async fn stalled_http_proxy_consumes_one_shared_budget() {
        // Offline-safe: the blackhole accepts but never responds, so the probe
        // must burn one shared budget across the judge pool rather than one
        // full timeout per judge.
        let blackhole = spawn_stalled_clients().await;
        let pool = JudgePool::from_targets(Vec::from([
            std::sync::Arc::new(ValidationTarget::online("http://127.0.0.1:9/judge-a").unwrap()),
            std::sync::Arc::new(ValidationTarget::online("http://127.0.0.1:9/judge-b").unwrap()),
        ]));
        let started = Instant::now();
        let mut proxy = Proxy::new("127.0.0.1".parse().unwrap(), blackhole.port());
        let result = support_http(&mut proxy, Duration::from_millis(300), 1, &pool, false)
            .await
            .unwrap();
        let elapsed = started.elapsed();

        assert!(result.is_none());
        assert!(
            elapsed < Duration::from_millis(500),
            "shared budget not honoured: {elapsed:?}"
        );
    }
}
