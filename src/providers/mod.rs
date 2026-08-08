use std::{
    borrow::Cow,
    collections::{HashSet, VecDeque},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use async_trait::async_trait;
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request};
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use models::Source;
use tokio::time;

const MAX_SOURCE_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_REDIRECTS: usize = 10;

use crate::proxy::models::{Protocol, Proxy};

mod free_proxy_list;
mod freeproxy_world;
mod geonode;
mod github;
pub mod models;
mod my_proxy;
mod openproxylist;
pub mod parsers;
mod proxylist_org;
mod proxynova;
mod proxyscrape;

pub use free_proxy_list::FreeProxyListProvider;
pub use freeproxy_world::FreeProxyWorldProvider;
pub use geonode::GeonodeProvider;
pub use github::GithubRepoProvider;
pub use my_proxy::MyProxyProvider;
pub use openproxylist::OpenProxyListProvider;
pub use proxylist_org::ProxyListOrgProvider;
pub use proxynova::ProxyNovaProvider;
pub use proxyscrape::ProxyscrapeProvider;

pub use models::ProviderTier;
use models::ScrapeMode;

/// Builds one instance of every provider fluxy knows about.
///
/// Mirrors the registry in `mzyui/proxy-list` (engine/src/providers/index.js).
/// `proxyscan` is intentionally absent: its download endpoint returns HTTP 404
/// for every protocol and it is disabled upstream too.
///
/// Ordering matters: website providers come first because they publish fresh,
/// self-maintained lists, while [`GithubRepoProvider`] is deliberately last —
/// the GitHub mirrors are aggregated copies of those same sites and serve only
/// as a fallback when the primary sources are unreachable or empty.
pub fn all_providers() -> Vec<std::sync::Arc<dyn ProxyProvider + Send + Sync>> {
    vec![
        // Primary: live websites / APIs.
        std::sync::Arc::new(ProxyscrapeProvider),
        std::sync::Arc::new(OpenProxyListProvider),
        std::sync::Arc::new(GeonodeProvider),
        std::sync::Arc::new(FreeProxyListProvider),
        std::sync::Arc::new(FreeProxyWorldProvider),
        std::sync::Arc::new(ProxyListOrgProvider),
        std::sync::Arc::new(MyProxyProvider),
        std::sync::Arc::new(ProxyNovaProvider),
        // Fallback: aggregated GitHub mirrors.
        std::sync::Arc::new(GithubRepoProvider),
    ]
}

/// Contract for fetching proxies from a family of sources.
#[async_trait]
pub trait ProxyProvider {
    /// A short, stable identifier used in logs and diagnostics.
    fn name(&self) -> &'static str;

    /// Priority tier of this provider.
    ///
    /// Defaults to [`ProviderTier::Primary`]; aggregated mirrors override it
    /// with [`ProviderTier::Fallback`] so the fetcher can run them last.
    fn tier(&self) -> ProviderTier {
        ProviderTier::Primary
    }

    /// Returns a list of sources from which proxies can be fetched.
    ///
    /// # Returns
    ///
    /// A vector of `Source` objects representing the proxy sources.
    fn sources(&self) -> Vec<Source>;

    /// Fetches a source's response body, following redirects up to
    /// `MAX_REDIRECTS` and buffering the UTF-8 content across all frames.
    ///
    /// The request and every frame share a single `timeout` budget, so a stalled
    /// body cannot pin a semaphore permit forever.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is invalid, a redirect loop is detected,
    /// the body exceeds `MAX_SOURCE_BODY_BYTES`, or the deadline is exceeded.
    async fn fetch(
        &self,
        client: Arc<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>>,
        url: &str,
        timeout: Duration,
    ) -> anyhow::Result<Cow<'static, str>> {
        let mut urls: VecDeque<(url::Url, Option<url::Url>)> = VecDeque::new();
        let initial_url =
            url::Url::parse(url).with_context(|| format!("invalid provider URL `{url}`"))?;
        urls.push_back((initial_url, None));

        let user_agent = crate::user_agent::random_user_agent();
        let mut content = Vec::new(); // Accumulate bytes; decode once after all frames.
        let mut visited = HashSet::new();
        let mut redirect_count = 0usize;
        let deadline = time::Instant::now() + timeout;

        while let Some((url, previous_url)) = urls.pop_front() {
            if !visited.insert(url.as_str().to_owned()) {
                anyhow::bail!("redirect loop detected at {}", url);
            }
            let mut req = Request::builder()
                .uri(url.as_str())
                .header(hyper::header::USER_AGENT, user_agent);

            if let Some(previous_url) = previous_url {
                req = req.header(hyper::header::REFERER, previous_url.as_str());
            }

            // Send the request and await the response with a timeout
            let request = req
                .body(Empty::<Bytes>::new())
                .with_context(|| format!("failed to build request for {}", url))?;
            deadline
                .checked_duration_since(time::Instant::now())
                .with_context(|| format!("provider fetch timed out after {:?}", timeout))?;
            let mut response = time::timeout_at(deadline, client.request(request))
                .await
                .with_context(|| format!("request to {} timed out after {:?}", url, timeout))?
                .with_context(|| format!("request to {} failed", url))?;

            // Handle possible redirects
            if response.status().is_redirection() {
                if let Some(redirect) = response.headers().get(hyper::header::LOCATION) {
                    let redirect = redirect
                        .to_str()
                        .with_context(|| format!("{} returned a non-utf8 Location header", url))?;
                    let redirect = url.join(redirect).with_context(|| {
                        format!("{} returned invalid redirect Location `{redirect}`", url)
                    })?;
                    redirect_count += 1;
                    if redirect_count > MAX_REDIRECTS {
                        anyhow::bail!("too many redirects (max {})", MAX_REDIRECTS);
                    }
                    urls.push_back((redirect, Some(url)));
                    continue;
                }
            }

            // Read the response frames, bounded by the same deadline as the
            // request so a stalled body cannot hold a semaphore permit forever.
            while let Some(next) = time::timeout_at(deadline, response.frame())
                .await
                .with_context(|| format!("body stream from {} timed out", url))?
            {
                let frame =
                    next.with_context(|| format!("body stream from {} was interrupted", url))?;
                if let Some(chunk) = frame.data_ref() {
                    if content.len().saturating_add(chunk.len()) > MAX_SOURCE_BODY_BYTES {
                        anyhow::bail!(
                            "response body from {} exceeds {} bytes",
                            url,
                            MAX_SOURCE_BODY_BYTES
                        );
                    }
                    content.extend_from_slice(chunk);
                }
            }
        }
        Ok(Cow::Owned(
            String::from_utf8(content).context("provider response body is not valid UTF-8")?,
        ))
    }

    /// Scrapes proxies from a response body, using the source's `default_types`.
    ///
    /// # Errors
    ///
    /// Returns an error when the parsing task fails.
    async fn scrape(
        &self,
        html: Cow<'static, str>,
        tx: tokio::sync::mpsc::Sender<Proxy>,
        default_types: Arc<[Protocol]>,
    ) -> anyhow::Result<()> {
        self.scrape_with(html, tx, default_types, ScrapeMode::Plaintext)
            .await
    }

    /// Parses a response body according to `mode` and forwards every proxy.
    ///
    /// When a row carries its own protocol it replaces `default_types` for that
    /// proxy, otherwise the source defaults apply. The parser runs on a
    /// blocking thread (`spawn_blocking`) so CPU-bound scraping never starves
    /// the async runtime.
    async fn scrape_with(
        &self,
        body: Cow<'static, str>,
        tx: tokio::sync::mpsc::Sender<Proxy>,
        default_types: Arc<[Protocol]>,
        mode: ScrapeMode,
    ) -> anyhow::Result<()> {
        tokio::task::spawn_blocking(move || {
            let mut receiver_closed = false;
            let mut forward = |(ip, port, protocol): parsers::ParsedProxy| {
                if receiver_closed {
                    return false;
                }
                let expected_types = match protocol {
                    Some(protocol) => Arc::from([protocol]),
                    None => Arc::clone(&default_types),
                };
                let proxy = Proxy::with_expected_types(ip, port, expected_types);
                receiver_closed = tx.blocking_send(proxy).is_err();
                !receiver_closed
            };

            match mode {
                ScrapeMode::Plaintext => parsers::visit_plaintext(&body, &mut forward),
                ScrapeMode::GeonodeJson => parsers::visit_geonode(&body, &mut forward)?,
                ScrapeMode::ProxyNovaJson => parsers::visit_proxynova(&body, &mut forward)?,
                ScrapeMode::HtmlTable => parsers::visit_html_table(&body, &mut forward),
                ScrapeMode::RegexPairs => parsers::visit_regex_pairs(&body, &mut forward),
                ScrapeMode::Base64Rows => parsers::visit_base64_rows(&body, &mut forward),
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("provider parser task failed")??;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ProxyProvider, MAX_REDIRECTS};
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper_tls::HttpsConnector;
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};
    use std::{borrow::Cow, sync::Arc, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    struct TestProvider;

    #[async_trait::async_trait]
    impl ProxyProvider for TestProvider {
        fn name(&self) -> &'static str {
            "test"
        }

        fn sources(&self) -> Vec<super::Source> {
            Vec::new()
        }
    }

    fn test_client(
    ) -> Arc<Client<HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Empty<Bytes>>>
    {
        Arc::new(
            Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(HttpsConnector::new()),
        )
    }

    async fn read_headers(stream: &mut tokio::net::TcpStream) {
        let mut headers = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        while headers.len() <= 16 * 1024 {
            stream.read_exact(&mut byte).await.unwrap();
            headers.push(byte[0]);
            if headers.ends_with(b"\r\n\r\n") {
                return;
            }
        }
        panic!("test request headers exceed limit");
    }

    #[tokio::test]
    async fn fetch_preserves_utf8_split_across_body_frames() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/utf8");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_headers(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nA\xE2\r\n",
                )
                .await
                .unwrap();
            stream
                .write_all(b"2\r\n\x82\xAC\r\n1\r\nB\r\n0\r\n\r\n")
                .await
                .unwrap();
        });

        let body = TestProvider
            .fetch(test_client(), &url, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(body, "A€B");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn scrape_respects_bounded_channel_backpressure_under_load() {
        let mut body = String::new();
        for index in 1..=5_000u16 {
            let third = index / 250;
            let fourth = index % 250 + 1;
            body.push_str(&format!("10.20.{third}.{fourth}:8080\n"));
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let producer = tokio::spawn(TestProvider.scrape_with(
            Cow::Owned(body),
            tx,
            Arc::from([crate::proxy::models::Protocol::Socks5]),
            super::ScrapeMode::Plaintext,
        ));

        tokio::task::yield_now().await;
        assert!(!producer.is_finished());

        let mut received = 0usize;
        while rx.recv().await.is_some() {
            received += 1;
        }
        producer.await.unwrap().unwrap();
        assert_eq!(received, 5_000);
    }

    #[tokio::test]
    async fn closing_scrape_receiver_cancels_blocked_producer() {
        let body = "10.30.0.1:8080\n".repeat(5_000);
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let producer = tokio::spawn(TestProvider.scrape_with(
            Cow::Owned(body),
            tx,
            Arc::from([crate::proxy::models::Protocol::Socks5]),
            super::ScrapeMode::Plaintext,
        ));

        tokio::task::yield_now().await;
        drop(rx);

        tokio::time::timeout(Duration::from_secs(1), producer)
            .await
            .expect("producer must stop after receiver closes")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn fetch_times_out_when_response_body_stalls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/stalled");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_headers(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial",
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(250)).await;
        });

        let error = TestProvider
            .fetch(test_client(), &url, Duration::from_millis(50))
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("body stream"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fetch_rejects_redirect_loop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/loop");
        let redirect = url.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_headers(&mut stream).await;
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {redirect}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let error = TestProvider
            .fetch(test_client(), &url, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("redirect loop detected"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fetch_rejects_redirect_chain_above_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base = format!("http://{address}");
        let url = format!("{base}/0");
        let server = tokio::spawn(async move {
            for hop in 0..=MAX_REDIRECTS {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_headers(&mut stream).await;
                let location = format!("{base}/{}", hop + 1);
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let error = TestProvider
            .fetch(test_client(), &url, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("too many redirects"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fetch_does_not_follow_location_on_non_redirect_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/source");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_headers(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nLocation: /ignored\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
                )
                .await
                .unwrap();
        });

        let body = TestProvider
            .fetch(test_client(), &url, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(body, "body");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fetch_resolves_relative_redirect_location() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/source/start");
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            read_headers(&mut first).await;
            first
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: ../next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();

            let (mut second, _) = listener.accept().await.unwrap();
            let mut headers = Vec::with_capacity(256);
            let mut byte = [0u8; 1];
            while !headers.ends_with(b"\r\n\r\n") {
                second.read_exact(&mut byte).await.unwrap();
                headers.push(byte[0]);
            }
            assert!(headers.starts_with(b"GET /next HTTP/1.1"));
            second
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });

        let body = TestProvider
            .fetch(test_client(), &url, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(body, "ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn redirect_chain_shares_one_timeout_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/first");
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            read_headers(&mut first).await;
            tokio::time::sleep(Duration::from_millis(35)).await;
            first
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: /second\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();

            let (mut second, _) = listener.accept().await.unwrap();
            read_headers(&mut second).await;
            tokio::time::sleep(Duration::from_millis(35)).await;
            let _ = second
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        });

        let error = TestProvider
            .fetch(test_client(), &url, Duration::from_millis(50))
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("timed out"));
        server.abort();
    }
}
