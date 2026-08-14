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

/// Keeps only the providers whose name is included by `include` (when
/// non-empty) and absent from `exclude`.
pub fn select_providers(
    providers: Vec<std::sync::Arc<dyn ProxyProvider + Send + Sync>>,
    include: &[String],
    exclude: &[String],
) -> Vec<std::sync::Arc<dyn ProxyProvider + Send + Sync>> {
    providers
        .into_iter()
        .filter(|provider| {
            let in_list = include.is_empty() || include.iter().any(|name| name == provider.name());
            let excluded = exclude.iter().any(|name| name == provider.name());
            in_list && !excluded
        })
        .collect()
}

/// Provider that scrapes a single user-supplied plaintext URL.
pub struct CustomUrlProvider(pub Source);

impl CustomUrlProvider {
    /// Creates a provider from a plaintext proxy-list URL.
    pub fn new(url: &str) -> anyhow::Result<Self> {
        Ok(Self(Source::all(url)?))
    }
}

#[async_trait]
impl ProxyProvider for CustomUrlProvider {
    fn name(&self) -> &'static str {
        "custom"
    }

    fn sources(&self) -> Vec<Source> {
        vec![self.0.clone()]
    }
}

#[async_trait]
pub trait ProxyProvider {
    fn name(&self) -> &'static str;

    fn tier(&self) -> ProviderTier {
        ProviderTier::Primary
    }

    fn sources(&self) -> Vec<Source>;

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

        let user_agent = crate::user_agent::next_user_agent();
        let mut content = String::new();
        let mut pending = [0u8; 3];
        let mut pending_len = 0usize;
        let mut visited: HashSet<url::Url> = HashSet::new();
        let mut redirect_count = 0usize;
        let deadline = time::Instant::now() + timeout;

        while let Some((url, previous_url)) = urls.pop_front() {
            if !visited.insert(url.clone()) {
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
                    append_utf8(&mut content, &mut pending, &mut pending_len, chunk)?;
                }
            }
        }
        if pending_len > 0 {
            anyhow::bail!("provider response body is not valid UTF-8");
        }
        Ok(Cow::Owned(content))
    }

    async fn scrape(
        &self,
        html: Cow<'static, str>,
        tx: tokio::sync::mpsc::Sender<Proxy>,
        default_types: Arc<[Protocol]>,
    ) -> anyhow::Result<()> {
        self.scrape_with(html, tx, default_types, ScrapeMode::Plaintext)
            .await
    }

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

fn append_utf8(
    content: &mut String,
    pending: &mut [u8; 3],
    pending_len: &mut usize,
    bytes: &[u8],
) -> anyhow::Result<()> {
    let mut combined;
    let buf: &[u8] = if *pending_len == 0 {
        bytes
    } else {
        combined = Vec::with_capacity(*pending_len + bytes.len());
        combined.extend_from_slice(&pending[..*pending_len]);
        combined.extend_from_slice(bytes);
        &combined
    };
    match std::str::from_utf8(buf) {
        Ok(text) => {
            content.push_str(text);
            *pending_len = 0;
        }
        Err(e) if e.error_len().is_none() => {
            content.push_str(
                std::str::from_utf8(&buf[..e.valid_up_to()])
                    .expect("valid_up_to() is always a char boundary"),
            );
            let tail = &buf[e.valid_up_to()..];
            pending[..tail.len()].copy_from_slice(tail);
            *pending_len = tail.len();
        }
        Err(_) => anyhow::bail!("provider response body is not valid UTF-8"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{select_providers, ProxyProvider, MAX_REDIRECTS};
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper_tls::HttpsConnector;
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};
    use std::sync::Arc;
    use std::{borrow::Cow, time::Duration};
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

    fn provider_names(providers: &[Arc<dyn ProxyProvider + Send + Sync>]) -> Vec<&'static str> {
        providers.iter().map(|provider| provider.name()).collect()
    }

    #[test]
    fn select_providers_empty_lists_keep_everything() {
        let providers = super::all_providers();
        let selected = select_providers(providers.clone(), &[], &[]);
        assert_eq!(provider_names(&selected).len(), providers.len());
    }

    #[test]
    fn select_providers_include_keeps_only_matching_names() {
        let selected = select_providers(super::all_providers(), &["geonode".to_owned()], &[]);
        assert_eq!(provider_names(&selected), vec!["geonode"]);
    }

    #[test]
    fn select_providers_exclude_drops_matching_names() {
        let selected = select_providers(super::all_providers(), &[], &["github-raw".to_owned()]);
        let names = provider_names(&selected);
        assert!(!names.contains(&"github-raw"));
        assert_eq!(names.len(), super::all_providers().len() - 1);
    }

    #[test]
    fn select_providers_exclude_wins_over_include() {
        let selected = select_providers(
            super::all_providers(),
            &["proxyscrape".to_owned(), "geonode".to_owned()],
            &["proxyscrape".to_owned()],
        );
        assert_eq!(provider_names(&selected), vec!["geonode"]);
    }

    #[test]
    fn custom_provider_exposes_its_source_and_tier() {
        let provider = super::CustomUrlProvider::new("http://127.0.0.1:9999/list").unwrap();
        assert_eq!(provider.name(), "custom");
        assert_eq!(provider.tier(), super::ProviderTier::Primary);
        assert_eq!(provider.sources().len(), 1);
        assert_eq!(
            provider.sources()[0].url.to_string(),
            "http://127.0.0.1:9999/list"
        );
    }
}
