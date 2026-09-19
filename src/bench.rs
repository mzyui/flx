//! Offline throughput harness for the fetch and validate stages.
//!
//! Both cases run entirely on loopback (mock provider + echo judge, candidates
//! on closed local ports) so numbers are deterministic and network-free.
//! Ignored by default; run in release mode:
//!
//! ```text
//! cargo test --release --lib bench -- --ignored --nocapture
//! ```

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::fetcher::{Config as FetchConfig, ProxyFetcher};
use crate::proxy::models::{Anonymity, Protocol, Proxy};
use crate::test_support::spawn_echo_judge;
use crate::validator::{Config as ValidatorConfig, ProxyValidator};

/// Rows served by the mock provider; large enough to dominate setup cost.
const FETCH_ROWS: usize = 20_000;
/// Candidates fed to the validator; each advertises duplicated HTTP families.
const VALIDATION_CANDIDATES: usize = 5_000;

/// Serves one large `ip:port` list over loopback and returns its URL.
async fn spawn_list_server(rows: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut body = String::with_capacity(rows * 16);
        for i in 0..rows {
            let third = i / 256;
            let fourth = i % 256;
            body.push_str(&format!(
                "10.{}.{third}.{fourth}:{}\n",
                third % 256,
                1000 + (i % 60_000)
            ));
        }
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut chunk = [0u8; 1024];
        let mut received = Vec::new();
        loop {
            let read = stream.read(&mut chunk).await.unwrap_or(0);
            if read == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..read]);
            if received.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes()).await;
    });
    format!("http://{address}/list")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "throughput harness; run with --release --ignored --nocapture"]
async fn bench_fetch_throughput() {
    let url = spawn_list_server(FETCH_ROWS).await;
    let config = FetchConfig {
        providers: Arc::from(vec!["custom".to_owned()]),
        custom_sources: Arc::from(vec![url]),
        cache_ttl: None,
        ..FetchConfig::default()
    };

    let started = Instant::now();
    let mut fetcher = ProxyFetcher::gather(config).await.unwrap();
    let mut count = 0usize;
    while fetcher.get_one().await.is_some() {
        count += 1;
    }
    let elapsed = started.elapsed();

    eprintln!(
        "bench_fetch_throughput: {count} candidates in {elapsed:?} ({:.0}/s)",
        count as f64 / elapsed.as_secs_f64()
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "throughput harness; run with --release --ignored --nocapture"]
async fn bench_validate_throughput() {
    let judge = spawn_echo_judge().await;
    let expected = Arc::from([
        Protocol::Http(Anonymity::Anonymous),
        Protocol::Http(Anonymity::Unknown),
    ]);
    let candidates: Vec<Proxy> = (0..VALIDATION_CANDIDATES)
        .map(|i| {
            let port = 1 + (i % 30_000) as u16;
            Proxy::with_expected_types(Ipv4Addr::LOCALHOST, port, Arc::clone(&expected))
        })
        .collect();

    let config = ValidatorConfig {
        types: vec![Protocol::Http(Anonymity::Unknown)],
        http_judge_urls: vec![judge],
        https_judge_urls: vec![],
        ..ValidatorConfig::default()
    };

    let started = Instant::now();
    let mut validator = ProxyValidator::validate(futures_util::stream::iter(candidates), config)
        .await
        .unwrap();
    let progress = validator.progress();
    while validator.get_one().await.is_some() {}
    let elapsed = started.elapsed();

    eprintln!(
        "bench_validate_throughput: {} jobs, {} done in {elapsed:?} ({:.0} probes/s)",
        progress.total(),
        progress.done(),
        progress.done() as f64 / elapsed.as_secs_f64()
    );
}
