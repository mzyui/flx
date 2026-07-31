//! Per-provider live fetch check.
//!
//! Fetches every source of one provider and reports how many proxies it
//! yields. Network-dependent, so it is ignored by default:
//!
//! ```text
//! cargo run --release --example provider_check
//! ```

use std::sync::Arc;

use fluxy::providers::all_providers;
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper_tls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = Arc::new(
        Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(HttpsConnector::new()),
    );

    let mut grand_total = 0usize;
    for provider in all_providers() {
        let sources = provider.sources();
        let name = provider.name();
        let mut total = 0usize;
        let mut ok = 0usize;
        let mut failed = 0usize;

        for source in &sources {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<fluxy::proxy::models::Proxy>(10_000);
            let url = source.url.to_string();
            match provider
                .fetch(Arc::clone(&client), &url, source.timeout)
                .await
            {
                Ok(body) => {
                    let types = source.default_types.clone();
                    let mode = source.mode.clone();
                    if let Err(e) = provider.scrape_with(body, tx.clone(), types, mode).await {
                        eprintln!("  scrape error {}: {:#}", url, e);
                    }
                    drop(tx);
                    let mut drained = Vec::new();
                    while let Some(proxy) = rx.recv().await {
                        drained.push(proxy);
                    }
                    let count = drained.len();
                    if count > 0 {
                        ok += 1;
                    } else {
                        failed += 1;
                        eprintln!("  ZERO {}", url);
                    }
                    total += count;
                }
                Err(e) => {
                    failed += 1;
                    eprintln!("  FETCH FAIL {}: {:#}", url, e);
                }
            }
        }

        grand_total += total;
        println!(
            "{:<18} sources={:<3} ok={:<3} zero/fail={:<3} proxies={}",
            name,
            sources.len(),
            ok,
            failed,
            total
        );
    }
    println!(
        "grand total (with cross-source duplicates): {}",
        grand_total
    );
    Ok(())
}
