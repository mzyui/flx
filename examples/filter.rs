//! Fetch proxies, keep only fast anonymous/elite ones, sort by speed.
//!
//! Run: `cargo run --example filter`

use flx::{Anonymity, Flx, ProxyStreamExt, SortKey, SortOrder};
use futures_util::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let proxies = Flx::fetch()
        .validate_http()
        .stream()
        .await?
        .filter_levels([Anonymity::Anonymous, Anonymity::Elite])
        .filter_max_response_time(2.0)
        .into_sorted(SortKey::AvgResponseTime, SortOrder::Asc)
        .take(10)
        .collect::<Vec<_>>()
        .await;

    for proxy in &proxies {
        println!("{:.2}s {}", proxy.avg_response_time(), proxy.as_text());
    }
    Ok(())
}
