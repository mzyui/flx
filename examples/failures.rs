//! Collect a machine-readable record for every failed probe.
//!
//! Run: `cargo run --example failures`

use futures_util::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut run = flx::Flx::fetch()
        .validate_http()
        .report_failures()
        .limit(20)
        .stream_with_progress()
        .await?;

    let mut failures = run.take_failures().expect("report_failures was set");

    while run.next().await.is_some() {}

    while let Some(failure) = failures.recv().await {
        println!("{}:{} → {}", failure.ip, failure.port, failure.reason);
    }
    Ok(())
}
