//! Stream validation results as they arrive, with live counters.
//!
//! Run: `cargo run --example stream`

use futures_util::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut run = flx::Flx::fetch()
        .validate_http()
        .limit(20)
        .stream_with_progress()
        .await?;

    while let Some(proxy) = run.next().await {
        println!("{}", proxy.as_text());
    }

    // Counters are final once the stream ends.
    let progress = run.progress();
    println!(
        "{} passed of {} checked",
        progress.passed(),
        progress.total()
    );
    Ok(())
}
