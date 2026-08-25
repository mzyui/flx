//! Read proxies from a file without validating them (parse-only pass-through).
//!
//! Useful to normalize, deduplicate, and re-emit a list. Scheme-prefixed
//! lines keep their protocol; bare `ip:port` lines stay multi-type.
//! Run: `cargo run --example passthrough -- proxies.txt`

use flx::Flx;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "proxies.txt".to_owned());

    let proxies = Flx::from_file(&path)?.no_validate().collect().await?;

    for proxy in &proxies {
        println!("{}", proxy.as_text());
    }
    println!("{} candidates read", proxies.len());
    Ok(())
}
