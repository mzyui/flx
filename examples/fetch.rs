//! Fetch proxies from the built-in providers and print them as `ip:port`.
//!
//! ```sh
//! cargo run --example fetch -- --limit 10
//! ```

use fluxy::Fluxy;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let limit = std::env::args()
        .find_map(|arg| arg.strip_prefix("--limit=").map(str::to_owned))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10);

    let proxies = Fluxy::fetch().limit(limit).collect().await?;
    for proxy in &proxies {
        println!("{}", proxy.as_text());
    }
    println!("{} proxies fetched", proxies.len());
    Ok(())
}
