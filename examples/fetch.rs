//! Fetch proxies from the built-in providers and print them as `ip:port`.
//!
//! Run: `cargo run --example fetch`

use flx::Flx;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let proxies = Flx::fetch().validate_http().limit(10).collect().await?;

    for proxy in &proxies {
        println!("{}", proxy.as_text());
    }
    println!("{} valid proxies", proxies.len());
    Ok(())
}
