//! Validate a file of SOCKS5 endpoints.
//!
//! Run: `cargo run --example socks -- socks.txt`

use flx::{Flx, Protocol};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "socks.txt".to_owned());

    let proxies = Flx::from_file(&path)?
        .types([Protocol::Socks5])
        .collect()
        .await?;

    for proxy in &proxies {
        println!("socks5://{}", proxy.as_text());
    }
    println!("{} working SOCKS5 proxies", proxies.len());
    Ok(())
}
