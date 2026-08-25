//! Validate proxies from an `ip:port` file against online judges.
//!
//! Lines may be bare `ip:port` or scheme-prefixed (`http://`, `socks5://`, …).
//! Run: `cargo run --example validate -- proxies.txt`

use flx::{Flx, Protocol};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "proxies.txt".to_owned());

    let proxies = Flx::from_file(&path)?
        .types([Protocol::Http(flx::Anonymity::Unknown), Protocol::Socks5])
        .collect()
        .await?;

    for proxy in &proxies {
        println!("{proxy}");
    }
    println!("{} valid of file `{path}`", proxies.len());
    Ok(())
}
