//! Require a proxy to support BOTH protocols of an AND group.
//!
//! A group `[HTTP, SOCKS5]` only passes when the same endpoint forwards as
//! HTTP and tunnels as SOCKS5. Run: `cargo run --example groups`

use flx::{Anonymity, Flx, Protocol};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let proxies = Flx::fetch()
        .groups(vec![vec![
            Protocol::Http(Anonymity::Unknown),
            Protocol::Socks5,
        ]])
        .limit(10)
        .collect()
        .await?;

    for proxy in &proxies {
        println!("{proxy}");
    }
    Ok(())
}
