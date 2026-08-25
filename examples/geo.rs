//! Fetch proxies annotated with GeoIP data and keep one country only.
//!
//! The first run downloads the GeoLite2 database (a few tens of MB).
//! Run: `cargo run --example geo`

use flx::Flx;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let proxies = Flx::fetch()
        .validate_http()
        .with_geo() // annotate every result with country/IP-class data
        .countries(["ID".to_owned()]) // implies with_geo; keeps ISO code `ID` only
        .limit(10)
        .collect()
        .await?;

    for proxy in &proxies {
        let country = proxy.geo.iso_code.as_deref().unwrap_or("--");
        println!("{country} {}", proxy.as_text());
    }
    Ok(())
}
