//! Fetch proxies from the built-in providers, validate them as HTTP proxies,
//! and print the survivors with their measured anonymity.
//!
//! ```sh
//! cargo run --example fetch_and_validate -- --limit 20 --country ID
//! ```

use fluxy::{Anonymity, Fluxy, Protocol};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let limit = std::env::args()
        .find_map(|arg| arg.strip_prefix("--limit=").map(str::to_owned))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(20);
    let country =
        std::env::args().find_map(|arg| arg.strip_prefix("--country=").map(str::to_owned));

    let mut fluxy = Fluxy::fetch()
        .types([Protocol::Http(Anonymity::Unknown)])
        .limit(limit);
    if let Some(country) = country {
        fluxy = fluxy.countries([country]);
    }

    let proxies = fluxy.collect().await?;
    for proxy in &proxies {
        println!("{proxy}");
    }
    println!("{} proxies validated", proxies.len());
    Ok(())
}
