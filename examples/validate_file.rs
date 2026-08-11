//! Validate an existing plaintext `ip:port` file and print the survivors.
//!
//! ```sh
//! cargo run --example validate_file -- proxies.txt SOCKS5
//! ```

use fluxy::{Fluxy, Protocol};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: validate_file <path> [protocol]");
    let protocol = args
        .next()
        .unwrap_or_else(|| "HTTP".to_owned())
        .parse::<Protocol>()
        .expect("invalid protocol; try HTTP, HTTPS, SOCKS4, SOCKS5");

    let proxies = Fluxy::from_file(path)?.types([protocol]).collect().await?;
    for proxy in &proxies {
        println!("{proxy}");
    }
    println!("{} proxies validated", proxies.len());
    Ok(())
}
