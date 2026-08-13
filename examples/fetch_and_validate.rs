//! Fetch proxies, validate them as HTTP, and print the survivors.

use fluxy::{Anonymity, Fluxy, Protocol};

fn flag(args: &[String], name: &str) -> Option<String> {
    let long = format!("--{name}");
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(value) = arg.strip_prefix(&format!("{long}=")) {
            return Some(value.to_owned());
        }
        if arg == &long {
            return iter.next().cloned();
        }
    }
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();

    if let Some(level) = flag(&args, "log") {
        let level = match level.as_str() {
            "debug" => log::LevelFilter::Debug,
            "info" => log::LevelFilter::Info,
            "warn" => log::LevelFilter::Warn,
            "error" => log::LevelFilter::Error,
            "trace" => log::LevelFilter::Trace,
            _ => log::LevelFilter::Off,
        };
        fluxy::initialize_logging(level)?;
    }

    let limit = flag(&args, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(20);
    let country = flag(&args, "country");

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
