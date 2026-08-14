//! Fetch proxies and print them as ip:port.

use flx::Flx;

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
        flx::initialize_logging(level)?;
    }

    let limit = flag(&args, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10);

    let proxies = Flx::fetch().limit(limit).collect().await?;
    for proxy in &proxies {
        println!("{}", proxy.as_text());
    }
    println!("{} proxies fetched", proxies.len());
    Ok(())
}
