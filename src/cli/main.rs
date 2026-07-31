use std::{fs::File, io::Write};

use anyhow::Context;
use argument::Cli;
use clap::{
    error::{ContextKind, ContextValue, ErrorKind},
    CommandFactory, Parser,
};
#[cfg(feature = "log")]
use fluxy::initialize_logging;
use fluxy::{
    proxy::models::{Anonymity, Protocol, Proxy},
    ProxySource, ProxyValidator,
};
use futures_util::{Stream, StreamExt};
use tokio::runtime;

mod argument;

fn main() -> std::process::ExitCode {
    match run_application() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {:?}", e);
            std::process::ExitCode::FAILURE
        }
    }
}

fn report_invalid_type_value(value: &str) {
    let mut error = clap::Error::new(ErrorKind::ValueValidation).with_cmd(&Cli::command());
    error.insert(
        ContextKind::InvalidArg,
        ContextValue::String("--types".to_owned()),
    );
    error.insert(
        ContextKind::InvalidValue,
        ContextValue::String(value.to_string()),
    );
    let _ = error.print();
}

fn convert_protocols(types: &[String]) -> Vec<Protocol> {
    types
        .iter()
        .map_while(|type_str| {
            let mut parts = type_str.split(':');
            if let Some(protocol) = parts.next() {
                match protocol {
                    "HTTP" => {
                        if let Some(anonymity) = parts.next() {
                            match anonymity {
                                "Transparent" => {
                                    return Some(Protocol::Http(Anonymity::Transparent))
                                }
                                "Anonymous" => return Some(Protocol::Http(Anonymity::Anonymous)),
                                "Elite" => return Some(Protocol::Http(Anonymity::Elite)),
                                _ => {}
                            }
                        }
                        return Some(Protocol::Http(Anonymity::Unknown));
                    }
                    "HTTPS" => return Some(Protocol::Https),
                    "SOCKS4" => return Some(Protocol::Socks4),
                    "SOCKS5" => return Some(Protocol::Socks5),
                    "CONNECT" => {
                        if let Some(Ok(port)) = parts.next().map(|p| p.parse::<u16>()) {
                            return Some(Protocol::Connect(port));
                        }
                    }
                    _ => report_invalid_type_value(type_str),
                }
            }
            None
        })
        .collect()
}

async fn process_result<S>(source: S, options: Cli) -> anyhow::Result<()>
where
    S: Stream<Item = Proxy>,
{
    let mut output_file = match options.output_file.as_ref() {
        Some(file_path) => Some(
            File::options()
                .write(true)
                .create(true)
                .truncate(true)
                .open(file_path)
                .with_context(|| format!("failed to open output file {}", file_path.display()))?,
        ),
        None => None,
    };

    let mut found_proxy = false;
    let mut source = std::pin::pin!(source.enumerate());
    while let Some((index, proxy)) = source.next().await {
        if !found_proxy {
            found_proxy = true;
        }
        let should_end = options.limit > 0 && index + 1 >= options.limit;
        let output = match options.format.as_str() {
            "text" => proxy.as_text().into_owned(),
            "json" => {
                let mut json_output = String::new();
                if index == 0 {
                    json_output.push_str("[\n");
                }
                json_output.push_str("  ");
                json_output.push_str(&proxy.as_json());
                if !should_end {
                    json_output.push(',');
                }
                json_output
            }
            _ => format!("{}", proxy),
        };

        if let Some(ref mut file) = output_file {
            file.write_all(output.as_bytes())
                .context("failed to write proxy to output file")?;
            file.write_all(b"\n")
                .context("failed to write newline to output file")?;
        } else {
            println!("{}", output);
        }

        if should_end {
            break;
        }
    }

    if found_proxy && options.format == "json" {
        if let Some(ref mut file) = output_file {
            file.write_all(b"]")
                .context("failed to finalize json output file")?;
        } else {
            println!("]");
        }
    }
    Ok(())
}

fn run_application() -> anyhow::Result<()> {
    let options = Cli::parse();

    #[cfg(feature = "log")]
    {
        let log_level = match options.log_level.as_str() {
            "debug" => log::LevelFilter::Debug,
            "info" => log::LevelFilter::Info,
            "warn" => log::LevelFilter::Warn,
            "error" => log::LevelFilter::Error,
            "trace" => log::LevelFilter::Trace,
            _ => log::LevelFilter::Off,
        };
        initialize_logging(log_level)?;
    }

    let runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;
    runtime.block_on(async {
        let proxy_source: std::pin::Pin<Box<dyn Stream<Item = Proxy> + Send + 'static>> =
            if let Some(file) = &options.file {
                let source = ProxySource::from_file(file.clone())
                    .with_context(|| format!("failed to read proxies from {}", file.display()))?;
                Box::pin(futures_util::stream::iter(source))
            } else {
                let source = ProxySource::from_fetcher(fluxy::fetcher::Config {
                    request_timeout: options.timeout,
                    concurrency_limit: options.fetch_concurrency as usize,
                    countries: options.countries.clone(),
                    ..Default::default()
                })
                .await
                .context("failed to start proxy fetcher")?;
                Box::pin(source)
            };

        if !options.types.is_empty() {
            let protocols = convert_protocols(&options.types);
            if protocols.is_empty() {
                std::process::exit(-1)
            }
            let validated_proxies = ProxyValidator::validate(
                proxy_source,
                fluxy::validator::Config {
                    types: protocols,
                    concurrency_limit: options.max_connections as usize,
                    max_attempts: options.max_attempts,
                    request_timeout: options.timeout,
                },
            )
            .await
            .context("failed to start proxy validator")?;
            process_result(validated_proxies, options)
                .await
                .context("failed to write results")?;
        } else {
            process_result(proxy_source, options)
                .await
                .context("failed to write results")?;
        }

        Ok(())
    })
}
