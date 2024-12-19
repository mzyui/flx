use std::{fs::File, io::Write};

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
use tokio::runtime;

mod argument;

fn main() {
    if let Err(e) = run_application() {
        eprintln!("Error: {:?}", e);
    }
}

#[allow(unused_must_use)]
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
    error.print();
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

fn process_result<I>(source: I, options: Cli) -> anyhow::Result<()>
where
    I: Iterator<Item = Proxy>,
{
    let mut output_file = options.output_file.map(|file_path| {
        File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path)
            .unwrap()
    });

    for (index, proxy) in source.enumerate() {
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
            file.write_all(output.as_bytes()).unwrap();
            file.write_all(b"\n").unwrap();
        } else {
            println!("{}", output);
        }

        if should_end {
            break;
        }
    }

    if options.format == "json" {
        if let Some(ref mut file) = output_file {
            file.write_all(b"]")?;
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

    let runtime = runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        let proxy_source: Box<dyn Iterator<Item = Proxy> + Send + 'static> =
            if let Some(file) = &options.file {
                let source = ProxySource::from_file(file.clone())?;
                Box::new(source)
            } else {
                let source = ProxySource::from_fetcher(fluxy::fetcher::Config {
                    request_timeout: options.timeout,
                    concurrency_limit: 10,
                    countries: options.countries.clone(),
                    ..Default::default()
                })
                .await?;
                Box::new(source)
            };

        let proxy_iterator: Box<dyn Iterator<Item = Proxy>> = if !options.types.is_empty() {
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
            .await?;
            Box::new(validated_proxies)
        } else {
            proxy_source
        };

        process_result(proxy_iterator, options)?;
        Ok(())
    })
}
