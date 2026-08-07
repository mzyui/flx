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
use tokio::{io::AsyncWriteExt, runtime};

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
        .filter_map(|type_str| {
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
                    "HTTPS" => {
                        if let Some(anonymity) = parts.next() {
                            match anonymity {
                                "Transparent" => {
                                    return Some(Protocol::Https(Anonymity::Transparent))
                                }
                                "Anonymous" => return Some(Protocol::Https(Anonymity::Anonymous)),
                                "Elite" => return Some(Protocol::Https(Anonymity::Elite)),
                                _ => {}
                            }
                        }
                        return Some(Protocol::Https(Anonymity::Unknown));
                    }
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
        Some(file_path) => Some(tokio::io::BufWriter::new(
            tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(file_path)
                .await
                .with_context(|| format!("failed to open output file {}", file_path.display()))?,
        )),
        None => None,
    };

    let mut found_proxy = false;
    let mut source = std::pin::pin!(source.enumerate());
    let json = options.format == "json";
    while let Some((index, proxy)) = source.next().await {
        let should_end = options.limit > 0 && index + 1 >= options.limit;
        let output = match options.format.as_str() {
            "text" => proxy.as_text().to_owned(),
            "json" => {
                let mut json_output = String::new();
                // Open the array on the first element and prepend a comma before
                // every subsequent element, so we never emit a trailing comma and
                // always close the array cleanly.
                if index == 0 {
                    json_output.push_str("[\n  ");
                } else {
                    json_output.push_str(",\n  ");
                }
                json_output.push_str(&proxy.as_json());
                json_output
            }
            _ => format!("{}", proxy),
        };

        if let Some(ref mut file) = output_file {
            file.write_all(output.as_bytes())
                .await
                .context("failed to write proxy to output file")?;
            if json {
                file.write_all(b"\n")
                    .await
                    .context("failed to finalize json output file")?;
            } else {
                file.write_all(b"\n")
                    .await
                    .context("failed to write newline to output file")?;
            }
        } else {
            println!("{}{}", output, if json { "\n" } else { "" });
        }

        found_proxy = true;
        if should_end {
            break;
        }
    }

    if json {
        if found_proxy {
            // Close the array on its own line.
            write_output(&mut output_file, "]\n").await?;
        } else {
            // No proxies: valid empty JSON array on a single line.
            write_output(&mut output_file, "[]\n").await?;
        }
    }
    if let Some(file) = output_file.as_mut() {
        file.flush().await.context("failed to flush output file")?;
    }
    Ok(())
}

/// Writes `content` to the output file if present, otherwise to stdout.
async fn write_output(
    output_file: &mut Option<tokio::io::BufWriter<tokio::fs::File>>,
    content: &str,
) -> anyhow::Result<()> {
    if let Some(ref mut file) = output_file {
        file.write_all(content.as_bytes())
            .await
            .context("failed to write proxy to output file")?;
    } else {
        print!("{content}");
    }
    Ok(())
}

fn fetcher_config(options: &Cli) -> fluxy::fetcher::Config {
    fluxy::fetcher::Config {
        concurrency_limit: options.fetch_concurrency as usize,
        enable_geo_lookup: !options.countries.is_empty(),
        countries: options.countries.clone(),
        ..Default::default()
    }
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
                let file = file.clone();
                let proxies = tokio::task::spawn_blocking(move || {
                    ProxySource::from_file(file.clone())
                        .with_context(|| format!("failed to read proxies from {}", file.display()))
                        .map(Iterator::collect::<Vec<_>>)
                })
                .await
                .context("proxy file reader task failed")??;
                Box::pin(futures_util::stream::iter(proxies))
            } else {
                let source = ProxySource::from_fetcher(fetcher_config(&options))
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
                    http_judge_urls: options.http_judge_urls.clone(),
                    https_judge_urls: options.https_judge_urls.clone(),
                    insecure: options.insecure,
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;

    #[test]
    fn countries_enable_geo_lookup_for_fetcher() {
        let without_countries = Cli::parse_from(["fluxy"]);
        assert!(!fetcher_config(&without_countries).enable_geo_lookup);

        let with_countries = Cli::parse_from(["fluxy", "--countries", "ID"]);
        assert!(fetcher_config(&with_countries).enable_geo_lookup);
    }

    #[test]
    fn https_judge_urls_flag_parses_without_duplicate_attr() {
        // Regression for F-36: the `#[arg]` for `--https-judge-urls` was
        // declared twice; ensure the flag still accepts a custom value and
        // lands in the right field.
        let cli = Cli::parse_from([
            "fluxy",
            "--types",
            "SOCKS5",
            "--https-judge-urls",
            "https://example.com/azenv.php",
        ]);
        assert_eq!(
            cli.https_judge_urls,
            vec!["https://example.com/azenv.php".to_owned()]
        );
        // default still intact when flag omitted
        let defaults = Cli::parse_from(["fluxy", "--types", "SOCKS5"]);
        assert_eq!(
            defaults.https_judge_urls,
            vec![
                "https://aranguren.org/azenv.php".to_owned(),
                "https://wfuchs.de/azenv.php".to_owned(),
            ]
        );
    }

    /// Builds a minimal `Cli` wired to a temp output file, returns the path.
    fn cli_with_output(format: &str, limit: usize) -> (Cli, std::path::PathBuf) {
        let out = std::env::temp_dir().join(format!(
            "fluxy_json_test_{}_{}.json",
            std::process::id(),
            uuidish()
        ));
        let mut cli = Cli::parse_from(["fluxy"]);
        cli.format = format.to_owned();
        cli.limit = limit;
        cli.output_file = Some(out.clone());
        (cli, out)
    }

    fn uuidish() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        C.fetch_add(1, Ordering::Relaxed)
    }

    fn sample_proxy(ip: u8) -> Proxy {
        Proxy::new(
            std::net::Ipv4Addr::new(192, 168, 0, ip),
            8080 + u16::from(ip),
        )
    }

    #[test]
    fn invalid_type_does_not_stop_following_types() {
        let types = vec![
            "HTTP".to_owned(),
            "NOT_A_PROTOCOL".to_owned(),
            "SOCKS5".to_owned(),
        ];
        let protocols = convert_protocols(&types);

        assert_eq!(protocols.len(), 2);
        assert_eq!(protocols[0], Protocol::Http(Anonymity::Unknown));
        assert_eq!(protocols[1], Protocol::Socks5);
    }

    #[test]
    fn cli_rejects_zero_max_attempts() {
        let result = Cli::try_parse_from(["fluxy", "--types", "SOCKS5", "--max-attempts", "0"]);
        assert!(result.is_err());
    }

    fn run_json(proxies: &[Proxy], limit: usize) -> String {
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        let (cli, path) = cli_with_output("json", limit);
        rt.block_on(async {
            let s = stream::iter(proxies.iter().cloned());
            process_result(s, cli).await.unwrap();
        });
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        content
    }

    #[test]
    fn json_empty_yields_empty_array() {
        let out = run_json(&[], 0);
        assert_eq!(out, "[]\n", "empty source must produce valid []");
        // must parse as JSON
        serde_json::from_str::<serde_json::Value>(&out).unwrap();
    }

    #[test]
    fn json_single_has_no_trailing_comma() {
        let out = run_json(&[sample_proxy(1)], 0);
        assert!(out.starts_with("[\n"), "must open array");
        assert!(out.trim_end().ends_with("]"), "must close array");
        assert!(!out.contains(",]"), "no trailing comma before ]");
        let _: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    }

    #[test]
    fn json_multiple_is_valid_array() {
        let proxies = [sample_proxy(1), sample_proxy(2), sample_proxy(3)];
        let out = run_json(&proxies, 0);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed.len(), 3);
        assert!(!out.contains(",]"));
    }

    #[test]
    fn json_limit_truncates_without_trailing_comma() {
        let proxies = [
            sample_proxy(1),
            sample_proxy(2),
            sample_proxy(3),
            sample_proxy(4),
        ];
        // limit 2 -> exactly 2 elements, valid JSON, no trailing comma
        let out = run_json(&proxies, 2);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(!out.contains(",]"));
    }
}
