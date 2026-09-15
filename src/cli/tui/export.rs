//! Writes browsed results to a file in one of the CLI's output formats.
//!
//! The CLI's `process_result` writers stream straight to stdout and are not
//! reachable from here, so this module renders the same shapes over an
//! in-memory result set. Unifying the two is tracked as follow-up work.

use std::io::Write;
use std::path::Path;

use anyhow::Context as _;
use flx::proxy::models::{Anonymity, Protocol, Proxy};

const CSV_HEADER: &str = "ip,port,protocol,anonymity,country,ip_type,asn,average_response_time";

/// Writes `proxies` to `path`, returning how many rows were written.
pub(crate) fn write(path: &Path, format: &str, proxies: &[&Proxy]) -> anyhow::Result<usize> {
    let format = infer_format(format, path);
    if format == "pac" {
        anyhow::bail!(
            "pac export is not available from the TUI yet; use `flx find -f pac -o proxy.pac`"
        );
    }

    let file =
        std::fs::File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
    let mut writer = std::io::BufWriter::new(file);

    match format {
        "text" => {
            for proxy in proxies {
                writeln!(writer, "{}", proxy.as_text())?;
            }
        }
        "json" => {
            serde_json::to_writer(&mut writer, proxies)?;
            writeln!(writer)?;
        }
        "pretty-json" => {
            serde_json::to_writer_pretty(&mut writer, proxies)?;
            writeln!(writer)?;
        }
        "json-lines" => {
            for proxy in proxies {
                serde_json::to_writer(&mut writer, proxy)?;
                writeln!(writer)?;
            }
        }
        "csv" => {
            writeln!(writer, "{CSV_HEADER}")?;
            for proxy in proxies {
                write_csv_row(&mut writer, proxy)?;
            }
        }
        "prefix" => {
            for proxy in proxies {
                writeln!(
                    writer,
                    "{}://{}:{}",
                    prefix_scheme(proxy),
                    proxy.ip,
                    proxy.port
                )?;
            }
        }
        "proxychains" => {
            for proxy in proxies {
                writeln!(
                    writer,
                    "{} {} {}",
                    proxychains_type(proxy),
                    proxy.ip,
                    proxy.port
                )?;
            }
        }
        _ => {
            for proxy in proxies {
                writeln!(writer, "{proxy}")?;
            }
        }
    }

    writer.flush()?;
    Ok(proxies.len())
}

/// Falls back to the output path's extension when the format is the default.
fn infer_format<'a>(format: &'a str, path: &Path) -> &'a str {
    if format != "default" {
        return format;
    }
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => "json",
        Some("jsonl") => "json-lines",
        Some("csv") => "csv",
        Some("pac") => "pac",
        Some("txt") => "text",
        _ => "default",
    }
}

fn anonymity_of(proxy: &Proxy) -> &'static str {
    let best = proxy
        .proxy_types
        .iter()
        .filter_map(|proxy_type| match proxy_type.protocol {
            Protocol::Http(anonymity) | Protocol::Https(anonymity) => Some(anonymity),
            _ => None,
        })
        .max_by_key(|anonymity| anonymity.rank());
    match best {
        Some(Anonymity::Elite) => "elite",
        Some(Anonymity::Anonymous) => "anonymous",
        Some(Anonymity::Transparent) => "transparent",
        Some(Anonymity::Unknown) | None => "unknown",
    }
}

fn protocol_of(proxy: &Proxy) -> String {
    let protocol = proxy
        .proxy_types
        .first()
        .map(|proxy_type| proxy_type.protocol)
        .or_else(|| proxy.expected_types.first().copied());
    match protocol {
        Some(Protocol::Http(_)) => "http".to_owned(),
        Some(Protocol::Https(_)) => "https".to_owned(),
        Some(Protocol::Socks4) => "socks4".to_owned(),
        Some(Protocol::Socks5) => "socks5".to_owned(),
        Some(Protocol::Connect(port)) => format!("connect:{port}"),
        None => "unknown".to_owned(),
    }
}

fn ip_type_of(proxy: &Proxy) -> &'static str {
    match proxy.geo.ip_type {
        flx::IpType::Residential => "residential",
        flx::IpType::Datacenter => "datacenter",
        flx::IpType::Mobile => "mobile",
        flx::IpType::Unknown => "unknown",
    }
}

fn write_csv_row(writer: &mut impl Write, proxy: &Proxy) -> std::io::Result<()> {
    writeln!(
        writer,
        "{},{},{},{},{},{},{},{}",
        proxy.ip,
        proxy.port,
        protocol_of(proxy),
        anonymity_of(proxy),
        proxy.geo.iso_code.as_deref().unwrap_or_default(),
        ip_type_of(proxy),
        proxy.geo.asn.map(|asn| asn.to_string()).unwrap_or_default(),
        proxy.avg_response_time(),
    )
}

fn prefix_scheme(proxy: &Proxy) -> &'static str {
    match proxy.proxy_types.first().map(|entry| entry.protocol) {
        Some(Protocol::Https(_)) => "https",
        Some(Protocol::Socks4) => "socks4",
        Some(Protocol::Socks5) => "socks5",
        _ => "http",
    }
}

fn proxychains_type(proxy: &Proxy) -> &'static str {
    match proxy.proxy_types.first().map(|entry| entry.protocol) {
        Some(Protocol::Socks4) => "socks4",
        Some(Protocol::Socks5) => "socks5",
        _ => "http",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    fn temp_path(stem: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "flx_tui_export_{stem}_{}_{}.out",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn sample() -> Proxy {
        let mut proxy = Proxy::new(Ipv4Addr::new(203, 0, 113, 7), 8080);
        proxy
            .proxy_types
            .push(flx::ProxyType::checked(Protocol::Http(Anonymity::Elite)));
        proxy
    }

    #[test]
    fn text_export_writes_one_endpoint_per_line() {
        let proxy = sample();
        let path = temp_path("text");
        let count = write(&path, "text", &[&proxy]).expect("export succeeds");
        assert_eq!(count, 1);
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written, "203.0.113.7:8080\n");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn json_lines_export_keeps_one_object_per_line() {
        let proxy = sample();
        let path = temp_path("jsonl");
        write(&path, "json-lines", &[&proxy, &proxy]).expect("export succeeds");
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written.lines().count(), 2);
        assert!(written.contains("\"port\":8080"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn csv_export_emits_a_header_and_rows() {
        let proxy = sample();
        let path = temp_path("csv");
        write(&path, "csv", &[&proxy]).expect("export succeeds");
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.starts_with(CSV_HEADER));
        assert!(written.contains("203.0.113.7,8080"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn default_format_is_inferred_from_the_extension() {
        let proxy = sample();
        let path = temp_path("infer").with_extension("json");
        write(&path, "default", &[&proxy]).expect("export succeeds");
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.trim_start().starts_with('['));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pac_export_reports_that_it_is_unsupported() {
        let proxy = sample();
        let path = temp_path("pac").with_extension("pac");
        let error = write(&path, "pac", &[&proxy]).expect_err("pac is rejected");
        assert!(error.to_string().contains("pac"));
        let _ = std::fs::remove_file(&path);
    }
}
