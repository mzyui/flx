use anyhow::Context;
use flx::proxy::models::{Protocol, Proxy};
use flx::IpType;
use futures_util::{Stream, StreamExt};
use std::io::IsTerminal as _;
use std::io::Write as _;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use super::argument::OutputOptions;
use super::filters::ProxyFilter;
use super::guard::OutputGuard;
use super::RunOutcome;

// Resolves the output format when the user left `--format` at `default`: an
// explicit `-o` path infers the format from its file extension and a piped
// stdout switches to `json-lines`.
pub(crate) fn effective_format<'a>(
    format: &'a str,
    output_path: Option<&std::path::Path>,
    stdout_is_tty: bool,
) -> &'a str {
    if format != "default" {
        return format;
    }
    if let Some(path) = output_path {
        return match path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase())
            .as_deref()
        {
            Some("json") => "json",
            Some("jsonl") | Some("ndjson") => "json-lines",
            Some("csv") => "csv",
            Some("pac") => "pac",
            _ => format,
        };
    }
    if stdout_is_tty {
        format
    } else {
        "json-lines"
    }
}

// Controls document finalization when `process_result` chains one output
// pass after another. Empty JSON is only suppressed on the first pass, and
// the CSV header is only emitted once.
#[derive(Clone, Copy)]
pub struct FinalizeOpts {
    pub suppress_empty_json: bool,
    pub emit_csv_header: bool,
}

impl Default for FinalizeOpts {
    fn default() -> Self {
        Self {
            suppress_empty_json: false,
            emit_csv_header: true,
        }
    }
}

// Sorts proxies by the requested field, honoring `--order`.
fn sort_proxies(proxies: &mut [Proxy], sort: &str, order: Option<&str>) {
    match sort {
        "avg-response" | "response-time" => proxies.sort_by(|a, b| {
            a.avg_response_time()
                .partial_cmp(&b.avg_response_time())
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        "country" => proxies.sort_by(|a, b| a.geo.iso_code.cmp(&b.geo.iso_code)),
        _ => proxies.sort_by_key(super::filters::proxy_anonymity_rank),
    }
    if order == Some("desc") {
        proxies.reverse();
    }
}

// Simple deterministic-free Fisher-Yates shuffle: a xorshift64 PRNG seeded
// from wall-clock time avoids pulling in a `rand` dependency for one flag.
pub fn shuffle_proxies(proxies: &mut [Proxy]) {
    let mut state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e3779b97f4a7c15)
        ^ u64::from(std::process::id());
    if state == 0 {
        state = 0x9e3779b97f4a7c15;
    }
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for i in (1..proxies.len()).rev() {
        let j = (next() % (i as u64 + 1)) as usize;
        proxies.swap(i, j);
    }
}

/// Maps a proxy's best protocol to a proxychains type string.
fn proxychains_type(proxy: &Proxy) -> &'static str {
    for pt in &proxy.proxy_types {
        match pt.protocol {
            Protocol::Socks5 => return "socks5",
            Protocol::Socks4 => return "socks4",
            _ => {}
        }
    }
    for pt in &proxy.proxy_types {
        match pt.protocol {
            Protocol::Http(_) | Protocol::Https(_) => return "http",
            _ => {}
        }
    }
    "http"
}

/// Maps a proxy's best protocol to the URI scheme used by the `prefix`
/// format, with the same SOCKS-over-HTTP preference as `proxychains_type`.
fn prefix_scheme(proxy: &Proxy) -> &'static str {
    for pt in &proxy.proxy_types {
        match pt.protocol {
            Protocol::Socks5 => return "socks5",
            Protocol::Socks4 => return "socks4",
            _ => {}
        }
    }
    "http"
}

/// Renders a PAC `FindProxyForURL` function from a list of proxies.
fn render_pac(proxies: &[Proxy]) -> String {
    let mut out = String::from("function FindProxyForURL(url, host) {\n    return \"");
    for (i, proxy) in proxies.iter().enumerate() {
        if i > 0 {
            out.push_str("; ");
        }
        let directive = proxy
            .proxy_types
            .first()
            .map(|pt| match pt.protocol {
                Protocol::Socks5 => "SOCKS5",
                Protocol::Socks4 => "SOCKS",
                _ => "PROXY",
            })
            .unwrap_or("PROXY");
        out.push_str(&format!("{directive} {}:{}", proxy.ip, proxy.port));
    }
    out.push_str("; DIRECT\";\n}\n");
    out
}

pub async fn process_result<S>(
    source: S,
    options: OutputOptions,
    cancel: Arc<tokio::sync::Notify>,
    guard: &dyn OutputGuard,
    finalize: FinalizeOpts,
) -> anyhow::Result<RunOutcome>
where
    S: Stream<Item = Proxy> + Send + 'static,
{
    let format = effective_format(
        &options.format,
        options.output_file.as_deref(),
        std::io::stdout().is_terminal(),
    );
    if options.append && matches!(format, "json" | "pretty-json") {
        anyhow::bail!("--append cannot be combined with the {format} format");
    }
    let mut output_file = match options.output_file.as_ref() {
        Some(file_path) => {
            let mut open = tokio::fs::OpenOptions::new();
            open.write(true).create(true);
            if options.append {
                open.append(true);
            } else {
                open.truncate(true);
            }
            let file = open
                .open(file_path)
                .await
                .with_context(|| format!("failed to open output file {}", file_path.display()))?;
            Some(tokio::io::BufWriter::new(file))
        }
        None => None,
    };
    let appending_to_existing = options.append
        && matches!(options.output_file.as_ref(), Some(file_path)
            if matches!(tokio::fs::metadata(file_path).await, Ok(metadata) if metadata.len() > 0));

    let json = matches!(format, "json" | "pretty-json");
    let _csv = format == "csv";
    let mut found_proxy = false;
    let mut cancelled = false;
    let filter = Arc::new(ProxyFilter::from_options(&options));
    let source: std::pin::Pin<Box<dyn Stream<Item = Proxy> + Send>> =
        if options.sort.is_some() || options.shuffle {
            let mut proxies: Vec<Proxy> = source.collect().await;
            if options.shuffle {
                shuffle_proxies(&mut proxies);
            }
            if let Some(sort) = options.sort.as_deref() {
                sort_proxies(&mut proxies, sort, Some(options.order.as_str()));
            }
            Box::pin(futures_util::stream::iter(proxies))
        } else {
            Box::pin(source)
        };
    let mut source = std::pin::pin!(source
        .filter_map(move |proxy| {
            let filter = Arc::clone(&filter);
            async move { filter.matches(&proxy).then_some(proxy) }
        })
        .enumerate());

    // PAC needs all proxies up front to render FindProxyForURL.
    if format == "pac" {
        let mut proxies: Vec<Proxy> = Vec::new();
        loop {
            tokio::select! {
                _ = cancel.notified() => {
                    cancelled = true;
                    break;
                }
                item = source.next() => {
                    let Some((_index, proxy)) = item else { break };
                    if options.limit > 0 && proxies.len() >= options.limit {
                        break;
                    }
                    proxies.push(proxy);
                }
            }
        }
        if !cancelled {
            let pac = render_pac(&proxies);
            if let Some(ref mut file) = output_file {
                if let Err(error) = file.write_all(pac.as_bytes()).await {
                    return Err(
                        anyhow::Error::new(error).context("failed to write PAC to output file")
                    );
                }
            } else {
                guard.before_write();
                let mut stdout = std::io::stdout().lock();
                stdout
                    .write_all(pac.as_bytes())
                    .expect("failed to write PAC to stdout");
                guard.after_write();
            }
        }
        if let Some(file) = output_file.as_mut() {
            let _ = file.flush().await;
        }
        if cancelled {
            return Ok(RunOutcome::Cancelled);
        }
        return Ok(RunOutcome::Finished);
    }
    // One stdout lock for the whole run instead of `print!` re-acquiring the
    // global lock (`std::io::_print`) for every proxy.
    let mut stdout = std::io::stdout().lock();

    // Reusable per-item buffer: each proxy's bytes are assembled here (no
    // per-item `String` allocation) and written in a single call, so stdout
    // issues one syscall per proxy.
    let mut buf: Vec<u8> = Vec::new();

    // When `cancel` resolves (Ctrl+C in the real binary), the run finalizes a
    // valid JSON document instead of leaving an unterminated array behind.

    // Collects the write error, if any, so the document can still be closed
    // before the error is reported to the caller.
    let mut write_error: Option<anyhow::Error> = None;

    // Emit the CSV header once before the stream starts so the output is
    // always valid even when the stream is empty.
    if _csv && finalize.emit_csv_header && !appending_to_existing {
        buf.extend_from_slice(b"ip,port,type,response_time,country,ip_type\n");
        if let Some(ref mut file) = output_file {
            if let Err(error) = file.write_all(&buf).await {
                write_error = Some(
                    anyhow::Error::new(error).context("failed to write CSV header to output file"),
                );
            }
        } else {
            guard.before_write();
            stdout
                .write_all(&buf)
                .expect("failed to write CSV header to stdout");
            guard.after_write();
        }
        buf.clear();
    }

    loop {
        tokio::select! {
            _ = cancel.notified() => {
                cancelled = true;
                break;
            }
            item = source.next() => {
                let Some((index, proxy)) = item else { break };
                let should_end = options.limit > 0 && index + 1 >= options.limit;
                buf.clear();
                match format {
                    "text" => {
                        buf.extend_from_slice(proxy.as_text().as_bytes());
                        buf.push(b'\n');
                    }
                    "json" => {
                        if index == 0 {
                            buf.extend_from_slice(b"[\n  ");
                        } else {
                            buf.extend_from_slice(b",\n  ");
                        }
                        let body_start = buf.len();
                        if serde_json::to_writer(&mut buf, &proxy).is_err() {
                            // `as_json()` falls back to an empty string when
                            // serialization fails; mirror that by undoing the
                            // partial write.
                            buf.truncate(body_start);
                        }
                    }
                    "pretty-json" => {
                        if index == 0 {
                            buf.extend_from_slice(b"[\n");
                        } else {
                            buf.extend_from_slice(b",\n");
                        }
                        let pretty = proxy.as_pretty_json();
                        for (i, line) in pretty.lines().enumerate() {
                            if i > 0 {
                                buf.push(b'\n');
                            }
                            buf.extend_from_slice(b"  ");
                            buf.extend_from_slice(line.as_bytes());
                        }
                    }
                    "json-lines" => {
                        if serde_json::to_writer(&mut buf, &proxy).is_ok() {
                            buf.push(b'\n');
                        }
                    }
                    "csv" => {
                        write_csv_row(&mut buf, &proxy);
                    }
                    "proxychains" => {
                        let pt = proxychains_type(&proxy);
                        write!(&mut buf, "{pt} {} {}", proxy.ip, proxy.port).unwrap();
                        buf.push(b'\n');
                    }
                    "prefix" => {
                        write!(
                            &mut buf,
                            "{}://{}:{}",
                            prefix_scheme(&proxy),
                            proxy.ip,
                            proxy.port
                        )
                        .unwrap();
                        buf.push(b'\n');
                    }
                     _ => writeln!(&mut buf, "{}", proxy).expect("writing to a Vec cannot fail"),
                };

                if let Some(ref mut file) = output_file {
                    if let Err(error) = file.write_all(&buf).await {
                        write_error = Some(
                            anyhow::Error::new(error)
                                .context("failed to write proxy to output file"),
                        );
                        break;
                    }
                } else {
                    guard.before_write();
                    // `print!` panics on a broken pipe; keep that behaviour by
                    // panicking here too.
                    stdout
                        .write_all(&buf)
                        .expect("failed to write proxy to stdout");
                    guard.after_write();
                }

                found_proxy = true;
                if should_end {
                    break;
                }
            }
        }
    }

    if json {
        // Finalizing is best-effort: an interrupted or failing run must still
        // yield valid JSON, but a failure here is only interesting when nothing
        // else already went wrong.
        guard.before_write();
        if write_error.is_none() {
            write_error = finalize_json_output(
                &mut output_file,
                &mut stdout,
                found_proxy,
                finalize.suppress_empty_json,
            )
            .await
            .err();
        } else {
            let _ = finalize_json_output(
                &mut output_file,
                &mut stdout,
                found_proxy,
                finalize.suppress_empty_json,
            )
            .await;
        }
        guard.after_write();
    }
    if let Some(file) = output_file.as_mut() {
        let _ = file.flush().await;
    }
    // Flush stdout explicitly so a cancelled/failed run still delivers the
    // final bytes (e.g. the closing `]`) before we exit or report an error.
    let _ = stdout.flush();

    if cancelled {
        // Ctrl+C: the document above has been finalized; report the
        // interruption so `main` can exit with the conventional SIGINT status
        // (128 + 2) after the terminal settings have been restored on drop.
        return Ok(RunOutcome::Cancelled);
    }

    match write_error {
        Some(error) => Err(error),
        None => Ok(RunOutcome::Finished),
    }
}

async fn finalize_json_output(
    output_file: &mut Option<tokio::io::BufWriter<tokio::fs::File>>,
    stdout: &mut std::io::StdoutLock<'static>,
    found_proxy: bool,
    suppress_empty_json: bool,
) -> anyhow::Result<()> {
    let close = if found_proxy {
        "\n]\n"
    } else if suppress_empty_json {
        ""
    } else {
        "[]\n"
    };
    write_output(output_file, stdout, close).await
}

async fn write_output(
    output_file: &mut Option<tokio::io::BufWriter<tokio::fs::File>>,
    stdout: &mut std::io::StdoutLock<'static>,
    content: &str,
) -> anyhow::Result<()> {
    if let Some(ref mut file) = output_file {
        file.write_all(content.as_bytes())
            .await
            .context("failed to write proxy to output file")?;
    } else {
        stdout
            .write_all(content.as_bytes())
            .context("failed to write proxy to stdout")?;
    }
    Ok(())
}

// Emits the document a skipped fallback pass would have closed: an empty JSON
// array for JSON formats and nothing for any other format.
pub async fn emit_empty_skipped_fallback(options: &OutputOptions) -> anyhow::Result<()> {
    let format = effective_format(
        &options.format,
        options.output_file.as_deref(),
        std::io::stdout().is_terminal(),
    );
    if !matches!(format, "json" | "pretty-json") {
        return Ok(());
    }
    let mut stdout = std::io::stdout().lock();
    if let Some(ref file_path) = options.output_file {
        let mut file = tokio::io::BufWriter::new(
            tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(file_path)
                .await
                .with_context(|| format!("failed to open output file {}", file_path.display()))?,
        );
        file.write_all(b"[]\n")
            .await
            .context("failed to write proxy to output file")?;
        file.flush().await?;
    } else {
        stdout
            .write_all(b"[]\n")
            .context("failed to write proxy to stdout")?;
    }
    Ok(())
}

fn ip_type_str(proxy: &Proxy) -> &'static str {
    match proxy.geo.ip_type {
        IpType::Residential => "residential",
        IpType::Datacenter => "datacenter",
        IpType::Mobile => "mobile",
        IpType::Unknown => "unknown",
    }
}

fn write_csv_row(buf: &mut Vec<u8>, proxy: &Proxy) {
    let ip = proxy.ip.to_string();
    let port = proxy.port.to_string();
    let proxy_type = proxy
        .proxy_types
        .iter()
        .map(|pt| pt.protocol.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let response_time = format!("{:.2}", proxy.avg_response_time());
    let country = proxy.geo.iso_code.as_deref().unwrap_or("");

    for (i, field) in [
        ip.as_str(),
        port.as_str(),
        proxy_type.as_str(),
        response_time.as_str(),
        country,
        ip_type_str(proxy),
    ]
    .iter()
    .enumerate()
    {
        if i > 0 {
            buf.push(b',');
        }
        csv_quote(buf, field);
    }
    buf.push(b'\n');
}

fn csv_quote(buf: &mut Vec<u8>, field: &str) {
    if field.contains([',', '"', '\n', '\r']) {
        buf.push(b'"');
        for ch in field.chars() {
            if ch == '"' {
                buf.extend_from_slice(b"\"\"");
            } else {
                // CSV fields are ASCII-safe; non-ASCII is written as-is.
                let mut b = [0u8; 4];
                let encoded = ch.encode_utf8(&mut b);
                buf.extend_from_slice(encoded.as_bytes());
            }
        }
        buf.push(b'"');
    } else {
        buf.extend_from_slice(field.as_bytes());
    }
}
