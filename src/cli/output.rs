use anyhow::Context;
use flx::proxy::models::{Protocol, Proxy};
use flx::IpType;
use futures_util::{Stream, StreamExt};
use std::collections::HashMap;
use std::io::IsTerminal as _;
use std::io::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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

// Aggregated per-item distribution feeding the end-of-run summary line.
#[derive(Default)]
pub struct RunStats {
    protocols: Mutex<HashMap<&'static str, usize>>,
    countries: Mutex<HashMap<Box<str>, usize>>,
}

const RUN_STATS_TOP_COUNTRIES: usize = 3;

impl RunStats {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn record(&self, proxy: &Proxy) {
        {
            let mut protocols = self.protocols.lock().unwrap_or_else(|e| e.into_inner());
            for proxy_type in &proxy.proxy_types {
                let family = match flx::protocol_family(proxy_type.protocol) {
                    Protocol::Http(_) => "HTTP",
                    Protocol::Https(_) => "HTTPS",
                    Protocol::Socks4 => "SOCKS4",
                    Protocol::Socks5 => "SOCKS5",
                    Protocol::Connect(_) => "CONNECT",
                };
                *protocols.entry(family).or_default() += 1;
            }
        }
        if let Some(iso_code) = &proxy.geo.iso_code {
            let mut countries = self.countries.lock().unwrap_or_else(|e| e.into_inner());
            *countries.entry(iso_code.clone()).or_default() += 1;
        }
    }

    /// One-line distribution (`http: 12 · socks5: 3 · top: US 10, ID 4`),
    /// `None` when nothing was emitted.
    pub fn summary(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        {
            let protocols = self.protocols.lock().unwrap_or_else(|e| e.into_inner());
            let mut counts: Vec<(&'static str, usize)> =
                protocols.iter().map(|(k, v)| (*k, *v)).collect();
            counts.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            parts.extend(counts.into_iter().map(|(name, n)| format!("{name}: {n}")));
        }
        {
            let countries = self.countries.lock().unwrap_or_else(|e| e.into_inner());
            let mut counts: Vec<(&str, usize)> =
                countries.iter().map(|(k, v)| (k.as_ref(), *v)).collect();
            counts.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            if !counts.is_empty() {
                let mut top: Vec<String> = counts
                    .iter()
                    .take(RUN_STATS_TOP_COUNTRIES)
                    .map(|(iso, n)| format!("{iso} {n}"))
                    .collect();
                let remainder = counts.len().saturating_sub(RUN_STATS_TOP_COUNTRIES);
                if remainder > 0 {
                    top.push(format!("+{remainder} more"));
                }
                parts.push(format!("top: {}", top.join(", ")));
            }
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" · "))
        }
    }
}

// Item counter shared by chained output passes so a fallback pass extends
// the array opened by an earlier pass instead of starting a new document.
#[derive(Default)]
pub struct JsonDoc {
    items: AtomicUsize,
}

impl JsonDoc {
    pub fn items(&self) -> usize {
        self.items.load(Ordering::Relaxed)
    }

    fn add(&self, count: usize) {
        self.items.fetch_add(count, Ordering::Relaxed);
    }
}

// Links one pass to a shared `JsonDoc`. `leave_open` keeps the closing `]`
// unwritten so a later chained pass can append more items to the array.
#[derive(Clone)]
pub struct JsonContinuation {
    pub doc: Arc<JsonDoc>,
    pub leave_open: bool,
}

// Controls document finalization when `process_result` chains one output
// pass after another. Empty JSON is only suppressed on the first pass, and
// the CSV header is only emitted once.
#[derive(Clone)]
pub struct FinalizeOpts {
    pub suppress_empty_json: bool,
    pub emit_csv_header: bool,
    // A chained pass also opens its output file in append mode so bytes
    // written by earlier passes are never truncated away.
    pub continue_json: Option<JsonContinuation>,
    // Shared per-item distribution collector for the end-of-run summary;
    // chained passes share one instance so both passes count into it.
    pub stats: Option<Arc<RunStats>>,
}

impl Default for FinalizeOpts {
    fn default() -> Self {
        Self {
            suppress_empty_json: false,
            emit_csv_header: true,
            continue_json: None,
            stats: None,
        }
    }
}

// Sorts proxies by the requested field, honoring `--order`. The string flags
// are a CLI concern; the ordering itself lives in the shared library module.
fn sort_proxies(proxies: &mut [Proxy], sort: &str, order: Option<&str>) {
    let key = match sort {
        "avg-response" | "response-time" => flx::SortKey::AvgResponseTime,
        "country" => flx::SortKey::Country,
        _ => flx::SortKey::Anonymity,
    };
    let order = if order == Some("desc") {
        flx::SortOrder::Desc
    } else {
        flx::SortOrder::Asc
    };
    flx::sort_proxies(proxies, key, order);
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
    let chained = finalize.continue_json.is_some();
    let mut output_file = match options.output_file.as_ref() {
        Some(file_path) => {
            let mut open = tokio::fs::OpenOptions::new();
            open.write(true).create(true);
            if options.append || chained {
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
    // A chained pass resumes the array opened by an earlier one: the first
    // item emits a `,` separator when earlier passes already wrote items.
    let leave_open = finalize
        .continue_json
        .as_ref()
        .is_some_and(|chain| chain.leave_open);
    let mut item_count = finalize
        .continue_json
        .as_ref()
        .map_or(0, |chain| chain.doc.items());
    let _csv = format == "csv";
    let mut cancelled = false;
    let filter = Arc::new(ProxyFilter::from_options(&options));
    let source: std::pin::Pin<Box<dyn Stream<Item = Proxy> + Send>> =
        if options.sort.is_some() || options.shuffle {
            // Sorted/shuffled output cannot stream, so collection must stay
            // interruptible: without this select a Ctrl+C pressed during the
            // whole upstream run (fetch+validate) would be swallowed until
            // every item had arrived. A cancel keeps what already arrived.
            let mut buffered: Vec<Proxy> = Vec::new();
            let mut src = std::pin::pin!(source);
            loop {
                tokio::select! {
                    _ = cancel.notified(), if !cancelled => {
                        cancelled = true;
                        break;
                    }
                    item = src.next() => {
                        let Some(proxy) = item else { break };
                        // The limit counts filtered results, so the filter has
                        // to run here too — otherwise buffering would keep the
                        // upstream running long after enough results existed.
                        if filter.matches(&proxy) {
                            buffered.push(proxy);
                            if options.limit > 0 && buffered.len() >= options.limit {
                                break;
                            }
                        }
                    }
                }
            }
            if options.shuffle {
                flx::shuffle_proxies(&mut buffered);
            }
            if let Some(sort) = options.sort.as_deref() {
                sort_proxies(&mut buffered, sort, Some(options.order.as_str()));
            }
            Box::pin(futures_util::stream::iter(buffered))
        } else {
            Box::pin(source)
        };
    // The filter runs twice on the sorted/shuffled path (above and here); it
    // is a pure predicate, so the second pass is a no-op on kept items.
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
                _ = cancel.notified(), if !cancelled => {
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
                if let Err(error) = std::io::stdout().lock().write_all(pac.as_bytes()) {
                    // A downstream consumer (e.g. `head`) closing the pipe is
                    // normal termination, not a defect.
                    if error.kind() == std::io::ErrorKind::BrokenPipe {
                        guard.after_write();
                        return Ok(RunOutcome::Finished);
                    }
                    guard.after_write();
                    return Err(anyhow::Error::new(error).context("failed to write PAC to stdout"));
                }
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
    // Scratch for serializing one item before it is committed to `buf`, so a
    // failed serialization can be discarded without undoing prefix bytes.
    let mut body: Vec<u8> = Vec::new();

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
            if let Err(error) = stdout.write_all(&buf) {
                // `head` (or any early-closing consumer) is expected termination.
                if error.kind() == std::io::ErrorKind::BrokenPipe {
                    guard.after_write();
                    return Ok(RunOutcome::Finished);
                }
                write_error =
                    Some(anyhow::Error::new(error).context("failed to write CSV header to stdout"));
            }
            guard.after_write();
        }
        buf.clear();
    }

    loop {
        tokio::select! {
            _ = cancel.notified(), if !cancelled => {
                cancelled = true;
                break;
            }
            item = source.next() => {
                let Some((index, proxy)) = item else { break };
                let should_end = options.limit > 0 && index + 1 >= options.limit;
                buf.clear();
                // JSON arms clear this on a failed serialization; such an
                // item is skipped entirely instead of leaving a dangling
                // separator behind.
                let mut emitted = true;
                match format {
                    "text" => {
                        buf.extend_from_slice(proxy.as_text().as_bytes());
                        buf.push(b'\n');
                    }
                    "json" => {
                        // Serialize first so a failed item leaves no trace:
                        // writing the `[`/`,` prefix beforehand would strand
                        // it in the document when serialization aborts.
                        if !write_json_item(&mut buf, &mut body, item_count, &proxy) {
                            emitted = false;
                        }
                    }
                    "pretty-json" => {
                        if item_count == 0 {
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
                        body.clear();
                        if serde_json::to_writer(&mut body, &proxy).is_ok() {
                            buf.extend_from_slice(&body);
                            buf.push(b'\n');
                        } else {
                            // Drop the item entirely: partial bytes without a
                            // trailing newline would fuse with the next line.
                            emitted = false;
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

                if emitted {
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
                        // A downstream consumer closing the pipe (e.g. `head`)
                        // is normal, so end the run cleanly instead of panicking.
                        if let Err(error) = stdout.write_all(&buf) {
                            if error.kind() == std::io::ErrorKind::BrokenPipe {
                                guard.after_write();
                                break;
                            }
                            write_error = Some(
                                anyhow::Error::new(error)
                                    .context("failed to write proxy to stdout"),
                            );
                            guard.after_write();
                            break;
                        }
                        guard.after_write();
                    }

                    item_count += 1;
                    if let Some(chain) = &finalize.continue_json {
                        chain.doc.add(1);
                    }
                    if let Some(stats) = &finalize.stats {
                        stats.record(&proxy);
                    }
                }
                if should_end {
                    break;
                }
            }
        }
    }

    if json {
        // Finalizing is best-effort: an interrupted or failing run must still
        // yield valid JSON, but a failure here is only interesting when nothing
        // else already went wrong. A chained pass leaves the array open for a
        // later one, except when cancelled or already failing — an unterminated
        // document is worse than a doubled closer.
        guard.before_write();
        let close_document = !leave_open || cancelled || write_error.is_some();
        if write_error.is_none() {
            write_error = finalize_json_output(
                &mut output_file,
                &mut stdout,
                item_count,
                finalize.suppress_empty_json,
                close_document,
            )
            .await
            .err();
        } else {
            let _ = finalize_json_output(
                &mut output_file,
                &mut stdout,
                item_count,
                finalize.suppress_empty_json,
                close_document,
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
    item_count: usize,
    suppress_empty_json: bool,
    close_document: bool,
) -> anyhow::Result<()> {
    let close = if !close_document {
        // A later chained pass owns the closer.
        ""
    } else if item_count > 0 {
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

// Closes a chained JSON document once no further pass will run: appends the
// closer when an earlier pass already wrote items and a complete empty array
// otherwise; other formats need no finalization. The output file is opened in
// append mode so bytes written by earlier passes survive.
pub async fn close_chained_json(options: &OutputOptions, item_count: usize) -> anyhow::Result<()> {
    let format = effective_format(
        &options.format,
        options.output_file.as_deref(),
        std::io::stdout().is_terminal(),
    );
    if !matches!(format, "json" | "pretty-json") {
        return Ok(());
    }
    let closer: &[u8] = if item_count > 0 { b"\n]\n" } else { b"[]\n" };
    let mut stdout = std::io::stdout().lock();
    if let Some(ref file_path) = options.output_file {
        let mut file = tokio::io::BufWriter::new(
            tokio::fs::OpenOptions::new()
                .write(true)
                .append(true)
                .create(true)
                .open(file_path)
                .await
                .with_context(|| format!("failed to open output file {}", file_path.display()))?,
        );
        file.write_all(closer)
            .await
            .context("failed to write proxy to output file")?;
        file.flush().await?;
    } else {
        stdout
            .write_all(closer)
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
    // Written field-by-field straight into `buf`: intermediate `String`s here
    // would be pure allocator churn on the hottest output path. The numeric
    // and protocol fields can never contain CSV-special characters, so only
    // the free-form country and ip-type fields go through `csv_quote`.
    let _ = write!(buf, "{},{}", proxy.ip, proxy.port);
    buf.push(b',');
    for (i, pt) in proxy.proxy_types.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        let _ = write!(buf, "{}", pt.protocol);
    }
    buf.push(b',');
    let _ = write!(buf, "{:.2}", proxy.avg_response_time());
    buf.push(b',');
    csv_quote(buf, proxy.geo.iso_code.as_deref().unwrap_or(""));
    buf.push(b',');
    csv_quote(buf, ip_type_str(proxy));
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

// Serializes one item into the scratch buffer and, on success, commits it to
// `buf` with the array opener/continuation separator. On failure nothing is
// written: a dangling `[` or `,` would render the document invalid.
fn write_json_item<T: ?Sized + serde::Serialize>(
    buf: &mut Vec<u8>,
    body: &mut Vec<u8>,
    item_count: usize,
    value: &T,
) -> bool {
    body.clear();
    if serde_json::to_writer(&mut *body, value).is_err() {
        return false;
    }
    if item_count == 0 {
        buf.extend_from_slice(b"[\n  ");
    } else {
        buf.extend_from_slice(b",\n  ");
    }
    buf.extend_from_slice(body);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // Serializes to an error unconditionally, standing in for any future
    // `Proxy` field that serde_json cannot render.
    struct Unserializable;

    impl serde::Serialize for Unserializable {
        fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("boom"))
        }
    }

    #[test]
    fn failed_first_item_opens_the_array_with_the_next_one() {
        let mut buf = Vec::new();
        let mut body = Vec::new();
        assert!(!write_json_item(&mut buf, &mut body, 0, &Unserializable));
        assert!(buf.is_empty(), "a failed item must write nothing");

        assert!(write_json_item(&mut buf, &mut body, 0, &1u32));
        assert_eq!(buf, b"[\n  1", "the next item must open the array itself");
    }

    #[test]
    fn failed_middle_item_leaves_exactly_one_separator_between_neighbours() {
        let mut buf = Vec::new();
        let mut body = Vec::new();
        assert!(write_json_item(&mut buf, &mut body, 0, &1u32));
        let after_first = buf.clone();
        assert!(!write_json_item(&mut buf, &mut body, 1, &Unserializable));
        assert_eq!(buf, after_first, "a failed item must not touch the buffer");
        assert!(write_json_item(&mut buf, &mut body, 1, &2u32));
        assert_eq!(
            buf, b"[\n  1,\n  2",
            "exactly one separator must sit between the surviving items"
        );
    }
}
