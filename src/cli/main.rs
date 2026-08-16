use anyhow::Context;
use argument::Cli;
use argument::{Command, FetchArgs, FetcherArgs, FindArgs, OutputOptions, ValidatorArgs};
use clap::Parser;
#[cfg(feature = "progress_bar")]
use colored::Colorize;
#[cfg(feature = "log")]
use flx::initialize_logging;
use flx::{
    proxy::models::{Anonymity, Protocol, Proxy},
    IpType, ProxySource, ProxyValidator,
};
use futures_util::{Stream, StreamExt};
use std::io::IsTerminal as _;
use std::str::FromStr;
use std::sync::Arc;
use tokio::{io::AsyncWriteExt, runtime};

mod argument;
#[cfg(feature = "progress_bar")]
mod progress;

pub trait OutputGuard {
    fn before_write(&self);
    fn after_write(&self);
}

pub struct NoopGuard;

impl OutputGuard for NoopGuard {
    fn before_write(&self) {}
    fn after_write(&self) {}
}

#[cfg(feature = "progress_bar")]
pub enum OutputGuardEither<B> {
    Bar(B),
    Noop(NoopGuard),
}

#[cfg(feature = "progress_bar")]
impl<B: OutputGuard> OutputGuard for OutputGuardEither<B> {
    fn before_write(&self) {
        match self {
            OutputGuardEither::Bar(bar) => bar.before_write(),
            OutputGuardEither::Noop(noop) => noop.before_write(),
        }
    }

    fn after_write(&self) {
        match self {
            OutputGuardEither::Bar(bar) => bar.after_write(),
            OutputGuardEither::Noop(noop) => noop.after_write(),
        }
    }
}

/// Whether stdout is a pipe (FIFO) rather than a terminal or a regular file.
///
/// A piped stdout means a downstream process writes to the shared terminal (or
/// `2>&1` routes our own stderr into the pipe), so a stderr summary would mix
/// with that output. Regular-file redirects (`> out`) leave the terminal free
/// and are safe to keep the summary.
#[cfg(unix)]
fn stdout_is_pipe() -> bool {
    use std::os::unix::io::AsRawFd as _;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // fstat cannot fail on the already-open stdout descriptor.
    (unsafe { libc::fstat(std::io::stdout().as_raw_fd(), &mut stat) } == 0)
        && stat.st_mode & libc::S_IFMT == libc::S_IFIFO
}

#[cfg(not(unix))]
fn stdout_is_pipe() -> bool {
    !std::io::stdout().is_terminal()
}

/// Formats the end-of-run stats line for `find`, colored under the
/// `progress_bar` feature and plain otherwise.
#[cfg(feature = "progress_bar")]
fn format_validation_stats(
    valid: usize,
    failed: usize,
    checked: usize,
    elapsed: std::time::Duration,
    rate: f64,
    dst: Option<&str>,
) -> String {
    let v = format!("{valid} valid").green();
    let f = format!("{failed} failed").red();
    let suffix = dst.map(|d| format!(" → {d}")).unwrap_or_default();
    let lead = if dst.is_some() { "" } else { "\n" };
    format!("{lead}{v} · {f} · {checked} checked in {elapsed:?} ({rate:.1}/s){suffix}")
}

#[cfg(not(feature = "progress_bar"))]
fn format_validation_stats(
    valid: usize,
    failed: usize,
    checked: usize,
    elapsed: std::time::Duration,
    rate: f64,
    dst: Option<&str>,
) -> String {
    let suffix = dst.map(|d| format!(" → {d}")).unwrap_or_default();
    let lead = if dst.is_some() { "" } else { "\n" };
    format!("{lead}{valid} valid · {failed} failed · {checked} checked in {elapsed:?} ({rate:.1}/s){suffix}")
}

/// Formats the end-of-run line for `grab`, colored under the `progress_bar`
/// feature and plain otherwise.
#[cfg(feature = "progress_bar")]
fn format_gathered_stats(
    gathered: usize,
    elapsed: std::time::Duration,
    rate: f64,
    dst: Option<&str>,
) -> String {
    let n = format!("{gathered} proxies").green();
    let suffix = dst.map(|d| format!(" → {d}")).unwrap_or_default();
    let lead = if dst.is_some() { "" } else { "\n" };
    format!("{lead}Gathered {n} in {elapsed:?} ({rate:.1}/s){suffix}")
}

#[cfg(not(feature = "progress_bar"))]
fn format_gathered_stats(
    gathered: usize,
    elapsed: std::time::Duration,
    rate: f64,
    dst: Option<&str>,
) -> String {
    let suffix = dst.map(|d| format!(" → {d}")).unwrap_or_default();
    let lead = if dst.is_some() { "" } else { "\n" };
    format!("{lead}Gathered {gathered} proxies in {elapsed:?} ({rate:.1}/s){suffix}")
}

#[cfg(unix)]
mod quiet_signal_echo {
    pub struct QuietSignalEcho {
        fd: libc::c_int,
        original: libc::termios,
    }

    impl QuietSignalEcho {
        pub fn install() -> Option<Self> {
            let fd = [0, 1, 2]
                .into_iter()
                .find(|&fd| unsafe { libc::isatty(fd) } == 1)?;

            let mut original: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
                return None;
            }

            let mut quiet = original;
            quiet.c_lflag &= !libc::ECHOCTL;
            if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) } != 0 {
                return None;
            }

            Some(Self { fd, original })
        }
    }

    impl Drop for QuietSignalEcho {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
            }
        }
    }
}

#[cfg(not(unix))]
mod quiet_signal_echo {
    pub struct QuietSignalEcho;

    impl QuietSignalEcho {
        pub fn install() -> Option<Self> {
            None
        }
    }
}

use quiet_signal_echo::QuietSignalEcho;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunOutcome {
    Finished,
    Cancelled,
    NoCommand,
}

fn main() -> std::process::ExitCode {
    // Restore the terminal settings before the process leaves, on every path.
    let _quiet = QuietSignalEcho::install();
    match run_application() {
        Ok(RunOutcome::Finished) => std::process::ExitCode::SUCCESS,
        Ok(RunOutcome::Cancelled) => std::process::ExitCode::from(130),
        Ok(RunOutcome::NoCommand) => std::process::ExitCode::from(2),
        Err(e) => {
            #[cfg(feature = "log")]
            log::error!("Error: {e:?}");
            // Fatal errors must be visible even when the log level is off.
            eprintln!("Error: {e:?}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn report_invalid_type_value(value: &str) {
    eprintln!("error: invalid value '{value}' for TYPES");
}

#[cfg(test)]
fn convert_protocols(types: &[String]) -> Vec<Protocol> {
    types
        .iter()
        .filter_map(|type_str| match Protocol::from_str(type_str.as_str()) {
            Ok(protocol) => Some(protocol),
            Err(_) => {
                report_invalid_type_value(type_str);
                None
            }
        })
        .collect()
}

fn split_type_groups(tokens: &[String]) -> (Vec<Protocol>, Vec<Vec<Protocol>>) {
    let mut types = Vec::new();
    let mut groups: Vec<Vec<Protocol>> = Vec::new();
    for token in tokens {
        let mut parts: Vec<Protocol> = Vec::new();
        for part in token.split('+') {
            match Protocol::from_str(part) {
                Ok(protocol) => parts.push(protocol),
                Err(_) => report_invalid_type_value(part),
            }
        }
        match parts.len() {
            0 => {}
            1 => types.push(parts[0]),
            _ => {
                let mut seen: Vec<Protocol> = Vec::with_capacity(parts.len());
                parts.retain(|protocol| {
                    if seen.contains(protocol) {
                        false
                    } else {
                        seen.push(*protocol);
                        true
                    }
                });
                groups.push(parts);
            }
        }
    }
    (types, groups)
}

// Mirrors the validator's `advertised_matches_request`: an advertised type
// covers a requested one when their families line up and any `Unknown`
// anonymity side is tolerated.
fn advertised_covers_request(advertised: &[Protocol], requested: Protocol) -> bool {
    advertised.iter().any(|adv| match (*adv, requested) {
        (Protocol::Http(a), Protocol::Http(b)) | (Protocol::Https(a), Protocol::Https(b)) => {
            matches!(a, Anonymity::Unknown) || matches!(b, Anonymity::Unknown) || a == b
        }
        (Protocol::Connect(a), Protocol::Connect(b)) => a == b,
        (adv, req) => adv == req,
    })
}

// A candidate needs the fallback (missed-type) probe when nothing is
// advertised or at least one requested type its advertisement does not cover.
fn needs_missed_probe(proxy: &Proxy, requested: &[Protocol]) -> bool {
    let advertised = proxy.expected_types.as_ref();
    advertised.is_empty()
        || requested
            .iter()
            .any(|req| !advertised_covers_request(advertised, *req))
}

// Resolves the output format when the user left `--format` at `default`: an
// explicit `-o` path infers the format from its file extension and a piped
// stdout switches to `json-lines`.
fn effective_format<'a>(
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
struct FinalizeOpts {
    suppress_empty_json: bool,
    emit_csv_header: bool,
}

impl Default for FinalizeOpts {
    fn default() -> Self {
        Self {
            suppress_empty_json: false,
            emit_csv_header: true,
        }
    }
}

fn anonymity_rank_from_name(name: &str) -> u8 {
    match name {
        "transparent" => Anonymity::Transparent.rank(),
        "anonymous" => Anonymity::Anonymous.rank(),
        "elite" => Anonymity::Elite.rank(),
        _ => Anonymity::Unknown.rank(),
    }
}

/// Best anonymity rank across a proxy's validated types; types without an
/// anonymity level (SOCKS, CONNECT) count as `Unknown`.
fn proxy_anonymity_rank(proxy: &Proxy) -> u8 {
    proxy
        .proxy_types
        .iter()
        .filter_map(|proxy_type| match proxy_type.protocol {
            Protocol::Http(anonymity) | Protocol::Https(anonymity) => Some(anonymity.rank()),
            _ => None,
        })
        .max()
        .unwrap_or_else(|| Anonymity::Unknown.rank())
}

/// Sorts proxies by the requested field, honoring `--order`.
fn sort_proxies(proxies: &mut [Proxy], sort: &str, order: Option<&str>) {
    match sort {
        "avg-response" => proxies.sort_by(|a, b| {
            a.avg_response_time()
                .partial_cmp(&b.avg_response_time())
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        "country" => proxies.sort_by(|a, b| a.geo.iso_code.cmp(&b.geo.iso_code)),
        _ => proxies.sort_by_key(proxy_anonymity_rank),
    }
    if order == Some("desc") {
        proxies.reverse();
    }
}

/// Post-validation filters applied before a proxy is rendered.
struct ProxyFilter {
    min_anonymity_rank: Option<u8>,
    min_response_time: Option<f64>,
    max_response_time: Option<f64>,
}

impl ProxyFilter {
    fn from_options(options: &OutputOptions) -> Self {
        Self {
            min_anonymity_rank: options
                .min_anonymity
                .as_deref()
                .map(anonymity_rank_from_name),
            min_response_time: options.min_response_time,
            max_response_time: options.max_response_time,
        }
    }

    fn matches(&self, proxy: &Proxy) -> bool {
        if let Some(min_rank) = self.min_anonymity_rank {
            if proxy_anonymity_rank(proxy) < min_rank {
                return false;
            }
        }
        let response_time = proxy.avg_response_time();
        if let Some(min_time) = self.min_response_time {
            if response_time < min_time {
                return false;
            }
        }
        if let Some(max_time) = self.max_response_time {
            if response_time > max_time {
                return false;
            }
        }
        true
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

async fn process_result<S>(
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

    let json = matches!(format, "json" | "pretty-json");
    let _csv = format == "csv";
    let mut found_proxy = false;
    let mut cancelled = false;
    let filter = Arc::new(ProxyFilter::from_options(&options));
    let source: BoxStream = if let Some(sort) = options.sort.as_deref() {
        let mut proxies: Vec<Proxy> = source.collect().await;
        sort_proxies(&mut proxies, sort, Some(options.order.as_str()));
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
    use std::io::Write as _;

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
    if _csv && finalize.emit_csv_header {
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
                        write!(&mut buf, "socks5://{}:{}", proxy.ip, proxy.port).unwrap();
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
        use std::io::Write as _;
        stdout
            .write_all(content.as_bytes())
            .context("failed to write proxy to stdout")?;
    }
    Ok(())
}

// Emits the document a skipped fallback pass would have closed: an empty JSON
// array for JSON formats and nothing for any other format.
async fn emit_empty_skipped_fallback(options: &OutputOptions) -> anyhow::Result<()> {
    use std::io::Write as _;
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

fn fetcher_config(options: &FetcherArgs) -> flx::fetcher::Config {
    let ip_type = options.ip_type.as_deref().map(|name| match name {
        "residential" => IpType::Residential,
        "datacenter" => IpType::Datacenter,
        "mobile" => IpType::Mobile,
        "unknown" => IpType::Unknown,
        _ => IpType::Unknown,
    });
    flx::fetcher::Config {
        concurrency_limit: options.fetch_concurrency,
        enable_geo_lookup: options.with_geo
            || !options.countries.is_empty()
            || options.with_ip_type
            || options.ip_type.is_some(),
        enable_ip_type: options.with_ip_type || options.ip_type.is_some(),
        ip_type_filter: ip_type,
        countries: Arc::from(options.countries.as_slice()),
        cache_ttl: (options.cache_ttl > 0)
            .then(|| std::time::Duration::from_secs(options.cache_ttl.saturating_mul(60))),
        refresh_cache: options.refresh_cache,
        enforce_unique_ip: !options.no_dedup,
        providers: Arc::from(options.provider.as_slice()),
        excluded_providers: Arc::from(options.exclude_provider.as_slice()),
        custom_sources: Arc::from(options.source_url.as_slice()),
        offline: options.offline,
        fetch_delay: (options.fetch_delay_ms > 0)
            .then(|| std::time::Duration::from_millis(options.fetch_delay_ms)),
        fallback_threshold: options.fallback_threshold,
        fallback_phase_timeout: (options.fetch_phase_timeout > 0)
            .then(|| std::time::Duration::from_secs(options.fetch_phase_timeout)),
    }
}

fn list_sources() {
    for provider in flx::all_providers() {
        let tier = match provider.tier() {
            flx::ProviderTier::Primary => "primary",
            flx::ProviderTier::Fallback => "fallback",
        };
        eprintln!("{} ({tier}):", provider.name());
        for source in provider.sources() {
            eprintln!("  {}", source.url);
        }
    }
}

type BoxStream = std::pin::Pin<Box<dyn Stream<Item = Proxy> + Send>>;

async fn file_source(path: &std::path::Path) -> anyhow::Result<BoxStream> {
    let path = path.to_owned();
    let proxies = tokio::task::spawn_blocking(move || {
        ProxySource::from_file(path.clone())
            .with_context(|| format!("failed to read proxies from {}", path.display()))
            .map(Iterator::collect::<Vec<_>>)
    })
    .await
    .context("proxy file reader task failed")??;
    Ok(Box::pin(futures_util::stream::iter(proxies)))
}

fn run_application() -> anyhow::Result<RunOutcome> {
    let cli = Cli::parse();

    #[cfg(feature = "log")]
    {
        let log_level = match cli.log_level.as_str() {
            "debug" => log::LevelFilter::Debug,
            "info" => log::LevelFilter::Info,
            "warn" => log::LevelFilter::Warn,
            "error" => log::LevelFilter::Error,
            "trace" => log::LevelFilter::Trace,
            _ => log::LevelFilter::Off,
        };
        initialize_logging(log_level)?;
    }

    // No subcommand: a bare invocation is not an implicit grab. Print the
    // help text and report a usage error (exit code 2) instead of running.
    let Some(command) = cli.command else {
        use clap::CommandFactory as _;
        let mut stderr = std::io::stderr().lock();
        Cli::command().write_help(&mut stderr)?;
        return Ok(RunOutcome::NoCommand);
    };

    // `colored` decides by the stdout TTY, but the bar and summary paint on
    // stderr; force the color choice from `--no-color` for the whole run.
    #[cfg(feature = "progress_bar")]
    colored::control::set_override(!cli.no_color);

    let runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    // Ctrl+C (SIGINT): resolved inside `process_result`, which finalizes a
    // valid JSON document before the process exits. The runtime is built
    // with `enable_all()` above, so the tokio signal driver is available
    // here. An `Arc<Notify>` is shared so a fallback pass can keep listening.
    let cancel = Arc::new(tokio::sync::Notify::new());

    let outcome = runtime.block_on(async move {
        let notify = Arc::clone(&cancel);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            notify.notify_waiters();
        });
        match command {
            Command::Grab(grab) => run_grab(grab, cli.quiet, cancel).await,
            Command::Find(find) => run_find(find, cli.quiet, cli.no_color, cancel).await,
            Command::GeoUpdate => run_geo_update().await,
        }
    });
    runtime.shutdown_background();
    outcome
}

async fn run_grab(
    grab: FetchArgs,
    quiet: bool,
    cancel: Arc<tokio::sync::Notify>,
) -> anyhow::Result<RunOutcome> {
    if grab.fetcher.dry_run {
        list_sources();
        return Ok(RunOutcome::Finished);
    }
    let source = ProxySource::from_fetcher(fetcher_config(&grab.fetcher))
        .await
        .context("failed to start proxy fetcher")?;
    let accepted = source.accepted_handle();
    let started = std::time::Instant::now();
    let dst: Option<String> = grab
        .output
        .output_file
        .as_deref()
        .map(|p| p.to_string_lossy().into_owned());
    let outcome = process_result(
        source,
        grab.output,
        cancel,
        &NoopGuard,
        FinalizeOpts::default(),
    )
    .await;
    if !quiet && !stdout_is_pipe() {
        let gathered = accepted.load(std::sync::atomic::Ordering::Relaxed);
        let elapsed = started.elapsed();
        let rate = if elapsed.is_zero() {
            0.0
        } else {
            gathered as f64 / elapsed.as_secs_f64()
        };
        eprintln!(
            "{}",
            format_gathered_stats(gathered, elapsed, rate, dst.as_deref())
        );
    }
    outcome
}

async fn run_find(
    find: FindArgs,
    quiet: bool,
    no_color: bool,
    cancel: Arc<tokio::sync::Notify>,
) -> anyhow::Result<RunOutcome> {
    if find.fetcher.dry_run {
        list_sources();
        return Ok(RunOutcome::Finished);
    }

    let (mut protocols, groups) = split_type_groups(&find.validator.types);
    if protocols.is_empty() && groups.is_empty() {
        // Omitted `TYPES` defaults to plain HTTP validation.
        protocols.push(Protocol::Http(Anonymity::Unknown));
    }

    // Candidates are recorded while pass 1 streams so the fallback pass can
    // re-validate the same set without re-fetching.
    let recordings: Arc<std::sync::Mutex<Vec<Proxy>>> = Arc::default();
    let source: BoxStream = match &find.validator.file {
        Some(file) => Box::pin(tee_recorder(file_source(file).await?, recordings.clone())),
        None => Box::pin(tee_recorder(
            ProxySource::from_fetcher(fetcher_config(&find.fetcher))
                .await
                .context("failed to start proxy fetcher")?,
            recordings.clone(),
        )),
    };

    let pass1 = ProxyValidator::validate(
        source,
        validator_config(&find.validator, protocols.clone(), groups.clone(), false),
    )
    .await
    .context("failed to start proxy validator")?;
    if !quiet {
        let health = pass1.judge_health();
        if !health.failed.is_empty() {
            eprintln!("{}", format_judge_health(health));
        }
    }
    let progress1 = pass1.progress();
    let started = std::time::Instant::now();
    let dst: Option<String> = find
        .output
        .output_file
        .as_deref()
        .map(|p| p.to_string_lossy().into_owned());

    // The status line (stderr) repaints on a background thread and erases
    // itself on drop. It also hides around each stdout write so streamed
    // results never overwrite the line it is drawn on.
    let guard1 = make_guard(progress1.clone(), quiet, no_color);
    // An empty pass 1 leaves nothing on the wire so the fallback pass can
    // open the document itself; group-only requests never fall back.
    let outcome1 = process_result(
        pass1,
        find.output.clone(),
        cancel.clone(),
        &guard1,
        FinalizeOpts {
            suppress_empty_json: !protocols.is_empty(),
            emit_csv_header: true,
        },
    )
    .await;
    // Erase the status line before the summary so the two never share a row.
    drop(guard1);
    if !matches!(outcome1, Ok(RunOutcome::Finished)) {
        if matches!(outcome1, Ok(RunOutcome::Cancelled)) {
            report_validation_summary(
                progress1.passed(),
                progress1.done(),
                progress1.total(),
                started.elapsed(),
                dst.as_deref(),
                quiet,
            );
        }
        return outcome1;
    }

    // Fall back to the requested types the advertised set did not cover when
    // the gated pass came up empty or below the limit.
    let limit = find.output.limit;
    let p1_passed = progress1.passed();
    let needs_fallback =
        !protocols.is_empty() && (p1_passed == 0 || (limit > 0 && p1_passed < limit));

    if needs_fallback {
        let requested = protocols;
        // Only candidates whose advertisement leaves a requested type
        // uncovered can yield new results here; the rest already passed (or
        // failed) in pass 1 and would only repeat the judge preflight.
        let candidates: Vec<Proxy> =
            std::mem::take(&mut *recordings.lock().expect("recorder poisoned"))
                .into_iter()
                .filter(|proxy| needs_missed_probe(proxy, &requested))
                .collect();
        let mut options2 = find.output.clone();
        options2.limit = if limit > 0 { limit - p1_passed } else { 0 };

        if candidates.is_empty() {
            // The second pass would produce no probes, so skip the redundant
            // judge preflight and emit the document it would have closed.
            emit_empty_skipped_fallback(&options2).await?;
            report_validation_summary(
                p1_passed,
                progress1.done(),
                progress1.total(),
                started.elapsed(),
                dst.as_deref(),
                quiet,
            );
            return Ok(RunOutcome::Finished);
        }

        let pass2 = ProxyValidator::validate(
            futures_util::stream::iter(candidates),
            validator_config(&find.validator, requested, Vec::new(), true),
        )
        .await
        .context("failed to start proxy validator")?;
        let progress2 = pass2.progress();
        let guard2 = make_guard(progress2.clone(), quiet, no_color);
        let outcome2 = process_result(
            pass2,
            options2,
            cancel,
            &guard2,
            FinalizeOpts {
                suppress_empty_json: false,
                emit_csv_header: false,
            },
        )
        .await;
        drop(guard2);
        if !matches!(outcome2, Ok(RunOutcome::Finished)) {
            if matches!(outcome2, Ok(RunOutcome::Cancelled)) {
                report_validation_summary(
                    p1_passed + progress2.passed(),
                    progress1.done() + progress2.done(),
                    progress1.total() + progress2.total(),
                    started.elapsed(),
                    dst.as_deref(),
                    quiet,
                );
            }
            return outcome2;
        }
        report_validation_summary(
            p1_passed + progress2.passed(),
            progress1.done() + progress2.done(),
            progress1.total() + progress2.total(),
            started.elapsed(),
            dst.as_deref(),
            quiet,
        );
        return Ok(RunOutcome::Finished);
    }

    report_validation_summary(
        progress1.passed(),
        progress1.done(),
        progress1.total(),
        started.elapsed(),
        dst.as_deref(),
        quiet,
    );
    outcome1
}

fn format_judge_health(report: &flx::JudgeHealthReport) -> String {
    let mut reasons: Vec<&str> = report
        .failed
        .iter()
        .map(|(_, reason)| reason.as_str())
        .collect();
    reasons.sort_unstable();
    reasons.dedup();
    let suffix = if reasons.is_empty() {
        String::new()
    } else {
        format!(" ({})", reasons.join("; "))
    };
    format!(
        "{}/{} judges healthy; {} failed{}",
        report.healthy,
        report.candidates,
        report.failed.len(),
        suffix
    )
}

fn report_validation_summary(
    passed: usize,
    done: usize,
    checked: usize,
    elapsed: std::time::Duration,
    dst: Option<&str>,
    quiet: bool,
) {
    if quiet || stdout_is_pipe() {
        return;
    }
    let rate = if elapsed.is_zero() {
        0.0
    } else {
        checked as f64 / elapsed.as_secs_f64()
    };
    eprintln!(
        "{}",
        format_validation_stats(
            passed,
            done.saturating_sub(passed),
            checked,
            elapsed,
            rate,
            dst
        )
    );
}

// Forwards every candidate while appending a copy to the recordings buffer,
// so a fallback pass can replay the same set without re-fetching.
fn tee_recorder<S>(
    inner: S,
    recordings: Arc<std::sync::Mutex<Vec<Proxy>>>,
) -> impl Stream<Item = Proxy>
where
    S: Stream<Item = Proxy> + Unpin,
{
    futures_util::stream::unfold(inner, move |mut inner| {
        let recordings = Arc::clone(&recordings);
        async move {
            match inner.next().await {
                Some(proxy) => {
                    recordings
                        .lock()
                        .expect("candidate recorder mutex poisoned")
                        .push(proxy.clone());
                    Some((proxy, inner))
                }
                None => None,
            }
        }
    })
}

#[cfg(feature = "progress_bar")]
fn make_guard(
    progress: flx::ValidationProgress,
    quiet: bool,
    no_color: bool,
) -> OutputGuardEither<progress::ValidationBar> {
    match progress::ValidationBar::new(progress, quiet, no_color, stdout_is_pipe()) {
        Some(bar) => OutputGuardEither::Bar(bar),
        None => OutputGuardEither::Noop(NoopGuard),
    }
}

#[cfg(not(feature = "progress_bar"))]
fn make_guard(_progress: flx::ValidationProgress, _quiet: bool, _no_color: bool) -> NoopGuard {
    NoopGuard
}

async fn run_geo_update() -> anyhow::Result<RunOutcome> {
    match flx::sync_database()
        .await
        .context("failed to sync the GeoLite2 database")?
    {
        flx::SyncOutcome::Synced => {
            println!("GeoLite2 database synced from the P3TERX mirror");
        }
        flx::SyncOutcome::UpToDate => {
            println!("GeoLite2 database is up to date");
        }
    }
    Ok(RunOutcome::Finished)
}

fn validator_config(
    options: &ValidatorArgs,
    protocols: Vec<Protocol>,
    groups: Vec<Vec<Protocol>>,
    probe_missed_types: bool,
) -> flx::validator::Config {
    flx::validator::Config {
        types: protocols,
        groups,
        concurrency_limit: options.max_connections,
        max_attempts: options.max_attempts,
        request_timeout: options.timeout,
        http_judge_urls: options.http_judge_urls.clone(),
        https_judge_urls: options.https_judge_urls.clone(),
        insecure: !options.verify_tls,
        probe_missed_types,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use flx::proxy::models::Anonymity;
    use futures_util::stream;

    fn fetch_from(args: &[&str]) -> FetchArgs {
        let mut full = vec!["flx", "grab"];
        full.extend_from_slice(args);
        match Cli::parse_from(full).command {
            Some(Command::Grab(grab)) => grab,
            _ => panic!("expected a grab subcommand"),
        }
    }

    fn find_from(args: &[&str]) -> FindArgs {
        let mut full = vec!["flx", "find"];
        full.extend_from_slice(args);
        match Cli::parse_from(full).command {
            Some(Command::Find(find)) => find,
            _ => panic!("expected a find subcommand"),
        }
    }

    #[test]
    fn bare_flx_has_no_subcommand() {
        // A bare invocation parses with no command; `run_application` turns
        // that into a help message instead of an implicit run.
        let cli = Cli::parse_from(["flx"]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn bare_flx_rejects_fetch_flags() {
        // Fetch-only flags must be spelled `flx grab ...`; a bare invocation
        // that carries no subcommand cannot carry subcommand-scoped flags.
        assert!(Cli::try_parse_from(["flx", "--dry-run"]).is_err());
    }

    #[test]
    fn countries_enable_geo_lookup_for_fetcher() {
        let without_countries = fetch_from(&[]);
        assert!(!fetcher_config(&without_countries.fetcher).enable_geo_lookup);

        let with_countries = fetch_from(&["--countries", "ID"]);
        assert!(fetcher_config(&with_countries.fetcher).enable_geo_lookup);
    }

    #[test]
    fn with_geo_enables_geo_lookup_without_country_filter() {
        let geo_only = fetch_from(&["--with-geo"]);
        let config = fetcher_config(&geo_only.fetcher);
        assert!(config.enable_geo_lookup);
        assert!(config.countries.is_empty());

        let combined = fetch_from(&["--with-geo", "--countries", "ID"]);
        let config = fetcher_config(&combined.fetcher);
        assert!(config.enable_geo_lookup);
        assert_eq!(config.countries.as_ref(), ["ID".to_owned()]);
    }

    #[test]
    fn with_ip_type_enables_detection_without_filter() {
        let ip_type_only = fetch_from(&["--with-ip-type"]);
        let config = fetcher_config(&ip_type_only.fetcher);
        assert!(config.enable_geo_lookup);
        assert!(config.enable_ip_type);
        assert_eq!(config.ip_type_filter, None);
    }

    #[test]
    fn ip_type_filter_parses_and_implies_detection() {
        let filtered = fetch_from(&["--ip-type", "residential"]);
        let config = fetcher_config(&filtered.fetcher);
        assert!(config.enable_geo_lookup);
        assert!(config.enable_ip_type);
        assert_eq!(config.ip_type_filter, Some(flx::IpType::Residential));
    }

    #[test]
    fn invalid_ip_type_value_is_rejected() {
        assert!(Cli::try_parse_from(["flx", "find", "--ip-type", "bogus"]).is_err());
    }

    #[test]
    fn cache_ttl_maps_to_minutes_and_zero_disables() {
        let enabled = fetch_from(&["--cache-ttl", "10"]);
        assert_eq!(
            fetcher_config(&enabled.fetcher).cache_ttl,
            Some(std::time::Duration::from_secs(600))
        );

        let disabled = fetch_from(&["--cache-ttl", "0"]);
        assert_eq!(fetcher_config(&disabled.fetcher).cache_ttl, None);

        let default = fetch_from(&[]);
        assert_eq!(
            fetcher_config(&default.fetcher).cache_ttl,
            Some(std::time::Duration::from_secs(900))
        );
    }

    #[test]
    fn refresh_cache_flag_bypasses_cache() {
        let refreshed = fetch_from(&["--refresh-cache"]);
        assert!(fetcher_config(&refreshed.fetcher).refresh_cache);

        let default = fetch_from(&[]);
        assert!(fetcher_config(&default.fetcher).providers.is_empty());
        assert!(fetcher_config(&default.fetcher)
            .excluded_providers
            .is_empty());
    }

    #[test]
    fn source_url_flag_lands_in_fetcher_config() {
        let args = fetch_from(&[
            "--source-url",
            "http://127.0.0.1:9999/a.txt",
            "--source-url",
            "http://127.0.0.1:9999/b.txt",
        ]);
        assert_eq!(
            fetcher_config(&args.fetcher).custom_sources.as_ref(),
            [
                "http://127.0.0.1:9999/a.txt".to_owned(),
                "http://127.0.0.1:9999/b.txt".to_owned()
            ]
        );
    }

    #[test]
    fn offline_flag_lands_in_fetcher_config() {
        assert!(fetch_from(&["--offline"]).fetcher.offline);
        assert!(!fetch_from(&[]).fetcher.offline);
    }

    #[test]
    fn fetch_delay_flag_lands_in_fetcher_config() {
        let set = fetch_from(&["--fetch-delay-ms", "250"]);
        assert_eq!(
            fetcher_config(&set.fetcher).fetch_delay,
            Some(std::time::Duration::from_millis(250))
        );

        let default = fetch_from(&[]);
        assert_eq!(fetcher_config(&default.fetcher).fetch_delay, None);
    }

    #[test]
    fn fallback_threshold_flag_lands_in_fetcher_config() {
        let set = fetch_from(&["--fallback-threshold", "10"]);
        assert_eq!(fetcher_config(&set.fetcher).fallback_threshold, Some(10));

        let default = fetch_from(&[]);
        assert_eq!(fetcher_config(&default.fetcher).fallback_threshold, None);
    }

    #[test]
    fn fetch_phase_timeout_flag_lands_in_fetcher_config() {
        let set = fetch_from(&["--fetch-phase-timeout", "5"]);
        assert_eq!(
            fetcher_config(&set.fetcher).fallback_phase_timeout,
            Some(std::time::Duration::from_secs(5))
        );

        let default = fetch_from(&[]);
        assert_eq!(
            fetcher_config(&default.fetcher).fallback_phase_timeout,
            Some(std::time::Duration::from_secs(30))
        );

        let unbounded = fetch_from(&["--fetch-phase-timeout", "0"]);
        assert_eq!(
            fetcher_config(&unbounded.fetcher).fallback_phase_timeout,
            None
        );
    }

    #[test]
    fn needs_missed_probe_mirrors_validator_gating() {
        let http = Proxy::with_expected_types(
            std::net::Ipv4Addr::LOCALHOST,
            1111,
            std::sync::Arc::from([Protocol::Http(Anonymity::Unknown)]),
        );
        assert!(!needs_missed_probe(
            &http,
            &[Protocol::Http(Anonymity::Unknown)]
        ));
        assert!(!needs_missed_probe(
            &http,
            &[Protocol::Http(Anonymity::Elite)]
        ));
        assert!(needs_missed_probe(&http, &[Protocol::Socks5]));

        let empty = Proxy::with_expected_types(
            std::net::Ipv4Addr::LOCALHOST,
            1111,
            std::sync::Arc::from([]),
        );
        assert!(needs_missed_probe(
            &empty,
            &[Protocol::Http(Anonymity::Unknown)]
        ));

        let mixed = Proxy::with_expected_types(
            std::net::Ipv4Addr::LOCALHOST,
            1111,
            std::sync::Arc::from([Protocol::Http(Anonymity::Unknown), Protocol::Socks5]),
        );
        assert!(!needs_missed_probe(&mixed, &[Protocol::Socks5]));
        assert!(needs_missed_probe(&mixed, &[Protocol::Connect(9)]));

        let connect80 = Proxy::with_expected_types(
            std::net::Ipv4Addr::LOCALHOST,
            1111,
            std::sync::Arc::from([Protocol::Connect(80)]),
        );
        assert!(!needs_missed_probe(&connect80, &[Protocol::Connect(80)]));
        assert!(needs_missed_probe(&connect80, &[Protocol::Connect(25)]));
    }

    #[test]
    fn no_dedup_flag_disables_uniqueness() {
        let disabled = fetch_from(&["--no-dedup"]);
        assert!(!fetcher_config(&disabled.fetcher).enforce_unique_ip);

        let default = fetch_from(&[]);
        assert!(fetcher_config(&default.fetcher).enforce_unique_ip);
    }

    #[test]
    fn provider_flags_land_in_fetcher_config() {
        let args = fetch_from(&["--provider", "geonode", "--provider", "proxyscrape"]);
        assert_eq!(
            fetcher_config(&args.fetcher).providers.as_ref(),
            ["geonode".to_owned(), "proxyscrape".to_owned()]
        );

        let excluded = fetch_from(&["--exclude-provider", "github-raw"]);
        assert_eq!(
            fetcher_config(&excluded.fetcher)
                .excluded_providers
                .as_ref(),
            ["github-raw".to_owned()]
        );

        let default = fetch_from(&[]);
        assert!(fetcher_config(&default.fetcher).providers.is_empty());
        assert!(fetcher_config(&default.fetcher)
            .excluded_providers
            .is_empty());
    }

    #[test]
    fn dry_run_flag_is_accepted() {
        assert!(fetch_from(&["--dry-run"]).fetcher.dry_run);
        assert!(!fetch_from(&[]).fetcher.dry_run);
    }

    #[test]
    fn validation_filter_flags_are_accepted() {
        let args = find_from(&[
            "--min-anonymity",
            "anonymous",
            "--max-response-time",
            "1.5",
            "--min-response-time",
            "0.5",
        ]);
        assert_eq!(args.output.min_anonymity.as_deref(), Some("anonymous"));
        assert_eq!(args.output.max_response_time, Some(1.5));
        assert_eq!(args.output.min_response_time, Some(0.5));
        assert!(Cli::try_parse_from(["flx", "find", "--min-anonymity", "super"]).is_err());
    }

    #[test]
    fn cache_ttl_max_value_does_not_overflow() {
        let huge = fetch_from(&["--cache-ttl", "18446744073709551615"]);
        assert_eq!(
            fetcher_config(&huge.fetcher).cache_ttl,
            Some(std::time::Duration::from_secs(u64::MAX))
        );
    }

    #[test]
    fn https_judge_urls_flag_parses_custom_value() {
        let cli = find_from(&[
            "SOCKS5",
            "--https-judge-urls",
            "https://example.com/azenv.php",
        ]);
        assert_eq!(
            cli.validator.https_judge_urls,
            vec!["https://example.com/azenv.php".to_owned()]
        );
        // default still intact when flag omitted
        let defaults = find_from(&["SOCKS5"]);
        assert_eq!(
            defaults.validator.https_judge_urls,
            vec![
                "https://aranguren.org/azenv.php".to_owned(),
                "https://wfuchs.de/azenv.php".to_owned(),
            ]
        );
    }

    fn output_options(format: &str, limit: usize) -> (OutputOptions, std::path::PathBuf) {
        let out = std::env::temp_dir().join(format!(
            "flx_json_test_{}_{}.json",
            std::process::id(),
            uuidish()
        ));
        (
            OutputOptions {
                format: format.to_owned(),
                limit,
                output_file: Some(out.clone()),
                min_anonymity: None,
                min_response_time: None,
                max_response_time: None,
                sort: None,
                order: "asc".to_owned(),
            },
            out,
        )
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
    fn find_without_types_parses_cleanly() {
        let cli = find_from(&[]);
        assert!(cli.validator.types.is_empty());
    }

    #[test]
    fn types_split_into_singletons_and_and_groups() {
        let (types, groups) = split_type_groups(&[
            "HTTP".to_owned(),
            "HTTP+HTTPS".to_owned(),
            "SOCKS5".to_owned(),
        ]);
        assert_eq!(
            types,
            vec![Protocol::Http(Anonymity::Unknown), Protocol::Socks5]
        );
        assert_eq!(
            groups,
            vec![vec![
                Protocol::Http(Anonymity::Unknown),
                Protocol::Https(Anonymity::Unknown)
            ]]
        );
    }

    #[test]
    fn and_group_deduplicates_repeated_members() {
        let (types, groups) = split_type_groups(&["HTTP+HTTPS+HTTP".to_owned()]);
        assert!(types.is_empty());
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 2);
    }

    #[test]
    fn default_format_switches_to_json_lines_when_piped() {
        assert_eq!(effective_format("default", None, true), "default");
        assert_eq!(effective_format("default", None, false), "json-lines");
        // Explicit formats are never overridden.
        assert_eq!(effective_format("json", None, false), "json");
        assert_eq!(effective_format("pretty-json", None, false), "pretty-json");
    }

    #[test]
    fn default_format_follows_output_file_extension() {
        let f = |name: &'static str| Some(std::path::Path::new(name));
        assert_eq!(effective_format("default", f("a.json"), true), "json");
        assert_eq!(effective_format("default", f("a.JSON"), true), "json");
        assert_eq!(
            effective_format("default", f("a.jsonl"), true),
            "json-lines"
        );
        assert_eq!(
            effective_format("default", f("a.ndjson"), true),
            "json-lines"
        );
        assert_eq!(effective_format("default", f("a.csv"), true), "csv");
        assert_eq!(effective_format("default", f("a.pac"), true), "pac");
        assert_eq!(effective_format("default", f("a.txt"), true), "default");
        // The extension only infers when the format is still `default`.
        assert_eq!(effective_format("json", f("a.txt"), true), "json");
    }

    #[test]
    fn geo_update_subcommand_is_accepted() {
        let cli = Cli::parse_from(["flx", "geo-update"]);
        assert!(matches!(cli.command, Some(Command::GeoUpdate)));
        // a bare invocation carries no command
        let bare = Cli::parse_from(["flx"]);
        assert!(bare.command.is_none());
    }

    #[test]
    fn cli_rejects_zero_max_attempts() {
        let result = Cli::try_parse_from(["flx", "find", "SOCKS5", "--max-attempts", "0"]);
        assert!(result.is_err());
    }

    fn parse_json_lines(content: &str) -> Vec<serde_json::Value> {
        content
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn run_json_lines(proxies: &[Proxy], limit: usize) -> String {
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        let (options, path) = output_options("json-lines", limit);
        rt.block_on(async {
            let s = stream::iter(proxies.to_vec());
            process_result(
                s,
                options,
                Arc::new(tokio::sync::Notify::new()),
                &NoopGuard,
                FinalizeOpts::default(),
            )
            .await
            .unwrap();
        });
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        content
    }

    fn run_csv(proxies: &[Proxy], limit: usize) -> String {
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        let (options, path) = output_options("csv", limit);
        rt.block_on(async {
            let s = stream::iter(proxies.to_vec());
            process_result(
                s,
                options,
                Arc::new(tokio::sync::Notify::new()),
                &NoopGuard,
                FinalizeOpts::default(),
            )
            .await
            .unwrap();
        });
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        content
    }

    fn run_json(proxies: &[Proxy], limit: usize) -> String {
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        let (options, path) = output_options("json", limit);
        rt.block_on(async {
            let s = stream::iter(proxies.to_vec());
            // Tests never cancel: use a notify that never fires.
            process_result(
                s,
                options,
                Arc::new(tokio::sync::Notify::new()),
                &NoopGuard,
                FinalizeOpts::default(),
            )
            .await
            .unwrap();
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
    fn json_empty_is_suppressed_when_requested() {
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        let (options, path) = output_options("json", 0);
        rt.block_on(async {
            let s = stream::iter(Vec::<Proxy>::new());
            process_result(
                s,
                options,
                Arc::new(tokio::sync::Notify::new()),
                &NoopGuard,
                FinalizeOpts {
                    suppress_empty_json: true,
                    emit_csv_header: true,
                },
            )
            .await
            .unwrap();
        });
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        // The empty document is left to a later pass, so nothing is written.
        assert_eq!(content, "");
    }

    #[test]
    fn tee_recorder_forwards_and_records_candidates() {
        let proxies: Vec<Proxy> = (1u16..=3)
            .map(|port| Proxy::new(std::net::Ipv4Addr::LOCALHOST, port))
            .collect();
        let recordings: Arc<std::sync::Mutex<Vec<Proxy>>> = Arc::default();
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        let forwarded = rt.block_on(async {
            let s = tee_recorder(stream::iter(proxies.clone()), Arc::clone(&recordings));
            s.collect::<Vec<_>>().await
        });
        let recorded = recordings.lock().unwrap();
        assert_eq!(forwarded.len(), 3);
        assert_eq!(recorded.len(), 3);
        assert_eq!(forwarded[0].ip, proxies[0].ip);
        assert_eq!(forwarded[1].port, proxies[1].port);
        assert_eq!(recorded[2].port, proxies[2].port);
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
    fn json_one_entry_per_line_with_trailing_commas() {
        // Regression: entries used to leave a blank line and put the comma on
        // its own removed line. Each proxy must sit on its own line with the
        // comma at the end of the previous line and `]` alone on the last.
        let proxies = [sample_proxy(1), sample_proxy(2), sample_proxy(3)];
        let out = run_json(&proxies, 0);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 5, "expected [ + entry + entry + entry + ]");
        assert_eq!(lines[0], "[", "array must open on its own line");
        assert_eq!(lines[4], "]", "array must close on its own line");
        for body in &lines[1..4] {
            assert!(body.starts_with("  {"), "entries must be indented");
        }
        assert!(lines[1].ends_with(','));
        assert!(lines[2].ends_with(','));
        assert!(!lines[3].ends_with(','), "no comma on the last entry");
        assert!(!out.contains("\n\n"), "no blank lines between entries");
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

    #[test]
    fn quiet_flag_is_accepted() {
        let cli = Cli::parse_from(["flx", "--quiet"]);
        assert!(cli.quiet);
        assert!(!Cli::parse_from(["flx"]).quiet);
    }

    #[test]
    fn no_color_flag_is_accepted() {
        let cli = Cli::parse_from(["flx", "--no-color"]);
        assert!(cli.no_color);
        assert!(!Cli::parse_from(["flx"]).no_color);
    }

    #[test]
    fn quiet_with_json_format_is_valid() {
        let cli = Cli::parse_from(["flx", "--quiet", "grab", "--format", "json"]);
        assert!(cli.quiet);
        match cli.command {
            Some(Command::Grab(grab)) => assert_eq!(grab.output.format, "json"),
            _ => panic!("expected grab subcommand"),
        }
    }

    #[test]
    fn json_lines_empty_yields_nothing() {
        let out = run_json_lines(&[], 0);
        assert_eq!(out, "", "empty source must produce empty output");
    }

    #[test]
    fn json_lines_one_proxy_produces_one_line() {
        let out = run_json_lines(&[sample_proxy(1)], 0);
        let parsed = parse_json_lines(&out);
        assert_eq!(parsed.len(), 1);
        // No array brackets, no trailing comma
        assert!(!out.contains('['));
        assert!(!out.contains(']'));
    }

    #[test]
    fn json_lines_multiple_proxies_produce_one_per_line() {
        let proxies = [sample_proxy(1), sample_proxy(2), sample_proxy(3)];
        let out = run_json_lines(&proxies, 0);
        let parsed = parse_json_lines(&out);
        assert_eq!(parsed.len(), 3);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            assert!(serde_json::from_str::<serde_json::Value>(line).is_ok());
        }
    }

    #[test]
    fn json_lines_limit_truncates() {
        let proxies = [sample_proxy(1), sample_proxy(2), sample_proxy(3)];
        let out = run_json_lines(&proxies, 2);
        let parsed = parse_json_lines(&out);
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn csv_empty_yields_header_only() {
        let out = run_csv(&[], 0);
        assert_eq!(out, "ip,port,type,response_time,country,ip_type\n");
    }

    #[test]
    fn csv_one_proxy_produces_header_and_one_row() {
        let out = run_csv(&[sample_proxy(1)], 0);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "ip,port,type,response_time,country,ip_type");
        assert!(lines[1].starts_with("192.168.0.1,8081,"));
        assert!(lines[1].ends_with(",unknown"));
    }

    #[test]
    fn csv_multiple_proxies_produce_one_row_each() {
        let proxies = [sample_proxy(1), sample_proxy(2), sample_proxy(3)];
        let out = run_csv(&proxies, 0);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4, "header + 3 rows");
        assert_eq!(lines[0], "ip,port,type,response_time,country,ip_type");
        assert!(lines[1].contains("192.168.0.1"));
        assert!(lines[2].contains("192.168.0.2"));
        assert!(lines[3].contains("192.168.0.3"));
    }

    #[test]
    fn csv_limit_truncates_rows() {
        let proxies = [sample_proxy(1), sample_proxy(2), sample_proxy(3)];
        let out = run_csv(&proxies, 2);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "header + 2 rows");
    }

    fn validated_proxy(ip: u8, anonymity: &str, response_time: f64) -> Proxy {
        use flx::proxy::models::ProxyType;
        let mut proxy = Proxy::new(std::net::Ipv4Addr::new(10, 0, 0, ip), 8080 + u16::from(ip));
        proxy
            .proxy_types
            .push(ProxyType::checked(anonymity.parse::<Protocol>().unwrap()));
        proxy.runtimes.record(response_time);
        proxy
    }

    fn run_filtered(
        proxies: &[Proxy],
        min_anonymity: Option<&str>,
        min_response_time: Option<f64>,
        max_response_time: Option<f64>,
    ) -> Vec<serde_json::Value> {
        let (options, path) = output_options("json-lines", 0);
        let options = OutputOptions {
            min_anonymity: min_anonymity.map(str::to_owned),
            min_response_time,
            max_response_time,
            ..options
        };
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let s = stream::iter(proxies.to_vec());
            process_result(
                s,
                options,
                Arc::new(tokio::sync::Notify::new()),
                &NoopGuard,
                FinalizeOpts::default(),
            )
            .await
            .unwrap();
        });
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        parse_json_lines(&content)
    }

    #[test]
    fn process_result_filters_by_min_anonymity() {
        let proxies = [
            validated_proxy(1, "HTTP:Transparent", 0.2),
            validated_proxy(2, "HTTP:Anonymous", 0.2),
            validated_proxy(3, "HTTP:Elite", 0.2),
        ];
        let kept = run_filtered(&proxies, Some("anonymous"), None, None);
        assert_eq!(kept.len(), 2);
        assert!(kept[0]["ip"].as_str().unwrap().ends_with(".2"));
        assert!(kept[1]["ip"].as_str().unwrap().ends_with(".3"));
    }

    #[test]
    fn process_result_filters_by_response_time_bounds() {
        let proxies = [
            validated_proxy(1, "HTTP:Anonymous", 0.1),
            validated_proxy(2, "HTTP:Anonymous", 2.0),
            validated_proxy(3, "HTTP:Anonymous", 0.7),
        ];
        let kept = run_filtered(&proxies, None, Some(0.5), Some(1.0));
        assert_eq!(kept.len(), 1);
        assert!(kept[0]["ip"].as_str().unwrap().ends_with(".3"));
    }

    #[test]
    fn process_result_filters_with_all_bounds_combined() {
        let proxies = [
            validated_proxy(1, "HTTP:Transparent", 0.3),
            validated_proxy(2, "HTTP:Anonymous", 0.9),
            validated_proxy(3, "HTTP:Elite", 1.5),
        ];
        let kept = run_filtered(&proxies, Some("anonymous"), Some(0.5), Some(1.0));
        assert_eq!(kept.len(), 1);
        assert!(kept[0]["ip"].as_str().unwrap().ends_with(".2"));
    }

    #[test]
    fn process_result_default_keeps_socks_and_conntype_anonymity_free_proxies() {
        use flx::proxy::models::ProxyType;
        let mut proxy = Proxy::new(std::net::Ipv4Addr::new(10, 0, 0, 9), 1080);
        proxy.proxy_types.push(ProxyType::checked(Protocol::Socks5));
        proxy.runtimes.record(0.4);

        let kept = run_filtered(&[proxy], Some("elite"), None, None);
        assert_eq!(kept.len(), 1, "types without anonymity pass any threshold");
    }

    fn run_sorted(proxies: &[Proxy], sort: &str, order: &str) -> Vec<serde_json::Value> {
        let (options, path) = output_options("json-lines", 0);
        let options = OutputOptions {
            sort: Some(sort.to_owned()),
            order: order.to_owned(),
            ..options
        };
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let s = stream::iter(proxies.to_vec());
            process_result(
                s,
                options,
                Arc::new(tokio::sync::Notify::new()),
                &NoopGuard,
                FinalizeOpts::default(),
            )
            .await
            .unwrap();
        });
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        parse_json_lines(&content)
    }

    fn proxy_country(ip: u8, country: &str) -> Proxy {
        let mut proxy = Proxy::new(std::net::Ipv4Addr::new(10, 1, 0, ip), 8080);
        proxy.geo = Arc::new(flx::GeoData {
            iso_code: Some(country.to_owned().into()),
            ..flx::GeoData::default()
        });
        proxy
    }

    #[test]
    fn process_result_sorts_by_response_time() {
        let proxies = [
            validated_proxy(1, "HTTP:Anonymous", 0.9),
            validated_proxy(2, "HTTP:Anonymous", 0.1),
            validated_proxy(3, "HTTP:Anonymous", 0.5),
        ];
        let asc = run_sorted(&proxies, "avg-response", "asc");
        assert!(asc[0]["average_response_time"].as_f64().unwrap() < 0.5);
        assert!(asc[2]["average_response_time"].as_f64().unwrap() > 0.5);

        let desc = run_sorted(&proxies, "avg-response", "desc");
        assert!(desc[0]["average_response_time"].as_f64().unwrap() > 0.5);
        assert!(desc[2]["average_response_time"].as_f64().unwrap() < 0.5);
    }

    #[test]
    fn process_result_sorts_by_anonymity_rank() {
        let proxies = [
            validated_proxy(1, "HTTP:Anonymous", 0.2),
            validated_proxy(2, "HTTP:Transparent", 0.2),
            validated_proxy(3, "HTTP:Elite", 0.2),
        ];
        let asc = run_sorted(&proxies, "anonymity", "asc");
        assert!(asc[0]["type"]["protocol"]["Http"].as_str().unwrap() == "Transparent");
        assert!(asc[2]["type"]["protocol"]["Http"].as_str().unwrap() == "Elite");
    }

    #[test]
    fn process_result_sorts_by_country() {
        let proxies = [
            proxy_country(1, "US"),
            proxy_country(2, "ID"),
            proxy_country(3, "DE"),
        ];
        let asc = run_sorted(&proxies, "country", "asc");
        assert!(asc[0]["geo"]["iso_code"].as_str().unwrap() == "DE");
        assert!(asc[2]["geo"]["iso_code"].as_str().unwrap() == "US");

        let desc = run_sorted(&proxies, "country", "desc");
        assert!(
            asc[0]["geo"]["iso_code"].as_str().unwrap()
                != desc[0]["geo"]["iso_code"].as_str().unwrap()
        );
    }

    #[test]
    fn sort_and_order_flags_are_accepted() {
        let args = find_from(&["--sort", "country", "--order", "desc"]);
        assert_eq!(args.output.sort.as_deref(), Some("country"));
        assert_eq!(args.output.order, "desc");
        assert!(Cli::try_parse_from(["flx", "find", "--sort", "bogus"]).is_err());
        assert!(Cli::try_parse_from(["flx", "find", "--order", "sideways"]).is_err());
    }

    #[test]
    fn format_judge_health_renders_compact_summary() {
        let report = flx::JudgeHealthReport {
            candidates: 4,
            healthy: 1,
            failed: vec![
                ("http://a".to_owned(), "timeout".to_owned()),
                ("http://b".to_owned(), "timeout".to_owned()),
            ],
        };
        assert_eq!(
            format_judge_health(&report),
            "1/4 judges healthy; 2 failed (timeout)"
        );
    }

    #[test]
    fn no_color_with_json_format_is_valid() {
        let cli = Cli::parse_from(["flx", "--no-color", "grab", "--format", "json"]);
        assert!(cli.no_color);
        match cli.command {
            Some(Command::Grab(grab)) => assert_eq!(grab.output.format, "json"),
            _ => panic!("expected grab subcommand"),
        }
    }

    fn run_proxychains(proxies: &[Proxy], limit: usize) -> String {
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        let (options, path) = output_options("proxychains", limit);
        rt.block_on(async {
            let s = stream::iter(proxies.to_vec());
            process_result(
                s,
                options,
                Arc::new(tokio::sync::Notify::new()),
                &NoopGuard,
                FinalizeOpts::default(),
            )
            .await
            .unwrap();
        });
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        content
    }

    fn run_prefix(proxies: &[Proxy], limit: usize) -> String {
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        let (options, path) = output_options("prefix", limit);
        rt.block_on(async {
            let s = stream::iter(proxies.to_vec());
            process_result(
                s,
                options,
                Arc::new(tokio::sync::Notify::new()),
                &NoopGuard,
                FinalizeOpts::default(),
            )
            .await
            .unwrap();
        });
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        content
    }

    fn run_pac(proxies: &[Proxy], limit: usize) -> String {
        let rt = runtime::Builder::new_current_thread().build().unwrap();
        let (options, path) = output_options("pac", limit);
        rt.block_on(async {
            let s = stream::iter(proxies.to_vec());
            process_result(
                s,
                options,
                Arc::new(tokio::sync::Notify::new()),
                &NoopGuard,
                FinalizeOpts::default(),
            )
            .await
            .unwrap();
        });
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        content
    }

    #[test]
    fn proxychains_renders_type_ip_port() {
        let mut proxy = sample_proxy(1);
        proxy
            .proxy_types
            .push(flx::proxy::models::ProxyType::checked(Protocol::Socks5));
        let out = run_proxychains(&[proxy], 0);
        assert_eq!(out, "socks5 192.168.0.1 8081\n");
    }

    #[test]
    fn proxychains_falls_back_to_http_for_http_proxy() {
        let mut proxy = sample_proxy(2);
        proxy
            .proxy_types
            .push(flx::proxy::models::ProxyType::checked(Protocol::Http(
                Anonymity::Anonymous,
            )));
        let out = run_proxychains(&[proxy], 0);
        assert_eq!(out, "http 192.168.0.2 8082\n");
    }

    #[test]
    fn prefix_renders_socks5_url() {
        let proxy = sample_proxy(3);
        let out = run_prefix(&[proxy], 0);
        assert_eq!(out, "socks5://192.168.0.3:8083\n");
    }

    #[test]
    fn prefix_multiple_proxies() {
        let proxies: Vec<_> = (1..=3).map(sample_proxy).collect();
        let out = run_prefix(&proxies, 0);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "socks5://192.168.0.1:8081");
        assert_eq!(lines[1], "socks5://192.168.0.2:8082");
        assert_eq!(lines[2], "socks5://192.168.0.3:8083");
    }

    #[test]
    fn pac_empty_yields_direct_only() {
        let out = run_pac(&[], 0);
        assert!(out.contains("FindProxyForURL"));
        assert!(out.contains("DIRECT"));
        assert!(!out.contains("PROXY"));
    }

    #[test]
    fn pac_renders_proxy_directives() {
        let mut proxy = sample_proxy(1);
        proxy
            .proxy_types
            .push(flx::proxy::models::ProxyType::checked(Protocol::Http(
                Anonymity::Anonymous,
            )));
        let out = run_pac(&[proxy], 0);
        assert!(out.contains("PROXY 192.168.0.1:8081"));
        assert!(out.contains("DIRECT"));
    }

    #[test]
    fn pac_respects_limit() {
        let proxies: Vec<_> = (1..=5).map(sample_proxy).collect();
        let out = run_pac(&proxies, 3);
        assert_eq!(out.matches("PROXY").count(), 3);
    }
}
