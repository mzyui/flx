use anyhow::Context;
use argument::{Cli, Command, FetchArgs, FetcherArgs, FindArgs, OutputOptions, ValidatorArgs};
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
use std::future::Future;
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
            #[cfg(not(feature = "log"))]
            eprintln!("Error: {e:?}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn report_invalid_type_value(value: &str) {
    let mut error = clap::Error::new(ErrorKind::ValueValidation).with_cmd(&Cli::command());
    error.insert(
        ContextKind::InvalidArg,
        ContextValue::String("TYPES".to_owned()),
    );
    error.insert(
        ContextKind::InvalidValue,
        ContextValue::String(value.to_string()),
    );
    let _ = error.print();
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

fn effective_format(format: &str, has_output_file: bool, stdout_is_tty: bool) -> &str {
    if format == "default" && !has_output_file && !stdout_is_tty {
        "json-lines"
    } else {
        format
    }
}

async fn process_result<S, C>(
    source: S,
    options: OutputOptions,
    cancel: C,
    guard: &dyn OutputGuard,
) -> anyhow::Result<RunOutcome>
where
    S: Stream<Item = Proxy>,
    C: Future<Output = ()>,
{
    let format = effective_format(
        &options.format,
        options.output_file.is_some(),
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
    let mut source = std::pin::pin!(source.enumerate());

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
    let mut cancel = std::pin::pin!(cancel);

    // Collects the write error, if any, so the document can still be closed
    // before the error is reported to the caller.
    let mut write_error: Option<anyhow::Error> = None;

    // Emit the CSV header once before the stream starts so the output is
    // always valid even when the stream is empty.
    if _csv {
        buf.extend_from_slice(b"ip,port,type,response_time,country\n");
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
            _ = &mut cancel => {
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
            write_error = finalize_json_output(&mut output_file, &mut stdout, found_proxy)
                .await
                .err();
        } else {
            let _ = finalize_json_output(&mut output_file, &mut stdout, found_proxy).await;
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
) -> anyhow::Result<()> {
    let close = if found_proxy { "\n]\n" } else { "[]\n" };
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

fn fetcher_config(options: &FetcherArgs) -> fluxy::fetcher::Config {
    fluxy::fetcher::Config {
        concurrency_limit: options.fetch_concurrency as usize,
        enable_geo_lookup: options.with_geo || !options.countries.is_empty(),
        countries: Arc::from(options.countries.as_slice()),
        cache_ttl: (options.cache_ttl > 0)
            .then(|| std::time::Duration::from_secs(options.cache_ttl.saturating_mul(60))),
        refresh_cache: options.refresh_cache,
        enforce_unique_ip: !options.no_dedup,
        ..Default::default()
    }
}

fn list_sources() {
    for provider in fluxy::all_providers() {
        let tier = match provider.tier() {
            fluxy::ProviderTier::Primary => "primary",
            fluxy::ProviderTier::Fallback => "fallback",
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

    if let Some(shell) = cli.generate_completions {
        clap_complete::generate(shell, &mut Cli::command(), "flx", &mut std::io::stdout());
        return Ok(RunOutcome::Finished);
    }

    if cli.generate_man_page {
        clap_mangen::Man::new(Cli::command()).render(&mut std::io::stdout())?;
        return Ok(RunOutcome::Finished);
    }

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
        use std::io::IsTerminal as _;
        use std::io::Write as _;
        let help = Cli::command().render_help();
        let mut stderr = std::io::stderr().lock();
        if cli.no_color || !stderr.is_terminal() {
            writeln!(stderr, "{help}")?;
        } else {
            writeln!(stderr, "{}", help.ansi())?;
        }
        return Ok(RunOutcome::NoCommand);
    };

    let runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    // Ctrl+C (SIGINT): resolved inside `process_result`, which finalizes a
    // valid JSON document before the process exits. The runtime is built
    // with `enable_all()` above, so the tokio signal driver is available
    // here.
    let cancel = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    let outcome = runtime.block_on(async move {
        match command {
            Command::Grab(grab) => run_grab(grab, cli.quiet, cancel).await,
            Command::Find(find) => run_find(find, cli.quiet, cli.no_color, cancel).await,
            Command::GeoUpdate => run_geo_update().await,
        }
    });
    runtime.shutdown_background();
    outcome
}

async fn run_grab<C>(grab: FetchArgs, quiet: bool, cancel: C) -> anyhow::Result<RunOutcome>
where
    C: Future<Output = ()>,
{
    if grab.fetcher.dry_run {
        list_sources();
        return Ok(RunOutcome::Finished);
    }
    let source = ProxySource::from_fetcher(fetcher_config(&grab.fetcher))
        .await
        .context("failed to start proxy fetcher")?;
    let accepted = source.accepted_handle();
    let started = std::time::Instant::now();
    let outcome = process_result(source, grab.output, cancel, &NoopGuard).await;
    if !quiet {
        eprintln!(
            "Gathered {} proxies in {:.2}s",
            accepted.load(std::sync::atomic::Ordering::Relaxed),
            started.elapsed().as_secs_f64(),
        );
    }
    outcome
}

async fn run_find<C>(
    find: FindArgs,
    quiet: bool,
    no_color: bool,
    cancel: C,
) -> anyhow::Result<RunOutcome>
where
    C: Future<Output = ()>,
{
    if find.fetcher.dry_run {
        list_sources();
        return Ok(RunOutcome::Finished);
    }

    let (mut protocols, groups) = split_type_groups(&find.validator.types);
    if protocols.is_empty() && groups.is_empty() {
        // Omitted `TYPES` defaults to plain HTTP validation.
        protocols.push(Protocol::Http(Anonymity::Unknown));
    }

    let source: BoxStream = match &find.file {
        Some(file) => Box::pin(file_source(file).await?),
        None => Box::pin(
            ProxySource::from_fetcher(fetcher_config(&find.fetcher))
                .await
                .context("failed to start proxy fetcher")?,
        ),
    };

    let validated_proxies =
        ProxyValidator::validate(source, validator_config(&find.validator, protocols, groups))
            .await
            .context("failed to start proxy validator")?;
    let progress = validated_proxies.progress();
    let started = std::time::Instant::now();

    // The status line (stderr) repaints on a background thread and erases
    // itself on drop. It also hides around each stdout write so streamed
    // results never overwrite the line it is drawn on.
    #[cfg(feature = "progress_bar")]
    let guard: OutputGuardEither<progress::ValidationBar> =
        match progress::ValidationBar::new(progress.clone(), quiet, no_color) {
            Some(bar) => OutputGuardEither::Bar(bar),
            None => OutputGuardEither::Noop(NoopGuard),
        };
    #[cfg(not(feature = "progress_bar"))]
    let guard = NoopGuard;
    #[cfg(not(feature = "progress_bar"))]
    let _ = no_color;
    let outcome = process_result(validated_proxies, find.output, cancel, &guard).await;
    if !quiet {
        let passed = progress.passed();
        let failed = progress.done().saturating_sub(passed);
        eprintln!(
            "{passed} ok, {failed} failed, {} checked in {:.2}s",
            progress.total(),
            started.elapsed().as_secs_f64(),
        );
    }
    outcome
}

async fn run_geo_update() -> anyhow::Result<RunOutcome> {
    match fluxy::sync_database()
        .await
        .context("failed to sync the GeoLite2 database")?
    {
        fluxy::SyncOutcome::Synced => {
            println!("GeoLite2 database synced from the P3TERX mirror");
        }
        fluxy::SyncOutcome::UpToDate => {
            println!("GeoLite2 database is up to date");
        }
    }
    Ok(RunOutcome::Finished)
}

fn validator_config(
    options: &ValidatorArgs,
    protocols: Vec<Protocol>,
    groups: Vec<Vec<Protocol>>,
) -> fluxy::validator::Config {
    fluxy::validator::Config {
        types: protocols,
        groups,
        concurrency_limit: options.max_connections as usize,
        max_attempts: options.max_attempts,
        request_timeout: options.timeout,
        http_judge_urls: options.http_judge_urls.clone(),
        https_judge_urls: options.https_judge_urls.clone(),
        insecure: options.insecure,
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
    use fluxy::proxy::models::Anonymity;
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
        assert!(!fetcher_config(&default.fetcher).refresh_cache);
    }

    #[test]
    fn no_dedup_flag_disables_uniqueness() {
        let disabled = fetch_from(&["--no-dedup"]);
        assert!(!fetcher_config(&disabled.fetcher).enforce_unique_ip);

        let default = fetch_from(&[]);
        assert!(fetcher_config(&default.fetcher).enforce_unique_ip);
    }

    #[test]
    fn dry_run_flag_is_accepted() {
        assert!(fetch_from(&["--dry-run"]).fetcher.dry_run);
        assert!(!fetch_from(&[]).fetcher.dry_run);
    }

    #[test]
    fn generate_completions_flag_is_accepted() {
        let cli = Cli::parse_from(["flx", "--generate-completions", "bash"]);
        assert_eq!(cli.generate_completions, Some(clap_complete::Shell::Bash));
        assert!(Cli::parse_from(["flx", "--generate-man-page"]).generate_man_page);
    }

    #[test]
    fn generate_completions_produces_script() {
        let mut out = Vec::new();
        clap_complete::generate(
            clap_complete::Shell::Bash,
            &mut Cli::command(),
            "flx",
            &mut out,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("flx"));
    }

    #[test]
    fn generate_man_page_produces_text() {
        let mut out = Vec::new();
        clap_mangen::Man::new(Cli::command())
            .render(&mut out)
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("flx"));
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
    fn https_judge_urls_flag_parses_without_duplicate_attr() {
        // The `#[arg]` for `--https-judge-urls` was
        // declared twice; ensure the flag still accepts a custom value and
        // lands in the right field.
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
            "fluxy_json_test_{}_{}.json",
            std::process::id(),
            uuidish()
        ));
        (
            OutputOptions {
                format: format.to_owned(),
                limit,
                output_file: Some(out.clone()),
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
        assert_eq!(effective_format("default", false, true), "default");
        assert_eq!(effective_format("default", false, false), "json-lines");
        // Redirected to a file keeps "default" untouched.
        assert_eq!(effective_format("default", true, false), "default");
        // Explicit formats are never overridden.
        assert_eq!(effective_format("json", false, false), "json");
        assert_eq!(effective_format("pretty-json", false, false), "pretty-json");
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
            let s = stream::iter(proxies.iter().cloned());
            process_result(s, options, std::future::pending::<()>(), &NoopGuard)
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
            let s = stream::iter(proxies.iter().cloned());
            process_result(s, options, std::future::pending::<()>(), &NoopGuard)
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
            let s = stream::iter(proxies.iter().cloned());
            // Tests never cancel: use a future that stays pending.
            process_result(s, options, std::future::pending::<()>(), &NoopGuard)
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
        assert_eq!(out, "ip,port,type,response_time,country\n");
    }

    #[test]
    fn csv_one_proxy_produces_header_and_one_row() {
        let out = run_csv(&[sample_proxy(1)], 0);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "ip,port,type,response_time,country");
        assert!(lines[1].starts_with("192.168.0.1,8081,"));
    }

    #[test]
    fn csv_multiple_proxies_produce_one_row_each() {
        let proxies = [sample_proxy(1), sample_proxy(2), sample_proxy(3)];
        let out = run_csv(&proxies, 0);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4, "header + 3 rows");
        assert_eq!(lines[0], "ip,port,type,response_time,country");
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

    #[test]
    fn no_color_with_json_format_is_valid() {
        let cli = Cli::parse_from(["flx", "--no-color", "grab", "--format", "json"]);
        assert!(cli.no_color);
        match cli.command {
            Some(Command::Grab(grab)) => assert_eq!(grab.output.format, "json"),
            _ => panic!("expected grab subcommand"),
        }
    }
}
