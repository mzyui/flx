use anyhow::Context;
use argument::Cli;
use argument::{Command, FetchArgs, FetcherArgs, FindArgs, ValidatorArgs};
use clap::Parser;
#[cfg(feature = "progress_bar")]
use colored::Colorize;
#[cfg(feature = "log")]
use flx::initialize_logging;
use flx::{
    proxy::models::{Anonymity, Protocol, Proxy},
    FetchStage, IpType, ProxySource, ProxyValidator,
};
use futures_util::{Stream, StreamExt};
use std::io::Write as _;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::runtime;

mod argument;
mod filters;
mod guard;
mod output;
#[cfg(feature = "progress_bar")]
mod progress;
mod version;

#[cfg(test)]
mod tests;

pub(crate) use guard::*;
pub(crate) use output::*;
pub(crate) use version::*;

/// Formats the end-of-run stats line for `find`, colored under the
/// `progress_bar` feature and plain otherwise.
#[cfg(feature = "progress_bar")]
fn format_validation_stats(stats: &ValidationStats, rate: f64, dst: Option<&str>) -> String {
    let v = format!("{} valid", stats.passed).green();
    let f = format!("{} failed", stats.done.saturating_sub(stats.passed)).red();
    let suffix = dst.map(|d| format!(" → {d}")).unwrap_or_default();
    let lead = if dst.is_some() { "" } else { "\n" };
    format!(
        "{lead}{v} · {f} · {} total in {:?} ({rate:.1}/s){suffix}",
        stats.total, stats.elapsed
    )
}

#[cfg(not(feature = "progress_bar"))]
fn format_validation_stats(stats: &ValidationStats, rate: f64, dst: Option<&str>) -> String {
    let suffix = dst.map(|d| format!(" → {d}")).unwrap_or_default();
    let lead = if dst.is_some() { "" } else { "\n" };
    format!(
        "{lead}{} valid · {} failed · {} total in {:?} ({rate:.1}/s){suffix}",
        stats.passed,
        stats.done.saturating_sub(stats.passed),
        stats.total,
        stats.elapsed
    )
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
    use std::sync::Mutex;

    // Saved by `install` so a forced exit (which skips destructors) can
    // still hand back the original terminal settings.
    static ORIGINAL: Mutex<Option<(libc::c_int, libc::termios)>> = Mutex::new(None);

    /// Restores the saved settings at most once; harmless to call again.
    pub fn restore() {
        if let Some((fd, original)) = ORIGINAL.lock().unwrap_or_else(|e| e.into_inner()).take() {
            unsafe {
                libc::tcsetattr(fd, libc::TCSANOW, &original);
            }
        }
    }

    pub struct QuietSignalEcho;

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

            *ORIGINAL.lock().unwrap_or_else(|e| e.into_inner()) = Some((fd, original));

            Some(Self)
        }
    }

    impl Drop for QuietSignalEcho {
        fn drop(&mut self) {
            restore();
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

    pub fn restore() {}
}

use quiet_signal_echo::QuietSignalEcho;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunOutcome {
    Finished,
    Cancelled,
    NoCommand,
}

// Conventional shell status for a process killed by SIGINT (128 + 2).
const SIGINT_EXIT_CODE: u8 = 130;
// The first Ctrl+C shuts down gracefully (finalizing output documents); a
// second press force-quits so flx can always be stopped, even from a phase
// that never reaches a cancellation checkpoint.
const FORCE_EXIT_AFTER_PRESSES: usize = 2;

fn should_force_exit(press_count: usize) -> bool {
    press_count >= FORCE_EXIT_AFTER_PRESSES
}

// A forced exit skips every destructor, so the state they would hand back —
// buffered output, a hidden cursor, the saved termios — is restored here.
fn restore_terminal_and_exit() -> ! {
    let _ = std::io::stdout().lock().flush();
    #[cfg(feature = "progress_bar")]
    progress::force_show_cursor();
    let _ = std::io::stderr().lock().flush();
    quiet_signal_echo::restore();
    std::process::exit(i32::from(SIGINT_EXIT_CODE))
}

fn main() -> std::process::ExitCode {
    // Restore the terminal settings before the process leaves, on every path.
    let _quiet = QuietSignalEcho::install();
    match run_application() {
        Ok(RunOutcome::Finished) => std::process::ExitCode::SUCCESS,
        Ok(RunOutcome::Cancelled) => std::process::ExitCode::from(SIGINT_EXIT_CODE),
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
            || !options.exclude_country.is_empty()
            || options.with_ip_type
            || options.ip_type.is_some(),
        enable_ip_type: options.with_ip_type || options.ip_type.is_some(),
        ip_type_filter: ip_type,
        countries: Arc::from(options.countries.as_slice()),
        excluded_countries: Arc::from(options.exclude_country.as_slice()),
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
        provider_timeout: (options.provider_timeout > 0)
            .then(|| std::time::Duration::from_secs(options.provider_timeout)),
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

async fn file_source(paths: &[std::path::PathBuf]) -> anyhow::Result<BoxStream> {
    let proxies = flx::load_proxy_files(paths.to_owned()).await?;
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
    // One download observer for the whole process: the warmup bar (and the
    // `geo-update` bar) renders GeoLite2 download progress from this stream.
    let download = flx::install_download_observer().expect("download observer installs once");

    let outcome = runtime.block_on(async move {
        if !cli.skip_version_check && !cli.quiet {
            let current = env!("CARGO_PKG_VERSION").to_owned();
            tokio::spawn(async move {
                match fetch_latest_version().await {
                    Ok(latest) if check_version(&current, &latest) => {
                        eprintln!(
                            "A new flx version is available: {latest} (you are on {current})."
                        );
                    }
                    _ => {}
                }
            });
        }
        let notify = Arc::clone(&cancel);
        // Re-arm on every SIGINT: the first press hands a permit to the
        // graceful path (`notify_one` stores one even with no waiter yet,
        // so a press during the warmup phases is not lost before
        // `process_result` polls it); further presses force-quit so the
        // process is always stoppable.
        let presses = Arc::new(AtomicUsize::new(0));
        tokio::spawn(async move {
            loop {
                if tokio::signal::ctrl_c().await.is_err() {
                    return;
                }
                notify.notify_one();
                if should_force_exit(presses.fetch_add(1, Ordering::Relaxed) + 1) {
                    restore_terminal_and_exit();
                }
            }
        });
        match command {
            Command::Grab(grab) => run_grab(grab, cli.quiet, cli.no_color, &download, cancel).await,
            Command::Find(find) => run_find(find, cli.quiet, cli.no_color, &download, cancel).await,
            Command::GeoUpdate => run_geo_update(&download, cli.quiet, cli.no_color, cancel).await,
        }
    });
    runtime.shutdown_background();
    outcome
}

async fn run_grab(
    grab: FetchArgs,
    quiet: bool,
    no_color: bool,
    download: &tokio::sync::watch::Receiver<Option<flx::DownloadProgress>>,
    cancel: Arc<tokio::sync::Notify>,
) -> anyhow::Result<RunOutcome> {
    if grab.fetcher.dry_run || grab.fetcher.list_providers {
        list_sources();
        return Ok(RunOutcome::Finished);
    }
    let fetch_cfg = fetcher_config(&grab.fetcher);
    // The grab bar clashes with the proxies streamed to stdout, so only show it
    // when output is redirected (a file via `-o` or a piped stdout).
    let show_bar = !quiet && (grab.output.output_file.is_some() || stdout_is_pipe());
    let (gather_tx, gather_rx) = tokio::sync::watch::channel(0usize);
    let warmup = if show_bar {
        make_warmup(quiet, no_color, download, show_bar, Some(gather_rx))
    } else {
        None
    };
    if let Some(bar) = &warmup {
        let phase = if fetch_cfg.enable_geo_lookup {
            "Preparing GeoLite2 database …"
        } else {
            "Fetching proxy lists …"
        };
        bar.set_phase(phase);
    }
    let mut fetcher = tokio::select! {
        fetcher = ProxySource::from_fetcher(fetch_cfg) => {
            fetcher.context("failed to start proxy fetcher")?
        }
        _ = cancel.notified() => {
            drop(warmup);
            return Ok(RunOutcome::Cancelled);
        }
    };
    let accepted = fetcher.accepted_handle();
    let stages = fetcher.stage_events();
    if let Some(bar) = &warmup {
        bar.set_phase("Fetching proxy lists …");
    }
    // Repaint the bar on a fixed cadence so the gathered count stays live even
    // while the source stream is quiet.
    let ticker = warmup.as_ref().map(|bar| {
        let bar = Arc::clone(bar);
        let accepted = Arc::clone(&accepted);
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
        tokio::spawn(async move {
            loop {
                interval.tick().await;
                let _ = gather_tx.send_replace(accepted.load(std::sync::atomic::Ordering::Relaxed));
                bar.refresh();
            }
        })
    });
    let watcher = match (&warmup, stages) {
        (Some(bar), Some(mut rx)) => {
            let bar = Arc::clone(bar);
            Some(tokio::spawn(async move {
                while let Some(stage) = rx.recv().await {
                    let phase = match stage {
                        FetchStage::Primary => "Fetching primary sources …",
                        FetchStage::Fallback => "Fetching fallback sources …",
                        FetchStage::Done => "Done gathering",
                    };
                    bar.set_phase(phase);
                    if matches!(stage, FetchStage::Done) {
                        break;
                    }
                }
            }))
        }
        _ => None,
    };
    let started = std::time::Instant::now();
    let dst: Option<String> = grab
        .output
        .output_file
        .as_deref()
        .map(|p| p.to_string_lossy().into_owned());
    let guard: &dyn OutputGuard = match &warmup {
        Some(bar) => &**bar,
        None => &NoopGuard,
    };
    let outcome =
        process_result(fetcher, grab.output, cancel, guard, FinalizeOpts::default()).await;
    if let Some(task) = watcher {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = ticker {
        task.abort();
        let _ = task.await;
    }
    drop(warmup);
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
    download: &tokio::sync::watch::Receiver<Option<flx::DownloadProgress>>,
    cancel: Arc<tokio::sync::Notify>,
) -> anyhow::Result<RunOutcome> {
    if find.fetcher.dry_run || find.fetcher.list_providers {
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
    let warmup = make_warmup(quiet, no_color, download, false, None);
    let config = validator_config(&find.validator, protocols.clone(), groups.clone(), false);

    let mut pass1 = if !find.validator.files.is_empty() {
        if let Some(bar) = &warmup {
            bar.set_phase("Checking online judges …");
        }
        // Opening the sources is I/O and must stay interruptible like every
        // other phase of the run.
        let files = tokio::select! {
            files = file_source(&find.validator.files) => files?,
            _ = cancel.notified() => {
                drop(warmup);
                return Ok(RunOutcome::Cancelled);
            }
        };
        let source = Box::pin(tee_recorder(files, recordings.clone()));
        let validate = ProxyValidator::validate(source, config);
        tokio::pin!(validate);
        let pass = tokio::select! {
            pass = &mut validate => pass.context("failed to start proxy validator")?,
            _ = cancel.notified() => {
                drop(warmup);
                return Ok(RunOutcome::Cancelled);
            }
        };
        drop(warmup);
        pass
    } else {
        let fetch_cfg = fetcher_config(&find.fetcher);
        if let Some(bar) = &warmup {
            let phase = if fetch_cfg.enable_geo_lookup {
                "Preparing GeoLite2 database …"
            } else {
                "Fetching proxy lists …"
            };
            bar.set_phase(phase);
        }
        let mut fetcher = tokio::select! {
            fetcher = ProxySource::from_fetcher(fetch_cfg) => {
                fetcher.context("failed to start proxy fetcher")?
            }
            _ = cancel.notified() => {
                drop(warmup);
                return Ok(RunOutcome::Cancelled);
            }
        };
        let stages = fetcher.stage_events();
        let source = Box::pin(tee_recorder(fetcher, recordings.clone()));
        if let Some(bar) = &warmup {
            bar.set_phase("Fetching proxy lists …");
        }
        // Watch the gathering phases on a side task while the validator
        // preflights judges and consumes the stream in parallel.
        let watcher = match (&warmup, stages) {
            (Some(bar), Some(mut rx)) => {
                let bar = Arc::clone(bar);
                Some(tokio::spawn(async move {
                    while let Some(stage) = rx.recv().await {
                        let phase = match stage {
                            FetchStage::Primary => "Fetching primary sources …",
                            FetchStage::Fallback => "Fetching fallback sources …",
                            FetchStage::Done => "Checking online judges …",
                        };
                        bar.set_phase(phase);
                        if matches!(stage, FetchStage::Done) {
                            break;
                        }
                    }
                }))
            }
            _ => None,
        };
        let validate = ProxyValidator::validate(source, config);
        tokio::pin!(validate);
        let pass = tokio::select! {
            pass = &mut validate => pass.context("failed to start proxy validator")?,
            _ = cancel.notified() => {
                if let Some(task) = watcher {
                    task.abort();
                    let _ = task.await;
                }
                drop(warmup);
                return Ok(RunOutcome::Cancelled);
            }
        };
        if let Some(task) = watcher {
            task.abort();
            let _ = task.await;
        }
        drop(warmup);
        pass
    };
    let mut failure_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    if let Some(path) = find.validator.report_failures.clone() {
        if let Some(rx) = pass1.take_failures() {
            failure_tasks.push(tokio::spawn(async move {
                write_failures(rx, &path, true).await;
            }));
        }
    }
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
    // open the document itself; group-only requests never fall back. When a
    // fallback is possible, pass 1 leaves the JSON array unclosed and its
    // output file untruncated so pass 2 (or `close_chained_json` below) can
    // finish the document without losing pass-1 results.
    let may_fallback = !protocols.is_empty();
    let json_doc = may_fallback.then(|| Arc::new(JsonDoc::default()));
    let outcome1 = process_result(
        pass1,
        find.output.clone(),
        cancel.clone(),
        &guard1,
        FinalizeOpts {
            suppress_empty_json: may_fallback,
            emit_csv_header: true,
            continue_json: json_doc.clone().map(|doc| JsonContinuation {
                doc,
                leave_open: true,
            }),
        },
    )
    .await;
    // Erase the status line before the summary so the two never share a row.
    drop(guard1);
    if !matches!(outcome1, Ok(RunOutcome::Finished)) {
        if matches!(outcome1, Ok(RunOutcome::Cancelled)) {
            report_validation_summary(
                ValidationStats {
                    passed: progress1.passed(),
                    done: progress1.done(),
                    total: progress1.total(),
                    elapsed: started.elapsed(),
                },
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
    let needs_fallback = may_fallback && (p1_passed == 0 || (limit > 0 && p1_passed < limit));

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
            close_chained_json(&options2, json_doc.as_ref().map_or(0, |doc| doc.items())).await?;
            report_validation_summary(
                ValidationStats {
                    passed: p1_passed,
                    done: progress1.done(),
                    total: progress1.total(),
                    elapsed: started.elapsed(),
                },
                dst.as_deref(),
                quiet,
            );
            return Ok(RunOutcome::Finished);
        }

        // The fallback pass re-runs the judge preflight, so its startup is
        // raced against cancel exactly like the first pass.
        let validate2 = ProxyValidator::validate(
            futures_util::stream::iter(candidates),
            validator_config(&find.validator, requested, Vec::new(), true),
        );
        tokio::pin!(validate2);
        let mut pass2 = tokio::select! {
            pass = &mut validate2 => pass.context("failed to start proxy validator")?,
            _ = cancel.notified() => {
                report_validation_summary(
                    ValidationStats {
                        passed: p1_passed,
                        done: progress1.done(),
                        total: progress1.total(),
                        elapsed: started.elapsed(),
                    },
                    dst.as_deref(),
                    quiet,
                );
                return Ok(RunOutcome::Cancelled);
            }
        };
        if let Some(path) = find.validator.report_failures.clone() {
            if let Some(rx) = pass2.take_failures() {
                failure_tasks.push(tokio::spawn(async move {
                    write_failures(rx, &path, false).await;
                }));
            }
        }
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
                continue_json: json_doc.map(|doc| JsonContinuation {
                    doc,
                    leave_open: false,
                }),
            },
        )
        .await;
        drop(guard2);
        if !matches!(outcome2, Ok(RunOutcome::Finished)) {
            if matches!(outcome2, Ok(RunOutcome::Cancelled)) {
                report_validation_summary(
                    ValidationStats {
                        passed: p1_passed + progress2.passed(),
                        done: progress1.done() + progress2.done(),
                        total: progress1.total() + progress2.total(),
                        elapsed: started.elapsed(),
                    },
                    dst.as_deref(),
                    quiet,
                );
            }
            return outcome2;
        }
        report_validation_summary(
            ValidationStats {
                passed: p1_passed + progress2.passed(),
                done: progress1.done() + progress2.done(),
                total: progress1.total() + progress2.total(),
                elapsed: started.elapsed(),
            },
            dst.as_deref(),
            quiet,
        );
        for task in failure_tasks {
            let _ = task.await;
        }
        return Ok(RunOutcome::Finished);
    }

    // No fallback ran although one was possible (pass 1 filled the limit):
    // close the array pass 1 left open.
    if let Some(doc) = &json_doc {
        close_chained_json(&find.output, doc.items()).await?;
    }
    report_validation_summary(
        ValidationStats {
            passed: progress1.passed(),
            done: progress1.done(),
            total: progress1.total(),
            elapsed: started.elapsed(),
        },
        dst.as_deref(),
        quiet,
    );
    for task in failure_tasks {
        let _ = task.await;
    }
    outcome1
}

async fn write_failures(
    mut rx: tokio::sync::mpsc::Receiver<flx::ProxyFailure>,
    path: &std::path::Path,
    truncate: bool,
) {
    use std::io::Write;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(truncate)
        .append(!truncate)
        .open(path);
    let mut file = match file {
        Ok(file) => file,
        Err(error) => {
            #[cfg(feature = "log")]
            log::error!("cannot open failure report `{}`: {error:#}", path.display());
            let _ = error;
            return;
        }
    };
    while let Some(failure) = rx.recv().await {
        let line = serde_json::to_string(&failure).unwrap_or_default();
        if !line.is_empty() {
            let _ = writeln!(file, "{line}");
        }
    }
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

#[derive(Clone, Copy)]
struct ValidationStats {
    passed: usize,
    done: usize,
    total: usize,
    elapsed: std::time::Duration,
}

fn report_validation_summary(stats: ValidationStats, dst: Option<&str>, quiet: bool) {
    if quiet || stdout_is_pipe() {
        return;
    }
    let rate = if stats.elapsed.is_zero() {
        0.0
    } else {
        stats.total as f64 / stats.elapsed.as_secs_f64()
    };
    eprintln!("{}", format_validation_stats(&stats, rate, dst));
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

async fn run_geo_update(
    download: &tokio::sync::watch::Receiver<Option<flx::DownloadProgress>>,
    quiet: bool,
    no_color: bool,
    cancel: Arc<tokio::sync::Notify>,
) -> anyhow::Result<RunOutcome> {
    let warmup = make_warmup(quiet, no_color, download, false, None);
    if let Some(bar) = &warmup {
        bar.set_phase("Syncing GeoLite2 databases …");
    }
    let outcome = tokio::select! {
        outcome = flx::sync_database() => {
            outcome.context("failed to sync the GeoLite2 database")?
        }
        _ = cancel.notified() => {
            drop(warmup);
            return Ok(RunOutcome::Cancelled);
        }
    };
    drop(warmup);
    match outcome {
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
        insecure: options.no_verify_tls,
        probe_missed_types,
        support_cookies: options.support_cookies,
        support_referer: options.support_referer,
        retry_delay: std::time::Duration::from_millis(options.retry_delay_ms),
        report_failures: options.report_failures.is_some(),
    }
}
