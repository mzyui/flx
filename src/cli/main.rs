use anyhow::Context;
use argument::Cli;
#[cfg(feature = "serve")]
use argument::ServeArgs;
use argument::{Command, ConfigAction, ConfigCmd, FetchArgs, FindArgs};
use clap::{CommandFactory, FromArgMatches};
#[cfg(feature = "log")]
use flx::initialize_logging;
use flx::{
    proxy::models::{Anonymity, Protocol, Proxy},
    FetchStage, PauseGate, ProxySource, ProxyValidator, ValidationProgress,
};
// `flx serve` uses `.next()`; the CLI test module reaches this through `use super::*`.
#[allow(unused_imports)]
use futures_util::StreamExt;
use quotas::{split_type_requests, QuotaEnforcer, TypeQuota};
use std::io::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(feature = "progress_bar")]
use style::Colorize;
use tokio::runtime;

mod argument;
mod config;
mod filters;
mod guard;
mod output;
mod pipeline;
#[cfg(feature = "progress_bar")]
mod progress;
mod quotas;
#[cfg(feature = "progress_bar")]
mod status_line;
#[cfg(feature = "progress_bar")]
mod style;
#[cfg(feature = "tui")]
mod tui;
mod version;
mod wizard;

#[cfg(test)]
mod tests;

pub(crate) use guard::*;
pub(crate) use output::*;
pub(crate) use pipeline::*;
pub(crate) use version::*;

/// Format the end-of-run stats line for find.
#[cfg(feature = "progress_bar")]
fn format_validation_stats(stats: &ValidationStats, rate: f64, dst: Option<&str>) -> String {
    let v = format!("{} valid", stats.passed).green();
    let f = format!("{} failed", stats.done.saturating_sub(stats.passed)).red();
    let suffix = dst.map(|d| format!(" → {d}")).unwrap_or_default();
    let lead = if dst.is_some() { "" } else { "\n" };
    format!(
        "{lead}{v} · {f} · {} total in {} ({rate:.1}/s){suffix}",
        stats.total,
        format_duration(stats.elapsed)
    )
}

#[cfg(not(feature = "progress_bar"))]
fn format_validation_stats(stats: &ValidationStats, rate: f64, dst: Option<&str>) -> String {
    let suffix = dst.map(|d| format!(" → {d}")).unwrap_or_default();
    let lead = if dst.is_some() { "" } else { "\n" };
    format!(
        "{lead}{} valid · {} failed · {} total in {} ({rate:.1}/s){suffix}",
        stats.passed,
        stats.done.saturating_sub(stats.passed),
        stats.total,
        format_duration(stats.elapsed)
    )
}

/// Format durations as ms, s, or minutes.
fn format_duration(elapsed: std::time::Duration) -> String {
    if elapsed.as_millis() < 1_000 {
        format!("{}ms", elapsed.as_millis())
    } else if elapsed.as_secs() < 60 {
        format!("{:.1}s", elapsed.as_secs_f64())
    } else {
        format!("{}m {}s", elapsed.as_secs() / 60, elapsed.as_secs() % 60)
    }
}

/// Format the end-of-run line for grab.
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
    format!(
        "{lead}Gathered {n} in {} ({rate:.1}/s){suffix}",
        format_duration(elapsed)
    )
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
    format!(
        "{lead}Gathered {gathered} proxies in {} ({rate:.1}/s){suffix}",
        format_duration(elapsed)
    )
}

#[cfg(unix)]
mod quiet_signal_echo {
    use std::sync::Mutex;

    // Save termios so forced exits can restore it.
    static ORIGINAL: Mutex<Option<(libc::c_int, libc::termios)>> = Mutex::new(None);

    /// Restore saved terminal settings at most once.
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

const SIGINT_EXIT_CODE: u8 = 130;
/// Poll the serve pool while it fills.
#[cfg(feature = "serve")]
const SERVE_READY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
// Let a second Ctrl+C force-quit stuck phases.
const FORCE_EXIT_AFTER_PRESSES: usize = 2;

fn should_force_exit(press_count: usize) -> bool {
    press_count >= FORCE_EXIT_AFTER_PRESSES
}

// Restore output, cursor, and termios before forced exits.
fn restore_terminal_and_exit() -> ! {
    let _ = std::io::stdout().lock().flush();
    #[cfg(feature = "progress_bar")]
    progress::force_show_cursor();
    #[cfg(feature = "tui")]
    tui::force_restore();
    let _ = std::io::stderr().lock().flush();
    quiet_signal_echo::restore();
    std::process::exit(i32::from(SIGINT_EXIT_CODE))
}

fn main() -> std::process::ExitCode {
    let _quiet = QuietSignalEcho::install();
    match run_application() {
        Ok(RunOutcome::Finished) => std::process::ExitCode::SUCCESS,
        Ok(RunOutcome::Cancelled) => std::process::ExitCode::from(SIGINT_EXIT_CODE),
        Ok(RunOutcome::NoCommand) => std::process::ExitCode::from(2),
        Err(e) => {
            #[cfg(feature = "log")]
            log::error!("Error: {e:?}");
            // Surface fatal errors even when logging is off.
            eprintln!("Error: {e:?}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
fn convert_protocols(types: &[String]) -> Vec<Protocol> {
    types
        .iter()
        .filter_map(
            |type_str| match <Protocol as std::str::FromStr>::from_str(type_str) {
                Ok(protocol) => Some(protocol),
                Err(_) => {
                    quotas::report_invalid_type_value(type_str);
                    None
                }
            },
        )
        .collect()
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

fn run_application() -> anyhow::Result<RunOutcome> {
    let matches = Cli::command().get_matches();
    let mut cli = Cli::from_arg_matches(&matches).expect("clap validates args");

    // Apply config patches before reading flags.
    if !matches!(&cli.command, Some(Command::Config(_))) {
        let home = config_home();
        let cwd = std::env::current_dir().unwrap_or_default();
        if let Some(cfg) = config::load(
            cli.config.as_deref(),
            std::env::var("FLX_CONFIG").ok().as_deref(),
            cli.no_config,
            &home,
            &cwd,
        )? {
            config::apply_config(&mut cli, &cfg, &matches);
        }
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
        // A run that owns the inline viewport cannot log to it: stderr would
        // paint over the live UI. Nothing is written at `off`, so no file is made.
        #[cfg(feature = "tui")]
        let owns_screen = cli.tui && log_level != log::LevelFilter::Off;
        #[cfg(not(feature = "tui"))]
        let owns_screen = false;
        if owns_screen {
            let path = flx::screen_log_path()?;
            eprintln!("flx: logging to {}", path.display());
            flx::initialize_file_logging(log_level, &path)?;
        } else {
            initialize_logging(log_level)?;
        }
    }

    // `--tui` redirects a find/grab run into the terminal UI.
    // Only available with the `tui` Cargo feature; the flag is hidden otherwise.
    #[cfg(feature = "tui")]
    if cli.tui {
        return run_tui(&cli);
    }

    // Reject bare invocations with help and usage error.
    let Some(command) = cli.command else {
        use clap::CommandFactory as _;
        let mut stderr = std::io::stderr().lock();
        Cli::command().write_help(&mut stderr)?;
        return Ok(RunOutcome::NoCommand);
    };

    // Force color choice from --no-color for stderr painters.
    #[cfg(feature = "progress_bar")]
    style::set_override(!cli.no_color);

    let runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    // Share cancel notifications across passes.
    let cancel = Arc::new(tokio::sync::Notify::new());
    // Observe GeoLite2 downloads for progress bars.
    let download = flx::install_download_observer().expect("download observer installs once");

    let outcome = runtime.block_on(async move {
        if !cli.skip_version_check && !cli.quiet {
            let current = env!("CARGO_PKG_VERSION").to_owned();
            tokio::spawn(async move {
                // Prefer cached versions to avoid per-run network hits.
                let (latest, from_network) = match cached_latest_version() {
                    Some(v) => (v, false),
                    None => match fetch_latest_version().await {
                        Ok(v) => (v, true),
                        Err(_) => return,
                    },
                };
                if from_network {
                    cache_latest_version(&latest);
                }
                if check_version(&current, &latest) {
                    eprintln!("A new flx version is available: {latest} (you are on {current}).");
                }
            });
        }
        let notify = Arc::clone(&cancel);
        // Re-arm SIGINT so warmup presses reach process_result.
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
            #[cfg(feature = "serve")]
            Command::Serve(serve) => {
                run_serve(serve, cli.quiet, cli.no_color, &download, cancel).await
            }
            Command::GeoUpdate => run_geo_update(&download, cli.quiet, cli.no_color, cancel).await,
            Command::Config(config) => run_config(config, cli.no_config, cli.config.as_deref()),
        }
    });
    runtime.shutdown_background();
    outcome
}

// Hand a find/grab run to the terminal UI instead of streaming to stdout.
#[cfg(feature = "tui")]
fn run_tui(cli: &Cli) -> anyhow::Result<RunOutcome> {
    use tui::RunSpec;

    if !tui::is_interactive() {
        anyhow::bail!("--tui needs an interactive terminal (stdin and stdout must be a TTY)");
    }
    let spec = match &cli.command {
        Some(Command::Find(find)) => RunSpec {
            fetcher: find.fetcher.clone(),
            validator: Some(find.validator.clone()),
            output: find.output.clone(),
        },
        Some(Command::Grab(grab)) => RunSpec {
            fetcher: grab.fetcher.clone(),
            validator: None,
            output: grab.output.clone(),
        },
        Some(_) => anyhow::bail!("--tui only applies to `find` and `grab`"),
        None => anyhow::bail!("--tui needs a command: try `flx find --tui` or `flx grab --tui`"),
    };

    let runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;
    let ctx = tui::TuiCtx {
        no_color: cli.no_color,
        spec,
    };
    let outcome = runtime.block_on(tui::run(ctx))?;
    runtime.shutdown_background();
    Ok(outcome)
}

fn config_home() -> std::path::PathBuf {
    flx::base_dirs::config_dir().unwrap_or_else(std::env::temp_dir)
}

fn run_config(
    config: ConfigCmd,
    no_config: bool,
    config_flag: Option<&std::path::Path>,
) -> anyhow::Result<RunOutcome> {
    let home = config_home();
    let cwd = std::env::current_dir().unwrap_or_default();
    let env_path = std::env::var("FLX_CONFIG").ok();
    match config.action {
        ConfigAction::Path => {
            if no_config {
                println!("no config files in effect (--no-config)");
                return Ok(RunOutcome::Finished);
            }
            let paths =
                config::paths_in_effect(config_flag, env_path.as_deref(), no_config, &home, &cwd);
            let mut shown = 0;
            for path in [paths.primary, paths.project, paths.user]
                .into_iter()
                .flatten()
            {
                println!("{}", path.display());
                shown += 1;
            }
            if shown == 0 {
                println!(
                    "no config file found (checked {} and {})",
                    cwd.join(".flx.toml").display(),
                    home.join("flx").join("config.toml").display()
                );
            }
            Ok(RunOutcome::Finished)
        }
        ConfigAction::Init { path, force } => {
            let target = path.unwrap_or_else(|| home.join("flx").join("config.toml"));
            if target.exists() && !force {
                anyhow::bail!(
                    "config file already exists at {} (use --force to overwrite)",
                    target.display()
                );
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&target, config::template())?;
            println!("wrote config template to {}", target.display());
            Ok(RunOutcome::Finished)
        }
        ConfigAction::Show => {
            match config::load(config_flag, env_path.as_deref(), no_config, &home, &cwd)? {
                Some(cfg) => {
                    print!("{}", config::to_toml(&cfg));
                    Ok(RunOutcome::Finished)
                }
                None => {
                    println!("# no config values set (no config file found)");
                    Ok(RunOutcome::Finished)
                }
            }
        }
        ConfigAction::Wizard(wizard) => {
            let mut stdin = std::io::stdin().lock();
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            wizard::run_wizard(wizard, &home, &cwd, &mut stdin, &mut stdout)
        }
    }
}

// Unify warmup bars across feature configurations.
trait PhaseLabel {
    fn set_phase(&self, phase: &'static str);
}

#[cfg(feature = "progress_bar")]
impl PhaseLabel for progress::WarmupBar {
    fn set_phase(&self, phase: &'static str) {
        progress::WarmupBar::set_phase(self, phase)
    }
}

#[cfg(not(feature = "progress_bar"))]
impl PhaseLabel for WarmupBar {
    fn set_phase(&self, phase: &'static str) {
        WarmupBar::set_phase(self, phase)
    }
}

// Race fetcher startup against cancel with phase labels.
async fn start_fetch_phase<B>(
    fetch_cfg: flx::fetcher::Config,
    cancel: &Arc<tokio::sync::Notify>,
    warmup: Option<Arc<B>>,
    done_label: &'static str,
) -> anyhow::Result<Option<(flx::ProxyFetcher, Option<tokio::task::JoinHandle<()>>)>>
where
    B: PhaseLabel + Send + Sync + 'static,
{
    if let Some(bar) = warmup.as_deref() {
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
        _ = cancel.notified() => return Ok(None),
    };
    let stages = fetcher.stage_events();
    if let Some(bar) = warmup.as_deref() {
        bar.set_phase("Fetching proxy lists …");
    }
    // Relay gathering stages to keep the bar live.
    let watcher = match (warmup, stages) {
        (Some(bar), Some(mut rx)) => Some(tokio::spawn(async move {
            while let Some(stage) = rx.recv().await {
                let phase = match stage {
                    FetchStage::Primary => "Fetching primary sources …",
                    FetchStage::Fallback => "Fetching fallback sources …",
                    FetchStage::Done => done_label,
                };
                bar.set_phase(phase);
                if matches!(stage, FetchStage::Done) {
                    break;
                }
            }
        })),
        _ => None,
    };
    Ok(Some((fetcher, watcher)))
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
    // Show the grab bar only when stdout is redirected.
    let show_bar = !quiet && (grab.output.output_file.is_some() || stdout_is_pipe());
    let (gather_tx, gather_rx) = tokio::sync::watch::channel(0usize);
    let warmup = if show_bar {
        make_warmup(quiet, no_color, download, show_bar, Some(gather_rx))
    } else {
        None
    };
    let Some((fetcher, watcher)) =
        start_fetch_phase(fetch_cfg, &cancel, warmup.clone(), "Done gathering").await?
    else {
        drop(warmup);
        return Ok(RunOutcome::Cancelled);
    };
    let accepted = fetcher.accepted_handle();
    // Repaint gathered counts on a fixed cadence.
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
    let run_stats = crate::output::RunStats::new();
    let outcome = process_result(
        fetcher,
        grab.output,
        cancel,
        guard,
        FinalizeOpts {
            stats: Some(Arc::clone(&run_stats)),
            ..FinalizeOpts::default()
        },
    )
    .await;
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
        let dist = run_stats.summary();
        let mut report = format_gathered_stats(gathered, elapsed, rate, dst.as_deref());
        if let Some(dist) = &dist {
            report.push_str(&format!("\n  {dist}"));
        }
        eprintln!("{report}");
    }
    outcome
}

#[cfg(feature = "serve")]
fn parse_serve_credentials(raw: &str) -> anyhow::Result<(String, String)> {
    let (user, pass) = raw
        .split_once(':')
        .context("--auth must be in `user:pass` form")?;
    Ok((user.to_owned(), pass.to_owned()))
}

/// Stream one validated feed from files or providers.
#[cfg(feature = "serve")]
async fn validated_stream(
    serve: &ServeArgs,
    protocols: Vec<Protocol>,
    groups: Vec<Vec<Protocol>>,
) -> anyhow::Result<(BoxStream, ValidationProgress, Arc<PauseGate>)> {
    let config = validator_config(&serve.validator, protocols, groups, false);
    let source: BoxStream = if !serve.validator.files.is_empty() {
        file_source(&serve.validator.files).await?
    } else {
        let fetch_cfg = fetcher_config(&serve.fetcher);
        Box::pin(ProxySource::from_fetcher(fetch_cfg).await?)
    };
    let validator = ProxyValidator::validate(source, config).await?;
    let progress = validator.progress();
    let gate = validator.pause_gate();
    Ok((Box::pin(validator), progress, gate))
}

// Pause validating while the serve pool is full; resume when room frees.
#[cfg(feature = "serve")]
fn serve_should_pause(pool_len: usize, pool_size: usize) -> bool {
    pool_len >= pool_size.max(1)
}

// Print a serve log line without colliding with the status line.
#[cfg(feature = "serve")]
fn announce(bar: Option<&impl OutputGuard>, message: &str) {
    match bar {
        Some(bar) => {
            bar.before_write();
            eprintln!("{message}");
            bar.after_write();
        }
        None => eprintln!("{message}"),
    }
}

#[cfg(feature = "serve")]
async fn run_serve(
    serve: ServeArgs,
    quiet: bool,
    no_color: bool,
    download: &tokio::sync::watch::Receiver<Option<flx::DownloadProgress>>,
    cancel: Arc<tokio::sync::Notify>,
) -> anyhow::Result<RunOutcome> {
    if serve.fetcher.dry_run || serve.fetcher.list_providers {
        list_sources();
        return Ok(RunOutcome::Finished);
    }

    let (type_quotas, groups) = split_type_requests(&serve.validator.types);
    if type_quotas.iter().any(|quota| quota.quota.is_some()) {
        anyhow::bail!(
            "type quotas like HTTP=8 are not supported by `flx serve`; pass plain types instead"
        );
    }
    let mut protocols: Vec<Protocol> = type_quotas.iter().map(|quota| quota.protocol).collect();
    if protocols.is_empty() && groups.is_empty() {
        protocols.push(Protocol::Http(Anonymity::Unknown));
    }

    let pool_size = serve.pool_size.clamp(1, flx::rotator::MAX_POOL_SIZE);
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(flx::rotator::EVENT_CHANNEL_CAPACITY);
    let options = flx::ServeOptions {
        bind: serve.bind,
        port: serve.port,
        strategy: flx::Strategy::parse(&serve.strategy).context("unknown rotation strategy")?,
        pool_size,
        min_ready: serve.min_ready.clamp(1, pool_size),
        refresh_secs: serve
            .refresh_secs
            .unwrap_or(flx::rotator::DEFAULT_REFRESH_SECS),
        request_timeout: std::time::Duration::from_secs(
            serve
                .request_timeout
                .unwrap_or(flx::rotator::DEFAULT_REQUEST_TIMEOUT.as_secs()),
        ),
        auth: serve
            .auth
            .as_deref()
            .map(parse_serve_credentials)
            .transpose()?,
        event_tx: Some(event_tx),
        trace: serve.trace,
    };
    // Fail fast when the endpoint is already claimed (e.g. a stale instance).
    tokio::net::TcpListener::bind((serve.bind, serve.port))
        .await
        .with_context(|| {
            format!(
                "failed to bind the rotating endpoint on {}:{}",
                serve.bind, serve.port
            )
        })?;
    let rotator = Arc::new(flx::Rotator::new(options));
    let pool = rotator.pool();
    let min_ready = serve.min_ready.clamp(1, pool_size);
    let endpoint = format!("{}:{}", serve.bind, serve.port);
    let serve_bar = make_serve_bar(
        Arc::clone(&pool),
        min_ready,
        pool_size,
        endpoint,
        quiet,
        no_color,
        download,
    );
    if let Some(bar) = serve_bar.as_deref() {
        bar.set_phase("Filling the pool …");
    }
    // Print connection events without colliding with the status line.
    let _event_printer = {
        let bar = serve_bar.clone();
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                announce(bar.as_deref(), &event.to_string());
            }
        })
    };

    // Fan cancel notifications out to every serve task.
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn({
        let cancel = Arc::clone(&cancel);
        async move {
            cancel.notified().await;
            let _ = shutdown_tx.send(true);
        }
    });

    let mut server = tokio::spawn({
        let rotator = Arc::clone(&rotator);
        let shutdown = shutdown_rx.clone();
        async move { rotator.run_until_shutdown(shutdown).await }
    });

    // Flip the status line live without interrupting active connections.
    let static_pool = !serve.validator.files.is_empty();
    let live = {
        let pool = Arc::clone(&pool);
        let mut shutdown_rx = shutdown_rx.clone();
        let serve_bar = serve_bar.clone();
        tokio::spawn(async move {
            while pool.ready() == 0 {
                tokio::select! {
                    _ = tokio::time::sleep(SERVE_READY_POLL_INTERVAL) => {}
                    _ = shutdown_rx.changed() => return,
                }
            }
            if let Some(bar) = serve_bar.as_deref() {
                bar.set_phase("Serving …");
            }
        })
    };
    // Recheck pool room on a fixed cadence while the feed is paused.
    let mut room_tick = tokio::time::interval(SERVE_READY_POLL_INTERVAL);
    loop {
        if let Some(bar) = serve_bar.as_deref() {
            if serve.validator.files.is_empty() {
                bar.set_phase("Fetching proxy lists …");
            } else {
                bar.set_phase("Checking online judges …");
            }
        }
        let (mut stream, progress, gate) =
            validated_stream(&serve, protocols.clone(), groups.clone()).await?;
        if let Some(bar) = serve_bar.as_deref() {
            bar.set_progress(progress);
            bar.set_phase("Checking online judges …");
        }
        // Hold validating while the pool is full; evictions free room again.
        let mut paused_full = false;
        if serve_should_pause(pool.len(), pool_size) {
            if static_pool {
                // A full static pool needs no further candidates.
                drop(stream);
                rotator.force_ready();
                break;
            }
            gate.pause();
            paused_full = true;
            if let Some(bar) = serve_bar.as_deref() {
                bar.set_phase("Pool full — validating paused …");
            }
        }
        loop {
            tokio::select! {
                next = stream.next() => {
                    let Some(proxy) = next else { break };
                    pool.add(proxy);
                }
                _ = shutdown_rx.changed() => break,
                _ = room_tick.tick() => {}
                server_result = &mut server => {
                    // The server only ends early on startup failure.
                    match server_result {
                        Ok(Ok(())) => break,
                        Ok(Err(error)) => return Err(error),
                        Err(join) => return Err(anyhow::anyhow!("serve task failed: {join}")),
                    }
                }
            }
            let full = serve_should_pause(pool.len(), pool_size);
            if full && static_pool {
                break;
            }
            if full && !paused_full {
                gate.pause();
                paused_full = true;
                if let Some(bar) = serve_bar.as_deref() {
                    bar.set_phase("Pool full — validating paused …");
                }
            } else if !full && paused_full {
                gate.resume();
                paused_full = false;
                if let Some(bar) = serve_bar.as_deref() {
                    bar.set_phase("Checking online judges …");
                }
            }
        }
        drop(stream);
        rotator.force_ready();
        if let Some(bar) = serve_bar.as_deref() {
            if pool.ready() > 0 {
                bar.set_phase("Serving …");
            }
        }
        if static_pool {
            break;
        }
        if let Some(bar) = serve_bar.as_deref() {
            bar.set_phase("Waiting for refresh …");
        }
        let refresh = std::time::Duration::from_secs(
            serve
                .refresh_secs
                .unwrap_or(flx::rotator::DEFAULT_REFRESH_SECS),
        );
        tokio::select! {
            _ = tokio::time::sleep(refresh) => {}
            _ = shutdown_rx.changed() => break,
        }
    }
    let server_result = server.await;
    let _ = live.await;
    match server_result {
        Ok(Ok(())) => Ok(RunOutcome::Cancelled),
        Ok(Err(error)) => Err(error),
        Err(join) => Err(anyhow::anyhow!("serve task failed: {join}")),
    }
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

    let (mut type_quotas, groups) = split_type_requests(&find.validator.types);
    if type_quotas.is_empty() && groups.is_empty() {
        let default = TypeQuota::uncapped(Protocol::Http(Anonymity::Unknown));
        type_quotas.push(default);
    }
    let protocols: Vec<Protocol> = type_quotas.iter().map(|quota| quota.protocol).collect();
    // Shared quota state so pass 2 resumes with pass-1 room left.
    let quota_enforcer: Arc<Mutex<QuotaEnforcer>> =
        Arc::new(Mutex::new(QuotaEnforcer::new(type_quotas)));
    {
        let has_groups = !groups.is_empty();
        quota_enforcer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_has_groups(has_groups);
    }
    let has_quotas = quota_enforcer
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .has_any_quota();
    // Probes for filled families are pointless: strict output would reject
    // their results, so the validator skips them (groups always probe).
    let probe_gate: Option<flx::ProbeGate> = build_probe_gate(&quota_enforcer);

    // Record pass-1 candidates for fallback without re-fetching.
    let recordings: Arc<std::sync::Mutex<Vec<Proxy>>> = Arc::default();
    let recorded_types: Arc<[Protocol]> = Arc::from(protocols.clone());
    // Toggle validation pause via SIGUSR1 (Unix only) across both passes.
    #[cfg(unix)]
    let pause_holder: Arc<std::sync::Mutex<Option<Arc<PauseGate>>>> = Arc::default();
    #[cfg(unix)]
    let _pause_watcher = {
        let holder = Arc::clone(&pause_holder);
        let cancel_watcher = Arc::clone(&cancel);
        tokio::spawn(async move {
            let mut signals =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
                {
                    Ok(signals) => signals,
                    Err(_) => return,
                };
            loop {
                tokio::select! {
                    _ = signals.recv() => {
                        let gate = holder.lock().unwrap_or_else(|e| e.into_inner()).clone();
                        match gate {
                            Some(gate) if gate.is_paused() => {
                                gate.resume();
                                eprintln!("flx find resumed — validating new probes");
                            }
                            Some(gate) => {
                                gate.pause();
                                eprintln!(
                                    "flx find paused — in-flight probes finish, new probes held"
                                );
                            }
                            None => {
                                eprintln!("flx find pause signal arrived with no active pass");
                            }
                        }
                    }
                    _ = cancel_watcher.notified() => break,
                }
            }
        })
    };
    let warmup = make_warmup(quiet, no_color, download, false, None);
    let mut config = validator_config(&find.validator, protocols.clone(), groups.clone(), false);
    config.probe_gate = probe_gate.clone();

    let mut pass1 = if !find.validator.files.is_empty() {
        if let Some(bar) = &warmup {
            bar.set_phase("Checking online judges …");
        }
        // Keep source opening interruptible.
        let files = tokio::select! {
            files = file_source(&find.validator.files) => files?,
            _ = cancel.notified() => {
                drop(warmup);
                return Ok(RunOutcome::Cancelled);
            }
        };
        let source = Box::pin(tee_recorder(
            files,
            recordings.clone(),
            Arc::clone(&recorded_types),
        ));
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
        let Some((fetcher, watcher)) = start_fetch_phase(
            fetch_cfg,
            &cancel,
            warmup.clone(),
            "Checking online judges …",
        )
        .await?
        else {
            drop(warmup);
            return Ok(RunOutcome::Cancelled);
        };
        let source = Box::pin(tee_recorder(
            fetcher,
            recordings.clone(),
            Arc::clone(&recorded_types),
        ));
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
    #[cfg(unix)]
    pause_holder
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .replace(pass1.pause_gate());
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

    // Hide the status line around stdout writes.
    let guard1 = make_guard(progress1.clone(), quiet, no_color);
    // Leave pass-1 JSON open when fallback may append.
    let may_fallback = !protocols.is_empty();
    let json_doc = may_fallback.then(|| Arc::new(JsonDoc::default()));
    let run_stats = crate::output::RunStats::new();
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
            stats: Some(Arc::clone(&run_stats)),
            quotas: Some(Arc::clone(&quota_enforcer)),
        },
    )
    .await;
    drop(guard1);
    #[cfg(unix)]
    pause_holder
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    if !matches!(outcome1, Ok(RunOutcome::Finished)) {
        if matches!(outcome1, Ok(RunOutcome::Cancelled)) {
            report_validation_summary(
                ValidationStats::from_progress(&progress1, started.elapsed()),
                dst.as_deref(),
                run_stats.summary().as_deref(),
                quiet,
            );
        }
        return outcome1;
    }

    // Fall back when pass 1 misses types or the limit. Quota runs compare
    // emitted rows (not validated probes) so capped types stop at `=n`.
    let limit = find.output.limit;
    let p1_passed = progress1.passed();
    let emitted1 = json_doc.as_ref().map_or(p1_passed, |doc| doc.items());
    let needs_fallback = needs_fallback(
        has_quotas,
        &quota_enforcer,
        !groups.is_empty(),
        may_fallback,
        limit,
        emitted1,
        p1_passed,
    );

    if needs_fallback {
        let requested = protocols;
        let candidates: Vec<Proxy> =
            std::mem::take(&mut *recordings.lock().expect("recorder poisoned"));
        let mut options2 = find.output.clone();
        options2.limit = if limit > 0 {
            limit.saturating_sub(if has_quotas { emitted1 } else { p1_passed })
        } else {
            0
        };

        if candidates.is_empty() {
            // Skip empty fallback passes without judge preflight.
            close_chained_json(&options2, json_doc.as_ref().map_or(0, |doc| doc.items())).await?;
            report_validation_summary(
                ValidationStats::from_progress(&progress1, started.elapsed()),
                dst.as_deref(),
                run_stats.summary().as_deref(),
                quiet,
            );
            return Ok(RunOutcome::Finished);
        }

        let mut config2 = validator_config(&find.validator, requested, Vec::new(), true);
        config2.probe_gate = probe_gate.clone();
        let validate2 = ProxyValidator::validate(futures_util::stream::iter(candidates), config2);
        tokio::pin!(validate2);
        let mut pass2 = tokio::select! {
            pass = &mut validate2 => pass.context("failed to start proxy validator")?,
            _ = cancel.notified() => {
                report_validation_summary(
                    ValidationStats::from_progress(&progress1, started.elapsed()),
                    dst.as_deref(),
                    run_stats.summary().as_deref(),
                    quiet,
                );
                return Ok(RunOutcome::Cancelled);
            }
        };
        #[cfg(unix)]
        pause_holder
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(pass2.pause_gate());
        if let Some(path) = find.validator.report_failures.clone() {
            if let Some(rx) = pass2.take_failures() {
                failure_tasks.push(tokio::spawn(async move {
                    write_failures(rx, &path, false).await;
                }));
            }
        }
        let progress2 = pass2.progress();
        let guard2 = make_guard_with_label(progress2.clone(), quiet, no_color, "Validating pass 2");
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
                stats: Some(Arc::clone(&run_stats)),
                quotas: Some(Arc::clone(&quota_enforcer)),
            },
        )
        .await;
        drop(guard2);
        #[cfg(unix)]
        pause_holder
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let summary2 = || {
            ValidationStats::from_progress(&progress1, started.elapsed()).merged(
                &ValidationStats::from_progress(&progress2, started.elapsed()),
            )
        };
        if !matches!(outcome2, Ok(RunOutcome::Finished)) {
            if matches!(outcome2, Ok(RunOutcome::Cancelled)) {
                report_validation_summary(
                    summary2(),
                    dst.as_deref(),
                    run_stats.summary().as_deref(),
                    quiet,
                );
            }
            return outcome2;
        }
        report_validation_summary(
            summary2(),
            dst.as_deref(),
            run_stats.summary().as_deref(),
            quiet,
        );
        for task in failure_tasks {
            let _ = task.await;
        }
        return Ok(RunOutcome::Finished);
    }

    // Close pass-1 arrays when fallback never runs.
    if let Some(doc) = &json_doc {
        close_chained_json(&find.output, doc.items()).await?;
    }
    report_validation_summary(
        ValidationStats::from_progress(&progress1, started.elapsed()),
        dst.as_deref(),
        run_stats.summary().as_deref(),
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
    use tokio::io::AsyncWriteExt;
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(truncate)
        .append(!truncate)
        .open(path)
        .await;
    let mut file = match file {
        Ok(file) => file,
        Err(error) => {
            #[cfg(feature = "log")]
            log::error!("cannot open failure report `{}`: {error:#}", path.display());
            let _ = error;
            return;
        }
    };
    // Buffer failure lines to avoid per-record syscalls.
    let mut writer = tokio::io::BufWriter::new(&mut file);
    while let Some(failure) = rx.recv().await {
        let line = serde_json::to_string(&failure).unwrap_or_default();
        if !line.is_empty() {
            let _ = writer.write_all(line.as_bytes()).await;
            let _ = writer.write_all(b"\n").await;
        }
    }
    let _ = writer.flush().await;
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

impl ValidationStats {
    fn from_progress(progress: &ValidationProgress, elapsed: std::time::Duration) -> Self {
        Self {
            passed: progress.passed(),
            done: progress.done(),
            total: progress.total(),
            elapsed,
        }
    }

    fn merged(self, other: &Self) -> Self {
        Self {
            passed: self.passed + other.passed,
            done: self.done + other.done,
            total: self.total + other.total,
            elapsed: self.elapsed,
        }
    }
}

fn report_validation_summary(
    stats: ValidationStats,
    dst: Option<&str>,
    dist: Option<&str>,
    quiet: bool,
) {
    if quiet || stdout_is_pipe() {
        return;
    }
    // Same semantics as the live bars: completed probes per second.
    let rate = if stats.elapsed.is_zero() {
        0.0
    } else {
        stats.done as f64 / stats.elapsed.as_secs_f64()
    };
    let mut report = format_validation_stats(&stats, rate, dst);
    if let Some(dist) = dist {
        report.push_str(&format!("\n  {dist}"));
    }
    eprintln!("{report}");
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
