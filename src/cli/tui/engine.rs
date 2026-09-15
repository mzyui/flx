//! Runs the scrape/validate pipeline for the TUI and reports it as events.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use flx::proxy::models::{Anonymity, Protocol, Proxy};
use flx::{
    FetchStage, JudgeHealthReport, PauseGate, ProxyFailure, ProxySource, ProxyValidator,
    ValidationProgress,
};
use futures_util::StreamExt as _;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;

use crate::argument::{FetcherArgs, OutputOptions, ValidatorArgs};
use crate::filters::ProxyFilter;
use crate::pipeline;
use crate::quotas::{split_type_requests, QuotaEnforcer, TypeQuota};

/// Bound on queued proxy rows; overflow backpressures the pipeline.
pub(crate) const ENGINE_CHANNEL_CAPACITY: usize = 256;

/// Everything needed to start a run, taken straight from the CLI arguments.
#[derive(Clone)]
pub(crate) struct RunSpec {
    pub(crate) fetcher: FetcherArgs,
    pub(crate) validator: Option<ValidatorArgs>,
    pub(crate) output: OutputOptions,
}

impl RunSpec {
    /// Whether this is a validating (`find`) run rather than a plain scrape.
    pub(crate) fn is_find(&self) -> bool {
        self.validator.is_some()
    }
}

/// Coarse pipeline phase shown in the dashboard header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Starting,
    Preparing,
    FetchingPrimary,
    FetchingFallback,
    Gathering,
    CheckingJudges,
    ValidatingPass(u8),
    Finished,
    Failed,
}

impl Phase {
    pub(crate) fn label(self) -> String {
        match self {
            Phase::Starting => "starting".to_owned(),
            Phase::Preparing => "preparing".to_owned(),
            Phase::FetchingPrimary => "primary sources".to_owned(),
            Phase::FetchingFallback => "fallback sources".to_owned(),
            Phase::Gathering => "gathering".to_owned(),
            Phase::CheckingJudges => "checking judges".to_owned(),
            Phase::ValidatingPass(pass) => format!("validating pass {pass}"),
            Phase::Finished => "done".to_owned(),
            Phase::Failed => "failed".to_owned(),
        }
    }
}

/// State the UI polls each tick instead of receiving events for.
pub(crate) struct LiveState {
    pub(crate) phase: Phase,
    /// When the current phase began, so the spinner delay is per phase rather
    /// than per run.
    phase_started: Instant,
    pub(crate) gathered: Option<Arc<AtomicUsize>>,
    pub(crate) progress: Option<ValidationProgress>,
    pub(crate) gate: Option<Arc<PauseGate>>,
    pub(crate) error: Option<String>,
}

impl LiveState {
    fn new() -> Self {
        Self {
            phase: Phase::Starting,
            phase_started: Instant::now(),
            gathered: None,
            progress: None,
            gate: None,
            error: None,
        }
    }

    pub(crate) fn gathered(&self) -> usize {
        self.gathered
            .as_ref()
            .map_or(0, |handle| handle.load(Ordering::Relaxed))
    }

    pub(crate) fn paused(&self) -> bool {
        self.gate.as_ref().is_some_and(|gate| gate.is_paused())
    }

    /// How long the current phase has been running.
    pub(crate) fn phase_elapsed(&self) -> Duration {
        self.phase_started.elapsed()
    }

    /// Moves to `phase` and restarts its clock.
    fn enter(&mut self, phase: Phase) {
        self.phase = phase;
        self.phase_started = Instant::now();
    }
}

/// Discrete events pushed to the UI. The channel is the app's message bus, so
/// work done off the event loop (an export) reports back through it too.
pub(crate) enum EngineEvent {
    Proxy(Box<Proxy>),
    JudgeHealth(Box<JudgeHealthReport>),
    PassChanged(u8),
    Failure(Box<ProxyFailure>),
    /// Receipt for a background export: rows written, or why it failed.
    ExportDone {
        path: String,
        result: Result<usize, String>,
    },
    Finished(Box<RunSummary>),
    Error(String),
}

/// End-of-run tally.
#[derive(Clone, Debug)]
pub(crate) struct RunSummary {
    pub(crate) gathered: usize,
    pub(crate) valid: usize,
    pub(crate) failed: usize,
    pub(crate) elapsed: Duration,
}

/// Handle to a running pipeline.
pub(crate) struct RunHandle {
    task: JoinHandle<()>,
    pub(crate) live: Arc<Mutex<LiveState>>,
}

impl RunHandle {
    /// Aborts the pipeline task; dropping the stages closes their channels.
    pub(crate) fn cancel(&self) {
        self.task.abort();
    }

    /// Flips the cooperative validator pause gate.
    pub(crate) fn toggle_pause(&self) {
        let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(gate) = &live.gate {
            if gate.is_paused() {
                gate.resume();
            } else {
                gate.pause();
            }
        }
    }
}

/// Whether a row may be emitted under the active per-type quotas.
enum QuotaDecision {
    Emit,
    Skip,
    Stop,
}

fn quota_decision(proxy: &Proxy, enforcer: &Arc<Mutex<QuotaEnforcer>>) -> QuotaDecision {
    let mut guard = enforcer.lock().unwrap_or_else(|e| e.into_inner());
    if guard.should_emit(proxy) {
        QuotaDecision::Emit
    } else if guard.is_satisfied() {
        QuotaDecision::Stop
    } else {
        QuotaDecision::Skip
    }
}

fn quotas_saturated(enforcer: &Arc<Mutex<QuotaEnforcer>>) -> bool {
    enforcer
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_satisfied()
}

/// Starts a run in the background.
pub(crate) fn spawn(spec: RunSpec, tx: Sender<EngineEvent>) -> RunHandle {
    let live = Arc::new(Mutex::new(LiveState::new()));
    let task = tokio::spawn(drive(spec, tx, Arc::clone(&live)));
    RunHandle { task, live }
}

/// A handle that drives nothing, so state tests can pretend a run is live.
#[cfg(test)]
pub(crate) fn test_handle() -> RunHandle {
    RunHandle {
        task: tokio::spawn(async {}),
        live: Arc::new(Mutex::new(LiveState::new())),
    }
}

fn set_phase(live: &Arc<Mutex<LiveState>>, phase: Phase) {
    live.lock().unwrap_or_else(|e| e.into_inner()).enter(phase);
}

fn relay_stages(
    live: &Arc<Mutex<LiveState>>,
    stages: Option<Receiver<FetchStage>>,
    done_phase: Phase,
) {
    let Some(mut stages) = stages else {
        return;
    };
    let live = Arc::clone(live);
    tokio::spawn(async move {
        while let Some(stage) = stages.recv().await {
            let phase = match stage {
                FetchStage::Primary => Phase::FetchingPrimary,
                FetchStage::Fallback => Phase::FetchingFallback,
                FetchStage::Done => done_phase,
            };
            set_phase(&live, phase);
            if matches!(stage, FetchStage::Done) {
                break;
            }
        }
    });
}

async fn drive(spec: RunSpec, tx: Sender<EngineEvent>, live: Arc<Mutex<LiveState>>) {
    let started = Instant::now();
    let result = if spec.is_find() {
        run_find(&spec, &tx, &live, started).await
    } else {
        run_grab(&spec, &tx, &live, started).await
    };
    match result {
        Ok(summary) => {
            set_phase(&live, Phase::Finished);
            let _ = tx.send(EngineEvent::Finished(Box::new(summary))).await;
        }
        Err(error) => {
            let text = format!("{error:#}");
            live.lock().unwrap_or_else(|e| e.into_inner()).error = Some(text.clone());
            set_phase(&live, Phase::Failed);
            let _ = tx.send(EngineEvent::Error(text)).await;
        }
    }
}

async fn run_grab(
    spec: &RunSpec,
    tx: &Sender<EngineEvent>,
    live: &Arc<Mutex<LiveState>>,
    started: Instant,
) -> anyhow::Result<RunSummary> {
    set_phase(live, Phase::Preparing);
    let config = pipeline::fetcher_config(&spec.fetcher);
    let mut fetcher = ProxySource::from_fetcher(config)
        .await
        .context("failed to start the proxy fetcher")?;
    {
        let mut state = live.lock().unwrap_or_else(|e| e.into_inner());
        state.gathered = Some(fetcher.accepted_handle());
    }
    relay_stages(live, fetcher.stage_events(), Phase::Gathering);
    set_phase(live, Phase::FetchingPrimary);

    let filter = ProxyFilter::from_options(&spec.output);
    let limit = spec.output.limit;
    let mut emitted = 0usize;
    while let Some(proxy) = fetcher.next().await {
        if !filter.matches(&proxy) {
            continue;
        }
        if tx.send(EngineEvent::Proxy(Box::new(proxy))).await.is_err() {
            break;
        }
        emitted += 1;
        if limit > 0 && emitted >= limit {
            break;
        }
    }

    let gathered = live.lock().unwrap_or_else(|e| e.into_inner()).gathered();
    Ok(RunSummary {
        gathered,
        valid: emitted,
        failed: 0,
        elapsed: started.elapsed(),
    })
}

async fn run_find(
    spec: &RunSpec,
    tx: &Sender<EngineEvent>,
    live: &Arc<Mutex<LiveState>>,
    started: Instant,
) -> anyhow::Result<RunSummary> {
    let options = spec
        .validator
        .as_ref()
        .context("find needs validator settings")?;

    let (mut type_quotas, groups) = split_type_requests(&options.types);
    if type_quotas.is_empty() && groups.is_empty() {
        type_quotas.push(TypeQuota::uncapped(Protocol::Http(Anonymity::Unknown)));
    }
    let protocols: Vec<Protocol> = type_quotas.iter().map(|quota| quota.protocol).collect();
    let quota_enforcer = Arc::new(Mutex::new(QuotaEnforcer::new(type_quotas)));
    {
        let mut enforcer = quota_enforcer.lock().unwrap_or_else(|e| e.into_inner());
        enforcer.set_has_groups(!groups.is_empty());
    }
    let has_quotas = quota_enforcer
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .has_any_quota();
    let probe_gate = pipeline::build_probe_gate(&quota_enforcer);
    let filter = ProxyFilter::from_options(&spec.output);
    let limit = spec.output.limit;

    let recordings: Arc<Mutex<Vec<Proxy>>> = Arc::default();
    let recorded_types: Arc<[Protocol]> = Arc::from(protocols.clone());

    let mut config = pipeline::validator_config(options, protocols.clone(), groups.clone(), false);
    config.probe_gate = probe_gate.clone();

    let mut validator = if !options.files.is_empty() {
        set_phase(live, Phase::CheckingJudges);
        let source = pipeline::file_source(&options.files).await?;
        let source = Box::pin(pipeline::tee_recorder(
            source,
            Arc::clone(&recordings),
            Arc::clone(&recorded_types),
        ));
        ProxyValidator::validate(source, config)
            .await
            .context("failed to start the proxy validator")?
    } else {
        set_phase(live, Phase::Preparing);
        let fetch_config = pipeline::fetcher_config(&spec.fetcher);
        let mut fetcher = ProxySource::from_fetcher(fetch_config)
            .await
            .context("failed to start the proxy fetcher")?;
        {
            let mut state = live.lock().unwrap_or_else(|e| e.into_inner());
            state.gathered = Some(fetcher.accepted_handle());
        }
        relay_stages(live, fetcher.stage_events(), Phase::CheckingJudges);
        let source = Box::pin(pipeline::tee_recorder(
            fetcher,
            Arc::clone(&recordings),
            Arc::clone(&recorded_types),
        ));
        ProxyValidator::validate(source, config)
            .await
            .context("failed to start the proxy validator")?
    };

    let progress = validator.progress();
    let health = validator.judge_health();
    {
        let mut state = live.lock().unwrap_or_else(|e| e.into_inner());
        state.progress = Some(progress.clone());
        state.gate = Some(validator.pause_gate());
        state.phase = Phase::ValidatingPass(1);
        state.phase_started = Instant::now();
    }
    let _ = tx
        .send(EngineEvent::JudgeHealth(Box::new(health.clone())))
        .await;
    if let Some(mut failures) = validator.take_failures() {
        let tx = tx.clone();
        tokio::spawn(async move {
            while let Some(failure) = failures.recv().await {
                if tx
                    .send(EngineEvent::Failure(Box::new(failure)))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    let mut emitted1 = 0usize;
    while let Some(proxy) = validator.next().await {
        if !filter.matches(&proxy) {
            continue;
        }
        match quota_decision(&proxy, &quota_enforcer) {
            QuotaDecision::Emit => {}
            QuotaDecision::Skip => continue,
            QuotaDecision::Stop => break,
        }
        if tx.send(EngineEvent::Proxy(Box::new(proxy))).await.is_err() {
            break;
        }
        emitted1 += 1;
        if limit > 0 && emitted1 >= limit {
            break;
        }
        if quotas_saturated(&quota_enforcer) {
            break;
        }
    }

    let p1_passed = progress.passed();
    let mut valid = emitted1;
    let mut failed = progress.done().saturating_sub(progress.passed());

    let fallback = pipeline::needs_fallback(
        has_quotas,
        &quota_enforcer,
        !groups.is_empty(),
        !protocols.is_empty(),
        limit,
        emitted1,
        p1_passed,
    );

    if fallback {
        let requested = protocols;
        let candidates: Vec<Proxy> =
            std::mem::take(&mut *recordings.lock().unwrap_or_else(|e| e.into_inner()));
        if !candidates.is_empty() {
            set_phase(live, Phase::ValidatingPass(2));
            let _ = tx.send(EngineEvent::PassChanged(2)).await;
            let limit2 = if limit > 0 {
                limit.saturating_sub(if has_quotas { emitted1 } else { p1_passed })
            } else {
                0
            };
            let mut config2 = pipeline::validator_config(options, requested, Vec::new(), true);
            config2.probe_gate = probe_gate.clone();
            let mut second =
                ProxyValidator::validate(futures_util::stream::iter(candidates), config2)
                    .await
                    .context("failed to start the fallback validator")?;
            {
                let mut state = live.lock().unwrap_or_else(|e| e.into_inner());
                state.progress = Some(second.progress());
                state.gate = Some(second.pause_gate());
            }

            let mut rows2 = 0usize;
            while let Some(proxy) = second.next().await {
                if !filter.matches(&proxy) {
                    continue;
                }
                match quota_decision(&proxy, &quota_enforcer) {
                    QuotaDecision::Emit => {}
                    QuotaDecision::Skip => continue,
                    QuotaDecision::Stop => break,
                }
                if tx.send(EngineEvent::Proxy(Box::new(proxy))).await.is_err() {
                    break;
                }
                rows2 += 1;
                if limit2 > 0 && rows2 >= limit2 {
                    break;
                }
                if quotas_saturated(&quota_enforcer) {
                    break;
                }
            }

            let pass_two = second.progress();
            valid += rows2;
            failed += pass_two.done().saturating_sub(pass_two.passed());
        }
    }

    let gathered = live.lock().unwrap_or_else(|e| e.into_inner()).gathered();
    Ok(RunSummary {
        gathered,
        valid,
        failed,
        elapsed: started.elapsed(),
    })
}

/// Builds a spec from the CLI defaults, for tests that need one.
#[cfg(test)]
pub(crate) fn test_spec(find: bool) -> RunSpec {
    use crate::argument::{Cli, Command};
    use clap::{CommandFactory as _, FromArgMatches as _};

    let subcommand = if find { "find" } else { "grab" };
    let matches = Cli::command()
        .try_get_matches_from(["flx", subcommand])
        .expect("defaults parse");
    let cli = Cli::from_arg_matches(&matches).expect("defaults read");
    match cli.command {
        Some(Command::Find(find)) => RunSpec {
            fetcher: find.fetcher,
            validator: Some(find.validator),
            output: find.output,
        },
        Some(Command::Grab(grab)) => RunSpec {
            fetcher: grab.fetcher,
            validator: None,
            output: grab.output,
        },
        _ => unreachable!("only find and grab carry a run spec"),
    }
}
