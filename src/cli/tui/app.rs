//! Application state and action handling.
//!
//! `handle_action`, `on_engine_event`, and `on_tick` are the update half of the
//! loop and touch no terminal; the render half only reads state back out. That
//! split is what lets the interaction tests drive the app without a backend.

use std::time::{Duration, Instant};

use flx::proxy::models::Proxy;
use tokio::sync::mpsc::Sender;

use super::engine::{self, EngineEvent, RunHandle, RunSpec, RunSummary};
use super::event::{Action, InputPurpose, KeyContext, Screen};
use super::view::{self, RowModel, ViewState};

/// Upper bound on rows kept in memory for browsing and export.
const MAX_RESULTS: usize = 20_000;
/// Upper bound on remembered probe failures.
const MAX_FAILURE_LOG: usize = 64;
/// Rows moved by page-up/page-down.
const PAGE_ROWS: usize = 10;
/// How often the rate is resampled; a coarse cadence keeps it from jittering.
const RATE_SAMPLE_SECS: f64 = 0.5;
/// How long an ephemeral status line stays before it fades.
const MESSAGE_TTL: Duration = Duration::from_secs(6);
const EXPORT_FORMATS: [&str; 8] = [
    "default",
    "text",
    "json",
    "pretty-json",
    "json-lines",
    "csv",
    "prefix",
    "proxychains",
];

/// How loud a status line is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MessageKind {
    Info,
    Warning,
    Error,
}

/// One ephemeral status line, with the moment it appeared so it can fade.
pub(crate) struct Message {
    pub(crate) text: String,
    pub(crate) kind: MessageKind,
    shown_at: Instant,
}

/// An active text prompt (filter or export path).
pub(crate) struct InputBox {
    pub(crate) purpose: InputPurpose,
    pub(crate) buffer: String,
    pub(crate) original: String,
    pub(crate) options: Vec<String>,
    pub(crate) selected: usize,
}

/// What a `y/N` prompt will do once confirmed.
pub(crate) enum ConfirmKind {
    /// Overwrite the file already at this path.
    OverwriteExport(String),
    /// Abort the in-flight run.
    CancelRun,
}

/// A pending `y/N` question. Nothing irreversible happens until it is answered.
pub(crate) struct Confirm {
    pub(crate) question: String,
    pub(crate) kind: ConfirmKind,
}

pub(crate) struct App {
    pub(crate) screen: Screen,
    pub(crate) is_find: bool,
    pub(crate) view: ViewState,
    pub(crate) results: Vec<Proxy>,
    /// Rendered strings for `results`, kept index-aligned with it: both lists
    /// are only ever cleared together.
    pub(crate) rows: Vec<RowModel>,
    pub(crate) visible: Vec<usize>,
    pub(crate) overflow: usize,
    pub(crate) run: Option<RunHandle>,
    pub(crate) summary: Option<RunSummary>,
    pub(crate) health: Option<String>,
    pub(crate) failures: Vec<String>,
    pub(crate) input: Option<InputBox>,
    pub(crate) confirm: Option<Confirm>,
    pub(crate) help: bool,
    /// Rows the `?` panel is scrolled down; clamped to its content at render.
    pub(crate) help_scroll: u16,
    /// Detail lines are scrollable because the rich record exceeds the inline viewport.
    pub(crate) detail_scroll: u16,
    pub(crate) message: Option<Message>,
    pub(crate) should_quit: bool,
    pub(crate) started: Option<Instant>,
    /// When the run ended, which freezes the header's elapsed. `None` while it
    /// is still going.
    finished_at: Option<Instant>,
    pub(crate) cancelled: bool,
    pub(crate) rate: f64,
    /// Set by the first `g`, consumed by the next key.
    pending_g: bool,
    /// Digits typed so far, waiting for `G` to turn them into a row number.
    count: Option<usize>,
    /// True = selection sticks to the last row while the run is live.
    follow: bool,
    spec: RunSpec,
    tx: Option<Sender<EngineEvent>>,
    rate_mark: Option<(Instant, usize)>,
}

impl App {
    pub(crate) fn new(spec: RunSpec) -> Self {
        Self {
            screen: Screen::Running,
            is_find: spec.validator.is_some(),
            view: ViewState::default(),
            results: Vec::new(),
            rows: Vec::new(),
            visible: Vec::new(),
            overflow: 0,
            run: None,
            summary: None,
            health: None,
            failures: Vec::new(),
            input: None,
            confirm: None,
            help: false,
            help_scroll: 0,
            detail_scroll: 0,
            message: None,
            should_quit: false,
            started: None,
            finished_at: None,
            cancelled: false,
            rate: 0.0,
            pending_g: false,
            count: None,
            follow: true,
            spec,
            tx: None,
            rate_mark: None,
        }
    }

    /// Starts the first run over the configured spec.
    pub(crate) fn begin(&mut self, tx: Sender<EngineEvent>) {
        self.tx = Some(tx);
        self.begin_run();
    }

    fn begin_run(&mut self) {
        self.results.clear();
        self.rows.clear();
        self.visible.clear();
        self.overflow = 0;
        self.health = None;
        self.failures.clear();
        self.summary = None;
        self.cancelled = false;
        self.rate = 0.0;
        self.rate_mark = None;
        self.pending_g = false;
        self.count = None;
        self.finished_at = None;
        self.confirm = None;
        self.detail_scroll = 0;
        self.view.reset_position();
        self.follow = true;
        self.started = Some(Instant::now());
        self.run = self
            .tx
            .as_ref()
            .map(|tx| engine::spawn(self.spec.clone(), tx.clone()));
        self.screen = Screen::Running;
        self.message = None;
    }

    /// Label for the active pipeline (`find` or `grab`).
    pub(crate) fn mode_label(&self) -> &'static str {
        if self.is_find {
            "find"
        } else {
            "grab"
        }
    }

    pub(crate) fn key_context(&self) -> KeyContext {
        KeyContext {
            screen: self.screen,
            purpose: self.input.as_ref().map(|input| input.purpose),
            help: self.help,
            confirm: self.confirm.is_some(),
            pending_g: self.pending_g,
            count: self.count,
        }
    }

    /// Whether an overlay currently owns the keyboard and the focus ring.
    pub(crate) fn overlay_open(&self) -> bool {
        self.help || self.confirm.is_some() || self.input.is_some() || self.view.detail
    }

    /// Moves the selection to a browsed row, as a mouse click does.
    pub(crate) fn select_visible(&mut self, index: usize) {
        if index < self.visible.len() {
            self.follow = false;
            self.view.selected = index;
        }
    }

    fn info(&mut self, text: impl Into<String>) {
        self.set_message(text, MessageKind::Info);
    }

    fn warn(&mut self, text: impl Into<String>) {
        self.set_message(text, MessageKind::Warning);
    }

    fn fail(&mut self, text: impl Into<String>) {
        self.set_message(text, MessageKind::Error);
    }

    fn set_message(&mut self, text: impl Into<String>, kind: MessageKind) {
        self.message = Some(Message {
            text: text.into(),
            kind,
            shown_at: Instant::now(),
        });
    }

    pub(crate) fn handle_action(&mut self, action: Action) {
        self.pending_g = matches!(action, Action::PrefixG);
        if !matches!(action, Action::Count(_) | Action::GotoCount) {
            self.count = None;
        }

        if self.confirm.is_some() {
            self.handle_confirm(action);
            return;
        }
        if self.help {
            self.handle_help(action);
            return;
        }
        if self.input.is_some() {
            self.handle_typing(action);
            return;
        }
        if self.view.detail && self.handle_detail_scroll(action) {
            return;
        }

        let rows = self.visible.len();
        match action {
            Action::Interrupt => self.interrupt(),
            Action::ToggleHelp => {
                self.help_scroll = 0;
                self.help = true;
            }
            Action::Back => {
                if self.view.detail {
                    self.view.detail = false;
                } else if self.screen == Screen::Done {
                    self.should_quit = true;
                }
            }
            Action::PauseToggle => {
                if let Some(run) = &self.run {
                    run.toggle_pause();
                }
            }
            Action::CancelRun => {
                if self.screen == Screen::Running && self.run.is_some() {
                    self.confirm = Some(Confirm {
                        question: "cancel the run?".to_owned(),
                        kind: ConfirmKind::CancelRun,
                    });
                }
            }
            Action::SortCycle => {
                self.follow = false;
                self.view.cycle_sort();
                self.refresh_visible();
            }
            Action::OrderToggle => {
                self.follow = false;
                self.view.toggle_order();
                self.refresh_visible();
            }
            Action::EditFilter => {
                self.input = Some(InputBox {
                    purpose: InputPurpose::Filter,
                    buffer: self.view.filter.clone(),
                    original: self.view.filter.clone(),
                    options: Vec::new(),
                    selected: 0,
                });
            }
            Action::ClearFilter => {
                self.follow = false;
                self.view.filter.clear();
                self.view.reset_position();
                self.refresh_visible();
            }
            Action::Export => {
                let selected = EXPORT_FORMATS
                    .iter()
                    .position(|format| *format == self.spec.output.format)
                    .unwrap_or(0);
                self.input = Some(InputBox {
                    purpose: InputPurpose::ExportFormat,
                    buffer: EXPORT_FORMATS[selected].to_owned(),
                    original: String::new(),
                    options: EXPORT_FORMATS
                        .iter()
                        .map(|format| (*format).to_owned())
                        .collect(),
                    selected,
                });
            }
            Action::Rerun => self.begin_run(),
            Action::DrillIn => {
                self.view.detail = true;
                self.detail_scroll = 0;
            }
            Action::ToggleDetail => {
                self.view.detail = !self.view.detail;
                if self.view.detail {
                    self.detail_scroll = 0;
                }
            }
            Action::ScrollUp => {
                self.view.selected = self.view.selected.saturating_sub(1);
            }
            Action::ScrollDown => {
                self.view.selected = self.view.selected.saturating_add(1);
            }
            Action::PageUp => {
                self.view.selected = self.view.selected.saturating_sub(PAGE_ROWS);
            }
            Action::PageDown => {
                self.view.selected = self.view.selected.saturating_add(PAGE_ROWS);
            }
            Action::GotoTop => self.view.reset_position(),
            Action::GotoBottom => {
                self.view.selected = rows.saturating_sub(1);
            }
            Action::Count(digit) => self.push_count(digit),
            Action::GotoCount => self.goto_count(rows),
            Action::PrefixG
            | Action::Submit
            | Action::Cancel
            | Action::Backspace
            | Action::Text(_)
            | Action::ConfirmYes
            | Action::ConfirmNo => {}
        }
        view::clamp_selection(&mut self.view, rows);
        match action {
            Action::ScrollUp | Action::PageUp | Action::GotoTop | Action::GotoCount => {
                self.follow = false;
            }
            Action::ScrollDown | Action::PageDown => {
                self.follow = rows > 0 && self.view.selected + 1 >= rows;
            }
            Action::GotoBottom => self.follow = true,
            _ => {}
        }
    }

    /// Scrolls the rich detail record without moving the selected result row.
    fn handle_detail_scroll(&mut self, action: Action) -> bool {
        match action {
            Action::ScrollUp => self.detail_scroll = self.detail_scroll.saturating_sub(1),
            Action::ScrollDown => self.detail_scroll = self.detail_scroll.saturating_add(1),
            Action::PageUp => {
                self.detail_scroll = self.detail_scroll.saturating_sub(PAGE_ROWS as u16)
            }
            Action::PageDown => {
                self.detail_scroll = self.detail_scroll.saturating_add(PAGE_ROWS as u16)
            }
            Action::GotoTop => self.detail_scroll = 0,
            Action::GotoBottom => self.detail_scroll = u16::MAX,
            _ => return false,
        }
        true
    }

    /// The help panel owns the keyboard while it is open: it scrolls itself and
    /// nothing else, so a stray key cannot run a command from behind it.
    fn handle_help(&mut self, action: Action) {
        match action {
            Action::ToggleHelp => self.help = false,
            Action::ScrollUp => self.help_scroll = self.help_scroll.saturating_sub(1),
            Action::PageUp => self.help_scroll = self.help_scroll.saturating_sub(PAGE_ROWS as u16),
            Action::ScrollDown => self.help_scroll = self.help_scroll.saturating_add(1),
            Action::PageDown => {
                self.help_scroll = self.help_scroll.saturating_add(PAGE_ROWS as u16)
            }
            Action::GotoTop => self.help_scroll = 0,
            Action::GotoBottom => self.help_scroll = u16::MAX,
            _ => {}
        }
    }

    /// Appends a digit to the row number being typed.
    fn push_count(&mut self, digit: u8) {
        self.count = Some(
            self.count
                .unwrap_or(0)
                .saturating_mul(10)
                .saturating_add(usize::from(digit)),
        );
    }

    /// Moves the selection to the typed row number, 1-based as the table shows
    /// it, and clamps past-the-end numbers to the last row.
    fn goto_count(&mut self, rows: usize) {
        let Some(count) = self.count.take() else {
            return;
        };
        self.view.selected = count.saturating_sub(1).min(rows.saturating_sub(1));
    }

    /// Ctrl+C: stop a live run, otherwise leave. A second press therefore quits.
    fn interrupt(&mut self) {
        if self.screen == Screen::Running && self.run.is_some() {
            self.input = None;
            self.cancel_run();
        } else {
            self.should_quit = true;
        }
    }

    fn handle_confirm(&mut self, action: Action) {
        match action {
            Action::ConfirmYes => {
                let Some(confirm) = self.confirm.take() else {
                    return;
                };
                match confirm.kind {
                    ConfirmKind::CancelRun => self.cancel_run(),
                    ConfirmKind::OverwriteExport(path) => self.spawn_export(path),
                }
            }
            Action::ConfirmNo => self.confirm = None,
            Action::Interrupt => {
                self.confirm = None;
                self.interrupt();
            }
            _ => {}
        }
    }

    fn handle_typing(&mut self, action: Action) {
        if self
            .input
            .as_ref()
            .is_some_and(|input| input.purpose == InputPurpose::ExportFormat)
        {
            match action {
                Action::ScrollUp => self.shift_export_format(-1),
                Action::ScrollDown => self.shift_export_format(1),
                Action::Text(character) if character.is_ascii_digit() => {
                    if let Some(index) = character
                        .to_digit(10)
                        .and_then(|digit| digit.checked_sub(1))
                        .map(|digit| digit as usize)
                    {
                        if index < EXPORT_FORMATS.len() {
                            self.select_export_format(index);
                        }
                    }
                }
                Action::Submit => self.submit_input(),
                Action::Cancel => self.input = None,
                _ => {}
            }
            return;
        }

        match action {
            Action::Text(character) => {
                if let Some(input) = &mut self.input {
                    input.buffer.push(character);
                }
                self.refresh_filter_input();
            }
            Action::Backspace => {
                if let Some(input) = &mut self.input {
                    input.buffer.pop();
                }
                self.refresh_filter_input();
            }
            Action::Cancel => {
                let original = self
                    .input
                    .as_ref()
                    .filter(|input| input.purpose == InputPurpose::Filter)
                    .map(|input| input.original.clone());
                self.input = None;
                if let Some(original) = original {
                    self.view.filter = original;
                    self.refresh_visible();
                }
            }
            Action::Submit => self.submit_input(),
            _ => {}
        }
    }

    fn refresh_filter_input(&mut self) {
        let Some(filter) = self
            .input
            .as_ref()
            .filter(|input| input.purpose == InputPurpose::Filter)
            .map(|input| input.buffer.clone())
        else {
            return;
        };
        self.view.filter = filter;
        self.follow = false;
        self.view.reset_position();
        self.refresh_visible();
    }

    fn shift_export_format(&mut self, delta: isize) {
        let Some(input) = &mut self.input else {
            return;
        };
        let len = input.options.len();
        if len == 0 {
            return;
        }
        input.selected = (input.selected as isize + delta).rem_euclid(len as isize) as usize;
        input.buffer = input.options[input.selected].clone();
    }

    fn select_export_format(&mut self, selected: usize) {
        let Some(input) = &mut self.input else {
            return;
        };
        if selected < input.options.len() {
            input.selected = selected;
            input.buffer = input.options[selected].clone();
        }
    }

    fn submit_input(&mut self) {
        let Some(input) = self.input.take() else {
            return;
        };
        match input.purpose {
            InputPurpose::Filter => {
                self.view.filter = input.buffer.trim().to_owned();
                self.follow = false;
                self.view.reset_position();
                self.refresh_visible();
            }
            InputPurpose::ExportFormat => {
                self.spec.output.format = input.buffer;
                let path = self.default_export_path();
                self.input = Some(InputBox {
                    purpose: InputPurpose::ExportPath,
                    buffer: path,
                    original: String::new(),
                    options: Vec::new(),
                    selected: 0,
                });
            }
            InputPurpose::ExportPath => self.request_export(input.buffer.trim().to_owned()),
        }
    }

    /// Validation happens on submit, never per keystroke.
    fn request_export(&mut self, path: String) {
        if path.is_empty() {
            self.warn("export cancelled: empty path");
            return;
        }
        if std::path::Path::new(&path).exists() {
            self.confirm = Some(Confirm {
                question: format!("{path} exists — overwrite?"),
                kind: ConfirmKind::OverwriteExport(path),
            });
            return;
        }
        self.spawn_export(path);
    }

    /// Writes the browsed rows off the event loop, reporting back as a message.
    fn spawn_export(&mut self, path: String) {
        let format = self.spec.output.format.clone();
        let proxies: Vec<Proxy> = self
            .visible
            .iter()
            .filter_map(|index| self.results.get(*index).cloned())
            .collect();
        let count = proxies.len();
        let sender = self.tx.clone();
        self.info(format!("exporting {count} rows …"));
        tokio::task::spawn_blocking(move || {
            let borrowed: Vec<&Proxy> = proxies.iter().collect();
            let result = super::export::write(std::path::Path::new(&path), &format, &borrowed)
                .map_err(|error| format!("{error:#}"));
            if let Some(tx) = sender {
                let _ = tx.blocking_send(EngineEvent::ExportDone { path, result });
            }
        });
    }

    pub(crate) fn cancel_run(&mut self) {
        if let Some(run) = self.run.take() {
            run.cancel();
        }
        self.finish_run();
        self.cancelled = true;
        self.screen = Screen::Done;
        self.warn("cancelled");
    }

    /// Marks the run as over, which stops the header's clock: an elapsed time
    /// that kept climbing after the run ended would be a lie.
    fn finish_run(&mut self) {
        self.finished_at = Some(Instant::now());
    }

    pub(crate) fn on_engine_event(&mut self, event: EngineEvent) {
        match event {
            EngineEvent::Proxy(proxy) => {
                if self.results.len() < MAX_RESULTS {
                    self.rows.push(RowModel::new(&proxy));
                    self.results.push(*proxy);
                } else {
                    self.overflow += 1;
                }
            }
            EngineEvent::JudgeHealth(health) => {
                self.health = Some(format!(
                    "{}/{} judges healthy",
                    health.healthy, health.candidates
                ));
            }
            EngineEvent::PassChanged(pass) => {
                self.info(format!("validating pass {pass}"));
            }
            EngineEvent::Failure(failure) => {
                if self.failures.len() >= MAX_FAILURE_LOG {
                    self.failures.remove(0);
                }
                self.failures.push(format!(
                    "{}:{} {} — {}",
                    failure.ip, failure.port, failure.protocol, failure.reason
                ));
            }
            EngineEvent::ExportDone { path, result } => match result {
                Ok(count) => self.info(format!("exported {count} rows → {path}")),
                Err(error) => self.fail(format!("export failed: {error}")),
            },
            EngineEvent::Finished(summary) => {
                self.summary = Some(*summary);
                self.finish_run();
                self.run = None;
                self.screen = Screen::Done;
            }
            EngineEvent::Error(text) => {
                self.fail(text);
                self.finish_run();
                self.run = None;
                self.screen = Screen::Done;
            }
        }
    }

    pub(crate) fn on_tick(&mut self) {
        if let Some(message) = &self.message {
            if message.shown_at.elapsed() >= MESSAGE_TTL {
                self.message = None;
            }
        }
        self.refresh_visible();
        if self.follow && self.screen == Screen::Running && !self.visible.is_empty() {
            self.view.selected = self.visible.len() - 1;
        } else {
            view::clamp_selection(&mut self.view, self.visible.len());
        }
        self.update_rate();
    }

    fn update_rate(&mut self) {
        let Some(completed) = self.completed_probes() else {
            return;
        };
        let now = Instant::now();
        let Some((mark, previous)) = self.rate_mark else {
            self.rate_mark = Some((now, completed));
            return;
        };
        let seconds = now.duration_since(mark).as_secs_f64();
        if seconds < RATE_SAMPLE_SECS {
            return;
        }
        self.rate = completed.saturating_sub(previous) as f64 / seconds;
        self.rate_mark = Some((now, completed));
    }

    /// Probes the live run has finished, or `None` when nothing is running.
    fn completed_probes(&self) -> Option<usize> {
        let run = self.run.as_ref()?;
        let live = run.live.lock().unwrap_or_else(|e| e.into_inner());
        live.progress.as_ref().map(|progress| progress.done())
    }

    pub(crate) fn refresh_visible(&mut self) {
        let visible = view::visible(&self.rows, &self.view);
        self.visible = visible;
    }

    /// The selected row's full record, for the detail panel.
    pub(crate) fn selected_proxy(&self) -> Option<&Proxy> {
        self.visible
            .get(self.view.selected)
            .and_then(|index| self.results.get(*index))
    }

    pub(crate) fn live(&self) -> Option<std::sync::MutexGuard<'_, super::engine::LiveState>> {
        self.run
            .as_ref()
            .map(|run| run.live.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Wall-clock span of the current run, which stops when the run does.
    pub(crate) fn elapsed(&self) -> Duration {
        let Some(started) = self.started else {
            return Duration::ZERO;
        };
        let end = self.finished_at.unwrap_or_else(Instant::now);
        end.saturating_duration_since(started)
    }

    fn default_export_path(&self) -> String {
        let extension = match self.spec.output.format.as_str() {
            "json" | "pretty-json" => "json",
            "json-lines" => "jsonl",
            "csv" => "csv",
            "pac" => "pac",
            "proxychains" => "conf",
            _ => "txt",
        };
        format!("{}.{}", self.mode_label(), extension)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::engine::test_spec;
    use flx::{Protocol, ProxyType};
    use std::net::Ipv4Addr;

    fn app_with_results(count: usize) -> App {
        let mut app = App::new(test_spec(false));
        for slot in 0..count {
            let last = 1 + (slot % 254) as u8;
            let mut proxy = Proxy::new(Ipv4Addr::new(10, 0, 0, last), 8000 + slot as u16);
            proxy.proxy_types.push(ProxyType::checked(Protocol::Socks5));
            app.rows.push(RowModel::new(&proxy));
            app.results.push(proxy);
        }
        app.screen = Screen::Done;
        app.refresh_visible();
        app
    }

    #[test]
    fn rows_and_results_stay_index_aligned() {
        let app = app_with_results(5);
        assert_eq!(app.rows.len(), app.results.len());
    }

    fn summary(valid: usize, elapsed: Duration) -> RunSummary {
        RunSummary {
            gathered: valid,
            valid,
            failed: 0,
            elapsed,
        }
    }

    #[test]
    fn the_elapsed_timer_stops_when_the_run_ends() {
        let mut app = App::new(test_spec(true));
        app.started = Some(Instant::now() - Duration::from_secs(5));
        assert!(
            app.elapsed() >= Duration::from_secs(5),
            "the clock runs while the run does"
        );

        app.on_engine_event(EngineEvent::Finished(Box::new(summary(
            4,
            Duration::from_secs(5),
        ))));
        let stopped = app.elapsed();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            app.elapsed(),
            stopped,
            "a finished run's elapsed must not keep climbing"
        );
        assert!(stopped >= Duration::from_secs(5));
    }

    #[test]
    fn an_aborted_run_also_stops_the_clock() {
        let mut app = App::new(test_spec(true));
        app.started = Some(Instant::now() - Duration::from_secs(3));
        app.cancel_run();
        let cancelled = app.elapsed();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(app.elapsed(), cancelled, "cancelling stops the clock");

        let mut app = App::new(test_spec(true));
        app.started = Some(Instant::now() - Duration::from_secs(3));
        app.on_engine_event(EngineEvent::Error("no judges".to_owned()));
        let failed = app.elapsed();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(app.elapsed(), failed, "failing stops the clock");
    }

    #[test]
    fn the_clock_starts_again_on_the_next_run() {
        let mut app = App::new(test_spec(true));
        app.started = Some(Instant::now() - Duration::from_secs(5));
        app.on_engine_event(EngineEvent::Finished(Box::new(summary(
            1,
            Duration::from_secs(5),
        ))));

        app.handle_action(Action::Rerun);
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            app.elapsed() < Duration::from_secs(5),
            "a re-run starts a fresh clock, got {:?}",
            app.elapsed()
        );
    }

    #[test]
    fn a_finished_run_stops_sampling_the_rate() {
        let mut app = App::new(test_spec(true));
        app.on_engine_event(EngineEvent::Finished(Box::new(summary(
            4,
            Duration::from_secs(2),
        ))));
        app.rate = 12.5;
        app.on_tick();
        app.on_tick();

        assert_eq!(app.rate, 12.5, "a run that ended has no rate to recompute");
        assert!(
            app.rate_mark.is_none(),
            "and no sample is left waiting to be taken"
        );
    }

    #[test]
    fn a_typed_row_number_moves_the_selection_there() {
        let mut app = app_with_results(20);
        app.handle_action(Action::Count(1));
        app.handle_action(Action::Count(2));
        assert_eq!(app.key_context().count, Some(12));
        app.handle_action(Action::GotoCount);
        assert_eq!(app.view.selected, 11);

        assert_eq!(app.key_context().count, None);
        app.handle_action(Action::GotoCount);
        assert_eq!(app.view.selected, 11, "a second jump needs new digits");
    }

    #[test]
    fn a_row_number_beyond_the_list_lands_on_the_last_row() {
        let mut app = app_with_results(3);
        app.handle_action(Action::Count(9));
        app.handle_action(Action::Count(9));
        app.handle_action(Action::GotoCount);
        assert_eq!(
            app.view.selected, 2,
            "an out-of-range jump clamps instead of doing nothing"
        );

        app.handle_action(Action::Count(0));
        app.handle_action(Action::GotoCount);
        assert_eq!(app.view.selected, 0);
    }

    #[test]
    fn any_other_key_drops_a_half_typed_row_number() {
        let mut app = app_with_results(10);
        app.handle_action(Action::Count(7));
        app.handle_action(Action::ScrollDown);

        assert_eq!(app.key_context().count, None);
        app.handle_action(Action::GotoCount);
        assert_eq!(
            app.view.selected, 1,
            "the abandoned count must not jump anywhere"
        );
    }

    #[test]
    fn a_row_number_counts_rows_in_the_current_view() {
        let mut app = app_with_results(10);
        app.view.filter = "10.0.0.7".to_owned();
        app.refresh_visible();
        assert_eq!(app.visible.len(), 1);

        app.handle_action(Action::Count(5));
        app.handle_action(Action::GotoCount);
        assert_eq!(app.view.selected, 0);
    }

    #[test]
    fn rerunning_drops_a_half_typed_row_number() {
        let mut app = app_with_results(4);
        app.handle_action(Action::Count(3));
        app.handle_action(Action::Rerun);
        assert_eq!(app.key_context().count, None);
    }

    #[test]
    fn the_selection_clamps_after_every_action() {
        let mut app = app_with_results(3);
        app.handle_action(Action::GotoBottom);
        assert_eq!(app.view.selected, 2);
        app.handle_action(Action::PageDown);
        assert_eq!(app.view.selected, 2, "the cursor cannot leave the rows");

        app.handle_action(Action::GotoTop);
        assert_eq!(app.view.selected, 0);
        app.handle_action(Action::ScrollUp);
        assert_eq!(app.view.selected, 0, "scrolling up from the top is a no-op");
    }

    #[test]
    fn filter_updates_live_and_esc_restores_the_previous_query() {
        let mut app = app_with_results(4);
        app.view.filter = "10.0.0".to_owned();
        app.refresh_visible();
        app.handle_action(Action::EditFilter);
        app.handle_action(Action::Text('1'));
        assert_eq!(app.view.filter, "10.0.01");
        assert!(app.visible.len() < 4);
        app.handle_action(Action::Cancel);
        assert_eq!(app.view.filter, "10.0.0");
        assert_eq!(app.visible.len(), 4);
    }

    #[test]
    fn filtering_rebuilds_the_visible_list() {
        let mut app = app_with_results(4);
        app.handle_action(Action::EditFilter);
        for character in "10.0.0.1".chars() {
            app.handle_action(Action::Text(character));
        }
        app.handle_action(Action::Submit);
        assert_eq!(app.view.filter, "10.0.0.1");
        assert_eq!(app.visible, vec![0]);

        app.handle_action(Action::ClearFilter);
        assert_eq!(app.view.filter, "");
        assert_eq!(app.visible.len(), 4);
    }

    #[test]
    fn cancelling_a_prompt_leaves_the_filter_alone() {
        let mut app = app_with_results(4);
        app.handle_action(Action::EditFilter);
        app.handle_action(Action::Text('x'));
        app.handle_action(Action::Cancel);
        assert!(app.input.is_none());
        assert_eq!(app.view.filter, "", "an abandoned prompt changes nothing");
        assert_eq!(app.visible.len(), 4);
    }

    #[test]
    fn esc_closes_detail_before_it_leaves_the_screen() {
        let mut app = app_with_results(2);
        app.handle_action(Action::DrillIn);
        assert!(app.view.detail);
        app.handle_action(Action::Back);
        assert!(!app.view.detail, "the drill-down closes first");
        assert!(!app.should_quit);
        app.handle_action(Action::Back);
        assert!(app.should_quit, "a second Esc leaves the done screen");
    }

    #[test]
    fn d_toggles_the_drill_down() {
        let mut app = app_with_results(2);
        app.handle_action(Action::ToggleDetail);
        assert!(app.view.detail);
        app.handle_action(Action::ToggleDetail);
        assert!(!app.view.detail);
    }

    #[test]
    fn the_help_overlay_dismisses_on_its_own_key_only() {
        let mut app = app_with_results(2);
        app.handle_action(Action::ToggleHelp);
        assert!(app.help);
        app.handle_action(Action::ScrollDown);
        assert!(app.help, "other keys are swallowed while help is open");
        assert_eq!(app.view.selected, 0);
        app.handle_action(Action::ToggleHelp);
        assert!(!app.help);
    }

    #[tokio::test]
    async fn ctrl_c_cancels_a_live_run_then_quits_on_the_next_press() {
        let mut app = app_with_results(2);
        app.screen = Screen::Running;
        app.run = Some(crate::tui::engine::test_handle());
        app.handle_action(Action::Interrupt);
        assert_eq!(app.screen, Screen::Done);
        assert!(!app.should_quit, "the first press stops the run");

        app.handle_action(Action::Interrupt);
        assert!(app.should_quit, "the second press leaves");
    }

    #[test]
    fn export_opens_a_format_chooser_before_the_path_prompt() {
        let mut app = app_with_results(2);
        app.handle_action(Action::Export);
        assert_eq!(
            app.input.as_ref().map(|input| input.purpose),
            Some(InputPurpose::ExportFormat)
        );
        app.handle_action(Action::ScrollDown);
        assert_eq!(
            app.input.as_ref().map(|input| input.buffer.as_str()),
            Some("text")
        );
        app.handle_action(Action::Submit);
        assert_eq!(
            app.input.as_ref().map(|input| input.purpose),
            Some(InputPurpose::ExportPath)
        );
        assert_eq!(app.spec.output.format, "text");
    }

    #[test]
    fn an_empty_export_path_never_writes() {
        let mut app = app_with_results(2);
        app.handle_action(Action::Export);
        assert_eq!(
            app.input.as_ref().map(|input| input.purpose),
            Some(InputPurpose::ExportFormat)
        );
        app.handle_action(Action::Submit);
        let input = app.input.as_mut().expect("the path prompt is open");
        input.buffer.clear();
        app.handle_action(Action::Submit);
        let message = app.message.as_ref().expect("the refusal is reported");
        assert_eq!(message.kind, MessageKind::Warning);
        assert!(message.text.contains("empty path"), "got {}", message.text);
    }

    #[test]
    fn exporting_over_a_file_asks_before_overwriting() {
        let path = std::env::temp_dir().join(format!(
            "flx_tui_overwrite_{}_{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "already here").expect("the fixture is writable");

        let mut app = app_with_results(2);
        app.handle_action(Action::Export);
        app.handle_action(Action::Submit);
        let input = app.input.as_mut().expect("the path prompt is open");
        input.buffer = path.to_string_lossy().into_owned();
        app.handle_action(Action::Submit);

        let confirm = app.confirm.as_ref().expect("overwrite needs a yes");
        assert!(
            confirm.question.contains("overwrite"),
            "got {}",
            confirm.question
        );
        app.handle_action(Action::ConfirmNo);
        assert!(app.confirm.is_none());
        assert_eq!(
            std::fs::read_to_string(&path).expect("the file survives"),
            "already here",
            "declining must leave the existing file untouched"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn cancelling_a_run_asks_first_and_nothing_runs_until_then() {
        let mut app = app_with_results(0);
        app.screen = Screen::Running;
        app.run = Some(crate::tui::engine::test_handle());

        app.handle_action(Action::CancelRun);
        assert!(app.confirm.is_some(), "cancelling is confirmed");
        assert_eq!(app.screen, Screen::Running, "nothing happens on the prompt");

        app.handle_action(Action::ConfirmNo);
        assert!(app.confirm.is_none());
        assert_eq!(app.screen, Screen::Running);
        assert!(app.run.is_some(), "declining keeps the run alive");

        app.handle_action(Action::CancelRun);
        app.handle_action(Action::ConfirmYes);
        assert_eq!(app.screen, Screen::Done);
        assert!(app.run.is_none());
    }

    #[test]
    fn rerunning_clears_every_per_run_collection() {
        let mut app = app_with_results(4);
        app.overflow = 7;
        app.failures.push("10.0.0.9:80 http — timeout".to_owned());
        app.view.detail = true;
        app.view.selected = 3;

        app.handle_action(Action::Rerun);
        assert!(app.results.is_empty());
        assert!(app.rows.is_empty(), "the render cache is cleared with it");
        assert!(app.visible.is_empty());
        assert_eq!(app.overflow, 0);
        assert!(app.failures.is_empty());
        assert_eq!(app.view.selected, 0);
        assert_eq!(app.screen, Screen::Running);
    }

    #[test]
    fn the_overflow_cap_counts_instead_of_growing() {
        let mut app = App::new(test_spec(false));
        for slot in 0..MAX_RESULTS + 3 {
            let mut proxy = Proxy::new(Ipv4Addr::new(10, 0, 0, 1), 8000 + slot as u16);
            proxy.proxy_types.push(ProxyType::checked(Protocol::Socks5));
            app.on_engine_event(EngineEvent::Proxy(Box::new(proxy)));
        }
        assert_eq!(app.results.len(), MAX_RESULTS);
        assert_eq!(app.rows.len(), MAX_RESULTS);
        assert_eq!(app.overflow, 3);
    }

    #[test]
    fn the_failure_log_is_a_ring_buffer() {
        let mut app = App::new(test_spec(false));
        for slot in 0..MAX_FAILURE_LOG + 5 {
            app.on_engine_event(EngineEvent::Failure(Box::new(flx::ProxyFailure {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                port: 8000 + slot as u16,
                protocol: Protocol::Socks5,
                reason: format!("probe {slot}"),
            })));
        }
        assert_eq!(app.failures.len(), MAX_FAILURE_LOG);
        assert!(app.failures.last().expect("entries").contains("probe 68"));
    }

    #[test]
    fn a_finished_run_moves_to_the_done_screen() {
        let mut app = App::new(test_spec(true));
        app.on_engine_event(EngineEvent::Finished(Box::new(RunSummary {
            gathered: 10,
            valid: 4,
            failed: 6,
            elapsed: Duration::from_secs(2),
        })));
        assert_eq!(app.screen, Screen::Done);
        assert!(app.run.is_none());
        assert_eq!(app.summary.as_ref().expect("a summary").valid, 4);
    }

    #[test]
    fn an_engine_error_lands_as_a_status_line() {
        let mut app = App::new(test_spec(true));
        app.on_engine_event(EngineEvent::Error("no judges reachable".to_owned()));
        assert_eq!(app.screen, Screen::Done);
        let message = app.message.as_ref().expect("the error is shown");
        assert_eq!(message.kind, MessageKind::Error);
        assert_eq!(message.text, "no judges reachable");
    }

    #[test]
    fn export_receipts_arrive_as_status_lines() {
        let mut app = App::new(test_spec(false));
        app.on_engine_event(EngineEvent::ExportDone {
            path: "find.txt".to_owned(),
            result: Ok(12),
        });
        let message = app.message.as_ref().expect("the receipt is shown");
        assert_eq!(message.kind, MessageKind::Info);
        assert!(message.text.contains("12 rows"), "got {}", message.text);

        app.on_engine_event(EngineEvent::ExportDone {
            path: "find.txt".to_owned(),
            result: Err("permission denied".to_owned()),
        });
        assert_eq!(
            app.message.as_ref().expect("the failure is shown").kind,
            MessageKind::Error
        );
    }

    #[test]
    fn status_lines_fade_on_their_own() {
        let mut app = App::new(test_spec(false));
        app.info("exported 3 rows");
        assert!(app.message.is_some());
        app.on_tick();
        assert!(
            app.message.is_some(),
            "a fresh status line is still on screen"
        );

        let message = app.message.as_mut().expect("the status line");
        message.shown_at = Instant::now() - MESSAGE_TTL;
        app.on_tick();
        assert!(app.message.is_none(), "a stale status line fades");
    }

    #[test]
    fn the_export_path_default_follows_the_output_format() {
        let app = App::new(test_spec(false));
        assert_eq!(app.default_export_path(), "grab.txt");
        let app = App::new(test_spec(true));
        assert_eq!(app.default_export_path(), "find.txt");
    }

    fn push_proxy(app: &mut App, slot: usize) {
        let last = 1 + (slot % 254) as u8;
        let mut proxy = Proxy::new(Ipv4Addr::new(10, 0, 0, last), 8000 + slot as u16);
        proxy.proxy_types.push(ProxyType::checked(Protocol::Socks5));
        app.on_engine_event(EngineEvent::Proxy(Box::new(proxy)));
    }

    #[test]
    fn a_live_tick_pins_the_selection_to_the_last_row() {
        let mut app = app_with_results(3);
        app.screen = Screen::Running;
        app.on_tick();
        assert_eq!(app.view.selected, 2);
        push_proxy(&mut app, 3);
        push_proxy(&mut app, 4);
        app.on_tick();
        assert_eq!(app.view.selected, app.visible.len() - 1);
    }

    #[test]
    fn scrolling_up_breaks_the_follow() {
        let mut app = app_with_results(3);
        app.screen = Screen::Running;
        app.on_tick();
        app.handle_action(Action::ScrollUp);
        assert!(!app.follow);
        push_proxy(&mut app, 3);
        app.on_tick();
        assert_eq!(app.view.selected, 1);
        assert!(!app.follow);
    }

    #[test]
    fn going_to_the_bottom_rejoins_the_follow() {
        let mut app = app_with_results(3);
        app.screen = Screen::Running;
        app.handle_action(Action::ScrollUp);
        app.handle_action(Action::GotoBottom);
        assert!(app.follow);
        push_proxy(&mut app, 3);
        app.on_tick();
        assert_eq!(app.view.selected, app.visible.len() - 1);
        assert!(app.follow);
    }

    #[test]
    fn rerunning_rejoins_the_follow() {
        let mut app = app_with_results(4);
        app.follow = false;
        app.handle_action(Action::Rerun);
        assert!(app.follow);
        assert_eq!(app.view.selected, 0);
    }
}
