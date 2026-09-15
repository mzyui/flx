//! Interactive TUI for `find` and `grab`, opened with `--tui`.
//!
//! The run is configured entirely by CLI flags, so the TUI starts the pipeline
//! as soon as it opens, reports it live, then hands over to the results browser.

mod app;
mod engine;
mod event;
mod export;
mod term;
mod theme;
mod ui;
mod view;

use std::time::Duration;

use crossterm::event::{Event, EventStream, MouseButton, MouseEventKind};
use futures_util::StreamExt as _;
use ratatui::layout::Rect;
use tokio::sync::mpsc;

use crate::RunOutcome;

use self::app::App;
use self::engine::ENGINE_CHANNEL_CAPACITY;
use self::event::{action_for, Action};
use self::term::TerminalGuard;

pub(crate) use self::engine::RunSpec;
pub(crate) use self::term::force_restore;

/// Repaint cadence; also drives the rate sampling and the status-line fade.
const TICK_INTERVAL: Duration = Duration::from_millis(100);

/// Everything the TUI needs: how to color it, and what to run.
pub(crate) struct TuiCtx {
    pub(crate) no_color: bool,
    pub(crate) spec: RunSpec,
}

/// Whether a TUI can be shown: both stdin and stdout must be terminals.
pub(crate) fn is_interactive() -> bool {
    use crossterm::tty::IsTty as _;
    if std::env::var("TERM").is_ok_and(|term| term == "dumb") {
        return false;
    }
    std::io::stdin().is_tty() && std::io::stdout().is_tty()
}

/// Resolves when the process is asked to stop, or never on platforms without
/// these signals.
///
/// A signal cannot unwind Rust cleanup, so it becomes an ordinary quit event:
/// the loop boundary then restores the terminal exactly like a keypress does.
async fn wait_for_termination() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let terminate = signal(SignalKind::terminate()).ok();
        let interrupt = signal(SignalKind::interrupt()).ok();
        match (terminate, interrupt) {
            (Some(mut terminate), Some(mut interrupt)) => {
                tokio::select! {
                    _ = terminate.recv() => {}
                    _ = interrupt.recv() => {}
                }
            }
            (Some(mut terminate), None) => {
                terminate.recv().await;
            }
            (None, Some(mut interrupt)) => {
                interrupt.recv().await;
            }
            // No handler could be installed; never resolve rather than lie.
            (None, None) => std::future::pending::<()>().await,
        }
    }
    #[cfg(not(unix))]
    {
        // Windows has no SIGTERM, and a raw-mode process never sees Ctrl+C as
        // a signal, so there is nothing to watch here.
        std::future::pending::<()>().await;
    }
}

/// Runs the workbench until the user quits.
pub(crate) async fn run(ctx: TuiCtx) -> anyhow::Result<RunOutcome> {
    let TuiCtx { no_color, spec } = ctx;
    theme::configure(no_color, theme::detect_ascii());
    let mut guard = TerminalGuard::new()?;
    let mut app = App::new(spec);
    let (tx, mut rx) = mpsc::channel(ENGINE_CHANNEL_CAPACITY);
    app.begin(tx.clone());
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(TICK_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    while !app.should_quit {
        // The frame's area is what maps a click back to a row.
        let area = guard
            .terminal_mut()
            .draw(|frame| ui::render(frame, &app))?
            .area;
        tokio::select! {
            event = events.next() => match event {
                Some(Ok(Event::Key(key))) => {
                    if let Some(action) = action_for(key, app.key_context()) {
                        app.handle_action(action);
                    }
                }
                Some(Ok(Event::Mouse(mouse))) => handle_mouse(&mut app, area, mouse),
                Some(Ok(_)) => {}
                _ => app.should_quit = true,
            },
            Some(engine_event) = rx.recv() => app.on_engine_event(engine_event),
            _ = tick.tick() => app.on_tick(),
            _ = wait_for_termination() => app.should_quit = true,
        }
    }
    Ok(RunOutcome::Finished)
}

/// Mouse input only accelerates the keyboard, and only on the browse surface:
/// an overlay owns the frame while it is open.
fn handle_mouse(app: &mut App, area: Rect, mouse: crossterm::event::MouseEvent) {
    if app.overlay_open() {
        return;
    }
    match mouse.kind {
        MouseEventKind::ScrollUp => app.handle_action(Action::ScrollUp),
        MouseEventKind::ScrollDown => app.handle_action(Action::ScrollDown),
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(index) = ui::row_at(app, area, mouse.row) {
                app.select_visible(index);
            }
        }
        _ => {}
    }
}
