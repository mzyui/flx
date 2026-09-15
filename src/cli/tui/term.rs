//! Terminal lifecycle for the interactive TUI.
//!
//! Ratatui owns raw mode, the alternate screen, and its own restore-on-panic
//! hook, so this module only adds what the managed API leaves open: the cursor,
//! mouse capture, and an escape hatch for forced exits (`force_restore`) that
//! cannot rely on `Drop` running.

use std::io;
use std::sync::Mutex;

use anyhow::Context as _;
use crossterm::cursor::{Hide, Show};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use ratatui::DefaultTerminal;

pub(crate) type Tui = DefaultTerminal;

/// Set while a guard is alive so forced exits can still restore the terminal.
static RESTORE: Mutex<Option<fn()>> = Mutex::new(None);

/// Restores the terminal for callers that cannot rely on `Drop`.
pub(crate) fn force_restore() {
    let restore = *RESTORE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(restore) = restore {
        restore();
    }
}

/// Leaves mouse reporting, raw mode, and the alternate screen, then shows the
/// cursor again.
///
/// `ratatui::restore` owns raw mode and the screen but neither mouse capture
/// nor cursor visibility, and either would outlive the alternate screen.
fn restore() {
    let _ = execute!(io::stdout(), DisableMouseCapture);
    ratatui::restore();
    let _ = execute!(io::stdout(), Show);
}

/// Turns mouse reporting off on a panic, before Ratatui restores the screen.
///
/// Installed *before* `try_init`, which wraps whatever hook it finds: Ratatui
/// then restores raw mode and the screen after this runs. A hook installed
/// afterwards would be too late to leave mouse reporting off.
fn install_panic_cleanup() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(io::stdout(), DisableMouseCapture);
        previous(info);
    }));
}

/// Owns raw mode, the alternate screen, the cursor, and mouse reporting.
pub(crate) struct TerminalGuard {
    terminal: Tui,
}

impl TerminalGuard {
    pub(crate) fn new() -> anyhow::Result<Self> {
        install_panic_cleanup();
        let terminal = ratatui::try_init().context("failed to open the terminal")?;
        // Cursor hiding and mouse capture are not part of the managed init.
        let _ = execute!(io::stdout(), Hide, EnableMouseCapture);
        *RESTORE.lock().unwrap_or_else(|e| e.into_inner()) = Some(restore);
        Ok(Self { terminal })
    }

    pub(crate) fn terminal_mut(&mut self) -> &mut Tui {
        &mut self.terminal
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
        *RESTORE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}
