//! Terminal lifecycle for the interactive TUI.
//!
//! The inline viewport is constructed directly so cleanup can restore raw mode
//! without sending an alternate-screen escape sequence. This module also owns
//! the cursor, mouse capture, and an escape hatch for forced exits
//! (`force_restore`) that cannot rely on `Drop` running.

use std::io::{self, Write as _};
use std::sync::Mutex;

use anyhow::Context as _;
use crossterm::cursor::{Hide, MoveToColumn, Show};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::backend::Backend;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Position;
use ratatui::{DefaultTerminal, Terminal, TerminalOptions, Viewport};

/// Fixed height keeps the live UI bounded while preserving the shell scrollback.
pub(crate) const INLINE_HEIGHT: u16 = 12;

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

/// Leaves mouse reporting and raw mode, then shows the cursor again.
fn restore_terminal_state() {
    let _ = execute!(io::stdout(), DisableMouseCapture);
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), Show);
    let _ = io::stdout().flush();
}

/// Restores terminal state when the cursor position is unknown (forced exit,
/// panic): best effort move to a fresh line so the shell prompt does not land
/// on top of the last UI row.
fn restore() {
    restore_terminal_state();
    // The cursor may sit mid-line inside the viewport; column 0 + newline puts
    // the shell on a fresh line even without viewport geometry.
    let _ = execute!(io::stdout(), MoveToColumn(0));
    let _ = writeln!(io::stdout());
    let _ = io::stdout().flush();
}

/// Moves the cursor to the first line below the inline viewport.
///
/// Without this the shell prompt prints on the footer's row: ratatui leaves
/// the cursor wherever the last frame put it (usually hidden inside the
/// viewport), and showing the cursor does not move it.
fn move_below_viewport(terminal: &mut Tui) {
    let viewport = terminal.get_frame().area();
    if viewport.height == 0 {
        let _ = execute!(io::stdout(), MoveToColumn(0));
        let _ = writeln!(io::stdout());
        let _ = io::stdout().flush();
        return;
    }
    // Anchor to the last viewport row (always in bounds), then feed one
    // newline: with room below it lands on the blank line after the UI,
    // at the bottom edge it scrolls exactly one line up. This avoids both
    // failure modes of the old split path — `MoveTo(0, bottom)` is the
    // exclusive edge (out of bounds when the viewport touches the bottom
    // and may be ignored, leaving the prompt glued to the footer), while
    // `append_lines` alone prints at the current cursor, mid-viewport.
    let mut last_row = viewport.bottom().saturating_sub(1);
    if let Ok(size) = terminal.size() {
        if size.height > 0 {
            last_row = last_row.min(size.height.saturating_sub(1));
        }
    }
    let _ = terminal.set_cursor_position(Position::new(0, last_row));
    let _ = terminal.backend_mut().append_lines(1);
    let _ = execute!(io::stdout(), MoveToColumn(0));
    let _ = Backend::flush(terminal.backend_mut());
    let _ = io::stdout().flush();
}

/// Restores terminal state before delegating to the previous panic hook.
fn install_panic_cleanup() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore();
        previous(info);
    }));
}

/// Owns raw mode, the inline viewport, the cursor, and mouse reporting.
pub(crate) struct TerminalGuard {
    terminal: Tui,
}

impl TerminalGuard {
    pub(crate) fn new() -> anyhow::Result<Self> {
        install_panic_cleanup();
        enable_raw_mode().context("failed to enable raw mode")?;
        let terminal = match Terminal::with_options(
            CrosstermBackend::new(io::stdout()),
            TerminalOptions {
                viewport: Viewport::Inline(INLINE_HEIGHT),
            },
        ) {
            Ok(terminal) => terminal,
            Err(error) => {
                let _ = disable_raw_mode();
                return Err(anyhow::Error::new(error).context("failed to open the terminal"));
            }
        };
        // Cursor hiding and mouse capture are not part of terminal construction.
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
        // Position first while raw mode still holds, then restore modes: the
        // cursor ends on the line below the UI, so no extra newline is needed.
        move_below_viewport(&mut self.terminal);
        restore_terminal_state();
        *RESTORE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}
