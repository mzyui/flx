//! Repaint status lines on stderr at a fixed cadence.

use std::fmt::Display;
use std::io::{IsTerminal as _, Write};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Erase to screen end, return to line start, then step up per newline.
const ERASE_DOWN: &str = "\x1b[J";
const CURSOR_LEFT: &str = "\x1b[1000D";
const CURSOR_PREV_LINE: &str = "\x1b[F";

fn redraw_to(writer: &mut impl Write, ansi: bool, state: &impl Display) {
    let contents = state.to_string();
    if ansi {
        let line_count = contents.chars().filter(|c| *c == '\n').count();
        let _ = write!(writer, "{ERASE_DOWN}{contents}{CURSOR_LEFT}");
        for _ in 0..line_count {
            let _ = write!(writer, "{CURSOR_PREV_LINE}");
        }
    } else {
        let _ = writeln!(writer, "{contents}");
    }
}

fn redraw(ansi: bool, state: &impl Display) {
    redraw_to(&mut std::io::stderr().lock(), ansi, state);
}

fn clear_to(writer: &mut impl Write, ansi: bool) {
    if ansi {
        let _ = write!(writer, "{ERASE_DOWN}");
    }
}

fn clear(ansi: bool) {
    clear_to(&mut std::io::stderr().lock(), ansi);
}

/// Control how the status line renders.
pub struct Options {
    pub refresh_period: Duration,
    pub initially_visible: bool,
    pub enable_ansi_escapes: bool,
}

impl Default for Options {
    fn default() -> Self {
        let is_tty = std::io::stderr().is_terminal();
        Self {
            refresh_period: Duration::from_millis(if is_tty { 100 } else { 1000 }),
            initially_visible: true,
            enable_ansi_escapes: is_tty,
        }
    }
}

struct State<D> {
    data: D,
    visible: AtomicBool,
}

/// Repaint displayable data on stderr periodically.
pub struct StatusLine<D: Display> {
    state: Arc<State<D>>,
    options: Options,
}

impl<D: Display + Send + Sync + 'static> StatusLine<D> {
    /// Create a status line with default options.
    pub fn new(data: D) -> StatusLine<D> {
        Self::with_options(data, Options::default())
    }

    /// Create a status line with custom options.
    pub fn with_options(data: D, options: Options) -> StatusLine<D> {
        let state = Arc::new(State {
            data,
            visible: AtomicBool::new(options.initially_visible),
        });
        let state_ref = Arc::clone(&state);
        thread::spawn(move || {
            // Stop when the StatusLine drops its last external reference.
            while Arc::strong_count(&state_ref) > 1 {
                if state_ref.visible.load(Ordering::Acquire) {
                    redraw(options.enable_ansi_escapes, &state_ref.data);
                }
                thread::sleep(options.refresh_period);
            }
        });
        StatusLine { state, options }
    }
}

impl<D: Display> StatusLine<D> {
    /// Repaint immediately without waiting for the cadence.
    pub fn refresh(&self) {
        redraw(self.options.enable_ansi_escapes, &self.state.data);
    }

    /// Show or hide the status line.
    pub fn set_visible(&self, visible: bool) {
        let was_visible = self.state.visible.swap(visible, Ordering::Release);
        if !visible && was_visible {
            clear(self.options.enable_ansi_escapes);
        } else if visible && !was_visible {
            redraw(self.options.enable_ansi_escapes, &self.state.data);
        }
    }

    pub fn is_visible(&self) -> bool {
        self.state.visible.load(Ordering::Acquire)
    }
}

impl<D: Display> Deref for StatusLine<D> {
    type Target = D;

    fn deref(&self) -> &Self::Target {
        &self.state.data
    }
}

impl<D: Display> Drop for StatusLine<D> {
    fn drop(&mut self) {
        if self.is_visible() {
            clear(self.options.enable_ansi_escapes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_redraw_erases_then_rewrites() {
        let mut out = Vec::new();
        redraw_to(&mut out, true, &"ok");
        assert_eq!(out, b"\x1b[Jok\x1b[1000D");
    }

    #[test]
    fn ansi_redraw_multiline_walks_back_per_newline() {
        let mut out = Vec::new();
        redraw_to(&mut out, true, &"a\nb\nc");
        assert_eq!(out, b"\x1b[Ja\nb\nc\x1b[1000D\x1b[F\x1b[F");
    }

    #[test]
    fn plain_redraw_prints_full_line() {
        let mut out = Vec::new();
        redraw_to(&mut out, false, &"ok");
        assert_eq!(out, b"ok\n");
    }

    #[test]
    fn clear_emits_erase_only_with_ansi() {
        let mut out = Vec::new();
        clear_to(&mut out, true);
        assert_eq!(out, b"\x1b[J");
        out.clear();
        clear_to(&mut out, false);
        assert!(out.is_empty());
    }
}
