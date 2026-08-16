//! Validation progress status line.

use std::{
    fmt::{Display, Formatter},
    sync::{Arc, Mutex},
    time::Instant,
};

use colored::Colorize;
use flx::ValidationProgress;
use status_line::StatusLine;

use crate::OutputGuard;

struct Frame {
    progress: ValidationProgress,
    started: Instant,
    color: bool,
}

impl Frame {
    fn new(progress: ValidationProgress, color: bool) -> Self {
        Self {
            progress,
            started: Instant::now(),
            color,
        }
    }
}

impl Display for Frame {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let done = self.progress.done();
        let total = self.progress.total();
        let passed = self.progress.passed();
        let failed = done.saturating_sub(passed);
        let elapsed = self.started.elapsed().as_secs_f64();

        let rate = if elapsed > 0.0 {
            done as f64 / elapsed
        } else {
            0.0
        };

        if self.color {
            let valid = format!("{passed} valid").green();
            let fail = format!("{failed} fail").red();
            write!(
                f,
                "{} {done}/{total}  {valid} · {fail} ({rate:.0}/s)",
                "Validating".cyan().bold(),
            )
        } else {
            write!(
                f,
                "Validating {done}/{total}  {passed} valid · {failed} fail ({rate:.0}/s)",
            )
        }
    }
}

fn show_progress(quiet: bool, stderr_is_terminal: bool, stdout_is_pipe: bool) -> bool {
    !quiet && stderr_is_terminal && !stdout_is_pipe
}

fn use_color(no_color: bool) -> bool {
    !no_color
}

pub struct ValidationBar {
    _status: StatusLine<Frame>,
}

impl ValidationBar {
    pub fn new(
        progress: ValidationProgress,
        quiet: bool,
        no_color: bool,
        stdout_is_pipe: bool,
    ) -> Option<Self> {
        use std::io::IsTerminal as _;

        if !show_progress(quiet, std::io::stderr().is_terminal(), stdout_is_pipe) {
            return None;
        }
        // The global `colored` override is set once in `run_application`, so
        // the bar respects `--no-color` like the end-of-run summary.
        let status = StatusLine::new(Frame::new(progress, use_color(no_color)));
        Some(Self { _status: status })
    }

    fn hide(&self) {
        self._status.set_visible(false);
    }

    fn show(&self) {
        self._status.set_visible(true);
    }
}

impl OutputGuard for ValidationBar {
    fn before_write(&self) {
        // The bar only exists when stdout reaches the same terminal, so every
        // stdout write needs the line hidden until it is flushed.
        self.hide();
    }

    fn after_write(&self) {
        self.show();
    }
}

/// Repaintable warmup phase line shown before the validation bar takes over.
pub struct WarmupBar {
    status: StatusLine<WarmupFrame>,
    phase: Arc<Mutex<&'static str>>,
}

struct WarmupFrame {
    phase: Arc<Mutex<&'static str>>,
    color: bool,
}

impl Display for WarmupFrame {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let phase = self.phase.lock().unwrap_or_else(|e| e.into_inner());
        if self.color {
            write!(f, "{}", phase.bold().cyan())
        } else {
            write!(f, "{phase}")
        }
    }
}

impl WarmupBar {
    pub fn new(quiet: bool, no_color: bool, stdout_is_pipe: bool) -> Option<Self> {
        use std::io::IsTerminal as _;

        if !show_progress(quiet, std::io::stderr().is_terminal(), stdout_is_pipe) {
            return None;
        }
        let phase = Arc::new(Mutex::new("Warming up …"));
        let frame = WarmupFrame {
            phase: Arc::clone(&phase),
            color: use_color(no_color),
        };
        let status = StatusLine::with_options(frame, status_line::Options::default());
        Some(Self { status, phase })
    }

    pub fn set_phase(&self, phase: &'static str) {
        *self.phase.lock().unwrap_or_else(|e| e.into_inner()) = phase;
    }
}

impl OutputGuard for WarmupBar {
    fn before_write(&self) {
        self.status.set_visible(false);
    }

    fn after_write(&self) {
        self.status.set_visible(true);
    }
}

#[cfg(test)]
mod tests {
    use super::{show_progress, use_color, Frame, WarmupFrame};
    use flx::ValidationProgress;
    use std::sync::{Arc, Mutex};

    #[test]
    fn warmup_frame_renders_current_phase() {
        let frame = WarmupFrame {
            phase: Arc::new(Mutex::new("Fetching primary sources …")),
            color: false,
        };
        assert!(frame.to_string().contains("Fetching primary sources"));
    }

    #[test]
    fn progress_is_hidden_when_quiet_or_stdout_is_piped() {
        assert!(show_progress(false, true, false));
        assert!(!show_progress(true, true, false));
        assert!(!show_progress(false, false, false));
        // A piped stdout means a downstream process owns the terminal; the bar
        // must stay quiet there. Redirecting to a regular file keeps the bar.
        assert!(!show_progress(false, true, true));
    }

    #[test]
    fn color_follows_no_color_flag() {
        assert!(use_color(false));
        assert!(!use_color(true));
    }

    #[test]
    fn frame_renders_layout_with_counters() {
        let frame = Frame::new(ValidationProgress::default(), false);
        let rendered = frame.to_string();

        assert!(rendered.starts_with("Validating "));
        assert!(rendered.contains(" 0/0 "));
        assert!(rendered.contains("0 valid · 0 fail"));
        assert!(rendered.contains("0/s"));
        assert!(!rendered.contains('%'));
        assert!(!rendered.contains("ETA"));
        assert!(!rendered.contains('▐') && !rendered.contains('▌'));
    }

    #[test]
    fn frame_uses_ansi_codes_only_when_colored() {
        colored::control::set_override(false);
        let plain = Frame::new(ValidationProgress::default(), false).to_string();
        colored::control::set_override(true);
        let colored = Frame::new(ValidationProgress::default(), true).to_string();
        colored::control::set_override(false);

        assert!(!plain.contains('\x1b'));
        assert!(colored.contains('\x1b'));
    }
}
