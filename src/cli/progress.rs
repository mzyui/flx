//! Validation progress status line.

use std::{
    fmt::{Display, Formatter},
    time::Instant,
};

use colored::Colorize;
use fluxy::ValidationProgress;
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

fn show_progress(quiet: bool, stderr_is_terminal: bool, stdout_is_terminal: bool) -> bool {
    !quiet && stderr_is_terminal && stdout_is_terminal
}

fn use_color(no_color: bool) -> bool {
    !no_color
}

pub struct ValidationBar {
    _status: StatusLine<Frame>,
}

impl ValidationBar {
    pub fn new(progress: ValidationProgress, quiet: bool, no_color: bool) -> Option<Self> {
        use std::io::IsTerminal as _;

        if !show_progress(
            quiet,
            std::io::stderr().is_terminal(),
            std::io::stdout().is_terminal(),
        ) {
            return None;
        }
        // `colored` decides by the stdout TTY, but the bar paints on stderr, so
        // force the color choice from `--no-color` for the rest of the run.
        colored::control::set_override(use_color(no_color));
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

#[cfg(test)]
mod tests {
    use super::{show_progress, use_color, Frame};
    use fluxy::ValidationProgress;

    #[test]
    fn progress_is_hidden_when_quiet_or_not_a_terminal() {
        assert!(show_progress(false, true, true));
        assert!(!show_progress(true, true, true));
        assert!(!show_progress(false, false, true));
        // A piped stdout means a downstream process owns the terminal; the bar
        // must stay quiet there.
        assert!(!show_progress(false, true, false));
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
