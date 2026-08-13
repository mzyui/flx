//! Validation progress status line, rendered to stderr.
//!
//! A single self-refreshing line shown while `flx find` runs. It stays on
//! stderr so stdout pipelines (`| jq`, `> file`, `-o`) are never contaminated.
//! The line only appears on a terminal and is suppressed by `--quiet`; colors
//! are dropped by `--no-color`.

use std::{
    fmt::{Display, Formatter},
    time::Instant,
};

use colored::Colorize;
use fluxy::ValidationProgress;
use status_line::StatusLine;

use crate::OutputGuard;

/// Width of the filled bar, in terminal cells.
const BAR_WIDTH: usize = 24;

/// Local timing state around the live [`ValidationProgress`] counters.
///
/// The counters are re-read from the shared handle on every redraw so the line
/// tracks the run; `Instant` plus the read-only handle satisfy the
/// `Send + Sync` bound `status-line` needs for its background thread.
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
        let elapsed = self.started.elapsed().as_secs_f64();

        let fraction = if total == 0 {
            0.0
        } else {
            done as f64 / total as f64
        };
        let filled = (fraction * BAR_WIDTH as f64).round() as usize;
        let rate = if elapsed > 0.0 {
            done as f64 / elapsed
        } else {
            0.0
        };
        let eta = if rate > 0.0 && done < total {
            Some((total - done) as f64 / rate)
        } else {
            None
        };

        let blocks = "█".repeat(filled);
        let dots = "░".repeat(BAR_WIDTH.saturating_sub(filled));

        if self.color {
            let bar = format!("{blocks}{dots}").cyan();
            let ok = format!("{passed} ok").green();
            write!(
                f,
                "{} ▐{bar}▌ {done}/{total} {:.0}%  {ok} ({rate:.0}/s)  {}",
                "Validating".cyan().bold(),
                fraction * 100.0,
                format_eta(eta),
            )
        } else {
            write!(
                f,
                "Validating ▐{blocks}{dots}▌ {done}/{total} {:.0}%  {passed} ok ({rate:.0}/s)  {}",
                fraction * 100.0,
                format_eta(eta),
            )
        }
    }
}

fn format_eta(secs: Option<f64>) -> String {
    match secs {
        Some(secs) => {
            let secs = secs.max(0.0) as u64;
            if secs >= 60 {
                format!("ETA {}m {:02}s", secs / 60, secs % 60)
            } else {
                format!("ETA {secs}s")
            }
        }
        None => "ETA --".to_owned(),
    }
}

/// Whether a status line should be shown at all.
///
/// Non-essential output is suppressed by `--quiet`, and there is no point
/// rendering to a redirected stderr.
fn show_progress(quiet: bool, stderr_is_terminal: bool) -> bool {
    !quiet && stderr_is_terminal
}

/// Renders the status line with ANSI colors unless `--no-color` was given.
fn use_color(no_color: bool) -> bool {
    !no_color
}

/// Owns a validation status line for the duration of a `flx find` run.
///
/// The background thread from `status-line` repaints the line periodically and
/// `Drop` erases it, so keeping this value alive is all that is needed.
pub struct ValidationBar {
    _status: StatusLine<Frame>,
    guards_stdout: bool,
}

impl ValidationBar {
    /// Starts the status line, or returns `None` when it should stay hidden.
    pub fn new(progress: ValidationProgress, quiet: bool, no_color: bool) -> Option<Self> {
        use std::io::IsTerminal as _;

        if !show_progress(quiet, std::io::stderr().is_terminal()) {
            return None;
        }
        // `colored` decides by the stdout TTY, but the bar paints on stderr, so
        // force the color choice from `--no-color` for the rest of the run.
        colored::control::set_override(use_color(no_color));
        let status = StatusLine::new(Frame::new(progress, use_color(no_color)));
        Some(Self {
            _status: status,
            guards_stdout: std::io::stdout().is_terminal(),
        })
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
        // Only a shared terminal needs coordination; a redirected stdout
        // (pipe/file) never touches the line the bar is drawn on.
        if self.guards_stdout {
            self.hide();
        }
    }

    fn after_write(&self) {
        if self.guards_stdout {
            self.show();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{format_eta, show_progress, use_color, Frame, BAR_WIDTH};
    use fluxy::ValidationProgress;

    #[test]
    fn progress_is_hidden_when_quiet_or_not_a_terminal() {
        assert!(show_progress(false, true));
        assert!(!show_progress(true, true));
        assert!(!show_progress(false, false));
    }

    #[test]
    fn color_follows_no_color_flag() {
        assert!(use_color(false));
        assert!(!use_color(true));
    }

    #[test]
    fn frame_renders_layout_with_counters_and_bar() {
        let frame = Frame::new(ValidationProgress::default(), false);
        let rendered = frame.to_string();

        assert!(rendered.contains("Validating ▐"));
        assert!(rendered.contains("▌ 0/0 0%"));
        assert!(rendered.contains("0 ok"));
        assert!(rendered.contains("ETA --"));
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

    #[test]
    fn bar_width_is_bounded() {
        let frame = Frame::new(ValidationProgress::default(), false);
        let rendered = frame.to_string();
        let inside = rendered
            .split_once("▐")
            .and_then(|(_, rest)| rest.split_once('▌'))
            .map(|(bar, _)| bar)
            .expect("bar delimiters present");
        assert_eq!(inside.chars().count(), BAR_WIDTH);
    }

    #[test]
    fn eta_renders_minutes_and_seconds() {
        assert_eq!(format_eta(None), "ETA --");
        assert_eq!(format_eta(Some(42.0)), "ETA 42s");
        assert_eq!(format_eta(Some(130.0)), "ETA 2m 10s");
    }
}
