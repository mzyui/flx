//! Validation progress status line.

use std::{
    fmt::{Display, Formatter},
    sync::{Arc, Mutex},
    time::Instant,
};

use colored::Colorize;
use flx::{DownloadProgress, ValidationProgress};
use status_line::StatusLine;
use tokio::sync::watch;

use crate::OutputGuard;

/// Current terminal width in columns, or `None` when it cannot be determined.
fn terminal_width() -> Option<usize> {
    #[cfg(unix)]
    {
        // SAFETY: `ws` is a zeroed struct and TIOCGWINSZ only writes the window
        // size into it; stderr (fd 2) is always a valid file descriptor.
        let ws_col = unsafe {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 {
                ws.ws_col
            } else {
                0
            }
        };
        if ws_col > 0 {
            return Some(ws_col as usize);
        }
    }
    std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&w| w > 0)
}

/// Visible column length of `s`, ignoring ANSI escape sequences (which occupy
/// no terminal columns). Each non-escape char counts as one column.
fn visible_len(s: &str) -> usize {
    let mut len = 0;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip the rest of the escape sequence (ends on its final letter).
            for e in chars.by_ref() {
                if e.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            len += 1;
        }
    }
    len
}

/// Copy `s` up to `width` visible columns, preserving whole escape sequences
/// intact so a truncation never lands inside an escape code.
fn truncate_to_visible(s: &str, width: usize) -> String {
    let mut out = String::with_capacity(s.len());
    let mut vis = 0;
    let mut chars = s.chars();
    while vis < width {
        match chars.next() {
            None => break,
            Some('\x1b') => {
                out.push('\x1b');
                for e in chars.by_ref() {
                    out.push(e);
                    if e.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            Some(c) => {
                out.push(c);
                vis += 1;
            }
        }
    }
    out
}

/// Fit a rendered line to the terminal width: truncate overflow to exactly
/// `width` visible columns (closing any open color) and pad shorter lines with
/// spaces so the bar always spans the full terminal width. `None` width leaves
/// the line untouched. ANSI escapes are counted as zero width.
fn fit_terminal(line: String, color: bool, width: Option<usize>) -> String {
    let width = match width {
        Some(w) if w > 0 => w,
        _ => return line,
    };
    let vis = visible_len(&line);
    if vis > width {
        let mut out = truncate_to_visible(&line, width);
        if color {
            out.push_str("\x1b[0m");
        }
        return out;
    }
    let mut out = line;
    if color {
        out.push_str("\x1b[0m");
    }
    out.push_str(&" ".repeat(width - vis));
    out
}

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

        let line = if self.color {
            let valid = format!("{passed} valid").green();
            let fail = format!("{failed} fail").red();
            format!(
                "{} {done}/{total}  {valid} · {fail} ({rate:.0}/s)",
                "Validating".cyan().bold(),
            )
        } else {
            format!("Validating {done}/{total}  {passed} valid · {failed} fail ({rate:.0}/s)")
        };
        f.write_str(&fit_terminal(line, self.color, terminal_width()))
    }
}

fn show_progress(quiet: bool, stderr_is_terminal: bool, stdout_is_pipe: bool) -> bool {
    !quiet && stderr_is_terminal && !stdout_is_pipe
}

// Warmup bars clash with streamed stdout data, so for commands that print their
// payload to stdout (e.g. `grab`) the bar is hidden on a TTY and shown only when
// output is redirected (a file via `-o` or a piped stdout) where stderr stays clean.
fn show_warmup(
    quiet: bool,
    stderr_is_terminal: bool,
    stdout_is_pipe: bool,
    allow_piped: bool,
) -> bool {
    !quiet && stderr_is_terminal && (!stdout_is_pipe || allow_piped)
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
    download: watch::Receiver<Option<DownloadProgress>>,
    gathered: Option<watch::Receiver<usize>>,
    started: Instant,
    color: bool,
}

impl Display for WarmupFrame {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let line = if let Some(dl) = self.download.borrow().as_ref() {
            let text = if dl.total > 0 {
                let pct = (dl.downloaded as f64 / dl.total as f64) * 100.0;
                format!("Fetching {} … {pct:.2}%", dl.name)
            } else {
                let mb = dl.downloaded as f64 / (1024.0 * 1024.0);
                format!("Fetching {} … {mb:.1} MB", dl.name)
            };
            if self.color {
                text.bold().cyan().to_string()
            } else {
                text
            }
        } else if let Some(gathered) = &self.gathered {
            let n = *gathered.borrow();
            let elapsed = self.started.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                n as f64 / elapsed
            } else {
                0.0
            };
            let phase = self.phase.lock().unwrap_or_else(|e| e.into_inner());
            let text = format!("{phase} Gathered {n} proxies ({rate:.0}/s)");
            if self.color {
                text.bold().cyan().to_string()
            } else {
                text
            }
        } else {
            let phase = self.phase.lock().unwrap_or_else(|e| e.into_inner());
            if self.color {
                phase.bold().cyan().to_string()
            } else {
                phase.to_string()
            }
        };
        f.write_str(&fit_terminal(line, self.color, terminal_width()))
    }
}

impl WarmupBar {
    pub fn new(
        quiet: bool,
        no_color: bool,
        stdout_is_pipe: bool,
        allow_piped: bool,
        download: watch::Receiver<Option<DownloadProgress>>,
        gathered: Option<watch::Receiver<usize>>,
    ) -> Option<Self> {
        use std::io::IsTerminal as _;

        if !show_warmup(
            quiet,
            std::io::stderr().is_terminal(),
            stdout_is_pipe,
            allow_piped,
        ) {
            return None;
        }
        let phase = Arc::new(Mutex::new("Warming up …"));
        let frame = WarmupFrame {
            phase: Arc::clone(&phase),
            download,
            gathered,
            started: Instant::now(),
            color: use_color(no_color),
        };
        let status = StatusLine::with_options(frame, status_line::Options::default());
        Some(Self { status, phase })
    }

    pub fn set_phase(&self, phase: &'static str) {
        *self.phase.lock().unwrap_or_else(|e| e.into_inner()) = phase;
    }

    pub fn refresh(&self) {
        self.status.refresh();
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
    use super::{fit_terminal, show_progress, use_color, visible_len, Frame, WarmupFrame};
    use flx::{DownloadProgress, ValidationProgress};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, Instant};
    use tokio::sync::watch;

    // `colored`'s color decision is a process-global override, so the tests
    // that render colored output must not interleave with each other.
    static COLOR_LOCK: Mutex<()> = Mutex::new(());

    fn lock_color() -> MutexGuard<'static, ()> {
        COLOR_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn with_color<T>(f: impl FnOnce() -> T) -> T {
        let _guard = lock_color();
        colored::control::set_override(true);
        let result = f();
        colored::control::set_override(false);
        result
    }

    fn frame(
        phase: &'static str,
        download: watch::Receiver<Option<DownloadProgress>>,
        gathered: Option<watch::Receiver<usize>>,
        color: bool,
    ) -> WarmupFrame {
        WarmupFrame {
            phase: Arc::new(Mutex::new(phase)),
            download,
            gathered,
            started: Instant::now() - Duration::from_secs(4),
            color,
        }
    }

    #[test]
    fn warmup_frame_renders_current_phase() {
        let (_, download) = watch::channel(None);
        let frame = frame("Fetching primary sources …", download, None, false);
        assert!(frame.to_string().contains("Fetching primary sources"));
    }

    #[test]
    fn warmup_frame_renders_download_percentage() {
        let (tx, download) = watch::channel(None);
        tx.send_replace(Some(DownloadProgress {
            name: "GeoLite2-City.mmdb",
            downloaded: 400,
            total: 1000,
        }));
        let frame = frame("Fetching proxy lists …", download, None, false);
        let rendered = frame.to_string();
        assert!(rendered.contains("GeoLite2-City.mmdb"));
        assert!(rendered.contains("40.00%"));
    }

    #[test]
    fn warmup_frame_colors_download_line_like_phases() {
        let (tx, download) = watch::channel(None);
        tx.send_replace(Some(DownloadProgress {
            name: "GeoLite2-City.mmdb",
            downloaded: 400,
            total: 1000,
        }));
        let frame = frame("Fetching primary sources …", download, None, true);
        let rendered = with_color(|| frame.to_string());
        assert!(rendered.contains("\x1b[1;36mFetching GeoLite2-City.mmdb"));
        assert!(rendered.ends_with("\x1b[0m"));
    }

    #[test]
    fn warmup_frame_renders_gathered_count_and_rate() {
        let (_, download) = watch::channel(None);
        let (tx, gathered) = watch::channel(0usize);
        tx.send_replace(12);
        let frame = frame(
            "Fetching primary sources …",
            download,
            Some(gathered),
            false,
        );

        let rendered = frame.to_string();
        assert!(rendered.contains("Fetching primary sources"));
        assert!(rendered.contains("Gathered 12 proxies"));
        assert!(rendered.contains("(3/s)"));
    }

    #[test]
    fn warmup_frame_download_line_wins_over_gathered() {
        let (dl_tx, download) = watch::channel(None);
        dl_tx.send_replace(Some(DownloadProgress {
            name: "GeoLite2-City.mmdb",
            downloaded: 400,
            total: 1000,
        }));
        let (gather_tx, gathered) = watch::channel(0usize);
        gather_tx.send_replace(12);
        let frame = frame(
            "Fetching primary sources …",
            download,
            Some(gathered),
            false,
        );

        let rendered = frame.to_string();
        assert!(rendered.contains("GeoLite2-City.mmdb"));
        assert!(!rendered.contains("Gathered"));
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
        let _guard = lock_color();
        colored::control::set_override(false);
        let plain = Frame::new(ValidationProgress::default(), false).to_string();
        colored::control::set_override(true);
        let colored = Frame::new(ValidationProgress::default(), true).to_string();
        colored::control::set_override(false);

        assert!(!plain.contains('\x1b'));
        assert!(colored.contains('\x1b'));
    }

    #[test]
    fn fit_terminal_pads_short_lines_to_width() {
        // Shorter-than-terminal lines are padded to exactly the terminal width.
        let colored = fit_terminal("Validating 0/0".to_string(), true, Some(200));
        assert!(colored.starts_with("Validating 0/0\x1b[0m"));
        assert_eq!(visible_len(&colored), 200);
        assert!(colored.ends_with(' '));

        let plain = fit_terminal("Validating 0/0".to_string(), false, Some(200));
        assert!(plain.starts_with("Validating 0/0"));
        assert_eq!(visible_len(&plain), 200);
        assert!(plain.ends_with(' '));
    }

    #[test]
    fn fit_terminal_truncates_to_width() {
        let line = "abcdefghij".to_string();
        assert_eq!(fit_terminal(line.clone(), false, Some(3)), "abc");
    }

    #[test]
    fn fit_terminal_appends_reset_when_colored() {
        let line = "abcdefghijkl".to_string();
        // 12 visible at width 10: truncate to 10 visible, then close color.
        assert_eq!(fit_terminal(line, true, Some(10)), "abcdefghij\x1b[0m");
    }

    #[test]
    fn fit_terminal_truncates_visible_columns_only() {
        // 10 visible at width 5: truncate to 5 visible columns.
        let line = "abcdefghij".to_string();
        assert_eq!(fit_terminal(line, true, Some(5)), "abcde\x1b[0m");
    }

    #[test]
    fn fit_terminal_ignores_ansi_in_length() {
        // Escape codes carry zero visible width; "Validatingx" is 11 visible.
        let line = "\x1b[1;36mValidatingx\x1b[0m".to_string();
        assert_eq!(visible_len(&line), 11);
        assert_eq!(fit_terminal(line, true, Some(5)), "\x1b[1;36mValid\x1b[0m");
    }

    #[test]
    fn fit_terminal_noop_without_width() {
        assert_eq!(
            fit_terminal(
                "a very long line that should remain".to_string(),
                true,
                None
            ),
            "a very long line that should remain"
        );
    }
}
