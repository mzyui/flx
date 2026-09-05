//! Render validation progress on stderr.

use std::{
    fmt::{Display, Formatter},
    sync::{
        atomic::{AtomicUsize, Ordering},
        {Arc, Mutex},
    },
    time::Instant,
};

use crate::status_line::{Options as StatusLineOptions, StatusLine};
use crate::style::Colorize;
use flx::{DownloadProgress, ValidationProgress};
use tokio::sync::watch;

use crate::OutputGuard;

const VALIDATING_ICON: &str = "▸";
const PHASE_ICON: &str = "⟳";
const DOWNLOAD_ICON: &str = "⇣";
const GATHER_ICON: &str = "✦";
const ELLIPSIS_TAIL: &str = " …";

/// Compose icon-phase lines without whole-line hues.
fn phase_line(phase: &str, color: bool) -> String {
    let body = phase.trim_end();
    let (text, tail) = match body.strip_suffix('…') {
        Some(head) => (head.trim_end(), ELLIPSIS_TAIL),
        None => (body, ""),
    };
    if !color {
        return format!("{PHASE_ICON} {text}{tail}");
    }
    format!("{} {}{}", PHASE_ICON.cyan(), text.bold(), tail.dimmed())
}

const HIDE_CURSOR: &str = "\x1b[?25l";
const SHOW_CURSOR: &str = "\x1b[?25h";

static LIVE_CURSOR_HIDERS: AtomicUsize = AtomicUsize::new(0);

fn cursor_escape(prev: usize, next: usize) -> Option<&'static str> {
    match (prev, next) {
        (0, 1) => Some(HIDE_CURSOR),
        (1, 0) => Some(SHOW_CURSOR),
        _ => None,
    }
}

fn apply_cursor_escape(escape: Option<&'static str>) {
    use std::io::{IsTerminal as _, Write as _};
    if let Some(escape) = escape {
        // Emit escapes only on TTY stderr.
        if std::io::stderr().is_terminal() {
            let _ = std::io::stderr().lock().write_all(escape.as_bytes());
        }
    }
}

/// Restore the cursor after forced exits skip destructors.
pub(crate) fn force_show_cursor() {
    use std::io::{IsTerminal as _, Write as _};
    if LIVE_CURSOR_HIDERS.load(Ordering::Acquire) > 0 && std::io::stderr().is_terminal() {
        let _ = std::io::stderr().lock().write_all(SHOW_CURSOR.as_bytes());
    }
}

/// Hide the cursor while any status bar lives.
struct CursorHider;

impl CursorHider {
    fn acquire() -> Self {
        let prev = LIVE_CURSOR_HIDERS.fetch_add(1, Ordering::AcqRel);
        apply_cursor_escape(cursor_escape(prev, prev + 1));
        Self
    }
}

impl Drop for CursorHider {
    fn drop(&mut self) {
        let prev = LIVE_CURSOR_HIDERS.fetch_sub(1, Ordering::AcqRel);
        apply_cursor_escape(cursor_escape(prev, prev - 1));
    }
}

fn terminal_width() -> Option<usize> {
    #[cfg(unix)]
    {
        // SAFETY: TIOCGWINSZ only writes the window size into ws.
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

/// Measure visible columns ignoring ANSI escapes.
fn visible_len(s: &str) -> usize {
    let mut len = 0;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
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

/// Truncate to visible columns without splitting escapes.
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

/// Fit lines to terminal width with padding or truncation.
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
            let rate = format!(" ({rate:.0}/s)").dimmed();
            format!(
                "{} {} {done}/{total} · {valid} · {fail}{rate}",
                VALIDATING_ICON.cyan(),
                "Validating".bold(),
            )
        } else {
            format!("{VALIDATING_ICON} Validating {done}/{total} · {passed} valid · {failed} fail ({rate:.0}/s)")
        };
        f.write_str(&fit_terminal(line, self.color, terminal_width()))
    }
}

fn show_progress(quiet: bool, stderr_is_terminal: bool, stdout_is_pipe: bool) -> bool {
    !quiet && stderr_is_terminal && !stdout_is_pipe
}

// Hide warmup bars on TTY stdout to avoid clashing with payloads.
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
    _cursor: CursorHider,
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
        let _cursor = CursorHider::acquire();
        let status = StatusLine::new(Frame::new(progress, use_color(no_color)));
        Some(Self {
            _status: status,
            _cursor,
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
        // Hide the bar while stdout writes to the same terminal.
        self.hide();
    }

    fn after_write(&self) {
        self.show();
    }
}

/// Render warmup phases before validation starts.
pub struct WarmupBar {
    status: StatusLine<WarmupFrame>,
    phase: Arc<Mutex<&'static str>>,
    _cursor: CursorHider,
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
            let detail = if dl.total > 0 {
                let pct = (dl.downloaded as f64 / dl.total as f64) * 100.0;
                format!("{ELLIPSIS_TAIL} {pct:.2}%")
            } else {
                let mb = dl.downloaded as f64 / (1024.0 * 1024.0);
                format!("{ELLIPSIS_TAIL} {mb:.1} MB")
            };
            if self.color {
                format!("{} {}{}", DOWNLOAD_ICON.cyan(), dl.name, detail.dimmed())
            } else {
                format!("{DOWNLOAD_ICON} {}{detail}", dl.name)
            }
        } else if let Some(gathered) = &self.gathered {
            let n = *gathered.borrow();
            let elapsed = self.started.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                n as f64 / elapsed
            } else {
                0.0
            };
            if self.color {
                let rate_text = format!(" ({rate:.0}/s)").dimmed();
                format!(
                    "{} {} {n} proxies{rate_text}",
                    GATHER_ICON.cyan(),
                    "Gathering".bold()
                )
            } else {
                format!("{GATHER_ICON} Gathering {n} proxies ({rate:.0}/s)")
            }
        } else {
            let phase = self.phase.lock().unwrap_or_else(|e| e.into_inner());
            phase_line(&phase, self.color)
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
        let _cursor = CursorHider::acquire();
        let phase = Arc::new(Mutex::new("Warming up …"));
        let frame = WarmupFrame {
            phase: Arc::clone(&phase),
            download,
            gathered,
            started: Instant::now(),
            color: use_color(no_color),
        };
        let status = StatusLine::with_options(frame, StatusLineOptions::default());
        Some(Self {
            status,
            phase,
            _cursor,
        })
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
    use super::{
        cursor_escape, fit_terminal, show_progress, use_color, visible_len, CursorHider, Frame,
        WarmupFrame, HIDE_CURSOR, LIVE_CURSOR_HIDERS, SHOW_CURSOR,
    };
    use flx::{DownloadProgress, ValidationProgress};
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, Instant};
    use tokio::sync::watch;

    fn lock_color() -> MutexGuard<'static, ()> {
        crate::style::color_lock()
    }

    static CURSOR_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn cursor_escapes_are_the_standard_ansi_ones() {
        assert_eq!(HIDE_CURSOR, "\x1b[?25l");
        assert_eq!(SHOW_CURSOR, "\x1b[?25h");
    }

    #[test]
    fn cursor_escape_transitions() {
        assert_eq!(cursor_escape(0, 1), Some(HIDE_CURSOR));
        assert_eq!(cursor_escape(1, 0), Some(SHOW_CURSOR));
        assert_eq!(cursor_escape(1, 2), None);
        assert_eq!(cursor_escape(2, 1), None);
        assert_eq!(cursor_escape(0, 0), None);
    }

    #[test]
    fn cursor_hider_hides_once_and_restores_on_last_release() {
        let _guard = CURSOR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let before = LIVE_CURSOR_HIDERS.load(Ordering::Acquire);

        let hider = CursorHider::acquire();
        assert_eq!(LIVE_CURSOR_HIDERS.load(Ordering::Acquire), before + 1);

        let extra = CursorHider::acquire();
        assert_eq!(LIVE_CURSOR_HIDERS.load(Ordering::Acquire), before + 2);

        drop(extra);
        assert_eq!(LIVE_CURSOR_HIDERS.load(Ordering::Acquire), before + 1);

        drop(hider);
        assert_eq!(LIVE_CURSOR_HIDERS.load(Ordering::Acquire), before);
    }

    fn with_color<T>(f: impl FnOnce() -> T) -> T {
        let _guard = lock_color();
        crate::style::set_override(true);
        let result = f();
        crate::style::set_override(false);
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
        assert!(frame.to_string().starts_with("⟳ Fetching primary sources"));
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
    fn warmup_frame_colors_download_line_accent_only() {
        let (tx, download) = watch::channel(None);
        tx.send_replace(Some(DownloadProgress {
            name: "GeoLite2-City.mmdb",
            downloaded: 400,
            total: 1000,
        }));
        let frame = frame("Fetching primary sources …", download, None, true);
        let rendered = with_color(|| frame.to_string());
        assert!(rendered.starts_with("\x1b[36m⇣\x1b[0m GeoLite2-City.mmdb"));
        assert!(rendered.contains("\x1b[2m … 40.00%\x1b[0m"));
        assert!(rendered.ends_with("\x1b[0m"));
        assert!(!rendered.contains("\x1b[1;36m"));
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
        assert_eq!(rendered, "✦ Gathering 12 proxies (3/s)");
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

        assert!(rendered.starts_with("▸ Validating "));
        assert!(rendered.contains(" 0/0 "));
        assert!(rendered.contains("0 valid · 0 fail"));
        assert!(rendered.contains("0/s"));
        assert!(!rendered.contains('%'));
        assert!(!rendered.contains("ETA"));
        assert!(!rendered.contains('▐') && !rendered.contains('▌'));
    }

    #[test]
    fn frame_colors_icon_and_rate_not_whole_line() {
        let colored = with_color(|| Frame::new(ValidationProgress::default(), true).to_string());
        assert!(colored.starts_with("\x1b[36m▸\x1b[0m "));
        assert!(colored.contains("\x1b[1mValidating\x1b[0m"));
        assert!(colored.contains("\x1b[2m (0/s)\x1b[0m"));
        assert!(!colored.contains("\x1b[1;36mValidating"));
    }

    #[test]
    fn frame_uses_ansi_codes_only_when_colored() {
        let _guard = lock_color();
        crate::style::set_override(false);
        let plain = Frame::new(ValidationProgress::default(), false).to_string();
        crate::style::set_override(true);
        let colored = Frame::new(ValidationProgress::default(), true).to_string();
        crate::style::set_override(false);

        assert!(!plain.contains('\x1b'));
        assert!(colored.contains('\x1b'));
    }

    #[test]
    fn fit_terminal_pads_short_lines_to_width() {
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
        assert_eq!(fit_terminal(line, true, Some(10)), "abcdefghij\x1b[0m");
    }

    #[test]
    fn fit_terminal_truncates_visible_columns_only() {
        let line = "abcdefghij".to_string();
        assert_eq!(fit_terminal(line, true, Some(5)), "abcde\x1b[0m");
    }

    #[test]
    fn fit_terminal_ignores_ansi_in_length() {
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
