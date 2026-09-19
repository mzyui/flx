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
#[cfg(feature = "serve")]
use flx::RotatorPool;
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

/// Shared rate: count per second, 0 when no time has passed.
fn rate_per_sec(count: usize, elapsed_secs: f64) -> f64 {
    if elapsed_secs > 0.0 {
        count as f64 / elapsed_secs
    } else {
        0.0
    }
}

/// Human throughput for download bars.
fn format_throughput(bytes_per_sec: f64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    const KB: f64 = 1024.0;
    if bytes_per_sec >= MB {
        format!("{:.1} MB/s", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.1} KB/s", bytes_per_sec / KB)
    } else {
        format!("{bytes_per_sec:.0} B/s")
    }
}

fn format_eta(remaining_bytes: usize, bytes_per_sec: f64) -> Option<String> {
    if bytes_per_sec <= 0.0 {
        return None;
    }
    let secs = remaining_bytes as f64 / bytes_per_sec;
    if !secs.is_finite() {
        return None;
    }
    let secs = secs.round() as u64;
    if secs >= 60 {
        Some(format!("ETA {}m {}s", secs / 60, secs % 60))
    } else {
        Some(format!("ETA {secs}s"))
    }
}

/// Download detail with percent/MB plus throughput and ETA.
fn download_detail(dl: &DownloadProgress, elapsed_secs: f64) -> String {
    let speed = rate_per_sec(dl.downloaded, elapsed_secs);
    let speed_text = format_throughput(speed);
    if dl.total > 0 {
        let pct = (dl.downloaded as f64 / dl.total as f64) * 100.0;
        let mut out = format!("{ELLIPSIS_TAIL} {pct:.2}% · {speed_text}");
        if let Some(eta) = format_eta(dl.total.saturating_sub(dl.downloaded), speed) {
            out.push_str(&format!(" · {eta}"));
        }
        out
    } else {
        let mb = dl.downloaded as f64 / (1024.0 * 1024.0);
        format!("{ELLIPSIS_TAIL} {mb:.1} MB · {speed_text}")
    }
}

/// Shorten plain text to at most `max_chars`, adding an ellipsis when cut.
#[cfg(feature = "serve")]
fn shorten_plain(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        return s.to_owned();
    }
    if max_chars == 0 {
        return String::new();
    }
    let kept: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{kept}…")
}

struct Frame {
    progress: ValidationProgress,
    started: Instant,
    color: bool,
    label: &'static str,
}

impl Frame {
    fn new(progress: ValidationProgress, color: bool) -> Self {
        Self::with_label(progress, color, "Validating")
    }

    fn with_label(progress: ValidationProgress, color: bool, label: &'static str) -> Self {
        Self {
            progress,
            started: Instant::now(),
            color,
            label,
        }
    }
}

impl Display for Frame {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let done = self.progress.done();
        let total = self.progress.total();
        let passed = self.progress.passed();
        let failed = done.saturating_sub(passed);
        let rate = rate_per_sec(done, self.started.elapsed().as_secs_f64());

        let line = if self.color {
            let valid = format!("{passed} valid").green();
            let fail = format!("{failed} fail").red();
            let rate = format!(" ({rate:.0}/s)").dimmed();
            format!(
                "{} {} {done}/{total} · {valid} · {fail}{rate}",
                VALIDATING_ICON.cyan(),
                self.label.bold(),
            )
        } else {
            format!(
                "{} {} {done}/{total} · {passed} valid · {failed} fail ({rate:.0}/s)",
                VALIDATING_ICON, self.label
            )
        };
        f.write_str(&fit_terminal(line, self.color, terminal_width()))
    }
}

fn show_progress(quiet: bool, stderr_is_terminal: bool, stdout_is_pipe: bool) -> bool {
    !quiet && stderr_is_terminal && !stdout_is_pipe
}

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

    pub fn with_label(
        progress: ValidationProgress,
        quiet: bool,
        no_color: bool,
        stdout_is_pipe: bool,
        label: &'static str,
    ) -> Option<Self> {
        use std::io::IsTerminal as _;

        if !show_progress(quiet, std::io::stderr().is_terminal(), stdout_is_pipe) {
            return None;
        }
        let _cursor = CursorHider::acquire();
        let status = StatusLine::new(Frame::with_label(progress, use_color(no_color), label));
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
            let detail = download_detail(dl, self.started.elapsed().as_secs_f64());
            if self.color {
                format!("{} {}{}", DOWNLOAD_ICON.cyan(), dl.name, detail.dimmed())
            } else {
                format!("{DOWNLOAD_ICON} {}{detail}", dl.name)
            }
        } else if let Some(gathered) = &self.gathered {
            let n = *gathered.borrow();
            let rate = rate_per_sec(n, self.started.elapsed().as_secs_f64());
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

#[cfg(feature = "serve")]
const SERVE_ICON: &str = "●";

/// Render the persistent serve status: pool fill plus validation counters.
/// Requires the `serve` Cargo feature.
#[cfg(feature = "serve")]
pub struct ServeBar {
    _status: StatusLine<ServeFrame>,
    phase: Arc<Mutex<&'static str>>,
    progress: Arc<Mutex<Option<ValidationProgress>>>,
    _cursor: CursorHider,
}

#[cfg(feature = "serve")]
struct ServeFrame {
    phase: Arc<Mutex<&'static str>>,
    progress: Arc<Mutex<Option<ValidationProgress>>>,
    pool: Arc<RotatorPool>,
    min_ready: usize,
    pool_size: usize,
    endpoint: String,
    download: watch::Receiver<Option<DownloadProgress>>,
    started: Instant,
    color: bool,
}

#[cfg(feature = "serve")]
impl Display for ServeFrame {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(dl) = self.download.borrow().as_ref() {
            let detail = download_detail(dl, self.started.elapsed().as_secs_f64());
            let line = if self.color {
                format!("{} {}{}", DOWNLOAD_ICON.cyan(), dl.name, detail.dimmed())
            } else {
                format!("{DOWNLOAD_ICON} {}{detail}", dl.name)
            };
            return f.write_str(&fit_terminal(line, self.color, terminal_width()));
        }
        let ready = self.pool.ready();
        let stored = self.pool.len();
        let live = ready >= self.min_ready.max(1);
        let icon = if live { SERVE_ICON } else { PHASE_ICON };
        let phase_guard = self.phase.lock().unwrap_or_else(|e| e.into_inner());
        let pool_part = if live {
            format!("pool {ready}/{}", self.pool_size)
        } else {
            format!("pool {ready}/{} ready", self.min_ready)
        };
        let stored_part = if stored != ready {
            format!(" (stored {stored})")
        } else {
            String::new()
        };
        let snapshot = self
            .progress
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let rate = snapshot
            .as_ref()
            .map(|progress| rate_per_sec(progress.done(), self.started.elapsed().as_secs_f64()));
        let build = |phase: &str, endpoint: &str| -> String {
            match &snapshot {
                Some(progress) => {
                    let done = progress.done();
                    let total = progress.total();
                    let passed = progress.passed();
                    let failed = done.saturating_sub(passed);
                    let rate = rate.unwrap_or(0.0);
                    if self.color {
                        format!(
                            "{} {} · {} · {pool_part}{stored_part} · Validating {done}/{total} · {} · {} ({rate:.0}/s)",
                            icon.cyan(),
                            phase.bold(),
                            endpoint.dimmed(),
                            format!("{passed} valid").green(),
                            format!("{failed} fail").red(),
                        )
                    } else {
                        format!(
                            "{icon} {phase} · {endpoint} · {pool_part}{stored_part} · Validating {done}/{total} · {passed} valid · {failed} fail ({rate:.0}/s)",
                        )
                    }
                }
                None => {
                    if self.color {
                        format!(
                            "{} {} · {} · {pool_part}{stored_part}",
                            icon.cyan(),
                            phase.bold(),
                            endpoint.dimmed(),
                        )
                    } else {
                        format!("{icon} {phase} · {endpoint} · {pool_part}{stored_part}",)
                    }
                }
            }
        };
        let mut endpoint = self.endpoint.clone();
        let mut phase_string = (*phase_guard).to_owned();
        let width = terminal_width();
        let mut line = build(&phase_string, &endpoint);
        if let Some(w) = width {
            let mut vis = visible_len(&line);
            while vis > w && endpoint.chars().count() > 1 {
                let overflow = vis - w;
                let cur = endpoint.chars().count();
                let target = cur.saturating_sub(overflow).max(1);
                let next = shorten_plain(&endpoint, target);
                if next == endpoint {
                    break;
                }
                endpoint = next;
                line = build(&phase_string, &endpoint);
                vis = visible_len(&line);
            }
            while vis > w && phase_string.chars().count() > 1 {
                let overflow = vis - w;
                let cur = phase_string.chars().count();
                let target = cur.saturating_sub(overflow).max(1);
                let next = shorten_plain(&phase_string, target);
                if next == phase_string {
                    break;
                }
                phase_string = next;
                line = build(&phase_string, &endpoint);
                vis = visible_len(&line);
            }
        }
        f.write_str(&fit_terminal(line, self.color, width))
    }
}

#[cfg(feature = "serve")]
impl ServeBar {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: Arc<RotatorPool>,
        min_ready: usize,
        pool_size: usize,
        endpoint: String,
        quiet: bool,
        no_color: bool,
        download: watch::Receiver<Option<DownloadProgress>>,
    ) -> Option<Self> {
        use std::io::IsTerminal as _;

        if quiet || !std::io::stderr().is_terminal() {
            return None;
        }
        let _cursor = CursorHider::acquire();
        let phase = Arc::new(Mutex::new("Filling the pool …"));
        let progress = Arc::new(Mutex::new(None));
        let frame = ServeFrame {
            phase: Arc::clone(&phase),
            progress: Arc::clone(&progress),
            pool,
            min_ready,
            pool_size,
            endpoint,
            download,
            started: Instant::now(),
            color: use_color(no_color),
        };
        let status = StatusLine::with_options(frame, StatusLineOptions::default());
        Some(Self {
            _status: status,
            phase,
            progress,
            _cursor,
        })
    }

    pub fn set_phase(&self, phase: &'static str) {
        *self.phase.lock().unwrap_or_else(|e| e.into_inner()) = phase;
    }

    pub fn set_progress(&self, progress: ValidationProgress) {
        *self.progress.lock().unwrap_or_else(|e| e.into_inner()) = Some(progress);
    }
}

#[cfg(feature = "serve")]
impl OutputGuard for ServeBar {
    fn before_write(&self) {
        self._status.set_visible(false);
    }

    fn after_write(&self) {
        self._status.set_visible(true);
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serve")]
    use super::shorten_plain;
    #[cfg(feature = "serve")]
    use super::ServeFrame;
    use super::{
        cursor_escape, download_detail, fit_terminal, format_throughput, rate_per_sec,
        show_progress, use_color, visible_len, CursorHider, Frame, WarmupFrame, HIDE_CURSOR,
        LIVE_CURSOR_HIDERS, SHOW_CURSOR,
    };
    use flx::{DownloadProgress, ValidationProgress};
    #[cfg(feature = "serve")]
    use flx::{RotatorPool, Strategy};
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

    #[cfg(feature = "serve")]
    fn serve_frame(
        pool: Arc<RotatorPool>,
        phase: &'static str,
        progress: Option<ValidationProgress>,
        download: watch::Receiver<Option<DownloadProgress>>,
        color: bool,
    ) -> ServeFrame {
        ServeFrame {
            phase: Arc::new(Mutex::new(phase)),
            progress: Arc::new(Mutex::new(progress)),
            pool,
            min_ready: 1,
            pool_size: 25,
            endpoint: "127.0.0.1:8080".to_owned(),
            download,
            started: Instant::now() - Duration::from_secs(4),
            color,
        }
    }

    #[cfg(feature = "serve")]
    fn serve_pool() -> Arc<RotatorPool> {
        let pool = Arc::new(RotatorPool::new(Strategy::RoundRobin));
        assert!(pool.add(flx::Proxy::new(std::net::Ipv4Addr::LOCALHOST, 8081)));
        pool
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
        assert!(rendered.contains("\x1b[2m … 40.00%"));
        assert!(rendered.contains("/s"));
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

    #[cfg(feature = "serve")]
    #[test]
    fn serve_frame_shows_filling_pool_with_validation_counters() {
        let (_, download) = watch::channel(None);
        let pool = Arc::new(RotatorPool::new(Strategy::RoundRobin));
        let frame = serve_frame(
            pool,
            "Filling the pool …",
            Some(ValidationProgress::default()),
            download,
            false,
        );
        let rendered = frame.to_string();
        assert!(rendered.starts_with("⟳"), "{rendered}");
        assert!(rendered.contains("Filling the pool"), "{rendered}");
        assert!(rendered.contains("pool 0/1 ready"), "{rendered}");
        assert!(rendered.contains("Validating 0/0"), "{rendered}");
        assert!(rendered.contains("127.0.0.1:8080"), "{rendered}");
    }

    #[cfg(feature = "serve")]
    #[test]
    fn serve_frame_switches_to_serving_icon_when_ready() {
        let (_, download) = watch::channel(None);
        let frame = serve_frame(
            serve_pool(),
            "Serving …",
            Some(ValidationProgress::default()),
            download,
            false,
        );
        let rendered = frame.to_string();
        assert!(rendered.starts_with("●"), "{rendered}");
        assert!(rendered.contains("pool 1/25"), "{rendered}");
    }

    #[cfg(feature = "serve")]
    #[test]
    fn serve_frame_download_line_wins_over_pool() {
        let (tx, download) = watch::channel(None);
        tx.send_replace(Some(DownloadProgress {
            name: "GeoLite2-City.mmdb",
            downloaded: 400,
            total: 1000,
        }));
        let frame = serve_frame(
            serve_pool(),
            "Serving …",
            Some(ValidationProgress::default()),
            download,
            false,
        );
        let rendered = frame.to_string();
        assert!(rendered.contains("GeoLite2-City.mmdb"), "{rendered}");
        assert!(!rendered.contains("pool"), "{rendered}");
    }

    #[cfg(feature = "serve")]
    #[test]
    fn serve_frame_uses_ansi_codes_only_when_colored() {
        let _guard = lock_color();
        crate::style::set_override(false);
        let (_, download) = watch::channel(None);
        let plain = serve_frame(serve_pool(), "Serving …", None, download, false).to_string();
        let (_, download) = watch::channel(None);
        crate::style::set_override(true);
        let colored = serve_frame(serve_pool(), "Serving …", None, download, true).to_string();
        crate::style::set_override(false);

        assert!(!plain.contains('\x1b'), "{plain}");
        assert!(colored.contains('\x1b'), "{colored}");
    }

    #[test]
    fn rate_per_sec_handles_zero_elapsed() {
        assert_eq!(rate_per_sec(10, 0.0), 0.0);
        assert_eq!(rate_per_sec(10, 2.0), 5.0);
    }

    #[test]
    fn throughput_formats_adaptively() {
        assert!(format_throughput(2.5 * 1024.0 * 1024.0).contains("MB/s"));
        assert!(format_throughput(512.0 * 1024.0).contains("KB/s"));
        assert!(format_throughput(10.0).contains("B/s"));
    }

    #[test]
    fn download_detail_shows_speed_and_eta() {
        let dl = DownloadProgress {
            name: "GeoLite2-City.mmdb",
            downloaded: 400,
            total: 1000,
        };
        let detail = download_detail(&dl, 2.0);
        assert!(detail.contains("40.00%"), "{detail}");
        assert!(detail.contains("/s"), "{detail}");
        assert!(detail.contains("ETA"), "{detail}");
    }

    #[test]
    fn download_detail_without_total_shows_mb_and_speed() {
        let dl = DownloadProgress {
            name: "GeoLite2-City.mmdb",
            downloaded: 1024 * 1024,
            total: 0,
        };
        let detail = download_detail(&dl, 1.0);
        assert!(detail.contains("MB"), "{detail}");
        assert!(detail.contains("/s"), "{detail}");
    }

    #[test]
    fn frame_with_pass_two_label() {
        let frame = Frame::with_label(ValidationProgress::default(), false, "Validating pass 2");
        let rendered = frame.to_string();
        assert!(rendered.contains("Validating pass 2"), "{rendered}");
        assert!(rendered.contains("/s"), "{rendered}");
    }

    #[cfg(feature = "serve")]
    #[test]
    fn shorten_plain_adds_ellipsis_when_cut() {
        assert_eq!(shorten_plain("abcdef", 6), "abcdef");
        assert_eq!(shorten_plain("abcdef", 3), "ab…");
        assert_eq!(shorten_plain("abcdef", 1), "…");
    }
}
