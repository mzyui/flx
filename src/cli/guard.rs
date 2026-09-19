#[cfg(not(unix))]
use std::io::IsTerminal as _;
use std::sync::Arc;

#[cfg(feature = "serve")]
use flx::RotatorPool;
use flx::{DownloadProgress, ValidationProgress};
use tokio::sync::watch;

#[cfg(feature = "progress_bar")]
use super::progress;

/// Hide progress UI around stdout writes.
pub trait OutputGuard {
    fn before_write(&self);
    fn after_write(&self);
}

pub struct NoopGuard;

impl OutputGuard for NoopGuard {
    fn before_write(&self) {}
    fn after_write(&self) {}
}

#[cfg(feature = "progress_bar")]
pub enum OutputGuardEither<B> {
    Bar(B),
    Noop(NoopGuard),
}

#[cfg(feature = "progress_bar")]
impl<B: OutputGuard> OutputGuard for OutputGuardEither<B> {
    fn before_write(&self) {
        match self {
            OutputGuardEither::Bar(bar) => bar.before_write(),
            OutputGuardEither::Noop(noop) => noop.before_write(),
        }
    }

    fn after_write(&self) {
        match self {
            OutputGuardEither::Bar(bar) => bar.after_write(),
            OutputGuardEither::Noop(noop) => noop.after_write(),
        }
    }
}

/// Detect piped stdout sharing the terminal.
#[cfg(unix)]
pub(crate) fn stdout_is_pipe() -> bool {
    use std::os::unix::io::AsRawFd as _;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(std::io::stdout().as_raw_fd(), &mut stat) } == 0)
        && stat.st_mode & libc::S_IFMT == libc::S_IFIFO
}

#[cfg(not(unix))]
pub(crate) fn stdout_is_pipe() -> bool {
    !std::io::stdout().is_terminal()
}

#[cfg(feature = "progress_bar")]
pub fn make_guard(
    progress: ValidationProgress,
    quiet: bool,
    no_color: bool,
) -> OutputGuardEither<progress::ValidationBar> {
    match progress::ValidationBar::new(progress, quiet, no_color, stdout_is_pipe()) {
        Some(bar) => OutputGuardEither::Bar(bar),
        None => OutputGuardEither::Noop(NoopGuard),
    }
}

#[cfg(feature = "progress_bar")]
pub fn make_guard_with_label(
    progress: ValidationProgress,
    quiet: bool,
    no_color: bool,
    label: &'static str,
) -> OutputGuardEither<progress::ValidationBar> {
    match progress::ValidationBar::with_label(progress, quiet, no_color, stdout_is_pipe(), label) {
        Some(bar) => OutputGuardEither::Bar(bar),
        None => OutputGuardEither::Noop(NoopGuard),
    }
}

#[cfg(not(feature = "progress_bar"))]
pub fn make_guard(_progress: ValidationProgress, _quiet: bool, _no_color: bool) -> NoopGuard {
    NoopGuard
}

#[cfg(not(feature = "progress_bar"))]
pub fn make_guard_with_label(
    _progress: ValidationProgress,
    _quiet: bool,
    _no_color: bool,
    _label: &'static str,
) -> NoopGuard {
    NoopGuard
}

#[cfg(feature = "progress_bar")]
pub fn make_warmup(
    quiet: bool,
    no_color: bool,
    download: &watch::Receiver<Option<DownloadProgress>>,
    allow_piped: bool,
    gathered: Option<watch::Receiver<usize>>,
) -> Option<Arc<progress::WarmupBar>> {
    progress::WarmupBar::new(
        quiet,
        no_color,
        stdout_is_pipe(),
        allow_piped,
        download.clone(),
        gathered,
    )
    .map(Arc::new)
}

#[cfg(not(feature = "progress_bar"))]
pub fn make_warmup(
    _quiet: bool,
    _no_color: bool,
    _download: &watch::Receiver<Option<DownloadProgress>>,
    _allow_piped: bool,
    _gathered: Option<watch::Receiver<usize>>,
) -> Option<Arc<WarmupBar>> {
    None
}

#[cfg(not(feature = "progress_bar"))]
pub struct WarmupBar;

#[cfg(not(feature = "progress_bar"))]
impl WarmupBar {
    pub fn set_phase(&self, _phase: &'static str) {}

    pub fn set_progress(&self, _progress: ValidationProgress) {}

    pub fn refresh(&self) {}
}

#[cfg(all(feature = "serve", feature = "progress_bar"))]
pub fn make_serve_bar(
    pool: Arc<RotatorPool>,
    min_ready: usize,
    pool_size: usize,
    endpoint: String,
    quiet: bool,
    no_color: bool,
    download: &watch::Receiver<Option<DownloadProgress>>,
) -> Option<Arc<progress::ServeBar>> {
    progress::ServeBar::new(
        pool,
        min_ready,
        pool_size,
        endpoint,
        quiet,
        no_color,
        download.clone(),
    )
    .map(Arc::new)
}

#[cfg(all(feature = "serve", not(feature = "progress_bar")))]
pub fn make_serve_bar(
    _pool: Arc<RotatorPool>,
    _min_ready: usize,
    _pool_size: usize,
    _endpoint: String,
    _quiet: bool,
    _no_color: bool,
    _download: &watch::Receiver<Option<DownloadProgress>>,
) -> Option<Arc<WarmupBar>> {
    None
}

#[cfg(not(feature = "progress_bar"))]
impl OutputGuard for WarmupBar {
    fn before_write(&self) {}
    fn after_write(&self) {}
}
