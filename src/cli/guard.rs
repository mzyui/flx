#[cfg(not(unix))]
use std::io::IsTerminal as _;
use std::sync::Arc;

use flx::{DownloadProgress, ValidationProgress};
use tokio::sync::watch;

#[cfg(feature = "progress_bar")]
use super::progress;

/// A hook that hides the progress UI around each stdout write.
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

/// Whether stdout is a pipe (FIFO) rather than a terminal or a regular file.
///
/// A piped stdout means a downstream process writes to the shared terminal (or
/// `2>&1` routes our own stderr into the pipe), so a stderr summary would mix
/// with that output. Regular-file redirects (`> out`) leave the terminal free
/// and are safe to keep the summary.
#[cfg(unix)]
pub(crate) fn stdout_is_pipe() -> bool {
    use std::os::unix::io::AsRawFd as _;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // fstat cannot fail on the already-open stdout descriptor.
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

#[cfg(not(feature = "progress_bar"))]
pub fn make_guard(_progress: ValidationProgress, _quiet: bool, _no_color: bool) -> NoopGuard {
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

// No-op warmup bar for builds without the `progress_bar` feature.
#[cfg(not(feature = "progress_bar"))]
pub struct WarmupBar;

#[cfg(not(feature = "progress_bar"))]
impl WarmupBar {
    pub fn set_phase(&self, _phase: &'static str) {}
}

#[cfg(not(feature = "progress_bar"))]
impl OutputGuard for WarmupBar {
    fn before_write(&self) {}
    fn after_write(&self) {}
}
