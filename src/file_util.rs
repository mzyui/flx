//! Guards against Tokio runtime-shutdown file-write failures.
//!
//! `tokio::fs::File` schedules writes on the blocking pool via
//! `spawn_mandatory_blocking`. When the runtime is shutting down that spawn
//! returns `None`, the write fails with `ErrorKind::Other` and the message
//! `"background task failed"`, and the file's internal buffer slot is left
//! empty. Any later `write` on the same handle then panics inside Tokio
//! (`buf_cell.take().unwrap()` in `poll_write`).
//!
//! Long-lived append handles must therefore never be reused after that
//! specific error: drop (and optionally reopen) the handle instead.

use std::{io, path::Path};

/// Tokio's sentinel for a write scheduled past runtime shutdown.
const BACKGROUND_TASK_FAILED: &str = "background task failed";

/// Reports whether `error` is Tokio's runtime-shutdown write sentinel.
///
/// Only this error poisons the `tokio::fs::File` handle; ordinary I/O errors
/// leave the handle reusable.
pub fn is_background_task_failed(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Other && error.to_string().contains(BACKGROUND_TASK_FAILED)
}

/// Reports whether an `anyhow` error chain contains the shutdown sentinel.
pub fn is_shutdown_cause(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(is_background_task_failed)
    })
}

/// Opens `path` for appending, creating it when missing.
pub async fn open_append(path: &Path) -> io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
}

/// Reopens `path` for appending when `error` is the shutdown sentinel.
///
/// Returns `Ok(Some(file))` when the handle was poisoned and a fresh handle
/// was opened, `Ok(None)` for any other error (the old handle stays usable).
pub async fn reopen_after_shutdown(
    path: &Path,
    error: &anyhow::Error,
) -> anyhow::Result<Option<tokio::fs::File>> {
    if !is_shutdown_cause(error) {
        return Ok(None);
    }
    Ok(Some(open_append(path).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_the_shutdown_sentinel() {
        let shutdown = io::Error::other(BACKGROUND_TASK_FAILED);
        assert!(is_background_task_failed(&shutdown));
    }

    #[test]
    fn ignores_ordinary_errors() {
        assert!(!is_background_task_failed(&io::Error::other(
            "disk is full"
        )));
        assert!(!is_background_task_failed(&io::Error::new(
            io::ErrorKind::NotFound,
            BACKGROUND_TASK_FAILED
        )));
        assert!(!is_background_task_failed(&io::Error::from(
            io::ErrorKind::BrokenPipe
        )));
    }

    #[test]
    fn detects_the_sentinel_through_anyhow_context() {
        let error = anyhow::Error::new(io::Error::other(BACKGROUND_TASK_FAILED))
            .context("failed to append health record");
        assert!(is_shutdown_cause(&error));
    }

    #[test]
    fn ignores_non_shutdown_anyhow_chains() {
        let error = anyhow::Error::new(io::Error::from(io::ErrorKind::BrokenPipe)).context("flush");
        assert!(!is_shutdown_cause(&error));
    }
}
