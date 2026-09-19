use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use anyhow::Context;
use tokio::{task::JoinSet, time};

use super::support::ValidationTarget;

const JUDGE_FAILURE_COOLDOWN: Duration = Duration::from_secs(30);

/// Round-robin pool of preflighted online judges.
///
/// Built once via [`JudgePool::build`]; workers fetch per-attempt candidates and
/// report judge health so failing judges cool down without pool locking.
pub struct JudgePool {
    judges: Mutex<Vec<Arc<ValidationTarget>>>,
    cursor: AtomicUsize,
    epoch: time::Instant,
}

impl JudgePool {
    /// Preflights `urls` concurrently and returns a pool of the judges that pass.
    ///
    /// Duplicate URLs are probed once and `on_dropped` is invoked for every URL
    /// rejected locally or by preflight; the pool returns early once the first
    /// judge passes while stragglers keep reporting in the background.
    ///
    /// # Errors
    ///
    /// Returns an error when `urls` is empty or no candidate passes preflight.
    pub async fn build<F>(
        urls: &[String],
        timeout: Duration,
        insecure: bool,
        mut on_dropped: F,
    ) -> anyhow::Result<Arc<Self>>
    where
        F: FnMut(&str, &str) + Send + 'static,
    {
        if urls.is_empty() {
            anyhow::bail!("judge pool must contain at least one candidate URL");
        }
        let mut seen = HashSet::with_capacity(urls.len());
        let mut candidates = Vec::with_capacity(urls.len());
        for url in urls {
            if !seen.insert(url.clone()) {
                continue;
            }
            match ValidationTarget::online(url) {
                Ok(target) => candidates.push((url.clone(), target)),
                Err(error) => on_dropped(url, &format!("{error:#}")),
            }
        }

        let pool = Arc::new(Self::empty());
        let mut tasks = JoinSet::new();
        for (url, target) in candidates {
            let pool = Arc::clone(&pool);
            tasks.spawn(async move {
                let result = target.verify_online(timeout, insecure).await;
                if result.is_ok() {
                    pool.append(Arc::new(target));
                }
                (url, result)
            });
        }

        loop {
            if !pool.is_empty() {
                break;
            }
            match tasks.join_next().await {
                Some(Ok((_url, Ok(())))) => {}
                Some(Ok((url, Err(error)))) => on_dropped(&url, &format!("{error:#}")),
                Some(Err(error)) => {
                    return Err(error).context("online judge preflight task failed");
                }
                None => break,
            }
        }
        if pool.is_empty() {
            anyhow::bail!(
                "no online judge passed preflight; all {} candidate URL(s) failed",
                urls.len()
            );
        }

        tokio::spawn(async move {
            while let Some(joined) = tasks.join_next().await {
                match joined {
                    Ok((_url, Ok(()))) => {}
                    Ok((url, Err(error))) => on_dropped(&url, &format!("{error:#}")),
                    Err(error) => on_dropped("<judge>", &format!("{error:#}")),
                }
            }
        });

        Ok(pool)
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    #[cfg(test)]
    /// Return next healthy judge; callers must ensure pool is non-empty.
    pub fn next(&self) -> Arc<ValidationTarget> {
        debug_assert!(!self.is_empty(), "judge pool must not be empty");
        let start = self.cursor.fetch_add(1, Ordering::Relaxed);

        let now_ms = self.now_ms();
        let judges = self.judges.lock().unwrap_or_else(|e| e.into_inner());
        for offset in 0..judges.len() {
            let index = (start + offset) % judges.len();
            let target = &judges[index];
            if target.health.cooldown_until_ms.load(Ordering::Relaxed) <= now_ms {
                return Arc::clone(target);
            }
        }
        Arc::clone(&judges[start % judges.len()])
    }

    pub(crate) fn candidates(&self) -> Vec<Arc<ValidationTarget>> {
        let now_ms = self.now_ms();
        let judges = self.judges.lock().unwrap_or_else(|e| e.into_inner());
        let mut candidates: Vec<Arc<ValidationTarget>> = judges
            .iter()
            .filter(|target| target.health.cooldown_until_ms.load(Ordering::Relaxed) <= now_ms)
            .cloned()
            .collect();
        if candidates.is_empty() && !judges.is_empty() {
            let start = self.cursor.fetch_add(1, Ordering::Relaxed) % judges.len();
            candidates.push(Arc::clone(&judges[start]));
        }
        candidates.sort_unstable_by_key(|target| {
            let ema = target.health.rtt_ema_ms.load(Ordering::Relaxed);
            if ema == 0 {
                u64::MAX
            } else {
                ema
            }
        });
        candidates
    }

    /// Parks `target` in cooldown so later candidates skip it temporarily.
    pub fn report_failure(&self, target: &ValidationTarget) {
        let until = self
            .epoch
            .elapsed()
            .saturating_add(JUDGE_FAILURE_COOLDOWN)
            .as_millis() as u64;
        target
            .health
            .cooldown_until_ms
            .store(until, Ordering::Relaxed);
    }

    pub(crate) fn report_success(&self, target: &ValidationTarget, elapsed: Duration) {
        let elapsed_ms = elapsed.as_millis() as u64;
        if elapsed_ms == 0 {
            return;
        }
        let ema = &target.health.rtt_ema_ms;
        let prev = ema.load(Ordering::Relaxed);
        let next = if prev == 0 {
            elapsed_ms
        } else {
            (prev * 7 + elapsed_ms * 3) / 10
        };
        ema.store(next, Ordering::Relaxed);
    }

    /// Number of judges currently in the pool.
    pub fn len(&self) -> usize {
        self.judges.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether the pool holds no judges.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn empty() -> Self {
        Self {
            judges: Mutex::new(Vec::new()),
            cursor: AtomicUsize::new(0),
            epoch: time::Instant::now(),
        }
    }

    pub(crate) fn append(&self, target: Arc<ValidationTarget>) {
        self.judges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(target);
    }

    pub(crate) fn from_targets(targets: Vec<Arc<ValidationTarget>>) -> Self {
        Self {
            judges: Mutex::new(targets),
            cursor: AtomicUsize::new(0),
            epoch: time::Instant::now(),
        }
    }
}
