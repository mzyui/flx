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

pub struct JudgePool {
    judges: Mutex<Vec<Arc<ValidationTarget>>>,
    cursor: AtomicUsize,
    epoch: time::Instant,
}

impl JudgePool {
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
                continue; // de-duplicate without a redundant preflight
            }
            match ValidationTarget::online(url) {
                Ok(target) => candidates.push((url.clone(), target)),
                Err(error) => on_dropped(url, &format!("{error:#}")),
            }
        }

        // Preflight every candidate concurrently; a passing judge is appended
        // to the shared pool the moment it verifies, so validation never waits
        // for the slowest candidate.
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

        // Wait until the first judge has passed (appended) or every candidate
        // has finished. Failures that land first are still reported.
        loop {
            if !pool.is_empty() {
                break;
            }
            match tasks.join_next().await {
                Some(Ok((_url, Ok(())))) => {} // already appended by the task
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

        // The remaining candidates finish in the background: survivors are
        // appended as they verify, failures are reported.
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
    pub fn next(&self) -> Arc<ValidationTarget> {
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
        // Fastest judges first so each proxy pays the minimal RTT. Unknown
        // judges (EMA 0) are treated as slow and sink to the end.
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

    pub fn report_failure(&self, target: &ValidationTarget) {
        let until = self
            .epoch
            .elapsed()
            .saturating_add(JUDGE_FAILURE_COOLDOWN)
            .as_millis() as u64;
        // Lock-free: the health state lives on the target itself, so hot-path
        // reports never contend on the judge-list lock.
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
            // EMA with alpha 0.3: ema = ema*0.7 + sample*0.3
            (prev * 7 + elapsed_ms * 3) / 10
        };
        ema.store(next, Ordering::Relaxed);
    }

    pub fn len(&self) -> usize {
        self.judges.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

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
