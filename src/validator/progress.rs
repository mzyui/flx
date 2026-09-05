use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// Report judge preflight results at validator startup.
#[derive(Debug, Clone, Default)]
pub struct JudgeHealthReport {
    pub candidates: usize,
    pub healthy: usize,
    pub failed: Vec<(String, String)>,
}

impl JudgeHealthReport {
    pub(crate) fn merge(&mut self, other: &JudgeHealthReport) {
        self.candidates += other.candidates;
        self.healthy += other.healthy;
        self.failed.extend(other.failed.iter().cloned());
    }
}

/// Track validation progress counters.
#[derive(Debug, Clone, Default)]
pub struct ValidationProgress {
    pub(crate) total: Arc<AtomicUsize>,
    pub(crate) done: Arc<AtomicUsize>,
    pub(crate) passed: Arc<AtomicUsize>,
}

impl ValidationProgress {
    pub fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    pub fn done(&self) -> usize {
        self.done.load(Ordering::Relaxed)
    }

    pub fn passed(&self) -> usize {
        self.passed.load(Ordering::Relaxed)
    }

    pub fn remaining(&self) -> usize {
        self.total().saturating_sub(self.done())
    }

    pub fn fraction(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            0.0
        } else {
            self.done() as f64 / total as f64
        }
    }
}
