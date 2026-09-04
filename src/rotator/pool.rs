//! Rotating proxy pool shared by the local serve endpoint.

use std::{
    collections::hash_map::RandomState,
    hash::BuildHasher,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use super::{Strategy, COOLDOWN, MAX_CONSECUTIVE_FAILURES, MAX_POOL_SIZE};
use crate::Proxy;

struct PoolEntry {
    proxy: Arc<Proxy>,
    failures: u32,
    cooldown_until: Option<Instant>,
}

impl PoolEntry {
    fn is_available(&self) -> bool {
        self.cooldown_until
            .is_none_or(|until| Instant::now() >= until)
    }
}

/// Thread-safe pool of validated proxies with rotation and health tracking.
///
/// Selection is O(1) under contention-free reads: a cursor (round-robin) or a
/// hash sample (random) picks the starting index and at most one lock-held scan
/// skips proxies in cooldown.
pub struct RotatorPool {
    entries: Mutex<Vec<PoolEntry>>,
    cursor: AtomicUsize,
    strategy: Strategy,
}

impl RotatorPool {
    pub fn new(strategy: Strategy) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            cursor: AtomicUsize::new(0),
            strategy,
        }
    }

    /// Adds a proxy, rejecting duplicates and entries beyond the pool cap.
    pub fn add(&self, proxy: Proxy) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= MAX_POOL_SIZE {
            return false;
        }
        let text = proxy.as_text();
        if entries.iter().any(|e| e.proxy.as_text() == text) {
            return false;
        }
        entries.push(PoolEntry {
            proxy: Arc::new(proxy),
            failures: 0,
            cooldown_until: None,
        });
        true
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of proxies outside their failure cooldown.
    pub fn ready(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|e| e.is_available())
            .count()
    }

    /// Picks the next available proxy, scanning past cooldown entries.
    pub fn pick(&self) -> Option<Arc<Proxy>> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.is_empty() {
            return None;
        }
        let total = entries.len();
        let start = match self.strategy {
            Strategy::Random => random_below(total),
            Strategy::RoundRobin => self.cursor.fetch_add(1, Ordering::Relaxed) % total,
        };
        (0..total).find_map(|offset| {
            let entry = &entries[(start + offset) % total];
            entry.is_available().then(|| Arc::clone(&entry.proxy))
        })
    }

    pub fn report_success(&self, proxy: &Proxy) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let text = proxy.as_text();
        if let Some(entry) = entries.iter_mut().find(|e| e.proxy.as_text() == text) {
            entry.failures = 0;
            entry.cooldown_until = None;
        }
    }
    /// Counts a failure; repeated failures cool the proxy down and finally
    /// evict it so dead endpoints cannot dominate the rotation.
    pub fn report_failure(&self, proxy: &Proxy) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let text = proxy.as_text();
        let Some(position) = entries.iter().position(|e| e.proxy.as_text() == text) else {
            return;
        };
        let entry = &mut entries[position];
        entry.failures += 1;
        if entry.failures >= MAX_CONSECUTIVE_FAILURES {
            entries.swap_remove(position);
        } else {
            entry.cooldown_until = Some(Instant::now() + COOLDOWN);
        }
    }
}

fn random_below(total: usize) -> usize {
    // No `rand` dependency: a fresh `RandomState` per draw is enough entropy
    // for rotation and costs a few multiplications, not a syscall.
    let hash = RandomState::new().hash_one(total);
    (hash % total as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn proxy(port: u16) -> Proxy {
        Proxy::new(Ipv4Addr::new(10, 0, 0, (port % 250) as u8), port)
    }

    #[test]
    fn round_robin_cycles_in_insertion_order() {
        let pool = RotatorPool::new(Strategy::RoundRobin);
        (1..=3).for_each(|port| {
            assert!(pool.add(proxy(port)));
        });
        let picked: Vec<u16> = (0..6).filter_map(|_| pool.pick().map(|p| p.port)).collect();
        assert_eq!(picked, [1, 2, 3, 1, 2, 3]);
    }

    #[test]
    fn duplicate_endpoints_are_rejected() {
        let pool = RotatorPool::new(Strategy::RoundRobin);
        assert!(pool.add(proxy(1)));
        assert!(!pool.add(proxy(1)));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn failures_cool_down_then_evict() {
        let pool = RotatorPool::new(Strategy::RoundRobin);
        pool.add(proxy(1));
        pool.add(proxy(2));
        for _ in 0..MAX_CONSECUTIVE_FAILURES - 1 {
            pool.report_failure(&proxy(1));
        }
        assert_eq!(pool.ready(), 1);
        let picked: Vec<u16> = (0..4).filter_map(|_| pool.pick().map(|p| p.port)).collect();
        assert!(picked.iter().all(|port| *port == 2));
        pool.report_failure(&proxy(1));
        assert_eq!(
            pool.len(),
            1,
            "proxy must be evicted after repeated failures"
        );
    }

    #[test]
    fn success_resets_the_failure_streak() {
        let pool = RotatorPool::new(Strategy::RoundRobin);
        pool.add(proxy(1));
        pool.report_failure(&proxy(1));
        pool.report_success(&proxy(1));
        assert_eq!(pool.ready(), 1);
        pool.report_failure(&proxy(1));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn pool_cap_is_enforced() {
        let pool = RotatorPool::new(Strategy::RoundRobin);
        for port in 1..=MAX_POOL_SIZE as u16 {
            pool.add(proxy(port));
        }
        assert!(!pool.add(proxy(MAX_POOL_SIZE as u16 + 1)));
        assert_eq!(pool.len(), MAX_POOL_SIZE);
    }

    #[test]
    fn pick_on_empty_pool_is_none() {
        let pool = RotatorPool::new(Strategy::Random);
        assert!(pool.pick().is_none());
    }
}
