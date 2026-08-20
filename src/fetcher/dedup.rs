use std::{
    collections::{hash_map::DefaultHasher, VecDeque},
    hash::{Hash, Hasher},
    net::Ipv4Addr,
};

use hashbrown::HashSet;

use crate::proxy::models::Protocol;

pub(crate) const MAX_DEDUP_ENDPOINTS: usize = 100_000;

pub(crate) type EndpointKey = (Ipv4Addr, u16, u64);

pub(crate) fn protocol_hash(protocols: &[Protocol]) -> u64 {
    let mut hasher = DefaultHasher::new();
    protocols.hash(&mut hasher);
    hasher.finish()
}

pub(crate) struct DedupTable {
    pub(crate) seen: HashSet<EndpointKey>,
    order: VecDeque<EndpointKey>,
    capacity: usize,
}

impl DedupTable {
    pub(crate) fn new() -> Self {
        Self::with_capacity(MAX_DEDUP_ENDPOINTS)
    }

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub(crate) fn insert(&mut self, endpoint: EndpointKey) -> bool {
        if self.seen.contains(&endpoint) {
            return false;
        }
        if self.seen.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(endpoint);
        self.order.push_back(endpoint);
        true
    }
}
