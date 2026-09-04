//! Local rotating proxy endpoint.
//!
//! Exposes a pool of validated proxies through a plain HTTP proxy listener:
//! every client connection is forwarded through the next available upstream,
//! rotating per connection. Plain HTTP forwarding and CONNECT tunneling are
//! supported; SOCKS upstreams are reached through the existing negotiators.

mod pool;
mod server;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::{net::TcpListener, time};

pub use pool::RotatorPool;

/// Bind and port defaults for the serve endpoint.
pub const DEFAULT_BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
pub const DEFAULT_PORT: u16 = 8080;
pub const DEFAULT_POOL_SIZE: usize = 100;
pub const MAX_POOL_SIZE: usize = 1_000;
/// The endpoint goes live once this many validated proxies are ready.
pub const DEFAULT_MIN_READY: usize = 1;
pub const DEFAULT_REFRESH_SECS: u64 = 300;
/// Single end-to-end budget per client connection covering the upstream
/// connect, the handshake, and the relay — never split per phase.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const MAX_CONSECUTIVE_FAILURES: u32 = 3;
const COOLDOWN: Duration = Duration::from_secs(60);
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const READY_WAIT_TIMEOUT: Duration = Duration::from_secs(120);
const READY_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Upstream selection strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Each connection takes the next proxy in pool order.
    RoundRobin,
    /// Each connection takes a hash-sampled proxy.
    Random,
}

impl Strategy {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "round-robin" => Some(Self::RoundRobin),
            "random" => Some(Self::Random),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RoundRobin => "round-robin",
            Self::Random => "random",
        }
    }
}

/// Configuration for the rotating endpoint.
#[derive(Debug, Clone)]
pub struct ServeOptions {
    pub bind: IpAddr,
    pub port: u16,
    pub strategy: Strategy,
    pub pool_size: usize,
    /// Validated proxies required before the endpoint starts serving.
    pub min_ready: usize,
    pub refresh_secs: u64,
    /// `user`/`pass` pair required from clients via `Proxy-Authorization: Basic`.
    pub auth: Option<(String, String)>,
    pub request_timeout: Duration,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            bind: DEFAULT_BIND,
            port: DEFAULT_PORT,
            strategy: Strategy::RoundRobin,
            pool_size: DEFAULT_POOL_SIZE,
            min_ready: DEFAULT_MIN_READY,
            refresh_secs: DEFAULT_REFRESH_SECS,
            auth: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }
}

/// The rotating endpoint: fills the pool through [`Rotator::pool`] and serves
/// client connections via [`Rotator::run`] until the shutdown token fires.
pub struct Rotator {
    pool: Arc<RotatorPool>,
    options: Arc<ServeOptions>,
    ready_bypass: AtomicBool,
}

impl Rotator {
    pub fn new(options: ServeOptions) -> Self {
        let strategy = options.strategy;
        Self {
            pool: Arc::new(RotatorPool::new(strategy)),
            options: Arc::new(options),
            ready_bypass: AtomicBool::new(false),
        }
    }

    pub fn pool(&self) -> Arc<RotatorPool> {
        Arc::clone(&self.pool)
    }

    /// Lets [`Rotator::run`] start serving even when the feed ended with fewer
    /// than [`ServeOptions::min_ready`] proxies (offline files, exhausted
    /// providers).
    pub fn force_ready(&self) {
        self.ready_bypass.store(true, Ordering::Relaxed);
    }

    /// Binds the endpoint and waits until [`ServeOptions::min_ready`] proxies
    /// are ready (bounded by [`READY_WAIT_TIMEOUT`] or [`Rotator::force_ready`])
    /// before serving, so early clients are not bounced with an empty rotation.
    /// Runs until cancelled.
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        let address = SocketAddr::new(self.options.bind, self.options.port);
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("failed to bind the rotating endpoint on {address}"))?;

        wait_for_ready(
            &self.pool,
            &self.ready_bypass,
            self.options.min_ready.min(MAX_POOL_SIZE),
        )
        .await;

        server::accept_loop(listener, Arc::clone(&self.pool), Arc::clone(&self.options)).await;
        Ok(())
    }
}

/// Polls until the pool holds `min_ready` available proxies, the caller flips
/// the bypass flag, or [`READY_WAIT_TIMEOUT`] elapses — whichever comes first.
async fn wait_for_ready(pool: &RotatorPool, bypass: &AtomicBool, min_ready: usize) {
    let ready = async {
        while !bypass.load(Ordering::Relaxed) && pool.ready() < min_ready {
            time::sleep(READY_POLL_INTERVAL).await;
        }
    };
    tokio::select! {
        _ = ready => {}
        _ = time::sleep(READY_WAIT_TIMEOUT) => {}
    }
}

use anyhow::Context as _;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn single_ready_proxy_goes_live_immediately() {
        let pool = RotatorPool::new(Strategy::RoundRobin);
        assert!(pool.add(crate::Proxy::new(std::net::Ipv4Addr::LOCALHOST, 8081)));
        let bypass = AtomicBool::new(false);
        tokio::select! {
            _ = wait_for_ready(&pool, &bypass, DEFAULT_MIN_READY) => {}
            _ = time::sleep(Duration::from_secs(5)) => {
                panic!("gate did not open for one ready proxy");
            }
        }
    }

    #[tokio::test]
    async fn force_ready_opens_the_gate_with_an_empty_pool() {
        let pool = RotatorPool::new(Strategy::RoundRobin);
        let bypass = AtomicBool::new(true);
        tokio::select! {
            _ = wait_for_ready(&pool, &bypass, 10) => {}
            _ = time::sleep(Duration::from_secs(5)) => {
                panic!("bypass flag did not open the gate");
            }
        }
    }
}
