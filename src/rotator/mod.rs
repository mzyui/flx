//! Serve validated proxies through a local rotating endpoint.

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

use tokio::sync::mpsc;
use tokio::{net::TcpListener, time};

pub use pool::RotatorPool;

/// Default loopback bind address for the rotating endpoint.
///
/// Only available with the `serve` Cargo feature.
pub const DEFAULT_BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// Default port for the rotating endpoint.
///
/// Only available with the `serve` Cargo feature.
pub const DEFAULT_PORT: u16 = 8080;
/// Cap pooled proxies; feeder refills up to it.
pub const MAX_POOL_SIZE: usize = 25;
/// Bound queued serve events; excess events drop instead of blocking relays.
pub const EVENT_CHANNEL_CAPACITY: usize = 1024;
/// Default pool capacity, equal to [`MAX_POOL_SIZE`].
///
/// Only available with the `serve` Cargo feature.
pub const DEFAULT_POOL_SIZE: usize = MAX_POOL_SIZE;
/// Gate serving until this many proxies are ready.
pub const DEFAULT_MIN_READY: usize = 1;
/// Default pool refill interval in seconds.
///
/// Only available with the `serve` Cargo feature.
pub const DEFAULT_REFRESH_SECS: u64 = 300;
/// Bound each connection end-to-end without per-phase splits.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const MAX_CONSECUTIVE_FAILURES: u32 = 3;
const COOLDOWN: Duration = Duration::from_secs(60);
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const READY_WAIT_TIMEOUT: Duration = Duration::from_secs(120);
const READY_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Upstream rotation strategy.
///
/// Only available with the `serve` Cargo feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Cycle upstreams in insertion order.
    RoundRobin,
    /// Pick a random start offset per connection.
    Random,
}

impl Strategy {
    /// Parses `round-robin` or `random`, or `None` for anything else.
    ///
    /// Only available with the `serve` Cargo feature.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "round-robin" => Some(Self::RoundRobin),
            "random" => Some(Self::Random),
            _ => None,
        }
    }

    /// Returns the CLI spelling (`round-robin` or `random`).
    ///
    /// Only available with the `serve` Cargo feature.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RoundRobin => "round-robin",
            Self::Random => "random",
        }
    }
}

/// Options for the rotating proxy endpoint.
///
/// Only available with the `serve` Cargo feature.
#[derive(Debug, Clone)]
pub struct ServeOptions {
    /// Address to bind the local endpoint to.
    pub bind: IpAddr,
    /// Port to bind the local endpoint to.
    pub port: u16,
    /// Upstream rotation strategy.
    pub strategy: Strategy,
    /// Maximum pooled proxies; capped at [`MAX_POOL_SIZE`].
    pub pool_size: usize,
    /// Proxies required before serving connections.
    pub min_ready: usize,
    /// Pool refill interval in seconds.
    pub refresh_secs: u64,
    /// Require Basic proxy auth from clients.
    pub auth: Option<(String, String)>,
    /// End-to-end budget per connection.
    pub request_timeout: Duration,
    /// Opt-in sink for per-connection events; `None` disables reporting.
    pub event_tx: Option<mpsc::Sender<ServeEvent>>,
    /// Emit per-phase trace lines (curl-like); needs `event_tx`.
    pub trace: bool,
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
            event_tx: None,
            trace: false,
        }
    }
}

/// Format durations as ms, s, or minutes.
fn fmt_dur(elapsed: Duration) -> String {
    if elapsed.as_millis() < 1_000 {
        format!("{}ms", elapsed.as_millis())
    } else if elapsed.as_secs() < 60 {
        format!("{:.1}s", elapsed.as_secs_f64())
    } else {
        format!("{}m {}s", elapsed.as_secs() / 60, elapsed.as_secs() % 60)
    }
}

/// Format byte counts as B, KB, or MB.
fn fmt_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    if bytes < KB {
        format!("{bytes}B")
    } else if bytes < MB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    }
}

/// One client connection seen by the rotating endpoint.
///
/// Targets are `host:port` authorities only, never paths or queries.
#[derive(Debug, Clone)]
pub enum ServeEvent {
    /// A parseable request head arrived from a client.
    Incoming {
        /// Connection sequence number.
        id: u64,
        /// Client socket address, if known.
        client: Option<SocketAddr>,
        /// Request method (e.g. `GET`, `CONNECT`).
        method: String,
        /// Request target authority (`host:port`).
        target: String,
    },
    /// The connection reached an upstream outcome.
    Completed {
        /// Connection sequence number.
        id: u64,
        /// Client socket address, if known.
        client: Option<SocketAddr>,
        /// Request method (e.g. `GET`, `CONNECT`).
        method: String,
        /// Request target authority (`host:port`).
        target: String,
        /// Upstream proxy that served it, if any.
        upstream: Option<String>,
        /// Whether the exchange succeeded.
        ok: bool,
        /// Failure reason when `ok` is false.
        reason: Option<String>,
        /// Time from accept to completion.
        elapsed: Duration,
    },
    /// One curl-like trace line for an in-flight connection.
    Trace {
        /// Connection sequence number.
        id: u64,
        /// Rendered trace line.
        text: String,
    },
}

impl std::fmt::Display for ServeEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incoming {
                id,
                client,
                method,
                target,
            } => {
                let client = client.map_or("-".to_owned(), |addr| addr.to_string());
                write!(f, "[#{id}] → {method} {target} from {client}")
            }
            Self::Completed {
                id,
                client: _,
                method,
                target,
                upstream,
                ok,
                reason,
                elapsed,
            } => {
                let upstream = upstream.as_deref().unwrap_or("-");
                if *ok {
                    write!(
                        f,
                        "[#{id}] ✓ {method} {target} via {upstream} {}",
                        fmt_dur(*elapsed)
                    )
                } else {
                    let reason = reason.as_deref().unwrap_or("failed");
                    write!(
                        f,
                        "[#{id}] ✗ {method} {target} via {upstream} FAIL {reason} {}",
                        fmt_dur(*elapsed)
                    )
                }
            }
            Self::Trace { id, text } => {
                write!(f, "[#{id}] {text}")
            }
        }
    }
}

/// Fill pools and serve connections until shutdown.
///
/// Created from [`ServeOptions`] via [`Rotator::new`]; feed it with
/// [`Rotator::pool`] then drive with [`Rotator::run`].
pub struct Rotator {
    pool: Arc<RotatorPool>,
    options: Arc<ServeOptions>,
    ready_bypass: AtomicBool,
}

impl Rotator {
    /// Creates a rotator backed by a fresh pool.
    ///
    /// # Arguments
    ///
    /// * `options` - Bind address, strategy, pool size, and timeouts.
    pub fn new(options: ServeOptions) -> Self {
        let strategy = options.strategy;
        Self {
            pool: Arc::new(RotatorPool::new(strategy)),
            options: Arc::new(options),
            ready_bypass: AtomicBool::new(false),
        }
    }

    /// Shares the pool fed by the validation pipeline.
    pub fn pool(&self) -> Arc<RotatorPool> {
        Arc::clone(&self.pool)
    }

    /// Bypass the readiness gate for exhausted feeds.
    pub fn force_ready(&self) {
        self.ready_bypass.store(true, Ordering::Relaxed);
    }

    /// Binds, waits for `min_ready` proxies, then serves until cancelled.
    ///
    /// # Errors
    ///
    /// Returns an error when the bind address cannot be claimed.
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        let (never, shutdown) = tokio::sync::watch::channel(false);
        std::mem::forget(never);
        self.run_until_shutdown(shutdown).await
    }

    /// Binds, waits for `min_ready` proxies, then serves until `shutdown`.
    ///
    /// In-flight connections drain before returning.
    ///
    /// # Errors
    ///
    /// Returns an error when the bind address cannot be claimed.
    pub async fn run_until_shutdown(
        self: Arc<Self>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let address = SocketAddr::new(self.options.bind, self.options.port);
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("failed to bind the rotating endpoint on {address}"))?;

        let ready_target = ready_target(self.options.pool_size, self.options.min_ready);
        wait_for_ready(&self.pool, &self.ready_bypass, ready_target).await;

        server::accept_loop(
            listener,
            Arc::clone(&self.pool),
            Arc::clone(&self.options),
            shutdown,
        )
        .await;
        Ok(())
    }
}

/// Readiness target, never above what the feeder will actually pool.
fn ready_target(pool_size: usize, min_ready: usize) -> usize {
    min_ready.min(pool_size.max(1)).min(MAX_POOL_SIZE)
}

/// Poll pool readiness until bypass or timeout.
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

    #[test]
    fn ready_target_never_exceeds_the_pool_size() {
        assert_eq!(
            ready_target(1, 5),
            1,
            "min_ready above pool_size must clamp"
        );
        assert_eq!(ready_target(25, 3), 3);
        assert_eq!(ready_target(0, 4), 1);
        assert_eq!(ready_target(1000, 1000), MAX_POOL_SIZE);
    }

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

    #[test]
    fn pool_is_capped_at_twenty_five_by_default() {
        assert_eq!(MAX_POOL_SIZE, 25);
        assert_eq!(DEFAULT_POOL_SIZE, MAX_POOL_SIZE);
        assert_eq!(
            ServeOptions::default().pool_size,
            DEFAULT_POOL_SIZE,
            "the serve facade must default to the capped pool"
        );
    }

    #[test]
    fn serve_events_render_authorities_without_paths() {
        let client: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let incoming = ServeEvent::Incoming {
            id: 12,
            client: Some(client),
            method: "CONNECT".to_owned(),
            target: "example.com:443".to_owned(),
        };
        assert_eq!(
            incoming.to_string(),
            "[#12] → CONNECT example.com:443 from 127.0.0.1:54321"
        );

        let completed = ServeEvent::Completed {
            id: 12,
            client: Some(client),
            method: "CONNECT".to_owned(),
            target: "example.com:443".to_owned(),
            upstream: Some("192.0.2.1:8080".to_owned()),
            ok: true,
            reason: None,
            elapsed: Duration::from_millis(1289),
        };
        let rendered = completed.to_string();
        assert_eq!(
            rendered, "[#12] ✓ CONNECT example.com:443 via 192.0.2.1:8080 1.3s",
            "{rendered}"
        );
        assert!(!rendered.contains('/'), "authorities must never leak paths");

        let failed = ServeEvent::Completed {
            id: 7,
            client: None,
            method: "GET".to_owned(),
            target: "-".to_owned(),
            upstream: None,
            ok: false,
            reason: Some("bad request".to_owned()),
            elapsed: Duration::from_millis(3),
        };
        assert_eq!(
            failed.to_string(),
            "[#7] ✗ GET - via - FAIL bad request 3ms"
        );

        let trace = ServeEvent::Trace {
            id: 12,
            text: "* TCP connect 4ms".to_owned(),
        };
        assert_eq!(trace.to_string(), "[#12] * TCP connect 4ms");
    }

    #[test]
    fn fmt_dur_humanizes_durations() {
        assert_eq!(fmt_dur(Duration::from_millis(12)), "12ms");
        assert_eq!(fmt_dur(Duration::from_millis(1289)), "1.3s");
        assert_eq!(fmt_dur(Duration::from_secs(64)), "1m 4s");
    }

    #[test]
    fn fmt_bytes_humanizes_counts() {
        assert_eq!(fmt_bytes(412), "412B");
        assert_eq!(fmt_bytes(2048), "2.0KB");
        assert_eq!(fmt_bytes(5 * 1024 * 1024), "5.0MB");
    }
}
