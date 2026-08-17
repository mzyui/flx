//! Gateway forward-proxy server (`flx serve`).

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use anyhow::{bail, Context as _};
use base64::Engine as _;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    time::{self, Instant},
};

use flx::{
    negotiators::{HttpsNegotiator, NegotiatorTrait, Socks4Negotiator, Socks5Negotiator},
    proxy::client::ProxyClient,
    proxy::models::{Protocol, Proxy},
    ProxyValidator,
};

use crate::argument::ServeArgs;
use crate::RunOutcome;

const MAX_HEAD_BYTES: usize = 16 * 1024;
const MAX_LINE_BYTES: usize = 16 * 1024;
const MAX_BODY_CHUNK: usize = 16 * 1024;
const REBUILD_BATCH: usize = 64;
const MAX_FAILOVERS: usize = 2;
const LATENCY_MAP_CAP: usize = 10_000;
const DRAIN_GRACE: Duration = Duration::from_secs(5);
const STATS_INTERVAL: Duration = Duration::from_secs(10);

const RESPONSE_407: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"flx\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESPONSE_503: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESPONSE_502: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESPONSE_400: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Runtime options for one `flx serve` process.
#[derive(Clone)]
struct ServeConfig {
    session: bool,
    idle: Duration,
    pool_wait: Duration,
    dial_timeout: Duration,
    auth: Option<Arc<str>>,
}

impl ServeConfig {
    fn from_args(args: &ServeArgs) -> Self {
        Self {
            session: args.session,
            idle: Duration::from_secs(args.session_timeout),
            pool_wait: Duration::from_secs(args.pool_wait),
            dial_timeout: Duration::from_secs(args.validator.timeout),
            auth: args.auth.as_deref().map(Arc::from),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartitionKind {
    Tunnel,
    Forward,
}

#[derive(Default)]
struct Snapshot {
    tunnel: Arc<[Proxy]>,
    forward: Arc<[Proxy]>,
}

#[derive(Default)]
struct Stats {
    failovers: AtomicUsize,
    errors: AtomicUsize,
    sessions_total: AtomicUsize,
    requests: AtomicUsize,
    bytes: AtomicUsize,
}

/// Live counters for rendering the serve status line and end-of-run summary.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ServeSnapshot {
    pub active_sessions: usize,
    pub max_sessions: usize,
    pub pool: usize,
    pub tunnel: usize,
    pub forward: usize,
    pub failovers: usize,
    pub errors: usize,
    pub sessions_total: usize,
    pub requests: usize,
    pub bytes: u64,
}

/// Shared proxy pool: an immutable snapshot on the hot path plus a pending
/// batch that is folded in on an amortized schedule.
#[derive(Clone)]
pub(crate) struct Pool {
    snapshot: Arc<RwLock<Snapshot>>,
    pending: Arc<Mutex<Vec<Proxy>>>,
    dirty: Arc<AtomicBool>,
    tunnel_rotor: Arc<AtomicUsize>,
    forward_rotor: Arc<AtomicUsize>,
    in_use: Arc<Mutex<HashSet<String>>>,
    latency: Arc<RwLock<std::collections::HashMap<String, f64>>>,
    notify: Arc<Notify>,
    session_notify: Arc<Notify>,
    sessions: Arc<AtomicUsize>,
    max_sessions: usize,
    pool_size: usize,
    use_fastest: bool,
    stats: Arc<Stats>,
}

impl Pool {
    pub(crate) fn new(max_sessions: usize, pool_size: usize, use_fastest: bool) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(Snapshot::default())),
            pending: Arc::new(Mutex::new(Vec::new())),
            dirty: Arc::new(AtomicBool::new(false)),
            tunnel_rotor: Arc::new(AtomicUsize::new(0)),
            forward_rotor: Arc::new(AtomicUsize::new(0)),
            in_use: Arc::new(Mutex::new(HashSet::new())),
            latency: Arc::new(RwLock::new(std::collections::HashMap::new())),
            notify: Arc::new(Notify::new()),
            session_notify: Arc::new(Notify::new()),
            sessions: Arc::new(AtomicUsize::new(0)),
            max_sessions,
            pool_size,
            use_fastest,
            stats: Arc::new(Stats::default()),
        }
    }

    fn len(&self) -> usize {
        let snap = self.snapshot.read().expect("pool snapshot poisoned");
        let pending = self.pending.lock().expect("pool pending poisoned");
        snap.tunnel.len() + snap.forward.len() + pending.len()
    }

    fn add(&self, proxy: Proxy) {
        if self.pool_size > 0 && self.len() >= self.pool_size {
            return;
        }
        let mut pending = self.pending.lock().expect("pool pending poisoned");
        if pending.len() >= REBUILD_BATCH {
            drop(pending);
            self.rebuild();
            return;
        }
        pending.push(proxy);
        drop(pending);
        self.dirty.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    fn ensure_fresh(&self) {
        if self.dirty.swap(false, Ordering::Acquire) {
            self.rebuild();
        }
    }

    fn rebuild(&self) {
        let mut pending = std::mem::take(&mut *self.pending.lock().expect("pool pending poisoned"));
        let mut snap = self.snapshot.write().expect("pool snapshot poisoned");
        let mut all = Vec::with_capacity(snap.tunnel.len() + snap.forward.len() + pending.len());
        all.extend_from_slice(&snap.tunnel);
        all.extend_from_slice(&snap.forward);
        all.append(&mut pending);
        if self.pool_size > 0 && all.len() > self.pool_size {
            all.truncate(self.pool_size);
        }
        snap.tunnel = all
            .iter()
            .filter(|p| proxy_is_tunnel_capable(p))
            .cloned()
            .collect::<Vec<_>>()
            .into();
        snap.forward = all
            .iter()
            .filter(|p| proxy_is_forward_capable(p))
            .cloned()
            .collect::<Vec<_>>()
            .into();
    }

    fn set_snapshot(&self, proxies: Vec<Proxy>) {
        let mut snap = self.snapshot.write().expect("pool snapshot poisoned");
        snap.tunnel = proxies
            .iter()
            .filter(|p| proxy_is_tunnel_capable(p))
            .cloned()
            .collect::<Vec<_>>()
            .into();
        snap.forward = proxies
            .iter()
            .filter(|p| proxy_is_forward_capable(p))
            .cloned()
            .collect::<Vec<_>>()
            .into();
    }

    fn pick(&self, kind: PartitionKind, exclude: &HashSet<String>) -> Option<Proxy> {
        self.ensure_fresh();
        let snap = self.snapshot.read().expect("pool snapshot poisoned");
        let (list, rotor) = match kind {
            PartitionKind::Tunnel => (&snap.tunnel, &self.tunnel_rotor),
            PartitionKind::Forward => (&snap.forward, &self.forward_rotor),
        };
        let n = list.len();
        if n == 0 {
            return None;
        }
        let start = rotor.fetch_add(1, Ordering::Relaxed) % n;
        if self.use_fastest {
            let lat = self.latency.read().expect("pool latency poisoned");
            let mut order: Vec<usize> = (0..n).collect();
            order.sort_by(|&a, &b| {
                let la = lat.get(list[a].as_text()).copied().unwrap_or(f64::INFINITY);
                let lb = lat.get(list[b].as_text()).copied().unwrap_or(f64::INFINITY);
                la.partial_cmp(&lb).unwrap_or(std::cmp::Ordering::Equal)
            });
            for offset in 0..n {
                let candidate = &list[order[(start + offset) % n]];
                if exclude.contains(candidate.as_text()) {
                    continue;
                }
                return Some(candidate.clone());
            }
        } else {
            for offset in 0..n {
                let candidate = &list[(start + offset) % n];
                if exclude.contains(candidate.as_text()) {
                    continue;
                }
                return Some(candidate.clone());
            }
        }
        None
    }

    async fn await_proxy(
        &self,
        kind: PartitionKind,
        wait: Duration,
        exclude: &HashSet<String>,
    ) -> Option<Proxy> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(proxy) = self.pick(kind, exclude) {
                return Some(proxy);
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::select! {
                _ = self.notify.notified() => {}
                _ = time::sleep_until(deadline) => return None,
            }
        }
    }

    fn record_latency(&self, endpoint: &str, secs: f64) {
        let mut lat = self.latency.write().expect("pool latency poisoned");
        if lat.len() >= LATENCY_MAP_CAP {
            lat.clear();
        }
        lat.insert(endpoint.to_owned(), secs);
    }

    fn mark_in_use(&self, endpoint: &str) {
        self.in_use
            .lock()
            .expect("pool in-use poisoned")
            .insert(endpoint.to_owned());
        self.sessions.fetch_add(1, Ordering::Relaxed);
    }

    fn release(&self, endpoint: &str) {
        self.in_use
            .lock()
            .expect("pool in-use poisoned")
            .remove(endpoint);
        let _ = self.sessions.fetch_sub(1, Ordering::Relaxed);
        self.session_notify.notify_one();
    }

    async fn await_session_slot(&self, wait: Duration) -> bool {
        if self.max_sessions == 0 {
            return true;
        }
        let deadline = Instant::now() + wait;
        loop {
            if self.sessions.load(Ordering::Relaxed) < self.max_sessions {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::select! {
                _ = self.session_notify.notified() => {}
                _ = time::sleep_until(deadline) => return false,
            }
        }
    }

    fn candidates_for_refresh(&self) -> Vec<Proxy> {
        self.ensure_fresh();
        let snap = self.snapshot.read().expect("pool snapshot poisoned");
        let in_use = self.in_use.lock().expect("pool in-use poisoned");
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for proxy in snap.tunnel.iter().chain(snap.forward.iter()) {
            if in_use.contains(proxy.as_text()) {
                continue;
            }
            if seen.insert(proxy.as_text().to_owned()) {
                out.push(proxy.clone());
            }
        }
        out
    }

    fn replace_validated(&self, fresh: Vec<Proxy>) {
        let mut keep: Vec<Proxy> = {
            let snap = self.snapshot.read().expect("pool snapshot poisoned");
            let in_use = self.in_use.lock().expect("pool in-use poisoned");
            snap.tunnel
                .iter()
                .chain(snap.forward.iter())
                .filter(|p| in_use.contains(p.as_text()))
                .cloned()
                .collect()
        };
        let mut seen = HashSet::new();
        keep.retain(|p| seen.insert(p.as_text().to_owned()));
        keep.extend(fresh);
        if self.pool_size > 0 && keep.len() > self.pool_size {
            keep.truncate(self.pool_size);
        }
        self.set_snapshot(keep);
    }

    pub(crate) fn snapshot(&self) -> ServeSnapshot {
        self.ensure_fresh();
        let snap = self.snapshot.read().expect("pool snapshot poisoned");
        ServeSnapshot {
            active_sessions: self.sessions.load(Ordering::Relaxed),
            max_sessions: self.max_sessions,
            pool: self.len(),
            tunnel: snap.tunnel.len(),
            forward: snap.forward.len(),
            failovers: self.stats.failovers.load(Ordering::Relaxed),
            errors: self.stats.errors.load(Ordering::Relaxed),
            sessions_total: self.stats.sessions_total.load(Ordering::Relaxed),
            requests: self.stats.requests.load(Ordering::Relaxed),
            bytes: self.stats.bytes.load(Ordering::Relaxed) as u64,
        }
    }
}

fn proxy_is_forward_capable(proxy: &Proxy) -> bool {
    proxy
        .proxy_types
        .iter()
        .any(|t| matches!(t.protocol, Protocol::Http(_)))
}

fn proxy_is_tunnel_capable(proxy: &Proxy) -> bool {
    proxy.proxy_types.iter().any(|t| {
        matches!(
            t.protocol,
            Protocol::Https(_)
                | Protocol::Http(_)
                | Protocol::Socks4
                | Protocol::Socks5
                | Protocol::Connect(_)
        )
    })
}

#[derive(Debug, Clone, Copy)]
enum UpstreamKind {
    HttpConnect,
    Socks4,
    Socks5,
}

fn upstream_tunnel_kind(proxy: &Proxy) -> Option<UpstreamKind> {
    let t = proxy.proxy_types.first()?;
    match t.protocol {
        Protocol::Http(_) | Protocol::Https(_) | Protocol::Connect(_) => {
            Some(UpstreamKind::HttpConnect)
        }
        Protocol::Socks4 => Some(UpstreamKind::Socks4),
        Protocol::Socks5 => Some(UpstreamKind::Socks5),
    }
}

struct Upstream {
    proxy: Proxy,
    stream: TcpStream,
    buf: Vec<u8>,
}

struct Header {
    name: Vec<u8>,
    value: Vec<u8>,
}

struct ClientHead {
    method: Vec<u8>,
    target: Vec<u8>,
    version: u8,
    headers: Vec<Header>,
}

struct UpstreamHead {
    bytes: Vec<u8>,
    status: u16,
    version: u8,
    chunked: bool,
    content_length: Option<u64>,
    headers: Vec<Header>,
}

struct RequestSemantics {
    content_length: Option<u64>,
    chunked: bool,
    expect_continue: bool,
    keep_alive: bool,
}

enum ResponseEnd {
    KeepAlive,
    ClientClose,
    Handoff,
}

enum RoundtripEnd {
    KeepGoing,
    ClientClose,
    Handoff(Upstream),
}

enum PipeEnd {
    ClientClosed,
    UpstreamGone,
    IdleTimeout,
}

// ── Headers ───────────────────────────────────────────────────────────

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn trim_ascii(mut v: &[u8]) -> &[u8] {
    while v.first().is_some_and(u8::is_ascii_whitespace) {
        v = &v[1..];
    }
    while v.last().is_some_and(u8::is_ascii_whitespace) {
        v = &v[..v.len() - 1];
    }
    v
}

fn header_value<'a>(headers: &'a [Header], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name.as_bytes()))
        .map(|h| h.value.as_slice())
}

fn header_values<'a>(headers: &'a [Header], name: &str) -> Vec<&'a [u8]> {
    headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name.as_bytes()))
        .map(|h| h.value.as_slice())
        .collect()
}

fn parse_u64_bytes(v: &[u8]) -> Option<u64> {
    std::str::from_utf8(trim_ascii(v)).ok()?.parse().ok()
}

fn parse_client_head(bytes: &[u8]) -> anyhow::Result<ClientHead> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(bytes) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => bail!("incomplete request head"),
        Err(httparse::Error::TooManyHeaders) => bail!("request exceeds 64 headers"),
        Err(e) => bail!("malformed request head: {e}"),
    }
    let method = req
        .method
        .ok_or_else(|| anyhow::anyhow!("request missing method"))?
        .as_bytes()
        .to_vec();
    let target = req
        .path
        .ok_or_else(|| anyhow::anyhow!("request missing target"))?
        .as_bytes()
        .to_vec();
    Ok(ClientHead {
        method,
        target,
        version: req.version.unwrap_or(0),
        headers: req
            .headers
            .iter()
            .map(|h| Header {
                name: h.name.as_bytes().to_vec(),
                value: h.value.to_vec(),
            })
            .collect(),
    })
}

fn parse_upstream_head(bytes: &[u8]) -> anyhow::Result<UpstreamHead> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(bytes) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => bail!("incomplete upstream response head"),
        Err(httparse::Error::TooManyHeaders) => bail!("upstream response exceeds 64 headers"),
        Err(e) => bail!("malformed upstream response head: {e}"),
    }
    let headers: Vec<Header> = resp
        .headers
        .iter()
        .map(|h| Header {
            name: h.name.as_bytes().to_vec(),
            value: h.value.to_vec(),
        })
        .collect();
    let chunked = headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case(b"transfer-encoding")
            && h.value
                .windows(7)
                .any(|w| w.eq_ignore_ascii_case(b"chunked"))
    });
    let content_length = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(b"content-length"))
        .map(|h| parse_u64_bytes(&h.value))
        .next()
        .flatten();
    Ok(UpstreamHead {
        bytes: bytes.to_vec(),
        status: resp.code.unwrap_or(0),
        version: resp.version.unwrap_or(0),
        chunked,
        content_length,
        headers,
    })
}

fn request_semantics(head: &ClientHead) -> anyhow::Result<RequestSemantics> {
    let cls = header_values(&head.headers, "content-length");
    let te = header_values(&head.headers, "transfer-encoding");
    let chunked = te
        .iter()
        .any(|v| v.windows(7).any(|w| w.eq_ignore_ascii_case(b"chunked")));
    let content_length = match cls.len() {
        0 => None,
        1 => Some(parse_u64_bytes(cls[0]).context("invalid Content-Length")?),
        _ => bail!("multiple Content-Length headers"),
    };
    if chunked && content_length.is_some() {
        bail!("request carries both Transfer-Encoding and Content-Length");
    }
    let expect_continue = header_value(&head.headers, "expect").is_some_and(|v| {
        v.windows(12)
            .any(|w| w.eq_ignore_ascii_case(b"100-continue"))
    });
    let keep_alive = {
        let Some(v) = header_value(&head.headers, "connection")
            .or_else(|| header_value(&head.headers, "proxy-connection"))
        else {
            return Ok(RequestSemantics {
                content_length,
                chunked,
                expect_continue,
                keep_alive: head.version == 1,
            });
        };
        let close = v.windows(5).any(|w| w.eq_ignore_ascii_case(b"close"));
        let keep = v.windows(10).any(|w| w.eq_ignore_ascii_case(b"keep-alive"));
        if head.version == 1 {
            !close
        } else {
            keep
        }
    };
    Ok(RequestSemantics {
        content_length,
        chunked,
        expect_continue,
        keep_alive,
    })
}

fn request_target(head: &ClientHead) -> anyhow::Result<String> {
    let raw = String::from_utf8_lossy(&head.target).into_owned();
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return Ok(raw);
    }
    let host = header_value(&head.headers, "host")
        .context("request missing Host header")?
        .to_owned();
    let host = String::from_utf8_lossy(trim_ascii(&host)).into_owned();
    if host.is_empty() {
        bail!("empty Host header");
    }
    if raw.is_empty() {
        return Ok(format!("http://{host}/"));
    }
    if raw.starts_with('/') {
        return Ok(format!("http://{host}{raw}"));
    }
    Ok(format!("http://{host}/{raw}"))
}

fn build_forward_head(head: &ClientHead, absolute: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&head.method);
    out.push(b' ');
    out.extend_from_slice(absolute.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    let mut has_host = false;
    for h in &head.headers {
        if h.name.eq_ignore_ascii_case(b"proxy-authorization")
            || h.name.eq_ignore_ascii_case(b"proxy-connection")
            || h.name.eq_ignore_ascii_case(b"connection")
        {
            continue;
        }
        if h.name.eq_ignore_ascii_case(b"host") {
            has_host = true;
        }
        out.extend_from_slice(&h.name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(trim_ascii(&h.value));
        out.extend_from_slice(b"\r\n");
    }
    if !has_host {
        if let Some(rest) = absolute.strip_prefix("http://") {
            let host = rest.split(['/', '?']).next().unwrap_or(rest);
            out.extend_from_slice(b"Host: ");
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"Connection: keep-alive\r\n\r\n");
    out
}

fn is_connect(head: &ClientHead) -> bool {
    head.method.eq_ignore_ascii_case(b"CONNECT")
}

fn connect_authority(target: &[u8]) -> anyhow::Result<String> {
    let s = String::from_utf8_lossy(target).into_owned();
    if s.is_empty() || s.contains(['/', ' ']) {
        bail!("invalid CONNECT authority");
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        bail!("CONNECT target must be authority-form");
    }
    let (host, port) = s
        .rsplit_once(':')
        .context("CONNECT authority has no port")?;
    if host.is_empty() {
        bail!("CONNECT authority missing host");
    }
    if host.contains(':') && !s.starts_with('[') {
        bail!("CONNECT IPv6 authority must be bracketed");
    }
    let _: u16 = port
        .parse()
        .context("CONNECT authority has an invalid port")?;
    Ok(s)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let max = a.len().max(b.len());
    for i in 0..max {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(av ^ bv);
    }
    diff == 0
}

fn check_auth(gate: Option<&str>, head: &ClientHead) -> bool {
    let Some(gate) = gate else {
        return true;
    };
    let Some(value) = header_value(&head.headers, "proxy-authorization") else {
        return false;
    };
    let value = trim_ascii(value);
    let Some(space) = value.iter().position(|&b| b == b' ') else {
        return false;
    };
    if !value[..space].eq_ignore_ascii_case(b"basic") {
        return false;
    }
    let token = trim_ascii(&value[space + 1..]);
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token) else {
        return false;
    };
    constant_time_eq(&decoded, gate.as_bytes())
}

fn upstream_keeps_alive(rh: &UpstreamHead) -> bool {
    let Some(v) = header_value(&rh.headers, "connection") else {
        return rh.version == 1;
    };
    !v.windows(5).any(|w| w.eq_ignore_ascii_case(b"close"))
}

fn rewrite_response_close(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() < 4 {
        return bytes.to_vec();
    }
    let mut out = Vec::with_capacity(bytes.len() + 32);
    for line in bytes[..bytes.len() - 4].split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let name_end = line.iter().position(|&b| b == b':').unwrap_or(line.len());
        let name = &line[..name_end];
        if name.eq_ignore_ascii_case(b"connection")
            || name.eq_ignore_ascii_case(b"proxy-connection")
        {
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out
}

// ── Buffered IO ───────────────────────────────────────────────────────

async fn read_bounded<R: AsyncRead + Unpin>(
    src: &mut R,
    buf: &mut [u8],
    idle: Duration,
) -> std::io::Result<usize> {
    if idle.is_zero() {
        src.read(buf).await
    } else {
        match time::timeout(idle, src.read(buf)).await {
            Ok(r) => r,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "idle timeout",
            )),
        }
    }
}

async fn read_head(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    idle: Duration,
) -> anyhow::Result<usize> {
    loop {
        if let Some(end) = find_head_end(buf) {
            return Ok(end);
        }
        if buf.len() >= MAX_HEAD_BYTES {
            bail!("request head exceeds the 16KB limit");
        }
        let mut chunk = [0u8; 4096];
        let n = read_bounded(stream, &mut chunk, idle).await?;
        if n == 0 {
            bail!("client closed while reading the request head");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn read_upstream_head(up: &mut Upstream, idle: Duration) -> anyhow::Result<UpstreamHead> {
    loop {
        if let Some(end) = find_head_end(&up.buf) {
            let head = parse_upstream_head(&up.buf[..end])?;
            up.buf.drain(..end);
            return Ok(head);
        }
        if up.buf.len() >= MAX_HEAD_BYTES {
            bail!("upstream response head exceeds the 16KB limit");
        }
        let mut chunk = [0u8; 4096];
        let n = read_bounded(&mut up.stream, &mut chunk, idle).await?;
        if n == 0 {
            bail!("upstream closed while sending the response head");
        }
        up.buf.extend_from_slice(&chunk[..n]);
    }
}

async fn relay_exact<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    src: &mut R,
    srcbuf: &mut Vec<u8>,
    dst: &mut W,
    mut n: u64,
    idle: Duration,
    count: &AtomicUsize,
) -> anyhow::Result<()> {
    let mut chunk = [0u8; MAX_BODY_CHUNK];
    while n > 0 {
        if srcbuf.is_empty() {
            let want = chunk.len().min(n as usize);
            let read = read_bounded(src, &mut chunk[..want], idle).await?;
            if read == 0 {
                bail!("unexpected EOF while relaying a framed body");
            }
            srcbuf.extend_from_slice(&chunk[..read]);
        }
        let take = (srcbuf.len() as u64).min(n) as usize;
        dst.write_all(&srcbuf[..take]).await?;
        count.fetch_add(take, Ordering::Relaxed);
        srcbuf.drain(..take);
        n -= take as u64;
    }
    Ok(())
}

async fn read_relay_line<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    src: &mut R,
    srcbuf: &mut Vec<u8>,
    dst: &mut W,
    idle: Duration,
    cap: usize,
    count: &AtomicUsize,
) -> anyhow::Result<Vec<u8>> {
    let mut line = Vec::with_capacity(64);
    loop {
        if let Some(pos) = srcbuf.iter().position(|&b| b == b'\n') {
            dst.write_all(&srcbuf[..=pos]).await?;
            count.fetch_add(pos + 1, Ordering::Relaxed);
            line.extend_from_slice(&srcbuf[..pos]);
            srcbuf.drain(..=pos);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(line);
        }
        if line.len().saturating_add(srcbuf.len()) > cap {
            bail!("framing line exceeds the 16KB limit");
        }
        if srcbuf.is_empty() {
            let mut chunk = [0u8; 1024];
            let n = read_bounded(src, &mut chunk, idle).await?;
            if n == 0 {
                bail!("unexpected EOF inside chunk framing");
            }
            srcbuf.extend_from_slice(&chunk[..n]);
        } else {
            line.extend_from_slice(srcbuf);
            srcbuf.clear();
        }
    }
}

async fn relay_chunked<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    src: &mut R,
    srcbuf: &mut Vec<u8>,
    dst: &mut W,
    idle: Duration,
    count: &AtomicUsize,
) -> anyhow::Result<()> {
    loop {
        let line = read_relay_line(src, srcbuf, dst, idle, MAX_LINE_BYTES, count).await?;
        let size_str =
            String::from_utf8_lossy(line.split(|&b| b == b';').next().unwrap_or_default());
        let size = u64::from_str_radix(size_str.trim(), 16).context("invalid chunk size")?;
        if size == 0 {
            loop {
                let trailer =
                    read_relay_line(src, srcbuf, dst, idle, MAX_LINE_BYTES, count).await?;
                if trailer.is_empty() {
                    return Ok(());
                }
            }
        }
        relay_exact(src, srcbuf, dst, size + 2, idle, count).await?;
    }
}

async fn relay_until_eof<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    src: &mut R,
    srcbuf: &mut Vec<u8>,
    dst: &mut W,
    idle: Duration,
    count: &AtomicUsize,
) -> anyhow::Result<()> {
    if !srcbuf.is_empty() {
        let bytes = std::mem::take(srcbuf);
        dst.write_all(&bytes).await?;
        count.fetch_add(bytes.len(), Ordering::Relaxed);
    }
    let mut chunk = [0u8; MAX_BODY_CHUNK];
    loop {
        let n = read_bounded(src, &mut chunk, idle).await?;
        if n == 0 {
            return Ok(());
        }
        dst.write_all(&chunk[..n]).await?;
        count.fetch_add(n, Ordering::Relaxed);
    }
}

// ── Upstream plumbing ─────────────────────────────────────────────────

async fn dial_upstream(pool: &Pool, proxy: &Proxy, timeout: Duration) -> anyhow::Result<TcpStream> {
    let mut p = proxy.clone();
    let started = Instant::now();
    let t = time::timeout(timeout, p.connect_timeout(timeout))
        .await
        .with_context(|| format!("dialing {} timed out", proxy.as_text()))?
        .with_context(|| format!("failed to connect to {}", proxy.as_text()))?;
    pool.record_latency(proxy.as_text(), started.elapsed().as_secs_f64());
    Ok(t.inner)
}

async fn negotiate_tunnel(
    stream: &mut TcpStream,
    proxy: &Proxy,
    authority: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let uri: hyper::Uri = format!("https://{authority}/")
        .parse()
        .context("invalid CONNECT authority")?;
    let kind = upstream_tunnel_kind(proxy).context("proxy has no tunnel protocol")?;
    let mut runtimes = flx::RuntimeStats::default();
    let negotiate = match kind {
        UpstreamKind::HttpConnect => {
            HttpsNegotiator.negotiate(stream, &mut runtimes, proxy.as_text(), &uri)
        }
        UpstreamKind::Socks4 => {
            Socks4Negotiator.negotiate(stream, &mut runtimes, proxy.as_text(), &uri)
        }
        UpstreamKind::Socks5 => {
            Socks5Negotiator.negotiate(stream, &mut runtimes, proxy.as_text(), &uri)
        }
    };
    time::timeout(timeout, negotiate)
        .await
        .with_context(|| {
            format!(
                "tunnel negotiation to {authority} through {} timed out",
                proxy.as_text()
            )
        })?
        .with_context(|| {
            format!(
                "failed to tunnel to {authority} through {}",
                proxy.as_text()
            )
        })?;
    Ok(())
}

async fn acquire_tunnel(
    pool: &Pool,
    cfg: &ServeConfig,
    guard: &mut PinGuard,
    exclude: &mut HashSet<String>,
    authority: &str,
) -> anyhow::Result<Option<Upstream>> {
    let mut last_error: Option<anyhow::Error> = None;
    for _ in 0..=MAX_FAILOVERS {
        let Some(proxy) = pool
            .await_proxy(PartitionKind::Tunnel, cfg.pool_wait, exclude)
            .await
        else {
            return Ok(None);
        };
        let result = async {
            let mut stream = dial_upstream(pool, &proxy, cfg.dial_timeout).await?;
            negotiate_tunnel(&mut stream, &proxy, authority, cfg.dial_timeout).await?;
            Ok::<TcpStream, anyhow::Error>(stream)
        }
        .await;
        match result {
            Ok(stream) => {
                guard.pin(pool, proxy.as_text().to_owned());
                return Ok(Some(Upstream {
                    proxy,
                    stream,
                    buf: Vec::new(),
                }));
            }
            Err(e) => {
                pool.stats.errors.fetch_add(1, Ordering::Relaxed);
                exclude.insert(proxy.as_text().to_owned());
                last_error = Some(e);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no tunnel upstream available")))
}

async fn forward_client_body(
    client: &mut TcpStream,
    buf: &mut Vec<u8>,
    dst: &mut TcpStream,
    semantics: &RequestSemantics,
    idle: Duration,
    count: &AtomicUsize,
) -> anyhow::Result<()> {
    if semantics.chunked {
        relay_chunked(client, buf, dst, idle, count).await
    } else if let Some(n) = semantics.content_length {
        relay_exact(client, buf, dst, n, idle, count).await
    } else {
        Ok(())
    }
}

fn no_body_response(status: u16, method: &[u8]) -> bool {
    status == 204
        || status == 304
        || (100..200).contains(&status)
        || method.eq_ignore_ascii_case(b"HEAD")
}

async fn relay_response_head_and_body(
    client: &mut TcpStream,
    up: &mut Upstream,
    rh: &UpstreamHead,
    method: &[u8],
    idle: Duration,
    count: &AtomicUsize,
) -> anyhow::Result<ResponseEnd> {
    let no_body = no_body_response(rh.status, method);
    let eof_delimited = !no_body && !rh.chunked && rh.content_length.is_none();
    if eof_delimited {
        let head = rewrite_response_close(&rh.bytes);
        client.write_all(&head).await?;
        count.fetch_add(head.len(), Ordering::Relaxed);
        relay_until_eof(&mut up.stream, &mut up.buf, client, idle, count).await?;
        return Ok(ResponseEnd::ClientClose);
    }
    client.write_all(&rh.bytes).await?;
    count.fetch_add(rh.bytes.len(), Ordering::Relaxed);
    let keeps = upstream_keeps_alive(rh);
    if no_body {
        return Ok(if keeps {
            ResponseEnd::KeepAlive
        } else {
            ResponseEnd::ClientClose
        });
    }
    if rh.chunked {
        relay_chunked(&mut up.stream, &mut up.buf, client, idle, count).await?;
    } else if let Some(cl) = rh.content_length {
        relay_exact(&mut up.stream, &mut up.buf, client, cl, idle, count).await?;
    }
    Ok(if keeps {
        ResponseEnd::KeepAlive
    } else {
        ResponseEnd::ClientClose
    })
}

async fn relay_final_response(
    client: &mut TcpStream,
    up: &mut Upstream,
    method: &[u8],
    idle: Duration,
    mut pending: Option<UpstreamHead>,
    count: &AtomicUsize,
) -> anyhow::Result<ResponseEnd> {
    loop {
        let rh = match pending.take() {
            Some(rh) => rh,
            None => read_upstream_head(up, idle).await?,
        };
        if rh.status == 101 {
            client.write_all(&rh.bytes).await?;
            count.fetch_add(rh.bytes.len(), Ordering::Relaxed);
            return Ok(ResponseEnd::Handoff);
        }
        if (100..200).contains(&rh.status) {
            client.write_all(&rh.bytes).await?;
            count.fetch_add(rh.bytes.len(), Ordering::Relaxed);
            continue;
        }
        return relay_response_head_and_body(client, up, &rh, method, idle, count).await;
    }
}

async fn expect_phase(
    client: &mut TcpStream,
    buf: &mut Vec<u8>,
    upstream: &mut Option<Upstream>,
    method: &[u8],
    semantics: &RequestSemantics,
    idle: Duration,
    count: &AtomicUsize,
) -> anyhow::Result<ResponseEnd> {
    loop {
        let up = upstream.as_mut().expect("upstream ensured");
        let rh = read_upstream_head(up, idle).await?;
        if rh.status == 100 {
            client.write_all(&rh.bytes).await?;
            count.fetch_add(rh.bytes.len(), Ordering::Relaxed);
            let up = upstream.as_mut().expect("upstream ensured");
            forward_client_body(client, buf, &mut up.stream, semantics, idle, count).await?;
            let up = upstream.as_mut().expect("upstream ensured");
            return relay_final_response(client, up, method, idle, None, count).await;
        }
        if rh.status == 101 {
            client.write_all(&rh.bytes).await?;
            count.fetch_add(rh.bytes.len(), Ordering::Relaxed);
            return Ok(ResponseEnd::Handoff);
        }
        if (100..200).contains(&rh.status) {
            client.write_all(&rh.bytes).await?;
            count.fetch_add(rh.bytes.len(), Ordering::Relaxed);
            continue;
        }
        let up = upstream.as_mut().expect("upstream ensured");
        let end = relay_response_head_and_body(client, up, &rh, method, idle, count).await?;
        if !buf.is_empty() {
            return Ok(ResponseEnd::ClientClose);
        }
        return Ok(end);
    }
}

async fn ensure_upstream(
    client: &mut TcpStream,
    pool: &Pool,
    cfg: &ServeConfig,
    guard: &mut PinGuard,
    upstream: &mut Option<Upstream>,
    exclude: &mut HashSet<String>,
) -> anyhow::Result<bool> {
    if upstream.is_some() {
        return Ok(true);
    }
    for _ in 0..=MAX_FAILOVERS {
        let Some(proxy) = pool
            .await_proxy(PartitionKind::Forward, cfg.pool_wait, exclude)
            .await
        else {
            let _ = client.write_all(RESPONSE_503).await;
            return Ok(false);
        };
        match dial_upstream(pool, &proxy, cfg.dial_timeout).await {
            Ok(stream) => {
                guard.pin(pool, proxy.as_text().to_owned());
                *upstream = Some(Upstream {
                    proxy,
                    stream,
                    buf: Vec::new(),
                });
                return Ok(true);
            }
            Err(_) => {
                pool.stats.errors.fetch_add(1, Ordering::Relaxed);
                exclude.insert(proxy.as_text().to_owned());
            }
        }
    }
    let _ = client.write_all(RESPONSE_502).await;
    Ok(false)
}

struct ForwardRequest<'a> {
    head: &'a ClientHead,
    forwarded: &'a [u8],
}

async fn plain_http_roundtrip(
    client: &mut TcpStream,
    buf: &mut Vec<u8>,
    pool: &Pool,
    cfg: &ServeConfig,
    guard: &mut PinGuard,
    mut upstream: Option<Upstream>,
    plan: ForwardRequest<'_>,
) -> anyhow::Result<(RoundtripEnd, Option<Upstream>)> {
    let semantics = request_semantics(plan.head)?;

    let mut exclude: HashSet<String> = HashSet::new();
    let mut wrote = false;
    for _ in 0..2 {
        if !ensure_upstream(client, pool, cfg, guard, &mut upstream, &mut exclude).await? {
            return Ok((RoundtripEnd::ClientClose, None));
        }
        let up = upstream.as_mut().expect("upstream ensured");
        let endpoint = up.proxy.as_text().to_owned();
        match up.stream.write_all(plan.forwarded).await {
            Ok(()) => {
                wrote = true;
                break;
            }
            Err(_) => {
                pool.stats.failovers.fetch_add(1, Ordering::Relaxed);
                guard.release();
                exclude.insert(endpoint);
                upstream = None;
            }
        }
    }
    if !wrote {
        let _ = client.write_all(RESPONSE_502).await;
        return Ok((RoundtripEnd::ClientClose, None));
    }

    let count = &pool.stats.bytes;
    let end = if semantics.expect_continue {
        expect_phase(
            client,
            buf,
            &mut upstream,
            &plan.head.method,
            &semantics,
            cfg.idle,
            count,
        )
        .await?
    } else {
        {
            let up = upstream.as_mut().expect("upstream ensured");
            forward_client_body(client, buf, &mut up.stream, &semantics, cfg.idle, count).await?;
        }
        let up = upstream.as_mut().expect("upstream ensured");
        relay_final_response(client, up, &plan.head.method, cfg.idle, None, count).await?
    };

    match end {
        ResponseEnd::Handoff => {
            let up = upstream.take().expect("upstream present");
            Ok((RoundtripEnd::Handoff(up), None))
        }
        ResponseEnd::KeepAlive => Ok((RoundtripEnd::KeepGoing, upstream)),
        ResponseEnd::ClientClose => Ok((RoundtripEnd::ClientClose, upstream)),
    }
}

async fn pipe_bidirectional(
    a: &mut TcpStream,
    b: &mut TcpStream,
    idle: Duration,
    count: &AtomicUsize,
) -> PipeEnd {
    let mut a2b = [0u8; MAX_BODY_CHUNK];
    let mut b2a = [0u8; MAX_BODY_CHUNK];
    loop {
        tokio::select! {
            r = read_bounded(a, &mut a2b, idle) => match r {
                Ok(0) => return PipeEnd::ClientClosed,
                Ok(n) => {
                    count.fetch_add(n, Ordering::Relaxed);
                    if b.write_all(&a2b[..n]).await.is_err() {
                        return PipeEnd::UpstreamGone;
                    }
                }
                Err(_) => return PipeEnd::IdleTimeout,
            },
            r = read_bounded(b, &mut b2a, idle) => match r {
                Ok(0) => return PipeEnd::UpstreamGone,
                Ok(n) => {
                    count.fetch_add(n, Ordering::Relaxed);
                    if a.write_all(&b2a[..n]).await.is_err() {
                        return PipeEnd::ClientClosed;
                    }
                }
                Err(_) => return PipeEnd::IdleTimeout,
            },
        }
    }
}

struct PinGuard {
    pool: Option<Pool>,
    endpoint: Option<String>,
}

impl PinGuard {
    fn new() -> Self {
        Self {
            pool: None,
            endpoint: None,
        }
    }

    fn pin(&mut self, pool: &Pool, endpoint: String) {
        pool.mark_in_use(&endpoint);
        if let Some(old) = self.endpoint.take() {
            self.pool
                .as_ref()
                .expect("pin guard pool present")
                .release(&old);
        }
        self.pool = Some(pool.clone());
        self.endpoint = Some(endpoint);
    }

    fn release(&mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            if let Some(pool) = self.pool.take() {
                pool.release(&endpoint);
            }
        }
    }
}

impl Drop for PinGuard {
    fn drop(&mut self) {
        self.release();
    }
}

async fn handle_connect(
    client: &mut TcpStream,
    pool: &Pool,
    cfg: &ServeConfig,
    guard: &mut PinGuard,
    authority: &str,
) -> anyhow::Result<()> {
    let mut exclude: HashSet<String> = HashSet::new();
    let mut upstream = match acquire_tunnel(pool, cfg, guard, &mut exclude, authority).await {
        Ok(Some(up)) => up,
        Ok(None) => {
            let _ = client.write_all(RESPONSE_503).await;
            return Ok(());
        }
        Err(_) => {
            let _ = client.write_all(RESPONSE_502).await;
            return Ok(());
        }
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let mut fails = 0;
    loop {
        match pipe_bidirectional(client, &mut upstream.stream, cfg.idle, &pool.stats.bytes).await {
            PipeEnd::ClientClosed | PipeEnd::IdleTimeout => break,
            PipeEnd::UpstreamGone => {
                if fails >= MAX_FAILOVERS {
                    break;
                }
                fails += 1;
                pool.stats.failovers.fetch_add(1, Ordering::Relaxed);
                exclude.insert(upstream.proxy.as_text().to_owned());
                drop(upstream);
                match acquire_tunnel(pool, cfg, guard, &mut exclude, authority).await {
                    Ok(Some(up)) => upstream = up,
                    _ => break,
                }
            }
        }
    }
    guard.release();
    Ok(())
}

async fn serve_session(
    client: &mut TcpStream,
    buf: &mut Vec<u8>,
    pool: &Pool,
    cfg: &ServeConfig,
    guard: &mut PinGuard,
) -> anyhow::Result<()> {
    let mut upstream: Option<Upstream> = None;
    loop {
        if !buf.is_empty() {
            bail!("pipelined request rejected");
        }
        let head_len = read_head(client, buf, cfg.idle).await?;
        pool.stats.requests.fetch_add(1, Ordering::Relaxed);
        let head_bytes = buf[..head_len].to_vec();
        buf.drain(..head_len);
        let head = match parse_client_head(&head_bytes) {
            Ok(head) => head,
            Err(_) => {
                let _ = client.write_all(RESPONSE_400).await;
                return Ok(());
            }
        };
        if !check_auth(cfg.auth.as_deref(), &head) {
            let _ = client.write_all(RESPONSE_407).await;
            return Ok(());
        }
        if is_connect(&head) {
            let authority = match connect_authority(&head.target) {
                Ok(authority) => authority,
                Err(_) => {
                    let _ = client.write_all(RESPONSE_400).await;
                    return Ok(());
                }
            };
            return handle_connect(client, pool, cfg, guard, &authority).await;
        }
        let absolute = match request_target(&head) {
            Ok(absolute) => absolute,
            Err(_) => {
                let _ = client.write_all(RESPONSE_400).await;
                return Ok(());
            }
        };
        let semantics = match request_semantics(&head) {
            Ok(semantics) => semantics,
            Err(_) => {
                let _ = client.write_all(RESPONSE_400).await;
                return Ok(());
            }
        };
        let forwarded = build_forward_head(&head, &absolute);
        let plan = ForwardRequest {
            head: &head,
            forwarded: &forwarded,
        };
        let (end, next) =
            match plain_http_roundtrip(client, buf, pool, cfg, guard, upstream, plan).await {
                Ok(result) => result,
                Err(_) => return Ok(()),
            };
        upstream = next;
        match end {
            RoundtripEnd::ClientClose => return Ok(()),
            RoundtripEnd::KeepGoing => {
                if !cfg.session {
                    upstream = None;
                    guard.release();
                }
            }
            RoundtripEnd::Handoff(mut up) => {
                let _ =
                    pipe_bidirectional(client, &mut up.stream, cfg.idle, &pool.stats.bytes).await;
                guard.release();
                return Ok(());
            }
        }
        if !semantics.keep_alive {
            return Ok(());
        }
    }
}

async fn serve_connection(mut client: TcpStream, pool: Pool, cfg: ServeConfig) {
    if !pool.await_session_slot(cfg.pool_wait).await {
        pool.stats.errors.fetch_add(1, Ordering::Relaxed);
        let _ = client.write_all(RESPONSE_503).await;
        return;
    }
    pool.stats.sessions_total.fetch_add(1, Ordering::Relaxed);
    let mut guard = PinGuard::new();
    let mut buf = Vec::with_capacity(2048);
    if let Err(e) = serve_session(&mut client, &mut buf, &pool, &cfg, &mut guard).await {
        #[cfg(feature = "log")]
        log::trace!("serve session ended: {e:#}");
        #[cfg(not(feature = "log"))]
        let _ = e;
    }
    guard.release();
}

async fn run_refresh(pool: Pool, vconfig: flx::validator::Config, _cfg: ServeConfig) {
    let candidates = pool.candidates_for_refresh();
    if candidates.is_empty() {
        return;
    }
    let mut validator =
        match ProxyValidator::validate(futures_util::stream::iter(candidates), vconfig).await {
            Ok(validator) => validator,
            Err(e) => {
                #[cfg(feature = "log")]
                log::warn!("pool refresh aborted (judges unreachable): {e:#}");
                #[cfg(not(feature = "log"))]
                let _ = e;
                return;
            }
        };
    let mut fresh = Vec::new();
    while let Some(proxy) = validator.get_one().await {
        fresh.push(proxy);
    }
    if !fresh.is_empty() {
        #[cfg(feature = "log")]
        log::info!("pool refreshed with {} validated proxies", fresh.len());
        pool.replace_validated(fresh);
    }
}

pub async fn run_serve(
    args: ServeArgs,
    quiet: bool,
    no_color: bool,
    download: &tokio::sync::watch::Receiver<Option<flx::DownloadProgress>>,
    cancel: &Arc<Notify>,
) -> anyhow::Result<RunOutcome> {
    if args.fetcher.dry_run {
        super::list_sources();
        return Ok(RunOutcome::Finished);
    }

    let (mut protocols, groups) = super::split_type_groups(&args.validator.types);
    if protocols.is_empty() && groups.is_empty() {
        // Serve needs both tunnel-capable and forward-capable upstreams, so
        // the default validates a protocol set that covers both partitions.
        protocols.extend([
            Protocol::Http(flx::Anonymity::Unknown),
            Protocol::Https(flx::Anonymity::Unknown),
            Protocol::Socks4,
            Protocol::Socks5,
        ]);
    }

    let warmup = super::make_warmup(quiet, no_color, download);
    let vconfig =
        super::validator_config(&args.validator, protocols.clone(), groups.clone(), false);

    let source = match &args.validator.file {
        Some(file) => {
            if let Some(bar) = &warmup {
                bar.set_phase("Checking online judges …");
            }
            super::file_source(file).await?
        }
        None => {
            let fetch_cfg = super::fetcher_config(&args.fetcher);
            let mut fetcher = tokio::select! {
                fetcher = flx::ProxySource::from_fetcher(fetch_cfg) => {
                    fetcher.context("failed to start proxy fetcher")?
                }
                _ = cancel.notified() => {
                    drop(warmup);
                    return Ok(RunOutcome::Cancelled);
                }
            };
            let stages = fetcher.stage_events();
            if let Some(bar) = &warmup {
                bar.set_phase("Fetching proxy lists …");
            }
            let watcher = match (&warmup, stages) {
                (Some(bar), Some(mut rx)) => {
                    let bar = Arc::clone(bar);
                    Some(tokio::spawn(async move {
                        while let Some(stage) = rx.recv().await {
                            let phase = match stage {
                                flx::FetchStage::Primary => "Fetching primary sources …",
                                flx::FetchStage::Fallback => "Fetching fallback sources …",
                                flx::FetchStage::Done => "Checking online judges …",
                            };
                            bar.set_phase(phase);
                            if matches!(stage, flx::FetchStage::Done) {
                                break;
                            }
                        }
                    }))
                }
                _ => None,
            };
            let source = futures_util::StreamExt::boxed(fetcher);
            if let Some(task) = watcher {
                task.abort();
                let _ = task.await;
            }
            source
        }
    };
    drop(warmup);

    let validate = ProxyValidator::validate(source, vconfig);
    tokio::pin!(validate);
    let validator = tokio::select! {
        validator = &mut validate => validator.context("failed to start proxy validator")?,
        _ = cancel.notified() => return Ok(RunOutcome::Cancelled),
    };

    let pool = Pool::new(args.max_sessions, args.pool_size, args.use_fastest);
    let consumer_pool = pool.clone();
    let consumer = tokio::spawn(async move {
        let mut validator = validator;
        while let Some(proxy) = validator.get_one().await {
            consumer_pool.add(proxy);
        }
        consumer_pool.rebuild();
    });

    let started = std::time::Instant::now();
    let serve_bar = super::make_serve_bar(quiet, no_color, pool.clone());
    let addr = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind gateway listener on {addr}"))?;
    if !quiet && args.host != "127.0.0.1" && args.host != "localhost" && args.auth.is_none() {
        eprintln!("warning: non-loopback bind without --auth exposes an open proxy");
    }
    if !quiet && serve_bar.is_none() {
        eprintln!("warming up: fetching and validating proxies …");
    }

    let clients_sem =
        (args.max_clients > 0).then(|| Arc::new(tokio::sync::Semaphore::new(args.max_clients)));
    let cfg = ServeConfig::from_args(&args);
    let mut sessions = tokio::task::JoinSet::new();

    // Non-TTY fallback stats; the status line already repaints itself on a TTY.
    let stats_pool = pool.clone();
    let stats_task = if quiet || serve_bar.is_some() {
        None
    } else {
        Some(tokio::spawn(async move {
            let mut tick = time::interval(STATS_INTERVAL);
            tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let snap = stats_pool.snapshot();
                eprintln!(
                    "serve stats: sessions active {}, pool {}, failovers {}, errors {}, requests {}, sessions total {}",
                    snap.active_sessions, snap.pool, snap.failovers, snap.errors, snap.requests, snap.sessions_total
                );
            }
        }))
    };

    let mut house_tick = time::interval(Duration::from_millis(500));
    house_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut pool_ready_announced = false;
    let mut pool_empty_announced = false;

    let mut refresh_tick = (args.refresh > 0).then(|| {
        let mut tick = time::interval(Duration::from_secs(args.refresh));
        tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        tick
    });

    let outcome = loop {
        tokio::select! {
            _ = cancel.notified() => break RunOutcome::Cancelled,
            conn = listener.accept() => {
                match conn {
                    Ok((client, _)) => {
                        let pool = pool.clone();
                        let cfg = cfg.clone();
                        let semaphore = clients_sem.clone();
                        sessions.spawn(async move {
                            if let Some(semaphore) = semaphore {
                                let _permit = semaphore.acquire_owned().await;
                            }
                            serve_connection(client, pool, cfg).await;
                        });
                    }
                    Err(e) => {
                        #[cfg(feature = "log")]
                        log::warn!("gateway accept failed: {e}");
                        #[cfg(not(feature = "log"))]
                        let _ = e;
                    }
                }
            }
            _ = async {
                if let Some(tick) = &mut refresh_tick {
                    tick.tick().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                let pool = pool.clone();
                let refresh_cfg = ServeConfig::from_args(&args);
                let refresh_vconfig = super::validator_config(
                    &args.validator,
                    protocols.clone(),
                    groups.clone(),
                    false,
                );
                tokio::spawn(async move { run_refresh(pool, refresh_vconfig, refresh_cfg).await });
            }
            _ = house_tick.tick() => {
                if !quiet && serve_bar.is_none() {
                    let snap = pool.snapshot();
                    if !pool_ready_announced && snap.tunnel + snap.forward > 0 {
                        pool_ready_announced = true;
                        eprintln!(
                            "serving on {addr} · {}",
                            super::format_pool_ready(snap.pool, snap.tunnel, snap.forward)
                        );
                    }
                    if !pool_empty_announced && consumer.is_finished() && snap.pool == 0 {
                        pool_empty_announced = true;
                        eprintln!("serve: pool empty (all candidates failed)");
                    }
                }
            }
        }
    };

    drop(listener);
    consumer.abort();
    let _ = consumer.await;
    let drain = time::timeout(DRAIN_GRACE, async {
        while sessions.join_next().await.is_some() {}
    });
    let _ = drain.await;
    drop(sessions);
    if let Some(task) = stats_task {
        task.abort();
    }
    if let Some(bar) = &serve_bar {
        bar.hide();
    }
    drop(serve_bar);
    if !quiet {
        let summary = super::format_serve_summary(pool.snapshot(), started.elapsed());
        eprintln!("{summary}");
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flx::proxy::models::{Anonymity, ProxyType};

    type Responder = Arc<dyn Fn(usize, u64, &[u8], Option<&[u8]>) -> (Vec<u8>, bool) + Send + Sync>;

    fn proxy_with(port: u16, types: &[Protocol]) -> Proxy {
        let mut proxy = Proxy::new(std::net::Ipv4Addr::LOCALHOST, port);
        proxy.proxy_types = types.iter().map(|t| ProxyType::checked(*t)).collect();
        proxy
    }

    fn http_proxy(port: u16) -> Proxy {
        proxy_with(port, &[Protocol::Http(Anonymity::Unknown)])
    }

    fn https_proxy(port: u16) -> Proxy {
        proxy_with(port, &[Protocol::Https(Anonymity::Unknown)])
    }

    fn socks5_proxy(port: u16) -> Proxy {
        proxy_with(port, &[Protocol::Socks5])
    }

    fn serve_config() -> ServeConfig {
        ServeConfig {
            session: true,
            idle: Duration::from_secs(60),
            pool_wait: Duration::from_secs(5),
            dial_timeout: Duration::from_secs(3),
            auth: None,
        }
    }

    fn cfg_with(change: impl FnOnce(&mut ServeConfig)) -> ServeConfig {
        let mut cfg = serve_config();
        change(&mut cfg);
        cfg
    }

    fn ok_response(body: &str, close: bool) -> Vec<u8> {
        let conn = if close {
            "Connection: close\r\n"
        } else {
            "Connection: keep-alive\r\n"
        };
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{conn}\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn head_has(head: &[u8], name: &str, value: &str) -> bool {
        let lower = String::from_utf8_lossy(head).to_ascii_lowercase();
        lower.lines().any(|line| {
            let Some((n, v)) = line.split_once(':') else {
                return false;
            };
            n.trim() == name && v.contains(value)
        })
    }

    fn fake_content_length(head: &[u8]) -> Option<u64> {
        let lower = String::from_utf8_lossy(head).to_ascii_lowercase();
        lower.lines().find_map(|line| {
            let (n, v) = line.split_once(':')?;
            (n.trim() == "content-length").then(|| v.trim().parse().ok())?
        })
    }

    struct ForwardFake {
        port: u16,
        records: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        conns: Arc<AtomicUsize>,
    }

    async fn fake_read_head(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
        loop {
            if let Some(end) = find_head_end(buf) {
                let head = buf[..end].to_vec();
                buf.drain(..end);
                return Some(head);
            }
            if buf.len() >= MAX_HEAD_BYTES {
                return None;
            }
            let mut chunk = [0u8; 1024];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    async fn fake_read_line(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
        loop {
            if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let mut line = buf[..pos].to_vec();
                buf.drain(..=pos);
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Some(line);
            }
            let mut chunk = [0u8; 1024];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    async fn fake_read_exact(
        stream: &mut TcpStream,
        buf: &mut Vec<u8>,
        n: usize,
    ) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        let mut remaining = n;
        while remaining > 0 {
            if buf.is_empty() {
                let mut chunk = [0u8; 1024];
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return None,
                    Ok(got) => buf.extend_from_slice(&chunk[..got]),
                }
            }
            let take = remaining.min(buf.len());
            out.extend_from_slice(&buf[..take]);
            buf.drain(..take);
            remaining -= take;
        }
        Some(out)
    }

    async fn fake_read_body(
        stream: &mut TcpStream,
        buf: &mut Vec<u8>,
        cl: Option<u64>,
        chunked: bool,
    ) -> Option<Vec<u8>> {
        let mut body = Vec::new();
        if let Some(payload) = cl {
            let mut remaining = payload;
            while remaining > 0 {
                if buf.is_empty() {
                    let mut chunk = [0u8; 1024];
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return None,
                        Ok(got) => buf.extend_from_slice(&chunk[..got]),
                    }
                }
                let take = (buf.len() as u64).min(remaining) as usize;
                body.extend_from_slice(&buf[..take]);
                buf.drain(..take);
                remaining -= take as u64;
            }
            return Some(body);
        }
        if chunked {
            loop {
                let line = fake_read_line(stream, buf).await?;
                let size_str =
                    String::from_utf8_lossy(line.split(|&b| b == b';').next().unwrap_or_default());
                let size = u64::from_str_radix(size_str.trim(), 16).ok()?;
                if size == 0 {
                    while !fake_read_line(stream, buf).await?.is_empty() {}
                    return Some(body);
                }
                body.extend(fake_read_exact(stream, buf, size as usize).await?);
                let _ = fake_read_exact(stream, buf, 2).await?;
            }
        }
        Some(body)
    }

    async fn spawn_forward_proxy(responder: Responder, rst_after_first: bool) -> ForwardFake {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let records: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::default();
        let conns = Arc::new(AtomicUsize::new(0));
        let records_task = Arc::clone(&records);
        let conns_task = Arc::clone(&conns);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let responder = Arc::clone(&responder);
                let records = Arc::clone(&records_task);
                let conns = Arc::clone(&conns_task);
                tokio::spawn(async move {
                    let conn = conns.fetch_add(1, Ordering::Relaxed);
                    let mut buf = Vec::new();
                    let mut reqs: u64 = 0;
                    loop {
                        let Some(head) = fake_read_head(&mut stream, &mut buf).await else {
                            return;
                        };
                        reqs += 1;
                        records.lock().expect("records mutex").push(head.clone());
                        let cl = fake_content_length(&head);
                        let chunked = head_has(&head, "transfer-encoding", "chunked");
                        let expects = head_has(&head, "expect", "100-continue");
                        let mut body = None;
                        if expects {
                            if stream
                                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                                .await
                                .is_err()
                            {
                                return;
                            }
                            body = fake_read_body(&mut stream, &mut buf, cl, chunked).await;
                        } else if cl.is_some() || chunked {
                            body = fake_read_body(&mut stream, &mut buf, cl, chunked).await;
                        }
                        let (response, close) = responder(conn, reqs, &head, body.as_deref());
                        if stream.write_all(&response).await.is_err() {
                            return;
                        }
                        if close {
                            break;
                        }
                    }
                    if rst_after_first {
                        #[allow(deprecated)]
                        let _ = stream.set_linger(Some(Duration::ZERO));
                    }
                });
            }
        });
        ForwardFake {
            port,
            records,
            conns,
        }
    }

    async fn spawn_connect_echo(prefix: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    if fake_read_head(&mut stream, &mut buf).await.is_none() {
                        return;
                    }
                    if stream
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let mut echo = [0u8; 1024];
                    loop {
                        match stream.read(&mut echo).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                let prefixed = format!("{prefix}:");
                                if stream.write_all(prefixed.as_bytes()).await.is_err() {
                                    return;
                                }
                                if stream.write_all(&echo[..n]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        port
    }

    async fn spawn_gateway(proxies: Vec<Proxy>, cfg: ServeConfig) -> (u16, Pool) {
        let pool = Pool::new(0, 0, false);
        for proxy in proxies {
            pool.add(proxy);
        }
        pool.rebuild();
        let port = spawn_gateway_with_pool(pool.clone(), cfg).await;
        (port, pool)
    }

    async fn spawn_gateway_with_pool(pool: Pool, cfg: ServeConfig) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let pool = pool.clone();
                let cfg = cfg.clone();
                tokio::spawn(async move { serve_connection(client, pool, cfg).await });
            }
        });
        port
    }

    async fn tcp(port: u16) -> TcpStream {
        TcpStream::connect(("127.0.0.1", port)).await.unwrap()
    }

    async fn read_until_head(stream: &mut TcpStream) -> (Vec<u8>, Vec<u8>) {
        let mut buf = Vec::new();
        loop {
            if let Some(end) = find_head_end(&buf) {
                let head = buf[..end].to_vec();
                let tail = buf[end..].to_vec();
                return (head, tail);
            }
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                return (buf, Vec::new());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn read_until_contains(stream: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
        let mut collected = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                return collected;
            }
            collected.extend_from_slice(&chunk[..n]);
            if collected.windows(needle.len()).any(|w| w == needle) {
                return collected;
            }
        }
    }

    async fn read_body(stream: &mut TcpStream, mut tail: Vec<u8>, n: usize) -> Vec<u8> {
        while tail.len() < n {
            let mut chunk = [0u8; 1024];
            let read = time::timeout(Duration::from_secs(2), stream.read(&mut chunk))
                .await
                .ok()
                .map_or(0, |r| r.unwrap_or(0));
            if read == 0 {
                break;
            }
            tail.extend_from_slice(&chunk[..read]);
        }
        tail
    }

    // ── unit: partitioning and rotation ────────────────────────────────

    #[test]
    fn capability_partitioning_matches_d3() {
        assert!(proxy_is_tunnel_capable(&https_proxy(1)));
        assert!(proxy_is_tunnel_capable(&socks5_proxy(1)));
        assert!(proxy_is_tunnel_capable(&proxy_with(1, &[Protocol::Socks4])));
        assert!(proxy_is_tunnel_capable(&proxy_with(
            1,
            &[Protocol::Connect(80)]
        )));
        assert!(
            proxy_is_tunnel_capable(&http_proxy(1)),
            "HTTP is dual per D3"
        );
        assert!(proxy_is_forward_capable(&http_proxy(1)));
        assert!(!proxy_is_forward_capable(&https_proxy(1)));
        assert!(!proxy_is_forward_capable(&socks5_proxy(1)));
        let dual = proxy_with(1, &[Protocol::Http(Anonymity::Unknown), Protocol::Socks5]);
        assert!(proxy_is_tunnel_capable(&dual));
        assert!(proxy_is_forward_capable(&dual));
    }

    #[tokio::test]
    async fn pick_round_robins_across_endpoints() {
        let pool = Pool::new(0, 0, false);
        pool.add(http_proxy(1111));
        pool.add(http_proxy(2222));
        pool.rebuild();
        let exclude = HashSet::new();
        let first = pool.pick(PartitionKind::Forward, &exclude).unwrap();
        let second = pool.pick(PartitionKind::Forward, &exclude).unwrap();
        let third = pool.pick(PartitionKind::Forward, &exclude).unwrap();
        assert_eq!(first.as_text(), "127.0.0.1:1111");
        assert_eq!(second.as_text(), "127.0.0.1:2222");
        assert_eq!(third.as_text(), first.as_text());
    }

    #[tokio::test]
    async fn pick_skips_excluded_endpoints() {
        let pool = Pool::new(0, 0, false);
        pool.add(http_proxy(1111));
        pool.add(http_proxy(2222));
        pool.add(http_proxy(3333));
        pool.rebuild();
        let mut exclude = HashSet::new();
        exclude.insert("127.0.0.1:1111".to_owned());
        let picked = pool.pick(PartitionKind::Forward, &exclude).unwrap();
        assert_eq!(picked.as_text(), "127.0.0.1:2222");
    }

    #[tokio::test]
    async fn pick_with_use_fastest_ranks_by_live_latency() {
        let pool = Pool::new(0, 0, true);
        pool.add(http_proxy(1111));
        pool.add(http_proxy(2222));
        pool.add(http_proxy(3333));
        pool.record_latency("127.0.0.1:3333", 0.05);
        pool.record_latency("127.0.0.1:1111", 2.0);
        pool.rebuild();
        let exclude = HashSet::new();
        let first = pool.pick(PartitionKind::Forward, &exclude).unwrap();
        assert_eq!(
            first.as_text(),
            "127.0.0.1:3333",
            "fastest proxy is pinned first"
        );
    }

    #[tokio::test]
    async fn pool_size_caps_the_snapshot() {
        let pool = Pool::new(0, 2, false);
        pool.add(http_proxy(1111));
        pool.add(http_proxy(2222));
        pool.add(http_proxy(3333));
        pool.rebuild();
        let snap = pool.snapshot.read().expect("snapshot");
        assert_eq!(snap.forward.len(), 2, "the third proxy must be dropped");
        let endpoints: Vec<&str> = snap.forward.iter().map(|p| p.as_text()).collect();
        assert!(endpoints.contains(&"127.0.0.1:1111"));
        assert!(!endpoints.contains(&"127.0.0.1:3333"));
    }

    #[test]
    fn constant_time_auth_compares_without_early_exit() {
        assert!(constant_time_eq(b"user:pass", b"user:pass"));
        assert!(!constant_time_eq(b"user:pass", b"user:pazz"));
        assert!(!constant_time_eq(b"user:pass", b"user:pass2"));
        assert!(!constant_time_eq(b"a", b"ab"));
    }

    #[test]
    fn auth_gate_checks_basic_credentials() {
        let mut proxy = Proxy::new(std::net::Ipv4Addr::LOCALHOST, 8080);
        proxy.proxy_types = vec![ProxyType::checked(Protocol::Http(Anonymity::Unknown))];
        let head = parse_client_head(
            format!(
                "GET http://x/ HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic {}\r\n\r\n",
                base64::engine::general_purpose::STANDARD.encode("user:pass")
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(check_auth(Some("user:pass"), &head));
        assert!(!check_auth(Some("user:other"), &head));
        assert!(check_auth(None, &head), "gate off always accepts");
    }

    #[test]
    fn forward_head_rewrites_to_absolute_form_and_strips_proxy_headers() {
        let mut proxy = Proxy::new(std::net::Ipv4Addr::LOCALHOST, 8080);
        proxy.proxy_types = vec![ProxyType::checked(Protocol::Http(Anonymity::Unknown))];
        let head = parse_client_head(
            b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic c2VjcmV0\r\nProxy-Connection: keep-alive\r\nX-Custom: yes\r\n\r\n",
        )
        .unwrap();
        let absolute = request_target(&head).unwrap();
        assert_eq!(absolute, "http://example.com/path?q=1");
        let forwarded = build_forward_head(&head, &absolute);
        let text = String::from_utf8_lossy(&forwarded).to_ascii_lowercase();
        assert!(text.starts_with("get http://example.com/path?q=1 http/1.1"));
        assert!(text.contains("host: example.com"));
        assert!(text.contains("x-custom: yes"));
        assert!(text.contains("connection: keep-alive"));
        assert!(!text.contains("proxy-authorization"));
        assert!(!text.contains("proxy-connection"));
    }

    #[test]
    fn absolute_forward_target_passes_through_unchanged() {
        let mut proxy = Proxy::new(std::net::Ipv4Addr::LOCALHOST, 8080);
        proxy.proxy_types = vec![ProxyType::checked(Protocol::Http(Anonymity::Unknown))];
        let head = parse_client_head(
            b"GET http://already-absolute.example/x HTTP/1.1\r\nHost: already-absolute.example\r\n\r\n",
        )
        .unwrap();
        let absolute = request_target(&head).unwrap();
        assert_eq!(absolute, "http://already-absolute.example/x");
    }

    #[test]
    fn no_body_responses_are_classified_correctly() {
        assert!(no_body_response(204, b"GET"));
        assert!(no_body_response(304, b"GET"));
        assert!(no_body_response(100, b"GET"));
        assert!(no_body_response(200, b"HEAD"));
        assert!(!no_body_response(200, b"GET"));
        assert!(!no_body_response(404, b"GET"));
    }

    #[test]
    fn connect_authority_validates_the_target() {
        assert_eq!(
            connect_authority(b"example.com:443").unwrap(),
            "example.com:443"
        );
        assert_eq!(
            connect_authority(b"[2001:db8::1]:443").unwrap(),
            "[2001:db8::1]:443"
        );
        assert!(connect_authority(b"http://example.com/").is_err());
        assert!(connect_authority(b"example.com").is_err());
        assert!(connect_authority(b"example.com:notaport").is_err());
    }

    #[test]
    fn connect_authority_rejects_unbracketed_ipv6() {
        assert!(connect_authority(b"2001:db8::1:443").is_err());
    }

    #[tokio::test]
    async fn refresh_candidates_exclude_in_use_endpoints() {
        let pool = Pool::new(0, 0, false);
        pool.add(http_proxy(1111));
        pool.add(http_proxy(2222));
        pool.add(http_proxy(3333));
        pool.rebuild();
        pool.mark_in_use("127.0.0.1:2222");
        let candidates = pool.candidates_for_refresh();
        let endpoints: Vec<&str> = candidates.iter().map(|p| p.as_text()).collect();
        assert!(endpoints.contains(&"127.0.0.1:1111"));
        assert!(!endpoints.contains(&"127.0.0.1:2222"));
        assert!(endpoints.contains(&"127.0.0.1:3333"));
    }

    #[tokio::test]
    async fn replace_validated_keeps_in_use_proxies() {
        let pool = Pool::new(0, 0, false);
        pool.add(http_proxy(1111));
        pool.add(http_proxy(2222));
        pool.rebuild();
        pool.mark_in_use("127.0.0.1:1111");
        let fresh = vec![http_proxy(4444), http_proxy(5555)];
        pool.replace_validated(fresh);
        let snap = pool.snapshot.read().expect("snapshot");
        let endpoints: Vec<&str> = snap.forward.iter().map(|p| p.as_text()).collect();
        assert!(endpoints.contains(&"127.0.0.1:1111"));
        assert!(endpoints.contains(&"127.0.0.1:4444"));
        assert!(!endpoints.contains(&"127.0.0.1:2222"));
    }

    // ── integration: CONNECT ───────────────────────────────────────────

    #[tokio::test]
    async fn connect_tunnel_echos_payload() {
        let echo = spawn_connect_echo("ECHO").await;
        let (gateway, _pool) = spawn_gateway(vec![https_proxy(echo)], serve_config()).await;
        let mut client = tcp(gateway).await;
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let (head, mut tail) = time::timeout(Duration::from_secs(2), read_until_head(&mut client))
            .await
            .unwrap();
        assert!(
            head.starts_with(b"HTTP/1.1 200"),
            "CONNECT must be answered 200: {head:?}"
        );
        client.write_all(b"ping").await.unwrap();
        tail.extend(
            time::timeout(
                Duration::from_secs(2),
                read_until_contains(&mut client, b"ping"),
            )
            .await
            .unwrap(),
        );
        assert!(
            String::from_utf8_lossy(&tail).contains("ECHO:ping"),
            "tunnel must echo the payload: {tail:?}"
        );
    }

    #[tokio::test]
    async fn two_clients_get_distinct_upstreams() {
        let up_a = spawn_connect_echo("UPA").await;
        let up_b = spawn_connect_echo("UPB").await;
        let (gateway, _pool) =
            spawn_gateway(vec![https_proxy(up_a), https_proxy(up_b)], serve_config()).await;

        let mut c1 = tcp(gateway).await;
        let mut c2 = tcp(gateway).await;
        for c in [&mut c1, &mut c2] {
            c.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                .await
                .unwrap();
            let (head, _tail) = time::timeout(Duration::from_secs(2), read_until_head(c))
                .await
                .unwrap();
            assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
        }
        c1.write_all(b"probe").await.unwrap();
        c2.write_all(b"probe").await.unwrap();
        let got1 = time::timeout(
            Duration::from_secs(2),
            read_until_contains(&mut c1, b"probe"),
        )
        .await
        .unwrap();
        let got2 = time::timeout(
            Duration::from_secs(2),
            read_until_contains(&mut c2, b"probe"),
        )
        .await
        .unwrap();
        let s1 = String::from_utf8_lossy(&got1).into_owned();
        let s2 = String::from_utf8_lossy(&got2).into_owned();
        assert_ne!(
            s1, s2,
            "two sessions must pin different upstreams (D1)\ngot1={s1:?}\ngot2={s2:?}"
        );
    }

    // ── integration: plain HTTP framing ────────────────────────────────

    #[tokio::test]
    async fn plain_forward_relays_absolute_form_and_keeps_connection() {
        let responder: Responder = Arc::new(|conn, reqs, _head, _body| {
            (ok_response(&format!("c{conn}r{reqs}"), false), false)
        });
        let fake = spawn_forward_proxy(responder, false).await;
        let (gateway, _pool) = spawn_gateway(vec![http_proxy(fake.port)], serve_config()).await;

        let mut client = tcp(gateway).await;
        client
            .write_all(b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let (head, tail) = time::timeout(Duration::from_secs(2), read_until_head(&mut client))
            .await
            .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"));
        let body = read_body(&mut client, tail, 4).await;
        assert_eq!(String::from_utf8_lossy(&body), "c0r1");

        let record = fake.records.lock().unwrap().first().unwrap().clone();
        let record = String::from_utf8_lossy(&record);
        assert!(
            record.starts_with("GET http://example.com/path HTTP/1.1"),
            "upstream must see the absolute-form request: {record}"
        );
    }

    #[tokio::test]
    async fn session_reuses_same_upstream_socket() {
        let responder: Responder =
            Arc::new(|_conn, reqs, _head, _body| (ok_response(&format!("r{reqs}"), false), false));
        let fake = spawn_forward_proxy(responder, false).await;
        let (gateway, _pool) = spawn_gateway(vec![http_proxy(fake.port)], serve_config()).await;

        let mut client = tcp(gateway).await;
        for _ in 0..2 {
            client
                .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .await
                .unwrap();
            let (_head, tail) = time::timeout(Duration::from_secs(2), read_until_head(&mut client))
                .await
                .unwrap();
            let body = read_body(&mut client, tail, 2).await;
            assert!(!body.is_empty());
        }
        assert_eq!(
            fake.conns.load(Ordering::Relaxed),
            1,
            "one session must reuse a single upstream socket (D5)"
        );
    }

    #[tokio::test]
    async fn session_false_re_pins_each_request() {
        let responder: Responder = Arc::new(|conn, _reqs, _head, _body| {
            let _ = conn;
            (ok_response("ok", false), false)
        });
        let fake = spawn_forward_proxy(responder, false).await;
        let cfg = cfg_with(|c| c.session = false);
        let (gateway, _pool) = spawn_gateway(vec![http_proxy(fake.port)], cfg).await;

        let mut client = tcp(gateway).await;
        for _ in 0..2 {
            client
                .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .await
                .unwrap();
            let (_head, _tail) =
                time::timeout(Duration::from_secs(2), read_until_head(&mut client))
                    .await
                    .unwrap();
        }
        assert_eq!(
            fake.conns.load(Ordering::Relaxed),
            2,
            "every request must pin a fresh upstream when --session is off"
        );
    }

    #[tokio::test]
    async fn pipelined_requests_close_the_connection() {
        let responder: Responder =
            Arc::new(|_conn, reqs, _head, _body| (ok_response(&format!("r{reqs}"), false), false));
        let fake = spawn_forward_proxy(responder, false).await;
        let (gateway, _pool) = spawn_gateway(vec![http_proxy(fake.port)], serve_config()).await;

        let mut client = tcp(gateway).await;
        client
            .write_all(
                b"GET http://example.com/1 HTTP/1.1\r\nHost: example.com\r\n\r\n\
                  GET http://example.com/2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
            .await
            .unwrap();
        let (head, tail) = time::timeout(Duration::from_secs(2), read_until_head(&mut client))
            .await
            .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"));
        let body = read_body(&mut client, tail, 2).await;
        assert_eq!(String::from_utf8_lossy(&body), "r1");
        let rest = time::timeout(
            Duration::from_secs(2),
            read_until_contains(&mut client, b""),
        )
        .await
        .unwrap();
        assert!(
            String::from_utf8_lossy(&rest).trim().is_empty(),
            "pipelining must close the session (D7): {rest:?}"
        );
    }

    #[tokio::test]
    async fn pool_empty_replies_503_after_pool_wait() {
        let cfg = cfg_with(|c| c.pool_wait = Duration::ZERO);
        let (gateway, _pool) = spawn_gateway(vec![], cfg).await;
        let mut client = tcp(gateway).await;
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let (head, _tail) = time::timeout(Duration::from_secs(2), read_until_head(&mut client))
            .await
            .unwrap();
        assert!(
            head.starts_with(b"HTTP/1.1 503"),
            "empty pool must yield 503: {head:?}"
        );
    }

    #[tokio::test]
    async fn auth_gate_requires_valid_credentials() {
        let echo = spawn_connect_echo("AUTH").await;
        let cfg = cfg_with(|c| c.auth = Some(Arc::from("user:pass")));
        let (gateway, _pool) = spawn_gateway(vec![https_proxy(echo)], cfg).await;

        let mut no_auth = tcp(gateway).await;
        no_auth
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let (head, _) = time::timeout(Duration::from_secs(2), read_until_head(&mut no_auth))
            .await
            .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 407"), "{head:?}");

        let mut wrong = tcp(gateway).await;
        wrong
            .write_all(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic d3Jvbmc6Y3JlZHM=\r\n\r\n",
            )
            .await
            .unwrap();
        let (head, _) = time::timeout(Duration::from_secs(2), read_until_head(&mut wrong))
            .await
            .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 407"), "{head:?}");

        let mut good = tcp(gateway).await;
        good.write_all(
            format!(
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {}\r\n\r\n",
                base64::engine::general_purpose::STANDARD.encode("user:pass")
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let (head, _) = time::timeout(Duration::from_secs(2), read_until_head(&mut good))
            .await
            .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
    }

    #[tokio::test]
    async fn idle_watchdog_closes_session_and_releases_pin() {
        let echo = spawn_connect_echo("IDLE").await;
        let pool = Pool::new(0, 0, false);
        pool.add(https_proxy(echo));
        pool.rebuild();
        let cfg = cfg_with(|c| c.idle = Duration::from_millis(150));
        let gateway = spawn_gateway_with_pool(pool.clone(), cfg).await;

        let mut client = tcp(gateway).await;
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let (head, _) = time::timeout(Duration::from_secs(2), read_until_head(&mut client))
            .await
            .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"));

        time::sleep(Duration::from_millis(400)).await;
        let mut probe = [0u8; 1];
        let n = time::timeout(Duration::from_secs(2), client.read(&mut probe))
            .await
            .unwrap()
            .unwrap_or(1);
        assert_eq!(n, 0, "idle watchdog must close an inactive session");
        assert!(
            pool.in_use.lock().unwrap().is_empty(),
            "the pin must be released when the session ends"
        );
        assert_eq!(pool.sessions.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn failover_re_pins_to_a_healthy_upstream() {
        let broken: Responder =
            Arc::new(|_conn, _reqs, _head, _body| (ok_response("BROKEN", false), true));
        let healthy: Responder =
            Arc::new(|_conn, _reqs, _head, _body| (ok_response("HEALTHY", false), false));
        let fake_broken = spawn_forward_proxy(broken, true).await;
        let fake_healthy = spawn_forward_proxy(healthy, false).await;

        let (gateway, pool) = spawn_gateway(
            vec![http_proxy(fake_broken.port), http_proxy(fake_healthy.port)],
            serve_config(),
        )
        .await;

        let mut client = tcp(gateway).await;
        for _ in 0..2 {
            client
                .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .await
                .unwrap();
            let (_head, tail) = time::timeout(Duration::from_secs(2), read_until_head(&mut client))
                .await
                .unwrap();
            let body = read_body(&mut client, tail, 512).await;
            let text = String::from_utf8_lossy(&body).into_owned();
            assert!(
                text.contains("BROKEN") || text.contains("HEALTHY"),
                "unexpected body: {text}"
            );
            if text.contains("HEALTHY") {
                break;
            }
        }
        assert!(
            pool.stats.failovers.load(Ordering::Relaxed) >= 1,
            "dead upstream must trigger a failover"
        );
        assert_eq!(
            fake_healthy.conns.load(Ordering::Relaxed),
            1,
            "the healthy upstream must serve the re-pinned request"
        );
    }

    #[tokio::test]
    async fn expect_100_continue_round_trips_the_body() {
        let responder: Responder = Arc::new(|_conn, _reqs, _head, body| {
            let payload = String::from_utf8_lossy(body.unwrap_or(b"")).into_owned();
            (ok_response(&format!("got:{payload}"), false), false)
        });
        let fake = spawn_forward_proxy(responder, false).await;
        let (gateway, _pool) = spawn_gateway(vec![http_proxy(fake.port)], serve_config()).await;

        let mut client = tcp(gateway).await;
        client
            .write_all(
                b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n",
            )
            .await
            .unwrap();
        let (head, _tail) = time::timeout(Duration::from_secs(2), read_until_head(&mut client))
            .await
            .unwrap();
        assert!(
            head.starts_with(b"HTTP/1.1 100"),
            "the interim 100 must reach the client: {head:?}"
        );
        client.write_all(b"hello").await.unwrap();
        let (head, tail) = time::timeout(Duration::from_secs(2), read_until_head(&mut client))
            .await
            .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
        let body = read_body(&mut client, tail, 512).await;
        assert!(
            String::from_utf8_lossy(&body).contains("got:hello"),
            "the request body must reach the upstream: {body:?}"
        );
    }

    #[tokio::test]
    async fn chunked_requests_and_responses_pass_through() {
        let responder: Responder = Arc::new(|_conn, _reqs, _head, body| {
            let payload = String::from_utf8_lossy(body.unwrap_or(b"")).into_owned();
            let echo = format!("echo:{payload}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                echo.len(),
                echo
            );
            (response.into_bytes(), false)
        });
        let fake = spawn_forward_proxy(responder, false).await;
        let (gateway, _pool) = spawn_gateway(vec![http_proxy(fake.port)], serve_config()).await;

        let mut client = tcp(gateway).await;
        client
            .write_all(b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n")
            .await
            .unwrap();
        let (head, tail) = time::timeout(Duration::from_secs(2), read_until_head(&mut client))
            .await
            .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
        let mut body = tail;
        if !body.windows(16).any(|w| w == b"echo:hello world") {
            body.extend(
                time::timeout(
                    Duration::from_secs(2),
                    read_until_contains(&mut client, b"echo:hello world"),
                )
                .await
                .unwrap(),
            );
        }
        assert!(
            String::from_utf8_lossy(&body).contains("echo:hello world"),
            "{body:?}"
        );
    }

    #[tokio::test]
    async fn head_response_without_body_keeps_the_connection() {
        let responder: Responder = Arc::new(|_conn, reqs, head, _body| {
            if head.starts_with(b"HEAD ") {
                // The upstream describes a body it never sends; the gateway
                // must not wait for those bytes.
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\nConnection: keep-alive\r\n\r\n"
                        .to_vec(),
                    false,
                )
            } else {
                (ok_response(&format!("body:{reqs}"), false), false)
            }
        });
        let fake = spawn_forward_proxy(responder, false).await;
        let (gateway, _pool) = spawn_gateway(vec![http_proxy(fake.port)], serve_config()).await;

        let mut client = tcp(gateway).await;
        client
            .write_all(b"HEAD http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let (head, _tail) = time::timeout(Duration::from_secs(2), read_until_head(&mut client))
            .await
            .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
        client
            .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let (head, tail) = time::timeout(Duration::from_secs(2), read_until_head(&mut client))
            .await
            .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"));
        let body = read_body(&mut client, tail, 512).await;
        assert!(String::from_utf8_lossy(&body).contains("body:"), "{body:?}");
    }

    #[tokio::test]
    async fn http10_keep_alive_reuses_the_upstream() {
        let responder: Responder =
            Arc::new(|_conn, reqs, _head, _body| (ok_response(&format!("r{reqs}"), false), false));
        let fake = spawn_forward_proxy(responder, false).await;
        let (gateway, _pool) = spawn_gateway(vec![http_proxy(fake.port)], serve_config()).await;

        let mut client = tcp(gateway).await;
        for _ in 0..2 {
            client
                .write_all(
                    b"GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n",
                )
                .await
                .unwrap();
            let (_head, tail) = time::timeout(Duration::from_secs(2), read_until_head(&mut client))
                .await
                .unwrap();
            let body = read_body(&mut client, tail, 2).await;
            assert!(!body.is_empty());
        }
        assert_eq!(
            fake.conns.load(Ordering::Relaxed),
            1,
            "HTTP/1.0 keep-alive must reuse the upstream socket"
        );
    }

    #[tokio::test]
    async fn max_sessions_serializes_concurrent_sessions() {
        let echo = spawn_connect_echo("SER").await;
        let pool = Pool::new(1, 0, false);
        pool.add(https_proxy(echo));
        pool.rebuild();
        let cfg = cfg_with(|c| c.pool_wait = Duration::ZERO);
        let gateway = spawn_gateway_with_pool(pool, cfg).await;

        let mut first = tcp(gateway).await;
        first
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let (head, _) = time::timeout(Duration::from_secs(2), read_until_head(&mut first))
            .await
            .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"));

        let mut second = tcp(gateway).await;
        second
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let (head, _) = time::timeout(Duration::from_secs(2), read_until_head(&mut second))
            .await
            .unwrap();
        assert!(
            head.starts_with(b"HTTP/1.1 503"),
            "a full session cap must yield 503: {head:?}"
        );

        drop(first);
        let mut third = tcp(gateway).await;
        third
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let (head, _) = time::timeout(Duration::from_secs(2), read_until_head(&mut third))
            .await
            .unwrap();
        assert!(
            head.starts_with(b"HTTP/1.1 200"),
            "a slot frees the next session: {head:?}"
        );
    }
}
