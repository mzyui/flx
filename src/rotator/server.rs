//! Relay client connections through pooled upstreams.

use std::{sync::Arc, time::Instant};

use anyhow::Context;
use base64::Engine as _;
use httparse::Status;
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time,
};

use super::{fmt_bytes, fmt_dur, ServeEvent, ServeOptions, REQUEST_HEAD_TIMEOUT};
use crate::{
    negotiators::{HttpsNegotiator, NegotiatorTrait, Socks4Negotiator, Socks5Negotiator},
    rotator::RotatorPool,
    Protocol,
};

const REQUEST_HEAD_LIMIT: usize = 16 * 1024;
const HTTPARSE_MAX_HEADERS: usize = 64;
const PROXY_RESPONSE_LIMIT: usize = 16 * 1024;
const DEFAULT_TARGET_PORT: u16 = 80;

const RESPONSE_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
const RESPONSE_BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESPONSE_NO_PROXY: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESPONSE_BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESPONSE_UNAUTHORIZED: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
    Proxy-Authenticate: Basic realm=\"flx\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Report one curl-like trace line when tracing is enabled.
fn trace(options: &ServeOptions, id: u64, text: String) {
    if options.trace {
        emit(
            options,
            super::ServeEvent::Trace {
                id,
                text: format!("* {text}"),
            },
        );
    }
}

/// Accept connections until shutdown, then drain in-flight relays.
///
/// Every relay phase is deadline-bounded, so the drain always terminates.
pub(super) async fn accept_loop(
    listener: TcpListener,
    pool: Arc<RotatorPool>,
    options: Arc<ServeOptions>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    // Run until runtime teardown aborts the task.
    let mut next_id = 0u64;
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, addr)) => {
                        next_id += 1;
                        let id = next_id;
                        if options.trace {
                            emit(
                                &options,
                                super::ServeEvent::Trace {
                                    id,
                                    text: format!("* accepted {addr}"),
                                },
                            );
                        }
                        let pool = Arc::clone(&pool);
                        let options = Arc::clone(&options);
                        connections.spawn(handle_connection(id, stream, pool, options));
                    }
                    Err(error) => {
                        #[cfg(feature = "log")]
                        log::warn!("rotator accept failed: {error}");
                        #[cfg(not(feature = "log"))]
                        let _ = error;
                    }
                }
            }
            _ = shutdown.changed() => break,
        }
    }
    while connections.join_next().await.is_some() {}
}

async fn handle_connection(
    id: u64,
    mut client: TcpStream,
    pool: Arc<RotatorPool>,
    options: Arc<ServeOptions>,
) {
    let _ = client.set_nodelay(true);
    let peer = client.peer_addr().ok();
    let started = Instant::now();
    // Share one deadline across head, connect, handshake, and relay.
    let deadline = started + options.request_timeout;
    let expected_auth = options.auth.as_ref().map(|(user, pass)| {
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        format!("Basic {encoded}").as_bytes().to_vec()
    });

    let request = match time::timeout(
        REQUEST_HEAD_TIMEOUT,
        read_request(&mut client, expected_auth.as_deref()),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(_)) | Err(_) => {
            let _ = client.write_all(RESPONSE_BAD_REQUEST).await;
            emit(
                &options,
                ServeEvent::Completed {
                    id,
                    client: peer,
                    method: "-".to_owned(),
                    target: "-".to_owned(),
                    upstream: None,
                    ok: false,
                    reason: Some("bad request".to_owned()),
                    elapsed: started.elapsed(),
                },
            );
            return;
        }
    };
    let target = format!("{}:{}", request.host, request.port);
    trace(
        &options,
        id,
        format!("head read {}", fmt_dur(started.elapsed())),
    );
    emit(
        &options,
        ServeEvent::Incoming {
            id,
            client: peer,
            method: request.method.clone(),
            target: target.clone(),
        },
    );

    if !request.authorized {
        let _ = client.write_all(RESPONSE_UNAUTHORIZED).await;
        emit(
            &options,
            ServeEvent::Completed {
                id,
                client: peer,
                method: request.method.clone(),
                target,
                upstream: None,
                ok: false,
                reason: Some("auth required".to_owned()),
                elapsed: started.elapsed(),
            },
        );
        return;
    }

    let Some(proxy) = pool.pick() else {
        let _ = client.write_all(RESPONSE_NO_PROXY).await;
        emit(
            &options,
            ServeEvent::Completed {
                id,
                client: peer,
                method: request.method.clone(),
                target,
                upstream: None,
                ok: false,
                reason: Some("no proxy".to_owned()),
                elapsed: started.elapsed(),
            },
        );
        return;
    };
    let via = proxy.as_text().to_owned();
    trace(
        &options,
        id,
        format!(
            "picked upstream {via} (pool {}/{})",
            pool.ready(),
            options.pool_size
        ),
    );

    match open_upstream(&proxy, &request, deadline, id, &options).await {
        Ok(mut upstream) => {
            let _ = upstream.set_nodelay(true);
            if options.trace {
                emit(
                    &options,
                    super::ServeEvent::Trace {
                        id,
                        text: format!("> {} {}", request.method, target),
                    },
                );
            }
            let sent = if request.tunnel {
                let established = client.write_all(RESPONSE_ESTABLISHED).await.is_ok();
                let tail_sent = request.forward.is_empty()
                    || upstream.write_all(&request.forward).await.is_ok();
                established && tail_sent
            } else {
                upstream.write_all(&request.forward).await.is_ok()
            };
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            // Legacy: only the timeout decides; inner io errors still count.
            let relay_start = Instant::now();
            let (relayed, up, down) = if !sent {
                (false, 0, 0)
            } else {
                match time::timeout(remaining, copy_bidirectional(&mut client, &mut upstream)).await
                {
                    Ok(Ok((up, down))) => (true, up, down),
                    Ok(Err(_)) => (true, 0, 0),
                    Err(_) => (false, 0, 0),
                }
            };
            if relayed {
                pool.report_success(&proxy);
                trace(
                    &options,
                    id,
                    format!(
                        "relay done up {} down {} in {}",
                        fmt_bytes(up),
                        fmt_bytes(down),
                        fmt_dur(relay_start.elapsed())
                    ),
                );
            } else {
                pool.report_failure(&proxy);
            }
            emit(
                &options,
                ServeEvent::Completed {
                    id,
                    client: peer,
                    method: request.method.clone(),
                    target,
                    upstream: Some(via),
                    ok: relayed,
                    reason: (!relayed).then(|| "relay failed".to_owned()),
                    elapsed: started.elapsed(),
                },
            );
        }
        Err(_error) => {
            pool.report_failure(&proxy);
            let (response, reason) = if request.tunnel {
                (RESPONSE_BAD_GATEWAY, "bad gateway")
            } else {
                (RESPONSE_NO_PROXY, "no proxy")
            };
            let _ = client.write_all(response).await;
            emit(
                &options,
                ServeEvent::Completed {
                    id,
                    client: peer,
                    method: request.method.clone(),
                    target,
                    upstream: Some(via),
                    ok: false,
                    reason: Some(reason.to_owned()),
                    elapsed: started.elapsed(),
                },
            );
        }
    }
}

struct ClientRequest {
    tunnel: bool,
    method: String,
    host: String,
    port: u16,
    authorized: bool,
    /// Forward full requests or CONNECT tails upstream.
    forward: Vec<u8>,
}

/// Report connection events without ever blocking the relay.
fn emit(options: &ServeOptions, event: super::ServeEvent) {
    if let Some(tx) = options.event_tx.as_ref() {
        let _ = tx.try_send(event);
    }
}

async fn read_request(
    client: &mut TcpStream,
    expected_auth: Option<&[u8]>,
) -> anyhow::Result<ClientRequest> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let head_end = loop {
        if bytes.len() > REQUEST_HEAD_LIMIT {
            anyhow::bail!("request head exceeds {REQUEST_HEAD_LIMIT} bytes");
        }
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            anyhow::bail!("client closed before sending a full request head");
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(end) = find_head_end(&bytes) {
            break end;
        }
    };

    let mut headers = [httparse::EMPTY_HEADER; HTTPARSE_MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    let consumed = match request.parse(&bytes)? {
        Status::Complete(consumed) => consumed,
        Status::Partial => anyhow::bail!("incomplete request head"),
    };
    let method: String = request
        .method
        .context("request without a method")?
        .to_owned();
    let path = request.path.context("request without a path")?;
    let authorized = match expected_auth {
        None => true,
        Some(expected) => request.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("proxy-authorization") && header.value == expected
        }),
    };
    let tunnel = method == "CONNECT";
    let (host, port) = if tunnel {
        parse_authority(path)?
    } else {
        let uri: hyper::Uri = path.parse().context("malformed request target")?;
        let host = uri
            .host()
            .context("request target has no host")?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        (host, uri.port_u16().unwrap_or(DEFAULT_TARGET_PORT))
    };

    // Preserve bytes trailing the head for upstream replay.
    let body_start = consumed.min(head_end);
    if tunnel {
        bytes.drain(..body_start);
    }
    Ok(ClientRequest {
        tunnel,
        method,
        host,
        port,
        authorized,
        forward: bytes,
    })
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn parse_authority(authority: &str) -> anyhow::Result<(String, u16)> {
    let (host, port) = authority
        .rsplit_once(':')
        .context("CONNECT authority has no port")?;
    let port = port
        .parse()
        .context("CONNECT authority has an invalid port")?;
    Ok((
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned(),
        port,
    ))
}

async fn open_upstream(
    proxy: &crate::Proxy,
    request: &ClientRequest,
    deadline: Instant,
    id: u64,
    options: &ServeOptions,
) -> anyhow::Result<TcpStream> {
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .context("connection budget exhausted before the upstream connect")
    };
    let connect_start = Instant::now();
    let mut stream = time::timeout(remaining()?, TcpStream::connect(proxy.as_text()))
        .await
        .with_context(|| format!("timed out connecting to upstream {}", proxy.as_text()))??;
    let _ = stream.set_nodelay(true);
    trace(
        options,
        id,
        format!("TCP connect {}", fmt_dur(connect_start.elapsed())),
    );

    let proxy_host = proxy.as_text();
    let protocol = proxy
        .proxy_types
        .iter()
        .map(|typed| typed.protocol)
        .find(|protocol| {
            matches!(
                protocol,
                Protocol::Socks4 | Protocol::Socks5 | Protocol::Https(_)
            )
        })
        .or_else(|| proxy.expected_types.first().copied());
    match protocol {
        Some(Protocol::Socks4) => {
            let uri = target_uri("http", &request.host, request.port)?;
            let handshake_start = Instant::now();
            time::timeout(
                remaining()?,
                Socks4Negotiator.negotiate(&mut stream, proxy_host, &uri),
            )
            .await
            .with_context(|| format!("SOCKS4 handshake with {proxy_host} timed out"))??;
            trace(
                options,
                id,
                format!("handshake socks4 {}", fmt_dur(handshake_start.elapsed())),
            );
        }
        Some(Protocol::Socks5) => {
            let uri = target_uri("http", &request.host, request.port)?;
            let handshake_start = Instant::now();
            time::timeout(
                remaining()?,
                Socks5Negotiator.negotiate(&mut stream, proxy_host, &uri),
            )
            .await
            .with_context(|| format!("SOCKS5 handshake with {proxy_host} timed out"))??;
            trace(
                options,
                id,
                format!("handshake socks5 {}", fmt_dur(handshake_start.elapsed())),
            );
        }
        Some(Protocol::Https(_)) if request.tunnel => {
            let uri = target_uri("https", &request.host, request.port)?;
            let handshake_start = Instant::now();
            time::timeout(
                remaining()?,
                HttpsNegotiator.negotiate(&mut stream, proxy_host, &uri),
            )
            .await
            .with_context(|| format!("CONNECT handshake with {proxy_host} timed out"))??;
            trace(
                options,
                id,
                format!(
                    "handshake https-connect {}",
                    fmt_dur(handshake_start.elapsed())
                ),
            );
        }
        _ if request.tunnel => {
            let handshake_start = Instant::now();
            let code = connect_http(&mut stream, &request.host, request.port, remaining()?).await?;
            trace(
                options,
                id,
                format!(
                    "handshake http-connect {}",
                    fmt_dur(handshake_start.elapsed())
                ),
            );
            if options.trace {
                emit(
                    options,
                    super::ServeEvent::Trace {
                        id,
                        text: format!("< HTTP/1.1 {code}"),
                    },
                );
            }
        }
        _ => {
            trace(options, id, "direct forward (no handshake)".to_owned());
        }
    }
    Ok(stream)
}

fn target_uri(scheme: &str, host: &str, port: u16) -> anyhow::Result<hyper::Uri> {
    hyper::Uri::try_from(format!("{scheme}://{host}:{port}/"))
        .with_context(|| format!("invalid target authority {host}:{port}"))
}

/// Tunnel HTTP-style upstreams and leave streams raw for relay.
async fn connect_http(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    budget: std::time::Duration,
) -> anyhow::Result<u16> {
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    let handshake = async {
        stream.write_all(request.as_bytes()).await?;
        let mut reader = tokio::io::BufReader::new(&mut *stream);
        let mut response = Vec::with_capacity(128);
        let mut line = Vec::with_capacity(64);
        loop {
            line.clear();
            use tokio::io::AsyncBufReadExt as _;
            if reader.read_until(b'\n', &mut line).await? == 0 {
                anyhow::bail!("upstream closed during the CONNECT handshake");
            }
            if response.len().saturating_add(line.len()) > PROXY_RESPONSE_LIMIT {
                anyhow::bail!("upstream CONNECT response exceeds the header limit");
            }
            response.extend_from_slice(&line);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut parsed = httparse::Response::new(&mut headers);
        if parsed.parse(&response)?.is_partial() {
            anyhow::bail!("upstream returned an incomplete CONNECT response");
        }
        let code = parsed.code.unwrap_or_default();
        if code != 200 {
            anyhow::bail!("CONNECT to {authority} returned status {code}");
        }
        Ok(code)
    };
    time::timeout(budget, handshake)
        .await
        .with_context(|| format!("CONNECT handshake with {host}:{port} timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotator::Strategy;
    use std::net::SocketAddr;

    pub(super) const ECHO_REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    const EXCHANGE_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

    pub(super) async fn spawn_echo_target() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut sink = [0u8; 2048];
                    let _ = socket.read(&mut sink).await;
                    let _ = socket.write_all(ECHO_REPLY).await;
                });
            }
        });
        address
    }

    pub(super) async fn spawn_relay_upstream(target: SocketAddr) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if let Ok(mut upstream) = TcpStream::connect(target).await {
                        let _ = copy_bidirectional(&mut client, &mut upstream).await;
                    }
                });
            }
        });
        address
    }

    pub(super) fn proxy_at(address: SocketAddr) -> crate::Proxy {
        let std::net::SocketAddr::V4(v4) = address else {
            unreachable!("loopback test addresses are IPv4")
        };
        crate::Proxy::new(*v4.ip(), v4.port())
    }

    pub(super) async fn serve_one(
        pool: Arc<RotatorPool>,
        auth: Option<(String, String)>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let options = Arc::new(ServeOptions {
            auth,
            ..ServeOptions::default()
        });
        // Never fires: tests drive shutdown by dropping the listener task.
        tokio::spawn(accept_loop(listener, pool, options, never_shutdown()));
        address
    }

    pub(super) async fn exchange(address: SocketAddr, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        let connect = time::timeout(EXCHANGE_BUDGET, TcpStream::connect(address)).await;
        let mut client = connect??;
        client.write_all(request).await?;
        let mut response = Vec::new();
        time::timeout(EXCHANGE_BUDGET, client.read_to_end(&mut response)).await??;
        Ok(response)
    }

    pub(super) fn plain_request(target: SocketAddr) -> String {
        format!("GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
    }

    /// Shutdown channel that never fires (sender is deliberately leaked).
    pub(super) fn never_shutdown() -> tokio::sync::watch::Receiver<bool> {
        let (never, shutdown) = tokio::sync::watch::channel(false);
        std::mem::forget(never);
        shutdown
    }

    /// Minimal SOCKS5 server that records the opening greeting.
    async fn spawn_socks5_upstream() -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            let _ = socket.read_exact(&mut greeting).await;
            let _ = tx.send(greeting.to_vec());
            let _ = socket.write_all(&[0x05, 0x00]).await;
            let mut request = [0u8; 10];
            let _ = socket.read_exact(&mut request).await;
            let _ = socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
        });
        (address, rx)
    }

    #[tokio::test]
    async fn validated_socks5_proxy_negotiates_socks5() {
        let (upstream, greeting_rx) = spawn_socks5_upstream().await;
        let mut proxy = proxy_at(upstream);
        proxy
            .proxy_types
            .push(crate::proxy::models::ProxyType::checked(Protocol::Socks5));
        let request = ClientRequest {
            tunnel: true,
            method: "CONNECT".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: 443,
            authorized: true,
            forward: Vec::new(),
        };
        let options = ServeOptions::default();
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let _stream = open_upstream(&proxy, &request, deadline, 1, &options)
            .await
            .expect("a validated SOCKS5 proxy must negotiate SOCKS5");
        let greeting = time::timeout(EXCHANGE_BUDGET, greeting_rx)
            .await
            .expect("upstream must observe the greeting")
            .expect("greeting sender must live");
        assert_eq!(
            greeting,
            vec![0x05, 0x01, 0x00],
            "upstream must receive a SOCKS5 method-selection greeting"
        );
    }

    #[tokio::test]
    async fn plain_http_requests_relay_through_the_pool() {
        let target = spawn_echo_target().await;
        let upstream = spawn_relay_upstream(target).await;
        let pool = Arc::new(RotatorPool::new(Strategy::RoundRobin));
        assert!(pool.add(proxy_at(upstream)));
        let address = serve_one(Arc::clone(&pool), None).await;

        let response = exchange(address, plain_request(target).as_bytes())
            .await
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{response:?}");
        assert_eq!(pool.ready(), 1, "relay success must be reported");
    }

    #[tokio::test]
    async fn connections_rotate_between_upstreams() {
        let target = spawn_echo_target().await;
        let first = spawn_relay_upstream(target).await;
        let second = spawn_relay_upstream(target).await;
        let pool = Arc::new(RotatorPool::new(Strategy::RoundRobin));
        assert!(pool.add(proxy_at(first)));
        assert!(pool.add(proxy_at(second)));
        let address = serve_one(pool, None).await;

        let request = plain_request(target);
        exchange(address, request.as_bytes()).await.unwrap();
        exchange(address, request.as_bytes()).await.unwrap();
    }

    #[tokio::test]
    async fn connection_events_flow_with_matching_ids() {
        let target = spawn_echo_target().await;
        let upstream = spawn_relay_upstream(target).await;
        let pool = Arc::new(RotatorPool::new(Strategy::RoundRobin));
        let via = proxy_at(upstream);
        let via_text = via.as_text().to_owned();
        assert!(pool.add(via));

        let (tx, mut rx) = tokio::sync::mpsc::channel(128);
        let options = Arc::new(ServeOptions {
            event_tx: Some(tx),
            trace: true,
            ..ServeOptions::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(accept_loop(listener, pool, options, never_shutdown()));

        let response = exchange(address, plain_request(target).as_bytes())
            .await
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{response:?}");

        let events = time::timeout(EXCHANGE_BUDGET, async {
            let mut events = Vec::new();
            while !events
                .iter()
                .any(|event| matches!(event, ServeEvent::Completed { .. }))
            {
                match rx.recv().await {
                    Some(event) => events.push(event),
                    None => break,
                }
            }
            events
        })
        .await
        .expect("completed event must arrive");

        let id = match events.iter().find_map(|event| match event {
            ServeEvent::Incoming {
                id,
                method,
                target: event_target,
                ..
            } if method == "GET" && *event_target == target.to_string() => Some(*id),
            _ => None,
        }) {
            Some(id) => id,
            None => panic!("incoming event missing in {events:?}"),
        };
        assert!(
            events.iter().all(|event| match event {
                ServeEvent::Incoming { id: event_id, .. }
                | ServeEvent::Completed { id: event_id, .. }
                | ServeEvent::Trace { id: event_id, .. } => *event_id == id,
            }),
            "every event of one connection shares its id: {events:?}"
        );
        let completed = events.iter().find_map(|event| match event {
            ServeEvent::Completed { ok, upstream, .. } => Some((*ok, upstream.clone())),
            _ => None,
        });
        assert_eq!(completed, Some((true, Some(via_text))));
        assert!(
            events.iter().any(|event| matches!(event, ServeEvent::Trace { text, .. } if text.contains("picked upstream"))),
            "trace lines must accompany the summary events: {events:?}"
        );
    }

    /// Relay upstream that stalls before replying, so shutdown lands mid-relay.
    async fn spawn_slow_relay_upstream(target: SocketAddr) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    if let Ok(mut upstream) = TcpStream::connect(target).await {
                        let _ = copy_bidirectional(&mut client, &mut upstream).await;
                    }
                });
            }
        });
        address
    }

    #[tokio::test]
    async fn shutdown_drains_inflight_connections() {
        let target = spawn_echo_target().await;
        let upstream = spawn_slow_relay_upstream(target).await;
        let pool = Arc::new(RotatorPool::new(Strategy::RoundRobin));
        assert!(pool.add(proxy_at(upstream)));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let options = Arc::new(ServeOptions::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(accept_loop(listener, pool, options, shutdown_rx));

        let client =
            tokio::spawn(async move { exchange(address, plain_request(target).as_bytes()).await });
        // Fire shutdown mid-relay, long before the slow upstream replies.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown_tx.send(true).unwrap();

        let response = time::timeout(EXCHANGE_BUDGET, client)
            .await
            .expect("client must finish")
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{response:?}");
        time::timeout(EXCHANGE_BUDGET, server)
            .await
            .expect("accept loop must return after drain")
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_stops_accepting_new_connections() {
        let target = spawn_echo_target().await;
        let upstream = spawn_relay_upstream(target).await;
        let pool = Arc::new(RotatorPool::new(Strategy::RoundRobin));
        assert!(pool.add(proxy_at(upstream)));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let options = Arc::new(ServeOptions::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(accept_loop(listener, pool, options, shutdown_rx));

        shutdown_tx.send(true).unwrap();
        time::timeout(EXCHANGE_BUDGET, server)
            .await
            .expect("accept loop must return on shutdown")
            .unwrap();
        assert!(
            TcpStream::connect(address).await.is_err(),
            "the listener must be gone after shutdown"
        );
    }
}

#[cfg(test)]
mod auth_tests {
    use super::tests::*;
    use super::*;
    use crate::rotator::Strategy;
    use std::net::SocketAddr;

    async fn spawn_connect_upstream(target: SocketAddr) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut head = Vec::with_capacity(256);
                    let mut chunk = [0u8; 256];
                    while !head.ends_with(b"\r\n\r\n") && !chunk.is_empty() {
                        let read = client.read(&mut chunk).await.unwrap_or(0);
                        if read == 0 {
                            break;
                        }
                        head.extend_from_slice(&chunk[..read]);
                    }
                    let target_host = format!("{target}");
                    if head.starts_with(b"CONNECT ")
                        && head
                            .windows(target_host.len())
                            .any(|w| w == target_host.as_bytes())
                    {
                        if let Ok(mut upstream) = TcpStream::connect(target).await {
                            let _ = client
                                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                                .await;
                            let _ = copy_bidirectional(&mut client, &mut upstream).await;
                        }
                    }
                });
            }
        });
        address
    }

    #[tokio::test]
    async fn connect_tunnels_relay_after_established() {
        let target = spawn_echo_target().await;
        let upstream = spawn_connect_upstream(target).await;
        let pool = Arc::new(RotatorPool::new(Strategy::RoundRobin));
        assert!(pool.add(proxy_at(upstream)));
        let address = serve_one(pool, None).await;

        let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        let mut head = [0u8; RESPONSE_ESTABLISHED.len()];
        client.read_exact(&mut head).await.unwrap();
        assert_eq!(head, RESPONSE_ESTABLISHED);
        client.write_all(b"anything").await.unwrap();
        let mut reply = [0u8; ECHO_REPLY.len()];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, ECHO_REPLY);
    }

    #[tokio::test]
    async fn missing_auth_gets_rejected_with_407() {
        let target = spawn_echo_target().await;
        let upstream = spawn_relay_upstream(target).await;
        let pool = Arc::new(RotatorPool::new(Strategy::RoundRobin));
        assert!(pool.add(proxy_at(upstream)));
        let address = serve_one(pool, Some(("user".into(), "pass".into()))).await;

        let response = exchange(address, plain_request(target).as_bytes())
            .await
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 407"), "{response:?}");
    }

    #[tokio::test]
    async fn correct_auth_is_accepted() {
        use base64::Engine as _;
        let target = spawn_echo_target().await;
        let upstream = spawn_relay_upstream(target).await;
        let pool = Arc::new(RotatorPool::new(Strategy::RoundRobin));
        assert!(pool.add(proxy_at(upstream)));
        let address = serve_one(pool, Some(("user".into(), "pass".into()))).await;

        let credentials = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let request = format!(
            "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {credentials}\r\n\r\n"
        );
        let response = exchange(address, request.as_bytes()).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"), "{response:?}");
    }

    async fn spawn_dead_upstream(target: SocketAddr) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = TcpStream::connect(target).await;
                    drop(client);
                });
            }
        });
        address
    }

    #[tokio::test]
    async fn dead_upstream_yields_an_error_and_a_failure_report() {
        let pool = Arc::new(RotatorPool::new(Strategy::RoundRobin));
        let unreachable_target = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let upstream = spawn_dead_upstream(unreachable_target).await;
        assert!(pool.add(proxy_at(upstream)));
        let address = serve_one(Arc::clone(&pool), None).await;

        let request = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let response = exchange(address, request.as_bytes()).await.unwrap();
        assert!(response.is_empty(), "{response:?}");
        assert_eq!(pool.ready(), 1, "a clean close must not evict the endpoint");
    }
}
