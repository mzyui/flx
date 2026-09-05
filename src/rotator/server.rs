//! Relay client connections through pooled upstreams.

use std::{sync::Arc, time::Instant};

use anyhow::Context;
use base64::Engine as _;
use httparse::Status;
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time,
};

use super::{ServeOptions, REQUEST_HEAD_TIMEOUT};
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

/// Accept connections until shutdown without head-of-line blocking.
pub(super) async fn accept_loop(
    listener: TcpListener,
    pool: Arc<RotatorPool>,
    options: Arc<ServeOptions>,
) {
    // Run until runtime teardown aborts the task.
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let pool = Arc::clone(&pool);
                let options = Arc::clone(&options);
                tokio::spawn(handle_connection(stream, pool, options));
            }
            Err(error) => {
                #[cfg(feature = "log")]
                log::warn!("rotator accept failed: {error}");
                #[cfg(not(feature = "log"))]
                let _ = error;
            }
        }
    }
}

async fn handle_connection(
    mut client: TcpStream,
    pool: Arc<RotatorPool>,
    options: Arc<ServeOptions>,
) {
    let _ = client.set_nodelay(true);
    // Share one deadline across head, connect, handshake, and relay.
    let deadline = Instant::now() + options.request_timeout;
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
            return;
        }
    };

    if !request.authorized {
        let _ = client.write_all(RESPONSE_UNAUTHORIZED).await;
        return;
    }

    let Some(proxy) = pool.pick() else {
        let _ = client.write_all(RESPONSE_NO_PROXY).await;
        return;
    };

    match open_upstream(&proxy, &request, deadline).await {
        Ok(mut upstream) => {
            let _ = upstream.set_nodelay(true);
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
            let relayed = sent
                && time::timeout(remaining, copy_bidirectional(&mut client, &mut upstream))
                    .await
                    .is_ok();
            if relayed {
                pool.report_success(&proxy);
            } else {
                pool.report_failure(&proxy);
            }
        }
        Err(_error) => {
            pool.report_failure(&proxy);
            let response = if request.tunnel {
                RESPONSE_BAD_GATEWAY
            } else {
                RESPONSE_NO_PROXY
            };
            let _ = client.write_all(response).await;
        }
    }
}

struct ClientRequest {
    tunnel: bool,
    host: String,
    port: u16,
    authorized: bool,
    /// Forward full requests or CONNECT tails upstream.
    forward: Vec<u8>,
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
    let method = request.method.context("request without a method")?;
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
) -> anyhow::Result<TcpStream> {
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .context("connection budget exhausted before the upstream connect")
    };
    let mut stream = time::timeout(remaining()?, TcpStream::connect(proxy.as_text()))
        .await
        .with_context(|| format!("timed out connecting to upstream {}", proxy.as_text()))??;
    let _ = stream.set_nodelay(true);

    let proxy_host = proxy.as_text();
    match proxy.expected_types.first() {
        Some(Protocol::Socks4) => {
            let uri = target_uri("http", &request.host, request.port)?;
            time::timeout(
                remaining()?,
                Socks4Negotiator.negotiate(&mut stream, proxy_host, &uri),
            )
            .await
            .with_context(|| format!("SOCKS4 handshake with {proxy_host} timed out"))??;
        }
        Some(Protocol::Socks5) => {
            let uri = target_uri("http", &request.host, request.port)?;
            time::timeout(
                remaining()?,
                Socks5Negotiator.negotiate(&mut stream, proxy_host, &uri),
            )
            .await
            .with_context(|| format!("SOCKS5 handshake with {proxy_host} timed out"))??;
        }
        Some(Protocol::Https(_)) if request.tunnel => {
            let uri = target_uri("https", &request.host, request.port)?;
            time::timeout(
                remaining()?,
                HttpsNegotiator.negotiate(&mut stream, proxy_host, &uri),
            )
            .await
            .with_context(|| format!("CONNECT handshake with {proxy_host} timed out"))??;
        }
        _ if request.tunnel => {
            connect_http(&mut stream, &request.host, request.port, remaining()?).await?
        }
        _ => {}
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
) -> anyhow::Result<()> {
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
        Ok(())
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
        tokio::spawn(accept_loop(listener, pool, options));
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
