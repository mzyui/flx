mod negotiate;
mod tls;

use std::{borrow::Cow, collections::HashSet};

use anyhow::Context;
use tokio::{io::BufReader, time};

use super::checker::{classify_anonymity, JudgePool, ValidationTarget};
use crate::proxy::{
    client::{ConnectionDriver, ProxyClient, ProxyRuntimes},
    models::{Protocol, Proxy, RuntimeStats},
};
use crate::resolver::my_ip;
use negotiate::{authority_for, negotiate_http_connect, negotiate_socks4, negotiate_socks5};
use tls::{verify_judge, verify_tls_judge};

#[derive(Debug, Clone)]
struct JudgeTarget {
    scheme: String,
    host: String,
    port: u16,
    authority: String,
    path_and_query: String,
    response_marker: String,
    request_token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStatus {
    TcpReachable,
    HandshakePassed,
    EndToEndPassed,
}

#[derive(Debug)]
struct ProtocolProbe {
    status: ValidationStatus,
}

impl ProtocolProbe {
    fn advance(&mut self, status: ValidationStatus) {
        self.status = status;
    }
}

impl JudgeTarget {
    fn from_validation_target(target: &ValidationTarget) -> anyhow::Result<Self> {
        let uri: hyper::Uri = target
            .url
            .parse()
            .with_context(|| format!("invalid local judge URL `{}`", target.url))?;
        let host = uri
            .host()
            .context("local judge URL must contain a host")?
            .to_owned();
        let port = uri
            .port_u16()
            .or_else(|| match uri.scheme_str() {
                Some("http") => Some(80),
                Some("https") => Some(443),
                _ => None,
            })
            .context("local judge URL must contain a port or known scheme")?;
        let path_and_query = uri
            .path_and_query()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());
        let authority = authority_for(&mut [0u8; 64], &host, port).into_owned();

        Ok(Self {
            scheme: uri.scheme_str().unwrap_or("http").to_owned(),
            host,
            port,
            authority,
            path_and_query,
            response_marker: target.response_marker.clone(),
            request_token: target.request_token.clone(),
        })
    }
}

pub(super) async fn support_tunnel(
    proxy: &mut Proxy,
    protocol: Protocol,
    pool: &JudgePool,
    params: &super::WorkParams,
) -> anyhow::Result<Option<ProxyRuntimes<Protocol>>> {
    let timeout = params.request_timeout;
    let max_attempts = params.max_attempts;
    // HTTPS tunnels are classified by anonymity, which requires knowing our own
    // public IP to detect transparent proxies. SOCKS/CONNECT only prove tunnel
    // capability, so they are reported without an anonymity class. The public-IP
    // lookup is performed lazily on the success path so a stalled/failed tunnel
    // never pays for a network round-trip it does not need.
    let needs_anonymity = matches!(protocol, Protocol::Https(_));

    // Build every judge's fixed fields once per proxy instead of re-parsing
    // each judge URL (six `String` allocations) on every attempt.
    let mut candidates = Vec::new();
    for validation_target in pool.candidates() {
        let target = JudgeTarget::from_validation_target(&validation_target)?;
        candidates.push((validation_target, target));
    }
    let total_attempts = max_attempts.saturating_mul(candidates.len());
    // Judges this proxy has already reported as failing (now cooling down);
    // re-probing them within this loop would only burn another connect.
    let mut cooling_down = HashSet::with_capacity(candidates.len());
    // One shared end-to-end budget across every attempt and judge so a tunnel
    // that accepts TCP but never completes a handshake is bounded once instead
    // of paying a full `timeout` per judge/attempt.
    let budget_started = time::Instant::now();
    let budget = timeout.saturating_mul(max_attempts as u32);

    for offset in 0..total_attempts {
        if offset > 0 && offset % candidates.len() == 0 && !params.retry_delay.is_zero() {
            time::sleep(params.retry_delay).await;
        }
        let remaining = budget
            .checked_sub(budget_started.elapsed())
            .unwrap_or_default();
        if remaining.is_zero() {
            break;
        }
        let (validation_target, target) = &candidates[offset % candidates.len()];
        if cooling_down.contains(&validation_target.url) {
            continue;
        }
        let started = time::Instant::now();
        let deadline = started + remaining.min(timeout);
        match time::timeout_at(
            deadline,
            probe_once(proxy, &protocol, target, deadline, params),
        )
        .await
        {
            Ok(Ok((body, driver))) => {
                pool.report_success(validation_target, started.elapsed());
                let mut runtimes = RuntimeStats::default();
                // The lookup runs under its own fixed budget (`MY_IP_LOOKUP_TIMEOUT`)
                // rather than the leftover probe deadline, so a tunnel that
                // answers just before its deadline is not rejected for a slow
                // my-IP fetch.
                let protocol = if needs_anonymity {
                    let my_ip = my_ip().await.context(
                        "cannot determine anonymity level without knowing our own public IP",
                    )?;
                    let anon = classify_anonymity(&body, &my_ip);
                    Protocol::Https(anon)
                } else {
                    protocol
                };
                runtimes.record(started.elapsed().as_secs_f64());
                return Ok(Some(ProxyRuntimes {
                    inner: protocol,
                    runtimes,
                    driver,
                }));
            }
            Ok(Err(_error)) => {
                #[cfg(feature = "log")]
                log::trace!(
                    "{}: {} tunnel validation failed: {:#}",
                    proxy.as_text(),
                    protocol,
                    _error
                );
                // Put the failing judge on cooldown so subsequent attempts
                // (and other proxies) round-robin away from it, mirroring the
                // HTTP path's `report_failure` behaviour.
                pool.report_failure(validation_target);
                cooling_down.insert(validation_target.url.clone());
            }
            Err(_elapsed) => {
                #[cfg(feature = "log")]
                log::trace!(
                    "{}: {} tunnel validation timed out after {:?}",
                    proxy.as_text(),
                    protocol,
                    timeout
                );
                pool.report_failure(validation_target);
                cooling_down.insert(validation_target.url.clone());
            }
        }
    }

    Ok(None)
}

async fn probe_once(
    proxy: &mut Proxy,
    protocol: &Protocol,
    target: &JudgeTarget,
    deadline: time::Instant,
    params: &super::WorkParams,
) -> anyhow::Result<(String, Option<ConnectionDriver>)> {
    let remaining = deadline
        .checked_duration_since(time::Instant::now())
        .context("tunnel validation timed out before TCP connect")?;
    let mut stream = BufReader::new(proxy.connect_timeout(remaining).await?.inner);

    // Only CONNECT tunnels render an authority string; other protocols reuse
    // the one cached on the `JudgeTarget`.
    let mut authority_buf = [0u8; 64];
    let authority = match protocol {
        Protocol::Connect(port) => authority_for(&mut authority_buf, &target.host, *port),
        _ => Cow::Borrowed(target.authority.as_str()),
    };
    let authority = authority.as_ref();

    let mut probe = ProtocolProbe {
        status: ValidationStatus::TcpReachable,
    };

    time::timeout_at(deadline, async {
        match protocol {
            Protocol::Https(_) | Protocol::Connect(_) => {
                negotiate_http_connect(&mut stream, authority).await
            }
            Protocol::Socks4 => negotiate_socks4(&mut stream, target).await,
            Protocol::Socks5 => negotiate_socks5(&mut stream, target).await,
            Protocol::Http(_) => anyhow::bail!("HTTP must be validated by support_http"),
        }
    })
    .await
    .context("proxy tunnel handshake timed out")??;
    probe.advance(ValidationStatus::HandshakePassed);
    let (body, driver) = time::timeout_at(deadline, async {
        if target.scheme == "https" {
            verify_tls_judge(stream.into_inner(), target, authority, params).await
        } else {
            let body = verify_judge(&mut stream, target, authority, params).await?;
            Ok((body, None))
        }
    })
    .await
    .context("judge probe timed out")??;
    probe.advance(ValidationStatus::EndToEndPassed);
    debug_assert_eq!(probe.status, ValidationStatus::EndToEndPassed);
    Ok((body, driver))
}

#[cfg(test)]
mod tests {
    use super::super::checker::{JudgePool, ValidationTarget};
    use super::{probe_once, support_tunnel, JudgeTarget};
    use crate::proxy::models::{Anonymity, Protocol, Proxy};
    use std::time::Duration;
    use std::vec::Vec;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time,
    };

    const JUDGE_URL: &str = "http://127.0.0.1:9/fluxy-test-token";

    fn test_params(request_timeout: Duration) -> super::super::WorkParams {
        super::super::WorkParams {
            max_attempts: 1,
            request_timeout,
            insecure: false,
            support_cookies: false,
            support_referer: false,
            retry_delay: std::time::Duration::ZERO,
        }
    }

    fn pool_with(target: ValidationTarget) -> JudgePool {
        JudgePool::from_targets(Vec::from([std::sync::Arc::new(target)]))
    }

    async fn read_headers(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
        let mut headers = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        while headers.len() <= 16 * 1024 {
            stream.read_exact(&mut byte).await?;
            headers.push(byte[0]);
            if headers.ends_with(b"\r\n\r\n") {
                return Ok(headers);
            }
        }
        anyhow::bail!("test proxy request headers exceed limit")
    }

    async fn serve_successful_protocol(
        mut stream: TcpStream,
        protocol: Protocol,
    ) -> anyhow::Result<()> {
        match protocol {
            Protocol::Https(_) | Protocol::Connect(_) => {
                let request = read_headers(&mut stream).await?;
                assert!(request.starts_with(b"CONNECT 127.0.0.1:9 HTTP/1.1"));
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
            }
            Protocol::Socks4 => {
                let mut request = [0u8; 8];
                stream.read_exact(&mut request).await?;
                assert_eq!(&request[..2], &[4, 1]);
                assert_eq!(&request[4..8], &[127, 0, 0, 1]);
                let mut user_id = [0u8; 1];
                loop {
                    stream.read_exact(&mut user_id).await?;
                    if user_id[0] == 0 {
                        break;
                    }
                }
                stream.write_all(&[0, 90, 0, 9, 127, 0, 0, 1]).await?;
                stream.flush().await?;
            }
            Protocol::Socks5 => {
                let mut greeting = [0u8; 3];
                stream.read_exact(&mut greeting).await?;
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await?;

                let mut request = [0u8; 10];
                stream.read_exact(&mut request).await?;
                assert_eq!(&request[..4], &[5, 1, 0, 1]);
                assert_eq!(&request[4..8], &[127, 0, 0, 1]);
                stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 9]).await?;
                stream.flush().await?;
            }
            Protocol::Http(_) => anyhow::bail!("HTTP is not a tunnel protocol"),
        }

        let request = read_headers(&mut stream).await?;
        assert!(request.starts_with(b"GET /fluxy-test-token HTTP/1.1"));
        let response_body = b"/fluxy-test-token";
        let response_headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        );
        stream.write_all(response_headers.as_bytes()).await?;
        stream.write_all(response_body).await?;
        Ok(())
    }

    async fn assert_end_to_end_validation(protocol: Protocol) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_protocol = protocol;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_successful_protocol(stream, server_protocol)
                .await
                .unwrap();
        });

        let mut proxy = Proxy::new("127.0.0.1".parse().unwrap(), address.port());
        let target = JudgeTarget::from_validation_target(&ValidationTarget {
            url: JUDGE_URL.to_owned(),
            response_marker: "fluxy-test-token".to_owned(),
            request_token: "fluxy-test-token".to_owned(),
        })
        .unwrap();
        let result = time::timeout(
            Duration::from_secs(1),
            probe_once(
                &mut proxy,
                &protocol,
                &target,
                time::Instant::now() + Duration::from_secs(1),
                &test_params(Duration::from_secs(1)),
            ),
        )
        .await;

        let server_result = time::timeout(Duration::from_secs(1), server).await.unwrap();
        assert!(
            matches!(result, Ok(Ok(_))),
            "{protocol} result: {result:?}, server: {server_result:?}"
        );
        server_result.unwrap();
    }

    #[tokio::test]
    async fn non_http_protocols_require_handshake_and_judge_response() {
        for protocol in [
            Protocol::Https(Anonymity::Unknown),
            Protocol::Connect(9),
            Protocol::Socks4,
            Protocol::Socks5,
        ] {
            assert_end_to_end_validation(protocol).await;
        }
    }

    #[tokio::test]
    async fn open_tcp_service_is_not_accepted_as_a_socks5_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            time::sleep(Duration::from_millis(200)).await;
        });

        let mut proxy = Proxy::new("127.0.0.1".parse().unwrap(), address.port());
        let pool = pool_with(ValidationTarget {
            url: JUDGE_URL.to_owned(),
            response_marker: "fluxy-test-token".to_owned(),
            request_token: "fluxy-test-token".to_owned(),
        });
        let params = test_params(Duration::from_millis(50));
        let result = support_tunnel(&mut proxy, Protocol::Socks5, &pool, &params)
            .await
            .unwrap();

        assert!(result.is_none());
        time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn stalled_handshake_obeys_validation_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            time::sleep(Duration::from_millis(250)).await;
        });

        let mut proxy = Proxy::new("127.0.0.1".parse().unwrap(), address.port());
        let pool = pool_with(ValidationTarget {
            url: JUDGE_URL.to_owned(),
            response_marker: "fluxy-test-token".to_owned(),
            request_token: "fluxy-test-token".to_owned(),
        });
        let started = time::Instant::now();
        let params = test_params(Duration::from_millis(50));
        let result = support_tunnel(
            &mut proxy,
            Protocol::Https(Anonymity::Unknown),
            &pool,
            &params,
        )
        .await
        .unwrap();

        assert!(result.is_none());
        assert!(started.elapsed() < Duration::from_millis(200));
        time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn tunnel_phases_share_one_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_headers(&mut stream).await.unwrap();
            assert!(request.starts_with(b"CONNECT 127.0.0.1:9 HTTP/1.1"));
            time::sleep(Duration::from_millis(35)).await;
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();

            let request = read_headers(&mut stream).await.unwrap();
            assert!(request.starts_with(b"GET /fluxy-test-token HTTP/1.1"));
            time::sleep(Duration::from_millis(35)).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nfluxy-test-token",
                )
                .await
                .unwrap();
        });

        let mut proxy = Proxy::new("127.0.0.1".parse().unwrap(), address.port());
        let target = JudgeTarget::from_validation_target(&ValidationTarget {
            url: JUDGE_URL.to_owned(),
            response_marker: "fluxy-test-token".to_owned(),
            request_token: "fluxy-test-token".to_owned(),
        })
        .unwrap();
        let deadline = time::Instant::now() + Duration::from_millis(50);
        let result = probe_once(
            &mut proxy,
            &Protocol::Connect(9),
            &target,
            deadline,
            &test_params(Duration::from_secs(1)),
        )
        .await;

        assert!(
            result.is_err(),
            "combined tunnel phases exceeded the deadline"
        );
        assert!(format!("{:#}", result.unwrap_err()).contains("timed out"));
        server.abort();
    }

    #[tokio::test]
    async fn connect_request_targets_the_requested_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_headers(&mut stream).await.unwrap();
            assert!(request.starts_with(b"CONNECT 127.0.0.1:8080 HTTP/1.1"));
        });

        let mut proxy = Proxy::new("127.0.0.1".parse().unwrap(), address.port());
        let target = JudgeTarget::from_validation_target(&ValidationTarget {
            url: JUDGE_URL.to_owned(),
            response_marker: "fluxy-test-token".to_owned(),
            request_token: "fluxy-test-token".to_owned(),
        })
        .unwrap();
        let deadline = time::Instant::now() + Duration::from_secs(1);
        let result = probe_once(
            &mut proxy,
            &Protocol::Connect(8080),
            &target,
            deadline,
            &test_params(Duration::from_secs(1)),
        )
        .await;

        assert!(result.is_err());
        server.await.unwrap();
    }

    #[test]
    fn failed_judge_is_skipped_while_on_cooldown() {
        // Regression test: `report_failure` must cool the judge down so `next()`
        // round-robins away from it.
        let targets: Vec<_> = (0..2)
            .map(|i| {
                std::sync::Arc::new(
                    ValidationTarget::online(&format!("http://{i}.example.com/")).unwrap(),
                )
            })
            .collect();
        let pool = JudgePool::from_targets(targets.clone());
        pool.report_failure(&targets[0]);
        for _ in 0..5 {
            assert_eq!(pool.next().url, targets[1].url);
        }
    }

    #[tokio::test]
    async fn tunnel_error_path_reports_failure_without_panic() {
        // Regression test: a failed tunnel probe must call `report_failure`
        // without panicking and keep the judge in the pool.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        // Accept then drop immediately => no CONNECT/HTTP response => probe fails.
        let server = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let mut proxy = Proxy::new("127.0.0.1".parse().unwrap(), address.port());
        let pool = pool_with(ValidationTarget {
            url: format!("http://{address}/"),
            response_marker: "fluxy-test-token".to_owned(),
            request_token: "fluxy-test-token".to_owned(),
        });
        let params = test_params(Duration::from_millis(200));
        let result = support_tunnel(&mut proxy, Protocol::Connect(9), &pool, &params).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(pool.len(), 1);
        server.abort();
    }

    async fn spawn_stalled_clients() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            for _ in 0..16 {
                match listener.accept().await {
                    Ok((stream, _)) => held.push(stream),
                    Err(_) => break,
                }
            }
            time::sleep(Duration::from_secs(30)).await;
        });
        address
    }

    #[tokio::test]
    async fn stalled_tunnel_consumes_one_shared_budget() {
        // Offline-safe: the blackhole accepts but never completes a handshake,
        // so the probe must burn one shared budget across the judge pool
        // rather than one full timeout per judge.
        let blackhole = spawn_stalled_clients().await;
        let pool = JudgePool::from_targets(Vec::from([
            std::sync::Arc::new(ValidationTarget::online("http://127.0.0.1:9/judge-a").unwrap()),
            std::sync::Arc::new(ValidationTarget::online("http://127.0.0.1:9/judge-b").unwrap()),
        ]));
        let started = time::Instant::now();
        let mut proxy = Proxy::new("127.0.0.1".parse().unwrap(), blackhole.port());
        let params = test_params(Duration::from_millis(300));
        let result = support_tunnel(&mut proxy, Protocol::Connect(9), &pool, &params)
            .await
            .unwrap();
        let elapsed = started.elapsed();

        assert!(result.is_none());
        assert!(
            elapsed < Duration::from_millis(500),
            "shared budget not honoured: {elapsed:?}"
        );
    }

    async fn serve_echoing_judge(mut stream: TcpStream, echo_cookie: bool, echo_referer: bool) {
        let connect = read_headers(&mut stream).await.unwrap();
        assert!(connect.starts_with(b"CONNECT 127.0.0.1:9 HTTP/1.1"));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let request = read_headers(&mut stream).await.unwrap();
        assert!(request.starts_with(b"GET /fluxy-test-token HTTP/1.1"));
        let mut body = String::from("fluxy-test-token");
        if echo_cookie {
            body.push_str("\nHTTP_COOKIE = cookie=ok");
        }
        if echo_referer {
            body.push_str("\nHTTP_REFERER = https://google.com/");
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    }

    async fn probe_with_echo(
        echo_cookie: bool,
        echo_referer: bool,
        support_cookies: bool,
        support_referer: bool,
    ) -> bool {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_echoing_judge(stream, echo_cookie, echo_referer).await;
        });

        let mut proxy = Proxy::new("127.0.0.1".parse().unwrap(), address.port());
        let target = JudgeTarget::from_validation_target(&ValidationTarget {
            url: JUDGE_URL.to_owned(),
            response_marker: "fluxy-test-token".to_owned(),
            request_token: "fluxy-test-token".to_owned(),
        })
        .unwrap();
        let result = time::timeout(
            Duration::from_secs(1),
            probe_once(
                &mut proxy,
                &Protocol::Connect(9),
                &target,
                time::Instant::now() + Duration::from_secs(1),
                &super::super::WorkParams {
                    max_attempts: 1,
                    request_timeout: Duration::from_secs(1),
                    insecure: false,
                    support_cookies,
                    support_referer,
                    retry_delay: std::time::Duration::ZERO,
                },
            ),
        )
        .await;

        let server_result = time::timeout(Duration::from_secs(1), server).await.unwrap();
        server_result.unwrap();
        matches!(result, Ok(Ok(_)))
    }

    #[tokio::test]
    async fn cookie_and_referer_echo_checks_gate_tunnel_validation() {
        assert!(probe_with_echo(true, true, false, false).await);
        assert!(probe_with_echo(false, false, false, false).await);
        assert!(probe_with_echo(true, true, true, true).await);
        assert!(!probe_with_echo(false, true, true, false).await);
        assert!(!probe_with_echo(true, false, false, true).await);
        assert!(!probe_with_echo(false, false, true, true).await);
    }
}
