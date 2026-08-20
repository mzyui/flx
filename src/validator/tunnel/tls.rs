use std::{sync::Arc, time::Duration};

use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

use crate::proxy::client::{spawn_connection_driver, ConnectionDriver};
use crate::validator::{checker::read_bounded_body, WorkParams};

const MAX_JUDGE_RESPONSE_BYTES: usize = 576 * 1024;

pub(super) async fn verify_tls_judge(
    stream: TcpStream,
    target: &super::JudgeTarget,
    authority: &str,
    params: &WorkParams,
) -> anyhow::Result<(String, Option<ConnectionDriver>)> {
    let insecure = params.insecure;
    let support_cookies = params.support_cookies;
    let support_referer = params.support_referer;
    use hyper::client::conn::http1::handshake;
    use hyper_util::rt::TokioIo;

    let connector = crate::proxy::client::tls_connector(insecure);
    let tls_stream = connector
        .connect(&target.host, stream)
        .await
        .with_context(|| format!("TLS handshake with judge {} failed", target.host))?;
    let (mut sender, connection) = handshake(TokioIo::new(tls_stream))
        .await
        .context("HTTP handshake with TLS judge failed")?;
    let driver = spawn_connection_driver(connection, Arc::from(authority), Duration::from_secs(30));
    let request = hyper::Request::get(&target.path_and_query)
        .header(hyper::header::HOST, authority)
        .header(hyper::header::CONNECTION, "close")
        .header("X-Fluxy-Token", &target.request_token)
        .header(hyper::header::COOKIE, "cookie=ok")
        .header(hyper::header::REFERER, "https://google.com/")
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;
    let response = sender.send_request(request).await?;
    if response.status() != hyper::StatusCode::OK {
        anyhow::bail!("TLS judge returned status {}", response.status());
    }
    let body = read_bounded_body(response.into_body(), MAX_JUDGE_RESPONSE_BYTES).await?;
    if body.len() > MAX_JUDGE_RESPONSE_BYTES {
        anyhow::bail!("TLS judge response exceeds validation limit");
    }
    // The token is pure ASCII, so a lossy string scan finds it with one O(n)
    // sub-string search.
    let body = String::from_utf8_lossy(&body);
    if !body.contains(&target.response_marker) {
        anyhow::bail!("response did not originate from the TLS judge");
    }
    if support_cookies && !body.contains("HTTP_COOKIE = cookie=ok") {
        anyhow::bail!("proxy did not forward the cookie header");
    }
    if support_referer && !body.contains("HTTP_REFERER = https://google.com/") {
        anyhow::bail!("proxy did not forward the referer header");
    }
    Ok((body.into_owned(), Some(driver)))
}

pub(super) async fn verify_judge(
    stream: &mut BufReader<TcpStream>,
    target: &super::JudgeTarget,
    authority: &str,
    params: &WorkParams,
) -> anyhow::Result<String> {
    let support_cookies = params.support_cookies;
    let support_referer = params.support_referer;
    let mut buf = [0u8; 2048];
    let request = crate::write_to_buffer(
        &mut buf,
        format_args!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nX-Fluxy-Token: {}\r\nCookie: cookie=ok\r\nReferer: https://google.com/\r\nConnection: close\r\n\r\n",
            target.path_and_query, authority, target.request_token
        ),
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        if response.len().saturating_add(read) > MAX_JUDGE_RESPONSE_BYTES {
            anyhow::bail!("local judge response exceeds validation limit");
        }
        response.extend_from_slice(&chunk[..read]);
    }

    let status = super::negotiate::parse_http_status(&response)?;
    if status != 200 {
        anyhow::bail!("local judge returned status {status} through tunnel");
    }
    let response = String::from_utf8_lossy(&response);
    if !response.contains(&target.response_marker) {
        anyhow::bail!("response did not originate from the local judge");
    }
    if support_cookies && !response.contains("HTTP_COOKIE = cookie=ok") {
        anyhow::bail!("proxy did not forward the cookie header");
    }
    if support_referer && !response.contains("HTTP_REFERER = https://google.com/") {
        anyhow::bail!("proxy did not forward the referer header");
    }
    Ok(response.into_owned())
}
