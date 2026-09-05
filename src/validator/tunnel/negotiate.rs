use std::{borrow::Cow, net::IpAddr, net::Ipv4Addr};

use anyhow::Context;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

use super::JudgeTarget;

const MAX_PROXY_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

pub(super) fn authority_for<'a>(buf: &'a mut [u8], host: &str, port: u16) -> Cow<'a, str> {
    let args = if host.contains(':') {
        format_args!("[{host}]:{port}")
    } else {
        format_args!("{host}:{port}")
    };
    crate::write_to_buffer(buf, args)
}

fn write_request<'a>(buf: &'a mut [u8], args: std::fmt::Arguments<'_>) -> Cow<'a, str> {
    crate::write_to_buffer(buf, args)
}

pub(super) async fn negotiate_http_connect(
    stream: &mut BufReader<TcpStream>,
    authority: &str,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 1024];
    let request = write_request(
        &mut buf,
        format_args!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n\r\n"
        ),
    );
    stream.write_all(request.as_bytes()).await?;

    let response = read_http_headers(stream).await?;
    let status = parse_http_status(&response)?;
    if status != 200 {
        anyhow::bail!("CONNECT to {authority} returned status {status}");
    }
    Ok(())
}

pub(super) async fn negotiate_socks4(
    stream: &mut BufReader<TcpStream>,
    target: &JudgeTarget,
) -> anyhow::Result<()> {
    let ip = target.host.parse::<Ipv4Addr>();
    let mut request = Vec::with_capacity(10 + target.host.len());
    request.extend_from_slice(&[4, 1]);
    request.extend_from_slice(&target.port.to_be_bytes());
    match ip {
        Ok(ip) => request.extend_from_slice(&ip.octets()),
        Err(_) => {
            request.extend_from_slice(&Ipv4Addr::new(0, 0, 0, 1).octets());
            request.push(0);
            request.extend_from_slice(target.host.as_bytes());
            request.push(0);
        }
    }
    if ip.is_ok() {
        request.push(0);
    }
    stream.write_all(&request).await?;

    let mut response = [0u8; 8];
    stream.read_exact(&mut response).await?;
    if response[0] != 0 || response[1] != 90 {
        anyhow::bail!("SOCKS4 proxy rejected request with code {}", response[1]);
    }
    Ok(())
}

pub(super) async fn negotiate_socks5(
    stream: &mut BufReader<TcpStream>,
    target: &JudgeTarget,
) -> anyhow::Result<()> {
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 0] {
        anyhow::bail!("SOCKS5 proxy did not accept unauthenticated mode");
    }

    let mut request = Vec::with_capacity(22 + target.host.len());
    request.extend_from_slice(&[5, 1, 0]);
    match target.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let length = u8::try_from(target.host.len())
                .context("SOCKS5 target hostname exceeds 255 bytes")?;
            request.extend_from_slice(&[3, length]);
            request.extend_from_slice(target.host.as_bytes());
        }
    }
    request.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 || header[1] != 0 {
        anyhow::bail!("SOCKS5 proxy rejected request with code {}", header[1]);
    }
    match header[3] {
        1 => read_discard(stream, 4).await?,
        4 => read_discard(stream, 16).await?,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            read_discard(stream, usize::from(length[0])).await?;
        }
        address_type => anyhow::bail!("SOCKS5 proxy returned invalid ATYP {address_type}"),
    }
    read_discard(stream, 2).await
}

async fn read_discard(stream: &mut BufReader<TcpStream>, length: usize) -> anyhow::Result<()> {
    // Use stack buffer; ATYP bounds addresses to 255 bytes.
    let mut bytes = [0u8; 256];
    if length > bytes.len() {
        anyhow::bail!("SOCKS reply address exceeds 256 bytes");
    }
    let slice = &mut bytes[..length];
    stream.read_exact(slice).await?;
    Ok(())
}

async fn read_http_headers(stream: &mut BufReader<TcpStream>) -> anyhow::Result<Vec<u8>> {
    let mut response = Vec::with_capacity(16 * 1024);
    let mut line = Vec::with_capacity(64);
    loop {
        line.clear();
        if stream.read_until(b'\n', &mut line).await? == 0 {
            break;
        }
        if response.len().saturating_add(line.len()) > MAX_PROXY_RESPONSE_HEADER_BYTES {
            anyhow::bail!("proxy response headers exceed limit");
        }
        response.extend_from_slice(&line);
        if response.ends_with(b"\r\n\r\n") {
            return Ok(response);
        }
    }
    anyhow::bail!("proxy response headers exceed limit")
}

pub(super) fn parse_http_status(response: &[u8]) -> anyhow::Result<u16> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Response::new(&mut headers);
    if parsed.parse(response)?.is_partial() {
        anyhow::bail!("incomplete HTTP response headers");
    }
    parsed
        .code
        .context("HTTP response did not include a status code")
}
