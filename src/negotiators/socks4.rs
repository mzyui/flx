use std::borrow::Cow;

use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

use async_trait::async_trait;
use hyper::Uri;

use super::NegotiatorTrait;
use crate::proxy::models::RuntimeStats;

/// Negotiator for SOCKS4 proxies.
pub struct Socks4Negotiator;

impl Socks4Negotiator {
    /// Builds the SOCKS4 CONNECT packet into a stack buffer, falling back to
    /// an owned `Vec` only for hosts too long for the buffer.
    fn build_connect_request<'a>(buf: &'a mut [u8], host: &str, port: u16) -> Cow<'a, [u8]> {
        // 2 (VN, CD) + 2 (port) + 4 (DST.IP) + 1 (USERID null) + host + 1.
        let total = 10 + host.len();
        if total > buf.len() {
            // Fallback for pathologically overlong hosts (domain format).
            let mut packet = Vec::with_capacity(total);
            packet.extend_from_slice(&[4u8, 1u8]); // VN, command
            packet.extend_from_slice(&port.to_be_bytes());
            packet.extend_from_slice(&[0, 0, 0, 1]);
            packet.push(0u8);
            packet.extend_from_slice(host.as_bytes());
            packet.push(0u8);
            return Cow::Owned(packet);
        }

        let mut len = 0usize;
        buf[len..len + 2].copy_from_slice(&[4u8, 1u8]); // VN, command
        len += 2;
        buf[len..len + 2].copy_from_slice(&port.to_be_bytes());
        len += 2;
        match host.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => {
                buf[len..len + 4].copy_from_slice(&ip.octets());
                len += 4;
                buf[len] = 0u8;
                len += 1;
            }
            Err(_) => {
                buf[len..len + 4].copy_from_slice(&[0, 0, 0, 1]);
                len += 4;
                buf[len] = 0u8;
                len += 1;
                buf[len..len + host.len()].copy_from_slice(host.as_bytes());
                len += host.len();
                buf[len] = 0u8;
                len += 1;
            }
        }
        Cow::Borrowed(&buf[..len])
    }
}

#[async_trait]
impl NegotiatorTrait for Socks4Negotiator {
    async fn negotiate(
        &self,
        stream: &mut TcpStream,
        runtimes: &mut RuntimeStats,
        _proxy_host: &str,
        uri: &Uri,
    ) -> anyhow::Result<()> {
        let host = uri.host().context("SOCKS4 target URI has no host")?;
        let port = uri
            .port_u16()
            .or_else(|| match uri.scheme_str() {
                Some("http") => Some(80),
                Some("https") => Some(443),
                _ => None,
            })
            .context("SOCKS4 target URI has no port")?;

        // SOCKS4 CONNECT request: VN=4, CD=1, DST.PORT (big-endian), DST.IP,
        // USERID, NULL terminator. A non-IPv4 host goes through the 0.0.0.1
        // domain-name fallback. Built into a stack buffer; no heap unless the
        // host is pathologically long.
        let mut packet_buf = [0u8; 512];
        let packet = Self::build_connect_request(&mut packet_buf, host, port);

        // Transmit the request, then read the 8-byte reply.
        let start_time = Instant::now();
        stream.write_all(&packet).await?;
        runtimes.record(start_time.elapsed().as_secs_f64());

        let mut response = [0u8; 8];
        let start_time = Instant::now();
        stream.read_exact(&mut response).await?;
        runtimes.record(start_time.elapsed().as_secs_f64());

        // The reply is [VN, CD, DST.PORT, DST.IP] with CD signalling success.
        let mut response_slice = &response[..];
        if response_slice.read_u8().await? != 0 {
            anyhow::bail!("InvalidData: invalid response version");
        }

        match response_slice.read_u8().await? {
            90 => {}
            91 => anyhow::bail!("Other: Request rejected or failed"),
            92 => anyhow::bail!("PermissionDenied: Request rejected because SOCKS server cannot connect to identd on the client"),
            93 => anyhow::bail!("PermissionDenied: Request rejected because the client program and identd report different user IDs"),
            code => anyhow::bail!("InvalidData: invalid response code: {}", code),
        }

        Ok(())
    }
}
