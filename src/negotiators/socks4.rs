use std::borrow::Cow;

use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use async_trait::async_trait;
use hyper::Uri;

use super::NegotiatorTrait;

/// Negotiates SOCKS4 proxy connections.
pub struct Socks4Negotiator;

impl Socks4Negotiator {
    fn build_connect_request<'a>(buf: &'a mut [u8], host: &str, port: u16) -> Cow<'a, [u8]> {
        let total = 10 + host.len();
        if total > buf.len() {
            let mut packet = Vec::with_capacity(total);
            packet.extend_from_slice(&[4u8, 1u8]);
            packet.extend_from_slice(&port.to_be_bytes());
            packet.extend_from_slice(&[0, 0, 0, 1]);
            packet.push(0u8);
            packet.extend_from_slice(host.as_bytes());
            packet.push(0u8);
            return Cow::Owned(packet);
        }

        let mut len = 0usize;
        buf[len..len + 2].copy_from_slice(&[4u8, 1u8]);
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

        let mut packet_buf = [0u8; 512];
        let packet = Self::build_connect_request(&mut packet_buf, host, port);

        stream.write_all(&packet).await?;

        let mut response = [0u8; 8];
        stream.read_exact(&mut response).await?;

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
