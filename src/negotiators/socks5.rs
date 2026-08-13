use std::{borrow::Cow, net::IpAddr};

use anyhow::Context;
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

use super::NegotiatorTrait;
use crate::proxy::models::RuntimeStats;

pub struct Socks5Negotiator;

impl Socks5Negotiator {
    fn build_connect_request<'a>(
        buf: &'a mut [u8],
        host: &str,
        port: u16,
    ) -> anyhow::Result<Cow<'a, [u8]>> {
        let mut len = 0usize;
        buf[len..len + 3].copy_from_slice(&[5u8, 1u8, 0u8]); // VER, CMD, RSV
        len += 3;
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                buf[len] = 1; // ATYP IPv4
                len += 1;
                buf[len..len + 4].copy_from_slice(&ip.octets());
                len += 4;
            }
            Ok(IpAddr::V6(ip)) => {
                buf[len] = 4; // ATYP IPv6
                len += 1;
                buf[len..len + 16].copy_from_slice(&ip.octets());
                len += 16;
            }
            Err(_) => {
                let length =
                    u8::try_from(host.len()).context("SOCKS5 target hostname exceeds 255 bytes")?;
                buf[len] = 3; // ATYP domain
                len += 1;
                buf[len] = length;
                len += 1;
                buf[len..len + host.len()].copy_from_slice(host.as_bytes());
                len += host.len();
            }
        }
        buf[len..len + 2].copy_from_slice(&port.to_be_bytes());
        len += 2;
        Ok(Cow::Borrowed(&buf[..len]))
    }
}

#[async_trait]
impl NegotiatorTrait for Socks5Negotiator {
    async fn negotiate(
        &self,
        stream: &mut TcpStream,
        runtimes: &mut RuntimeStats,
        _proxy_host: &str,
        uri: &hyper::Uri,
    ) -> anyhow::Result<()> {
        // Method selection: VER=5, NMETHODS=1, METHOD=0 (no authentication).
        let handshake_packet = [5, 1, 0];

        let start_time = Instant::now();
        stream.write_all(&handshake_packet).await?;
        runtimes.record(start_time.elapsed().as_secs_f64());

        // Reply is a two-byte [VER, METHOD] selection.
        let mut response_buf = [0; 2];
        let start_time = Instant::now();
        stream.read_exact(&mut response_buf).await?;
        runtimes.record(start_time.elapsed().as_secs_f64());

        if response_buf[0] != 0x05 {
            anyhow::bail!("InvalidData: invalid response version");
        }
        if response_buf[1] == 0xff {
            anyhow::bail!("PermissionDenied: authentication is required");
        }
        if response_buf[1] != 0x00 {
            anyhow::bail!("InvalidData: invalid response data");
        }
        let host = uri.host().context("SOCKS5 target URI has no host")?;
        let port = uri
            .port_u16()
            .or_else(|| match uri.scheme_str() {
                Some("http") => Some(80),
                Some("https") => Some(443),
                _ => None,
            })
            .context("SOCKS5 target URI has no port")?;

        // CONNECT request: VER=5, CMD=1, RSV=0, ATYP, DST.ADDR, DST.PORT (BE).
        // Built into a stack buffer; RFC 1928 bounds the domain to 255 bytes.
        let mut packet_buf = [0u8; 512];
        let connection_packet = Self::build_connect_request(&mut packet_buf, host, port)?;

        let start_time = Instant::now();
        stream.write_all(&connection_packet).await?;
        runtimes.record(start_time.elapsed().as_secs_f64());

        // Parse the reply header [VER, REP, RSV, ATYP], then discard the
        // variable-length bound address and trailing port.
        let mut response_buf = [0; 4];
        let start_time = Instant::now();
        stream.read_exact(&mut response_buf).await?;
        runtimes.record(start_time.elapsed().as_secs_f64());

        if response_buf[0] != 0x05 {
            anyhow::bail!("InvalidData: invalid response version");
        }
        if response_buf[1] != 0x00 {
            anyhow::bail!("InvalidData: invalid response data");
        }
        let address_length = match response_buf[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut length = [0u8; 1];
                stream.read_exact(&mut length).await?;
                usize::from(length[0])
            }
            address_type => anyhow::bail!("InvalidData: invalid response ATYP: {address_type}"),
        };
        // Discard the variable-length bound address and trailing port (the
        // domain ATYP caps the length at 255, so 257 bytes always fit).
        let mut tail_buf = [0u8; 258];
        let tail_len = address_length + 2;
        stream.read_exact(&mut tail_buf[..tail_len]).await?;

        Ok(())
    }
}
