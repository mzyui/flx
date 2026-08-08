use std::net::IpAddr;

use anyhow::Context;
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

use super::NegotiatorTrait;
use crate::proxy::models::RuntimeStats;

/// Negotiator for SOCKS5 proxies.
pub struct Socks5Negotiator;

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
        let mut connection_packet = Vec::with_capacity(22 + host.len());
        connection_packet.extend_from_slice(&[5u8, 1u8, 0u8]);
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                connection_packet.push(1);
                connection_packet.extend_from_slice(&ip.octets());
            }
            Ok(IpAddr::V6(ip)) => {
                connection_packet.push(4);
                connection_packet.extend_from_slice(&ip.octets());
            }
            Err(_) => {
                let length =
                    u8::try_from(host.len()).context("SOCKS5 target hostname exceeds 255 bytes")?;
                connection_packet.extend_from_slice(&[3, length]);
                connection_packet.extend_from_slice(host.as_bytes());
            }
        }
        connection_packet.extend_from_slice(&port.to_be_bytes());

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
        let mut tail = vec![0u8; address_length + 2];
        stream.read_exact(&mut tail).await?;

        Ok(())
    }
}
