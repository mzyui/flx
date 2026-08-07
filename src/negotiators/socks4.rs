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

/// A negotiator for SOCKS4 proxies.
pub struct Socks4Negotiator;

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

        // SOCKS4 CONNECT request: VN=4, CD=1, DSTPORT (BE), DSTIP, USERID='',
        // NULL terminator. All multi-byte fields are big-endian.
        let mut packet = Vec::with_capacity(10 + host.len());
        packet.push(4u8); // version
        packet.push(1u8); // command: CONNECT
        packet.extend_from_slice(&port.to_be_bytes());
        match host.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => {
                packet.extend_from_slice(&ip.octets());
                packet.push(0u8);
            }
            Err(_) => {
                packet.extend_from_slice(&[0, 0, 0, 1]);
                packet.push(0u8);
                packet.extend_from_slice(host.as_bytes());
                packet.push(0u8);
            }
        }

        // Send the connection request to the SOCKS4 proxy
        let start_time = Instant::now();
        stream.write_all(&packet).await?;
        runtimes.record(start_time.elapsed().as_secs_f64());

        // Read the response from the SOCKS4 proxy
        let mut response = [0u8; 8];
        let start_time = Instant::now();
        stream.read_exact(&mut response).await?;
        runtimes.record(start_time.elapsed().as_secs_f64());

        // Validate the response
        let mut response_slice = &response[..];
        if response_slice.read_u8().await? != 0 {
            anyhow::bail!("InvalidData: invalid response version");
        }

        match response_slice.read_u8().await? {
            90 => {} // 90: Request granted
            91 => anyhow::bail!("Other: Request rejected or failed"),
            92 => anyhow::bail!("PermissionDenied: Request rejected because SOCKS server cannot connect to identd on the client"),
            93 => anyhow::bail!("PermissionDenied: Request rejected because the client program and identd report different user IDs"),
            code => anyhow::bail!("InvalidData: invalid response code: {}", code),
        }

        Ok(())
    }
}
