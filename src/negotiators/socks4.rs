use std::net::Ipv4Addr;

use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

use async_trait::async_trait;
use hyper::Uri;

use super::NegotiatorTrait;

/// A negotiator for SOCKS4 proxies.
pub struct Socks4Negotiator;

#[async_trait]
impl NegotiatorTrait for Socks4Negotiator {
    /// Negotiates a connection with the SOCKS4 proxy.
    ///
    /// # Arguments
    ///
    /// * `stream`: The TCP stream to negotiate.
    /// * `proxy`: The proxy being used for the negotiation.
    /// * `_uri`: The URI to be accessed through the proxy (not used for SOCKS4).
    ///
    /// # Returns
    ///
    /// A result indicating success or failure of the negotiation.
    async fn negotiate(
        &self,
        stream: &mut TcpStream,
        runtimes: &mut Vec<f64>,
        proxy_host: &str,
        _uri: &Uri,
    ) -> anyhow::Result<()> {
        let (host, port) = proxy_host
            .rsplit_once(':')
            .context("SOCKS4 proxy host must be in `ip:port` form")?;
        let ip: Ipv4Addr = host
            .parse()
            .with_context(|| format!("SOCKS4 host `{}` is not an IPv4 address", host))?;
        let port: u16 = port
            .parse()
            .with_context(|| format!("SOCKS4 port `{}` is invalid", port))?;

        // SOCKS4 CONNECT request: VN=4, CD=1, DSTPORT (BE), DSTIP, USERID='',
        // NULL terminator. All multi-byte fields are big-endian.
        let mut packet = Vec::with_capacity(9);
        packet.push(4u8); // version
        packet.push(1u8); // command: CONNECT
        packet.extend_from_slice(&port.to_be_bytes());
        packet.extend_from_slice(&ip.octets());
        packet.push(0u8); // empty USERID, null-terminated

        // Send the connection request to the SOCKS4 proxy
        let start_time = Instant::now();
        stream.write_all(&packet).await?;
        runtimes.push(start_time.elapsed().as_secs_f64());

        // Read the response from the SOCKS4 proxy
        let mut response = [0u8; 8];
        let start_time = Instant::now();
        stream.read_exact(&mut response).await?;
        runtimes.push(start_time.elapsed().as_secs_f64());

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
