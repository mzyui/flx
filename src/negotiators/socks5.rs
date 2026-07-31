use std::net::Ipv4Addr;

use async_trait::async_trait;
use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

use super::NegotiatorTrait;

/// A negotiator for SOCKS5 proxies.
pub struct Socks5Negotiator;

#[async_trait]
impl NegotiatorTrait for Socks5Negotiator {
    /// Negotiates a connection with the SOCKS5 proxy.
    ///
    /// # Arguments
    ///
    /// * `stream`: The TCP stream to negotiate.
    /// * `proxy`: The proxy being used for the negotiation.
    /// * `_uri`: The URI to be accessed through the proxy (not used for SOCKS5).
    ///
    /// # Returns
    ///
    /// A result indicating success or failure of the negotiation.
    async fn negotiate(
        &self,
        stream: &mut TcpStream,
        runtimes: &mut Vec<f64>,
        proxy_host: &str,
        _uri: &hyper::Uri,
    ) -> anyhow::Result<()> {
        // Prepare the initial SOCKS5 handshake packet
        let handshake_packet = [5, 1, 0]; // Version, number of methods, no authentication

        let start_time = Instant::now();
        stream.write_all(&handshake_packet).await?;
        runtimes.push(start_time.elapsed().as_secs_f64());

        // Read the response from the SOCKS5 server
        let mut response_buf = [0; 2];
        let start_time = Instant::now();
        stream.read_exact(&mut response_buf).await?;
        runtimes.push(start_time.elapsed().as_secs_f64());

        if response_buf[0] != 0x05 {
            anyhow::bail!("InvalidData: invalid response version");
        }
        if response_buf[1] == 0xff {
            // TODO: Support for SOCKS5 authentication
            anyhow::bail!("PermissionDenied: authentication is required");
        }
        if response_buf[1] != 0x00 {
            anyhow::bail!("InvalidData: invalid response data");
        }
        let (host, port) = proxy_host
            .rsplit_once(':')
            .context("SOCKS5 proxy host must be in `ip:port` form")?;
        let ip: Ipv4Addr = host
            .parse()
            .with_context(|| format!("SOCKS5 host `{}` is not an IPv4 address", host))?;
        let port: u16 = port
            .parse()
            .with_context(|| format!("SOCKS5 port `{}` is invalid", port))?;

        // SOCKS5 CONNECT: VER=5, CMD=1, RSV=0, ATYP=1 (IPv4), DST.ADDR,
        // DST.PORT (big-endian).
        let mut connection_packet = Vec::with_capacity(10);
        connection_packet.extend_from_slice(&[5u8, 1u8, 0u8, 1u8]);
        connection_packet.extend_from_slice(&ip.octets());
        connection_packet.extend_from_slice(&port.to_be_bytes());

        let start_time = Instant::now();
        stream.write_all(&connection_packet).await?;
        runtimes.push(start_time.elapsed().as_secs_f64());

        // Read the response for the connection request
        let mut response_buf = [0; 10];
        let start_time = Instant::now();
        stream.read_exact(&mut response_buf).await?;
        runtimes.push(start_time.elapsed().as_secs_f64());

        if response_buf[0] != 0x05 {
            anyhow::bail!("InvalidData: invalid response version");
        }
        if response_buf[1] != 0x00 {
            anyhow::bail!("InvalidData: invalid response data");
        }

        Ok(())
    }
}
