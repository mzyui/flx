use std::io::Cursor;

use async_trait::async_trait;
use byteorder::BigEndian;
use byteorder_pack::PackTo;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

use crate::proxy::models::Proxy;

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
        proxy: &mut Proxy,
        _uri: &hyper::Uri,
    ) -> anyhow::Result<()> {
        // Prepare the initial SOCKS5 handshake packet
        let handshake_packet = [5, 1, 0]; // Version, number of methods, no authentication

        let start_time = Instant::now();
        stream.write_all(&handshake_packet).await?;
        proxy.runtimes.push(start_time.elapsed().as_secs_f64());

        // Read the response from the SOCKS5 server
        let mut response_buf = [0; 2];
        let start_time = Instant::now();
        stream.read_exact(&mut response_buf).await?;
        proxy.runtimes.push(start_time.elapsed().as_secs_f64());

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

        // Prepare the SOCKS5 connection request packet
        let data = (5u8, 1u8, 0u8, 1u8, proxy.ip.octets(), proxy.port);
        let mut cursor = Cursor::new(Vec::new());
        data.pack_to::<BigEndian, _>(&mut cursor)?;
        let connection_packet = cursor.into_inner();

        let start_time = Instant::now();
        stream.write_all(&connection_packet).await?;
        proxy.runtimes.push(start_time.elapsed().as_secs_f64());

        // Read the response for the connection request
        let mut response_buf = [0; 10];
        let start_time = Instant::now();
        stream.read_exact(&mut response_buf).await?;
        proxy.runtimes.push(start_time.elapsed().as_secs_f64());

        if response_buf[0] != 0x05 {
            anyhow::bail!("InvalidData: invalid response version");
        }
        if response_buf[1] != 0x00 {
            anyhow::bail!("InvalidData: invalid response data");
        }

        Ok(())
    }
}
