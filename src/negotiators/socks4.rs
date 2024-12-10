use std::io::Cursor;

use byteorder::BigEndian;
use byteorder_pack::PackTo;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

use async_trait::async_trait;
use hyper::Uri;

use super::NegotiatorTrait;
use crate::proxy::models::Proxy;

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
        proxy: &mut Proxy,
        _uri: &Uri,
    ) -> anyhow::Result<()> {
        // Prepare the SOCKS4 connection request packet
        let data = (4u8, 1u8, proxy.port, proxy.ip.octets(), 0u8);
        let mut cursor = Cursor::new(Vec::new());
        data.pack_to::<BigEndian, _>(&mut cursor)?;
        let packet = cursor.into_inner();

        // Send the connection request to the SOCKS4 proxy
        let start_time = Instant::now();
        stream.write_all(&packet).await?;
        proxy.runtimes.push(start_time.elapsed().as_secs_f64());

        // Read the response from the SOCKS4 proxy
        let mut response = [0u8; 8];
        let start_time = Instant::now();
        stream.read_exact(&mut response).await?;
        proxy.runtimes.push(start_time.elapsed().as_secs_f64());

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
