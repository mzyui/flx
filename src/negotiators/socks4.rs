use std::io::Cursor;

use byteorder::BigEndian;
use byteorder_pack::PackTo;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use async_trait::async_trait;
use hyper::Uri;

use super::NegotiatorTrait;
use crate::models::Proxy;

pub struct Socks4Negotiator;

#[async_trait]
impl NegotiatorTrait for Socks4Negotiator {
    async fn negotiate(
        &self,
        stream: &mut TcpStream,
        proxy: &mut Proxy,
        _uri: &Uri,
    ) -> anyhow::Result<()> {
        let data = (4u8, 1u8, proxy.port, proxy.ip.octets(), 0u8);
        let mut cursor = Cursor::new(Vec::new());
        data.pack_to::<BigEndian, _>(&mut cursor)?;
        let packet = cursor.into_inner();

        stream.write_all(&packet).await?;

        let mut response = [0u8; 8];
        stream.read_exact(&mut response).await?;
        let mut response = response.as_slice();

        if response.read_u8().await? != 0 {
            anyhow::bail!("InvalidData: invalid response version");
        }

        match response.read_u8().await? {
            90 => {} // Ok
            91 => anyhow::bail!("Other: request rejected or failed"),
            92 => anyhow::bail!("PermissionDenied: request rejected because SOCKS server cannot connect to idnetd on the client"),
            93 => anyhow::bail!("PermissionDenied: request rejected because the client program and identd report different user-ids"),
            _ => anyhow::bail!("InvalidData: invalid response code")
        }

        Ok(())
    }
}
