use std::io::Cursor;

use async_trait::async_trait;
use byteorder::BigEndian;
use byteorder_pack::PackTo;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

use crate::models::Proxy;

use super::NegotiatorTrait;

pub struct Socks5Negotiator;

#[async_trait]
impl NegotiatorTrait for Socks5Negotiator {
    async fn negotiate(
        &self,
        stream: &mut TcpStream,
        proxy: &mut Proxy,
        _uri: &hyper::Uri,
    ) -> anyhow::Result<()> {
        let packet = [5, 1, 0];

        let time_start = Instant::now();
        stream.write_all(&packet).await?;
        proxy.runtimes.push(time_start.elapsed().as_secs_f64());

        let mut buf = [0; 2];
        let time_start = Instant::now();
        stream.read_exact(&mut buf).await?;
        proxy.runtimes.push(time_start.elapsed().as_secs_f64());

        if buf[0] != 0x05 {
            anyhow::bail!("InvalidData: invalid response version");
        }
        if buf[1] == 0xff {
            // TODO: Add support for socks5 auth
            anyhow::bail!("PermissionDenied: auth is required");
        }
        if buf[1] != 0x00 {
            anyhow::bail!("InvalidData: invalid response data");
        }

        let data = (5u8, 1u8, 0u8, 1u8, proxy.ip.octets(), proxy.port);
        let mut buf = Cursor::new(Vec::new());
        data.pack_to::<BigEndian, _>(&mut buf)?;
        let packet = buf.into_inner();

        let time_start = Instant::now();
        stream.write_all(&packet).await?;
        proxy.runtimes.push(time_start.elapsed().as_secs_f64());

        let mut buf = [0; 10];
        let time_start = Instant::now();
        stream.read_exact(&mut buf).await?;
        proxy.runtimes.push(time_start.elapsed().as_secs_f64());

        if buf[0] != 0x05 {
            anyhow::bail!("InvalidData: invalid response version");
        }
        if buf[1] != 0x00 {
            anyhow::bail!("InvalidData: invalid response data");
        }

        Ok(())
    }
}
