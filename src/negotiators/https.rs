use std::borrow::Cow;

use async_trait::async_trait;
use hyper::Uri;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::NegotiatorTrait;

pub struct HttpsNegotiator;

impl HttpsNegotiator {
    fn write_authority<'a>(buf: &'a mut [u8], host: &str, port: u16) -> Cow<'a, str> {
        let args = if host.contains(':') {
            format_args!("[{host}]:{port}")
        } else {
            format_args!("{host}:{port}")
        };
        crate::write_to_buffer(buf, args)
    }

    fn write_connect_request<'a>(buf: &'a mut [u8], authority: &str) -> Cow<'a, str> {
        crate::write_to_buffer(
            buf,
            format_args!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\n\r\n"
            ),
        )
    }
}

#[async_trait]
impl NegotiatorTrait for HttpsNegotiator {
    async fn negotiate(
        &self,
        stream: &mut TcpStream,
        proxy_host: &str,
        uri: &Uri,
    ) -> anyhow::Result<()> {
        if let Some(host) = uri.host() {
            let port = uri.port_u16().unwrap_or(443);
            let mut authority_buf = [0u8; 256];
            let authority = Self::write_authority(&mut authority_buf, host, port);
            let mut request_buf = [0u8; 1024];
            let connect_request = Self::write_connect_request(&mut request_buf, &authority);

            // CONNECT only applies when tunnelling to an HTTPS target.
            if !uri.scheme().is_some_and(|s| s.as_str() == "https") {
                anyhow::bail!("Scheme is empty or not https");
            }

            self.log_trace(
                proxy_host,
                format_args!("Sending a connection request to {}", host),
            );
            stream.write_all(connect_request.as_bytes()).await?;

            let mut reader = tokio::io::BufReader::new(&mut *stream);
            let mut buf = Vec::with_capacity(16 * 1024);
            let mut line = Vec::with_capacity(64);
            loop {
                line.clear();
                if reader.read_until(b'\n', &mut line).await? == 0 {
                    break;
                }
                if buf.len().saturating_add(line.len()) > 16 * 1024 {
                    anyhow::bail!("HTTPS proxy response headers exceed limit");
                }
                buf.extend_from_slice(&line);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            if !buf.ends_with(b"\r\n\r\n") {
                anyhow::bail!("HTTPS proxy response headers exceed limit");
            }

            let mut header = [httparse::EMPTY_HEADER; 32];
            let mut response = httparse::Response::new(&mut header);
            if response.parse(&buf)?.is_partial() {
                anyhow::bail!("HTTPS proxy returned incomplete CONNECT response");
            }

            let code = response.code.unwrap_or_default();
            if code != 200 {
                anyhow::bail!(
                    "Got response {}: {}. Expecting 200 OK",
                    code,
                    response.reason.unwrap_or("Unknown reason")
                );
            }
            self.log_trace(proxy_host, "Connection successfully established");
        }
        Ok(())
    }

    fn with_tls(&self) -> bool {
        true
    }
}
