use std::borrow::Cow;

use anyhow::Context;
use async_trait::async_trait;
use hyper::Uri;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::NegotiatorTrait;

/// Negotiates HTTP CONNECT tunnels for HTTPS proxies.
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

            // Read byte-by-byte: a buffered reader would swallow any bytes the
            // upstream sends after the header, corrupting the established tunnel.
            let mut buf = Vec::with_capacity(1024);
            let mut byte = [0u8; 1];
            loop {
                stream
                    .read_exact(&mut byte)
                    .await
                    .context("HTTPS proxy closed before completing the CONNECT response")?;
                if buf.len() >= 16 * 1024 {
                    anyhow::bail!("HTTPS proxy response headers exceed limit");
                }
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn negotiate_keeps_bytes_after_the_connect_head() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 256];
            let _ = socket.read(&mut head).await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nGREETING")
                .await;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let mut stream = TcpStream::connect(address).await.unwrap();
        let uri = Uri::try_from("https://example.com:443/").unwrap();
        HttpsNegotiator
            .negotiate(&mut stream, &address.to_string(), &uri)
            .await
            .unwrap();

        let mut greeting = [0u8; 8];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut greeting),
        )
        .await
        .expect("bytes after the CONNECT head must survive")
        .unwrap();
        assert_eq!(&greeting, b"GREETING");
    }
}
