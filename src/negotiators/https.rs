use async_trait::async_trait;
use hyper::Uri;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};

use super::NegotiatorTrait;
use crate::models::Proxy;

pub struct HttpsNegotiator;

impl HttpsNegotiator {
    /// Generates a CONNECT request to be sent to the proxy server.
    ///
    /// # Arguments
    ///
    /// * `host`: The host to connect to through the proxy.
    ///
    /// # Returns
    ///
    /// A `String` containing the raw bytes of the CONNECT request.
    fn generate_connect_request(&self, host: &str) -> String {
        format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n")
    }
}

#[async_trait]
impl NegotiatorTrait for HttpsNegotiator {
    async fn negotiate(
        &self, stream: &mut TcpStream, proxy: &mut Proxy, uri: &Uri,
    ) -> anyhow::Result<()> {
        if let Some(host) = uri.host() {
            let connect = self.generate_connect_request(host);

            // Check if the request uses HTTPS
            if !uri.scheme().map(|s| s.as_str() == "https").unwrap_or(false) {
                anyhow::bail!("Schema is empty or not https");
            }

            self.log_trace(proxy, format!("Sending a connection request to {}", host));
            let time_start = time::Instant::now();
            stream.write_all(connect.as_bytes()).await?;
            proxy.runtimes.push(time_start.elapsed().as_secs_f64());

            let mut buf = [0; 1024 * 4];
            stream.read(&mut buf).await?;

            let mut header = [httparse::EMPTY_HEADER; 32];
            let mut response = httparse::Response::new(&mut header);
            response.parse(&buf)?;

            let code = response.code.unwrap_or_default();
            if code != 200 {
                anyhow::bail!(
                    "Got response {} {}. Expecting 200 OK",
                    code,
                    response.reason.unwrap_or_default()
                );
            }
            self.log_trace(proxy, "Connection successfully stabilized");
            proxy.runtimes.push(time_start.elapsed().as_secs_f64());
        }
        Ok(())
    }

    fn with_tls(&self) -> bool {
        true
    }
}
