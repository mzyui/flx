use async_trait::async_trait;
use hyper::Uri;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};

use super::NegotiatorTrait;

/// A negotiator for HTTPS proxies.
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
        format!(
            "CONNECT {}:443 HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
            host, host
        )
    }
}

#[async_trait]
impl NegotiatorTrait for HttpsNegotiator {
    async fn negotiate(
        &self,
        stream: &mut TcpStream,
        runtimes: &mut Vec<f64>,
        proxy_host: &str,
        uri: &Uri,
    ) -> anyhow::Result<()> {
        if let Some(host) = uri.host() {
            let connect_request = self.generate_connect_request(host);

            // Ensure the request uses HTTPS
            if !uri.scheme().map_or(false, |s| s.as_str() == "https") {
                anyhow::bail!("Scheme is empty or not https");
            }

            self.log_trace(
                proxy_host,
                format!("Sending a connection request to {}", host),
            );
            let start_time = time::Instant::now();
            stream.write_all(connect_request.as_bytes()).await?;
            runtimes.push(start_time.elapsed().as_secs_f64());

            let mut buf = [0; 64];
            stream.read_exact(&mut buf).await?;

            let mut header = [httparse::EMPTY_HEADER; 32];
            let mut response = httparse::Response::new(&mut header);
            response.parse(&buf)?;

            let code = response.code.unwrap_or_default();
            if code != 200 {
                anyhow::bail!(
                    "Got response {}: {}. Expecting 200 OK",
                    code,
                    response.reason.unwrap_or("Unknown reason")
                );
            }
            self.log_trace(proxy_host, "Connection successfully established");
            runtimes.push(start_time.elapsed().as_secs_f64());
        }
        Ok(())
    }

    /// Indicates that this negotiator requires TLS.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether TLS is required.
    fn with_tls(&self) -> bool {
        true
    }
}
