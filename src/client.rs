use std::{
    error::Error,
    fmt::{Debug, Display},
    sync::Arc,
};

use hyper::{
    body::{Body, Incoming},
    client::conn::http1::handshake,
    Request, Response,
};
use hyper_util::rt::TokioIo;
use native_tls::TlsConnector;
use tokio::{net::TcpStream, time};

use crate::{models::Proxy, negotiators::NegotiatorTrait};

/// A struct representing a client that connects to a proxy server.
#[derive(Debug)]
pub struct ProxyClient {
    pub proxy: Proxy, // The proxy configuration to connect through.
}

impl ProxyClient {
    /// Creates a new instance of `ProxyClient`.
    ///
    /// # Arguments
    ///
    /// * `proxy`: The `Proxy` configuration to be used.
    ///
    /// # Returns
    ///
    /// A new instance of `ProxyClient`.
    pub fn new(proxy: Proxy) -> Self {
        Self { proxy }
    }

    /// Connects to the proxy server.
    ///
    /// This method establishes a TCP connection to the proxy server defined in the `ProxyClient`.
    ///
    /// # Returns
    ///
    /// A `TcpStream` if the connection is successful, or an error if it fails.
    async fn connect(&mut self) -> anyhow::Result<TcpStream> {
        let time_start = time::Instant::now();
        self.log_trace("Starting TCP connection");
        let result = TcpStream::connect(self.proxy.as_text()).await?;
        let elapsed = time_start.elapsed();
        self.log_trace(format!("Connected in {:?}", elapsed));
        self.proxy.runtimes.push(elapsed.as_secs_f64());

        Ok(result)
    }

    pub async fn send_with_tls<B>(
        &mut self, req: Request<B>, stream: TcpStream,
    ) -> anyhow::Result<Response<Incoming>>
    where
        B: Body + 'static + Debug + Send,
        B::Data: Send,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        self.log_trace("Starting TLS connection");
        let time_start = time::Instant::now();
        let config = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()?;
        let connector = tokio_native_tls::TlsConnector::from(config);

        let tls_stream = connector
            .connect(&self.proxy.ip.to_string(), stream)
            .await?;
        self.proxy.runtimes.push(time_start.elapsed().as_secs_f64());
        self.log_trace("TLS connection established successfully");

        let time_start = time::Instant::now();
        let io = TokioIo::new(tls_stream);
        let (mut sender, conn) = handshake(io).await?;
        self.proxy.runtimes.push(time_start.elapsed().as_secs_f64());

        let addr = self.proxy.as_text();
        let handler = tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                #[cfg(feature = "log")]
                if log::max_level().eq(&log::LevelFilter::Trace) {
                    log::error!("{}: Connection error: {}", addr, err);
                }
            }
        });

        self.log_trace(format!("Sending a {:?}", req));
        let time_start = time::Instant::now();
        let response = sender.send_request(req).await?;
        self.proxy.runtimes.push(time_start.elapsed().as_secs_f64());
        handler.abort();
        Ok(response)
    }

    pub async fn send_without_tls<B>(
        &mut self, req: Request<B>, stream: TcpStream,
    ) -> anyhow::Result<Response<Incoming>>
    where
        B: Body + 'static + Debug + Send,
        B::Data: Send,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let time_start = time::Instant::now();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = handshake(io).await?;
        self.proxy.runtimes.push(time_start.elapsed().as_secs_f64());

        let addr = self.proxy.as_text();
        let handler = tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                #[cfg(feature = "log")]
                if log::max_level().eq(&log::LevelFilter::Trace) {
                    log::error!("{}: Connection error: {}", addr, err);
                }
            }
        });

        self.log_trace(format!("Sending a {:?}", req));
        let time_start = time::Instant::now();
        let response = sender.send_request(req).await?;
        self.proxy.runtimes.push(time_start.elapsed().as_secs_f64());
        handler.abort();
        Ok(response)
    }

    /// Sends a request through the proxy.
    ///
    /// This method handles the connection and the HTTP request to the specified endpoint.
    ///
    /// # Type Parameters
    ///
    /// * `B`: The type of the request body, which must implement `Body` and be `Debug` and `Send`.
    /// * `N`: The Type of negotiator that will be called before making an http request, Which must implement NegotiatorTrait and Sync
    ///
    /// # Arguments
    ///
    /// * `req`: The HTTP request to send.
    /// * `negotiator`: Function to negotiate with proxy server
    ///
    /// # Returns
    ///
    /// A `Response<Incoming>` if the request is successful, or an error if it fails.
    pub async fn send_request<B, N>(
        &mut self, req: Request<B>, negotiator: Arc<N>,
    ) -> anyhow::Result<Response<Incoming>>
    where
        B: Body + 'static + Debug + Send,
        B::Data: Send,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
        N: NegotiatorTrait + Sync,
    {
        let mut stream = self.connect().await?;

        if let Err(e) = negotiator
            .negotiate(&mut stream, &mut self.proxy, req.uri())
            .await
        {
            anyhow::bail!("Failed to negotiate: {}", e);
        }

        if negotiator.with_tls() {
            self.send_with_tls(req, stream).await
        } else {
            self.send_without_tls(req, stream).await
        }
    }

    /// Logs a trace message.
    ///
    /// # Arguments
    ///
    /// * `msg`: The message to log.
    pub fn log_trace<S>(&self, msg: S)
    where
        S: Display,
    {
        #[cfg(feature = "log")]
        log::trace!("{}: {}", self.proxy.as_text(), msg);
    }

    /// Logs an error message.
    ///
    /// # Arguments
    ///
    /// * `msg`: The message to log as an error.
    pub fn log_error<S>(&self, msg: S)
    where
        S: Display,
    {
        #[cfg(feature = "log")]
        if log::max_level().eq(&log::LevelFilter::Trace) {
            log::error!("{}: {}", self.proxy.as_text(), msg);
        }
    }
}
