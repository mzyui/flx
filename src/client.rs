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

/// Represents a client that connects to a proxy server.
#[derive(Debug)]
pub struct ProxyClient {
    pub proxy: Proxy, // The proxy configuration for the connection.
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

    /// Establishes a TCP connection to the proxy server.
    ///
    /// # Returns
    ///
    /// A `TcpStream` if the connection is successful, or an error if it fails.
    async fn connect(&mut self) -> anyhow::Result<TcpStream> {
        let start_time = time::Instant::now();
        self.log_trace("Starting TCP connection");

        let tcp_stream = TcpStream::connect(self.proxy.as_text()).await?;

        let elapsed_time = start_time.elapsed();
        self.log_trace(format!("Connected in {:?}", elapsed_time));
        self.proxy.runtimes.push(elapsed_time.as_secs_f64());

        Ok(tcp_stream)
    }

    /// Sends a request over TLS through the proxy.
    ///
    /// # Arguments
    ///
    /// * `req`: The HTTP request to send.
    /// * `stream`: The TCP stream to use for the connection.
    ///
    /// # Returns
    ///
    /// A `Response<Incoming>` if the request is successful, or an error if it fails.
    pub async fn send_with_tls<B>(
        &mut self,
        req: Request<B>,
        stream: TcpStream,
    ) -> anyhow::Result<Response<Incoming>>
    where
        B: Body + 'static + Debug + Send,
        B::Data: Send,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        self.log_trace("Starting TLS connection");
        let start_time = time::Instant::now();

        let tls_connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()?;
        let connector = tokio_native_tls::TlsConnector::from(tls_connector);

        let tls_stream = connector
            .connect(&self.proxy.ip.to_string(), stream)
            .await?;
        self.proxy.runtimes.push(start_time.elapsed().as_secs_f64());
        self.log_trace("TLS connection established successfully");

        let start_time = time::Instant::now();
        let io = TokioIo::new(tls_stream);
        let (mut sender, conn) = handshake(io).await?;
        self.proxy.runtimes.push(start_time.elapsed().as_secs_f64());

        let addr = self.proxy.as_text();
        let handler = tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                #[cfg(feature = "log")]
                if log::max_level().eq(&log::LevelFilter::Trace) {
                    log::error!("{}: Connection error: {}", addr, err);
                }
            }
        });

        self.log_trace(format!("Sending request: {:?}", req));
        let start_time = time::Instant::now();
        let response = sender.send_request(req).await?;
        self.proxy.runtimes.push(start_time.elapsed().as_secs_f64());
        handler.abort();

        Ok(response)
    }

    /// Sends a request without TLS through the proxy.
    ///
    /// # Arguments
    ///
    /// * `req`: The HTTP request to send.
    /// * `stream`: The TCP stream to use for the connection.
    ///
    /// # Returns
    ///
    /// A `Response<Incoming>` if the request is successful, or an error if it fails.
    pub async fn send_without_tls<B>(
        &mut self,
        req: Request<B>,
        stream: TcpStream,
    ) -> anyhow::Result<Response<Incoming>>
    where
        B: Body + 'static + Debug + Send,
        B::Data: Send,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let start_time = time::Instant::now();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = handshake(io).await?;
        self.proxy.runtimes.push(start_time.elapsed().as_secs_f64());

        let addr = self.proxy.as_text();
        let handler = tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                #[cfg(feature = "log")]
                if log::max_level().eq(&log::LevelFilter::Trace) {
                    log::error!("{}: Connection error: {}", addr, err);
                }
            }
        });

        self.log_trace(format!("Sending request: {:?}", req));
        let start_time = time::Instant::now();
        let response = sender.send_request(req).await?;
        self.proxy.runtimes.push(start_time.elapsed().as_secs_f64());
        handler.abort();

        Ok(response)
    }

    /// Sends a request through the proxy.
    ///
    /// This method manages the connection and the HTTP request to the specified endpoint.
    ///
    /// # Type Parameters
    ///
    /// * `B`: The type of the request body, which must implement `Body`, and be `Debug` and `Send`.
    /// * `N`: The negotiator type that will be called before making the HTTP request, which must implement `NegotiatorTrait` and `Sync`.
    ///
    /// # Arguments
    ///
    /// * `req`: The HTTP request to send.
    /// * `negotiator`: An optional function to negotiate with the proxy server.
    ///
    /// # Returns
    ///
    /// A `Response<Incoming>` if the request is successful, or an error if it fails.
    pub async fn send_request<B, N>(
        &mut self,
        req: Request<B>,
        negotiator: Option<Arc<N>>,
    ) -> anyhow::Result<Response<Incoming>>
    where
        B: Body + 'static + Debug + Send,
        B::Data: Send,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
        N: NegotiatorTrait + Sync,
    {
        let mut stream = self.connect().await?;
        let mut use_tls = false;

        if let Some(negotiator) = negotiator {
            if let Err(e) = negotiator
                .negotiate(&mut stream, &mut self.proxy, req.uri())
                .await
            {
                anyhow::bail!("Failed to negotiate: {}", e);
            }
            use_tls = negotiator.with_tls();
        }

        if use_tls || req.uri().scheme_str().unwrap_or("") == "https" {
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
