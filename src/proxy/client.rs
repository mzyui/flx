use std::{
    borrow::Cow,
    fmt::{Debug, Display},
    time::Duration,
};

use hyper::{
    body::{Body, Incoming},
    client::conn::http1::handshake,
    Request, Response,
};
use hyper_util::rt::TokioIo;
use native_tls::TlsConnector;
use tokio::{net::TcpStream, time};

use async_trait::async_trait;

use crate::{negotiators::NegotiatorTrait, proxy::models::Proxy};

#[derive(Debug)]
pub struct ProxyRuntimes<T> {
    pub inner: T,
    pub runtimes: Vec<f64>,
}

impl<T> ProxyRuntimes<T> {
    pub fn apply(&self, proxy: &mut Proxy) {
        proxy.runtimes.extend_from_slice(&self.runtimes);
    }
}

#[async_trait]
pub trait ProxyClient {
    fn host(&self) -> Cow<'static, str>;

    /// Establishes a TCP connection to the proxy server.
    ///
    /// # Returns
    ///
    /// A tuple containing a `TcpStream` if the connection is successful,
    /// and an array with the elapsed time in seconds as `f64`.
    /// If the connection fails, it returns an error.
    async fn connect_timeout(
        &mut self,
        timeout: Duration,
    ) -> anyhow::Result<ProxyRuntimes<TcpStream>> {
        let start_time = time::Instant::now();
        self.log_trace("Starting TCP connection");

        let host = self.host();
        let elapsed_time = start_time.elapsed();
        let tcp_stream = time::timeout(timeout, TcpStream::connect(host.into_owned())).await??;
        let runtimes = vec![elapsed_time.as_secs_f64()];
        self.log_trace(format!("Connected in {:?}", elapsed_time));

        Ok(ProxyRuntimes {
            inner: tcp_stream,
            runtimes,
        })
    }

    async fn send_request<B, N>(
        &mut self,
        req: Request<B>,
        negotiator: Option<N>,
        timeout: Duration,
    ) -> anyhow::Result<ProxyRuntimes<Response<Incoming>>>
    where
        B: Body + 'static + Debug + Send,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        N: NegotiatorTrait + Sync + Send,
    {
        let tcp = self.connect_timeout(timeout).await?;
        let mut stream = tcp.inner;
        let mut runtimes = tcp.runtimes;

        let mut use_tls = false;

        if let Some(negotiator) = negotiator {
            let proxy_host = self.host();
            if let Err(e) = negotiator
                .negotiate(&mut stream, &mut runtimes, &proxy_host, req.uri())
                .await
            {
                anyhow::bail!("Failed to negotiate: {}", e);
            }
            use_tls = negotiator.with_tls();
        }

        if use_tls || req.uri().scheme_str().unwrap_or("") == "https" {
            time::timeout(timeout, self.send_with_tls(req, stream, runtimes)).await?
        } else {
            time::timeout(timeout, self.send_without_tls(req, stream, runtimes)).await?
        }
    }

    async fn send_with_tls<B>(
        &mut self,
        req: Request<B>,
        stream: TcpStream,
        mut runtimes: Vec<f64>,
    ) -> anyhow::Result<ProxyRuntimes<Response<Incoming>>>
    where
        B: Body + 'static + Debug + Send,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.log_trace("Starting TLS connection");
        let start_time = time::Instant::now();

        let tls_connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()?;
        let connector = tokio_native_tls::TlsConnector::from(tls_connector);

        let host = self.host();
        let tls_stream = connector
            .connect(host.split(':').next().unwrap(), stream)
            .await?;
        runtimes.push(start_time.elapsed().as_secs_f64());
        self.log_trace("TLS connection established successfully");

        let start_time = time::Instant::now();
        let io = TokioIo::new(tls_stream);
        let (mut sender, conn) = handshake(io).await?;
        runtimes.push(start_time.elapsed().as_secs_f64());

        let host = self.host();
        let handler = tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                #[cfg(feature = "log")]
                if log::max_level().eq(&log::LevelFilter::Trace) {
                    log::error!("{}: Connection error: {}", host, err);
                }
            }
        });

        self.log_trace(format!("Sending request: {:?}", req));
        let start_time = time::Instant::now();
        let response = sender.send_request(req).await?;
        runtimes.push(start_time.elapsed().as_secs_f64());
        handler.abort();

        Ok(ProxyRuntimes {
            inner: response,
            runtimes,
        })
    }

    async fn send_without_tls<B>(
        &mut self,
        req: Request<B>,
        stream: TcpStream,
        mut runtimes: Vec<f64>,
    ) -> anyhow::Result<ProxyRuntimes<Response<Incoming>>>
    where
        B: Body + 'static + Debug + Send,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let start_time = time::Instant::now();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = handshake(io).await?;
        runtimes.push(start_time.elapsed().as_secs_f64());

        let host = self.host();
        let handler = tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                #[cfg(feature = "log")]
                if log::max_level().eq(&log::LevelFilter::Trace) {
                    log::error!("{}: Connection error: {}", host, err);
                }
            }
        });

        self.log_trace(format!("Sending request: {:?}", req));
        let start_time = time::Instant::now();
        let response = sender.send_request(req).await?;
        runtimes.push(start_time.elapsed().as_secs_f64());
        handler.abort();

        Ok(ProxyRuntimes {
            inner: response,
            runtimes,
        })
    }

    /// Logs a trace message.
    ///
    /// # Arguments
    ///
    /// * `msg`: The message to log.
    fn log_trace<S>(&self, msg: S)
    where
        S: Display,
    {
        #[cfg(feature = "log")]
        log::trace!("{}: {}", self.host(), msg);
    }

    /// Logs an error message.
    ///
    /// # Arguments
    ///
    /// * `msg`: The message to log as an error.
    fn log_error<S>(&self, msg: S)
    where
        S: Display,
    {
        #[cfg(feature = "log")]
        if log::max_level().eq(&log::LevelFilter::Trace) {
            log::error!("{}: {}", self.host(), msg);
        }
    }
}

impl ProxyClient for Proxy {
    fn host(&self) -> Cow<'static, str> {
        self.as_text()
    }
}
