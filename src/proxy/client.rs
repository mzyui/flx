use std::{
    borrow::Cow,
    fmt::{Debug, Display},
    time::Duration,
};

use anyhow::Context;
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

/// How long a background connection task is allowed to keep running after the
/// response headers arrived, so the body can still be streamed by the caller.
///
/// Aborting the task immediately (the previous behaviour) truncated in-flight
/// bodies and left the socket to be closed by the OS; letting the connection
/// future finish on its own is the graceful path, and the linger caps the
/// worst case so a stalled peer cannot leak the task forever.
const CONNECTION_LINGER: Duration = Duration::from_secs(30);

/// Process-wide TLS connector.
///
/// Building one loads the system root certificate store, so constructing it
/// per request (the previous behaviour) repeated that cost for every single
/// proxy check. The configuration never varies, so one instance is enough.
static TLS_CONNECTOR: std::sync::LazyLock<anyhow::Result<tokio_native_tls::TlsConnector>> =
    std::sync::LazyLock::new(|| {
        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .context("failed to build TLS connector")?;
        Ok(tokio_native_tls::TlsConnector::from(connector))
    });

/// Returns the shared TLS connector, cloning the cheap handle.
fn tls_connector() -> anyhow::Result<tokio_native_tls::TlsConnector> {
    match &*TLS_CONNECTOR {
        Ok(connector) => Ok(connector.clone()),
        Err(e) => Err(anyhow::anyhow!("TLS connector unavailable: {:#}", e)),
    }
}

/// Drives a hyper connection to completion in the background.
///
/// The task ends on its own when the connection closes, or after
/// `linger` if the peer never does.
fn spawn_connection_driver<F, E>(conn: F, host: Cow<'static, str>, linger: Duration)
where
    F: std::future::Future<Output = Result<(), E>> + Send + 'static,
    E: Display + Send + 'static,
{
    tokio::task::spawn(async move {
        match time::timeout(linger, conn).await {
            Ok(Ok(())) => {}
            Ok(Err(_err)) => {
                #[cfg(feature = "log")]
                if log::max_level().eq(&log::LevelFilter::Trace) {
                    log::error!("{}: Connection error: {}", host, _err);
                }
            }
            Err(_elapsed) => {
                #[cfg(feature = "log")]
                if log::max_level().eq(&log::LevelFilter::Trace) {
                    log::trace!("{}: Connection closed after linger timeout", host);
                }
            }
        }
        let _ = host;
    });
}

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
        let tcp_stream = time::timeout(timeout, TcpStream::connect(host.to_string()))
            .await
            .with_context(|| format!("timed out connecting to {} after {:?}", host, timeout))?
            .with_context(|| format!("failed to connect to {}", host))?;
        // Measured *after* the await: sampling before it recorded ~0s and made
        // every latency statistic meaningless.
        let elapsed_time = start_time.elapsed();
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
            negotiator
                .negotiate(&mut stream, &mut runtimes, &proxy_host, req.uri())
                .await
                .with_context(|| format!("failed to negotiate with proxy {}", proxy_host))?;
            use_tls = negotiator.with_tls();
        }

        if use_tls || req.uri().scheme_str().unwrap_or("") == "https" {
            time::timeout(timeout, self.send_with_tls(req, stream, runtimes))
                .await
                .context("timed out sending request over TLS")?
        } else {
            time::timeout(timeout, self.send_without_tls(req, stream, runtimes))
                .await
                .context("timed out sending request")?
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

        let connector = tls_connector()?;

        let host = self.host();
        let sni_host = host
            .split(':')
            .next()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| anyhow::anyhow!("proxy host `{}` has no hostname part", host))?;
        let tls_stream = connector
            .connect(sni_host, stream)
            .await
            .with_context(|| format!("TLS handshake with {} failed", host))?;
        runtimes.push(start_time.elapsed().as_secs_f64());
        self.log_trace("TLS connection established successfully");

        let start_time = time::Instant::now();
        let io = TokioIo::new(tls_stream);
        let (mut sender, conn) = handshake(io)
            .await
            .context("HTTP/1 handshake over TLS failed")?;
        runtimes.push(start_time.elapsed().as_secs_f64());

        let host = self.host();
        spawn_connection_driver(conn, host, CONNECTION_LINGER);

        self.log_trace(format!("Sending request: {:?}", req));
        let start_time = time::Instant::now();
        let response = sender
            .send_request(req)
            .await
            .context("failed to send request over TLS connection")?;
        runtimes.push(start_time.elapsed().as_secs_f64());

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
        let (mut sender, conn) = handshake(io).await.context("HTTP/1 handshake failed")?;
        runtimes.push(start_time.elapsed().as_secs_f64());

        let host = self.host();
        spawn_connection_driver(conn, host, CONNECTION_LINGER);

        self.log_trace(format!("Sending request: {:?}", req));
        let start_time = time::Instant::now();
        let response = sender
            .send_request(req)
            .await
            .context("failed to send request to proxy")?;
        runtimes.push(start_time.elapsed().as_secs_f64());

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
