use std::{
    borrow::Cow,
    fmt::{Debug, Display},
    sync::{Arc, LazyLock},
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

use crate::{
    negotiators::NegotiatorTrait,
    proxy::models::{Proxy, RuntimeStats},
};

const CONNECTION_LINGER: Duration = Duration::from_secs(30);

static TLS_CONNECTORS: LazyLock<[tokio_native_tls::TlsConnector; 2]> = LazyLock::new(|| {
    let build = |insecure: bool| -> tokio_native_tls::TlsConnector {
        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(insecure)
            .build()
            .expect("failed to build TLS connector");
        tokio_native_tls::TlsConnector::from(connector)
    };
    [build(false), build(true)]
});

pub(crate) fn tls_connector(insecure: bool) -> tokio_native_tls::TlsConnector {
    TLS_CONNECTORS[insecure as usize].clone()
}

pub(crate) fn spawn_connection_driver<F, E>(
    conn: F,
    host: Arc<str>,
    linger: Duration,
) -> ConnectionDriver
where
    F: std::future::Future<Output = Result<(), E>> + Send + 'static,
    E: Display + Send + 'static,
{
    let handle = tokio::task::spawn(async move {
        match time::timeout(linger, conn).await {
            Ok(Ok(())) => {}
            Ok(Err(_err)) =>
            {
                #[cfg(feature = "log")]
                if log::max_level().eq(&log::LevelFilter::Trace) {
                    log::error!("{}: Connection error: {}", host, _err);
                }
            }
            Err(_elapsed) =>
            {
                #[cfg(feature = "log")]
                if log::max_level().eq(&log::LevelFilter::Trace) {
                    log::trace!("{}: Connection closed after linger timeout", host);
                }
            }
        }
        let _ = host;
    });
    ConnectionDriver { handle }
}

#[derive(Debug)]
pub struct ConnectionDriver {
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Debug)]
pub struct ProxyRuntimes<T> {
    pub inner: T,
    pub runtimes: RuntimeStats,
    pub driver: Option<ConnectionDriver>,
}

impl<T> ProxyRuntimes<T> {
    pub fn apply(&self, proxy: &mut Proxy) {
        // The runtimes carry a single end-to-end sample recorded by the
        // validator, so recording its average folds it into the proxy's stats.
        let avg = self.runtimes.avg();
        if avg > 0.0 {
            proxy.runtimes.record(avg);
        }
    }
}

#[async_trait]
pub trait ProxyClient {
    fn host(&self) -> Cow<'_, str>;

    fn host_arc(&self) -> Arc<str> {
        Arc::from(self.host().as_ref())
    }

    async fn connect_timeout(
        &mut self,
        timeout: Duration,
    ) -> anyhow::Result<ProxyRuntimes<TcpStream>> {
        let start_time = time::Instant::now();
        self.log_trace("Starting TCP connection");

        let host = self.host();
        let tcp_stream = time::timeout(timeout, TcpStream::connect(host.as_ref()))
            .await
            .with_context(|| format!("timed out connecting to {} after {:?}", host, timeout))?
            .with_context(|| format!("failed to connect to {}", host))?;
        let elapsed_time = start_time.elapsed().as_secs_f64();
        self.log_trace(format!("Connected in {:.3}s", elapsed_time));

        Ok(ProxyRuntimes {
            inner: tcp_stream,
            runtimes: RuntimeStats::default(),
            driver: None,
        })
    }

    async fn send_request<B, N>(
        &mut self,
        req: Request<B>,
        negotiator: Option<N>,
        timeout: Duration,
        insecure: bool,
    ) -> anyhow::Result<ProxyRuntimes<Response<Incoming>>>
    where
        B: Body + 'static + Debug + Send,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        N: NegotiatorTrait + Sync + Send,
    {
        // Single end-to-end deadline shared across connect, negotiate, and send
        // so `--timeout N` bounds the whole request, not each phase separately
        // (which previously allowed up to 3×N).
        let deadline = time::Instant::now() + timeout;

        let remaining = deadline
            .checked_duration_since(time::Instant::now())
            .context("proxy request timed out before TCP connect")?;
        let tcp = self.connect_timeout(remaining).await?;
        let mut stream = tcp.inner;

        let mut use_tls = false;

        if let Some(negotiator) = negotiator {
            let proxy_host = self.host();
            let remaining = deadline
                .checked_duration_since(time::Instant::now())
                .with_context(|| format!("proxy negotiation with {} timed out", proxy_host))?;
            time::timeout(
                remaining,
                negotiator.negotiate(&mut stream, &proxy_host, req.uri()),
            )
            .await
            .with_context(|| format!("proxy negotiation with {} timed out", proxy_host))?
            .with_context(|| format!("failed to negotiate with proxy {}", proxy_host))?;
            use_tls = negotiator.with_tls();
        }

        let remaining = deadline
            .checked_duration_since(time::Instant::now())
            .context("proxy request timed out before send")?;
        if use_tls || req.uri().scheme_str().unwrap_or("") == "https" {
            time::timeout(
                remaining,
                self.send_via_conn(
                    req,
                    stream,
                    SendOptions {
                        tls: true,
                        insecure,
                    },
                ),
            )
            .await
            .context("timed out sending request over TLS")?
        } else {
            time::timeout(
                remaining,
                self.send_via_conn(
                    req,
                    stream,
                    SendOptions {
                        tls: false,
                        insecure,
                    },
                ),
            )
            .await
            .context("timed out sending request")?
        }
    }

    async fn send_via_conn<B>(
        &mut self,
        req: Request<B>,
        stream: TcpStream,
        opts: SendOptions,
    ) -> anyhow::Result<ProxyRuntimes<Response<Incoming>>>
    where
        B: Body + 'static + Debug + Send,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let host = self.host();

        if opts.tls {
            self.log_trace("Starting TLS connection");

            let connector = tls_connector(opts.insecure);
            let sni_host = req
                .uri()
                .host()
                .filter(|host| !host.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("request URI `{}` has no target hostname", req.uri())
                })?;
            let tls_stream = connector
                .connect(sni_host, stream)
                .await
                .with_context(|| format!("TLS handshake with {} failed", host))?;
            self.log_trace("TLS connection established successfully");

            let io = TokioIo::new(tls_stream);
            let (mut sender, conn) = handshake(io)
                .await
                .context("HTTP/1 handshake over TLS failed")?;
            let driver = spawn_connection_driver(conn, self.host_arc(), CONNECTION_LINGER);

            self.log_trace(format!("Sending request: {:?}", req));
            let response = sender
                .send_request(req)
                .await
                .context("failed to send request over TLS connection")?;

            return Ok(ProxyRuntimes {
                inner: response,
                runtimes: RuntimeStats::default(),
                driver: Some(driver),
            });
        }

        let io = TokioIo::new(stream);
        let (mut sender, conn) = handshake(io).await.context("HTTP/1 handshake failed")?;
        let driver = spawn_connection_driver(conn, self.host_arc(), CONNECTION_LINGER);

        self.log_trace(format!("Sending request: {:?}", req));
        let response = sender
            .send_request(req)
            .await
            .context("failed to send request to proxy")?;

        Ok(ProxyRuntimes {
            inner: response,
            runtimes: RuntimeStats::default(),
            driver: Some(driver),
        })
    }

    fn log_trace<S>(&self, _msg: S)
    where
        S: Display,
    {
        #[cfg(feature = "log")]
        log::trace!("{}: {}", self.host(), _msg);
    }

    fn log_error<S>(&self, _msg: S)
    where
        S: Display,
    {
        #[cfg(feature = "log")]
        if log::max_level().eq(&log::LevelFilter::Trace) {
            log::error!("{}: {}", self.host(), _msg);
        }
    }
}

#[derive(Clone, Copy)]
pub struct SendOptions {
    tls: bool,
    insecure: bool,
}

impl ProxyClient for Proxy {
    fn host(&self) -> Cow<'_, str> {
        // `text` is a precomputed `ip:port` Arc<str> (see Proxy::new), so the
        // borrowed form avoids a `String` allocation on every call.
        Cow::Borrowed(self.as_text())
    }

    fn host_arc(&self) -> Arc<str> {
        // Clone the precomputed endpoint instead of copying its bytes: the
        // background connection driver gets an `Arc` without re-allocating.
        Arc::clone(&self.text)
    }
}
