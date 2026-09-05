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
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::{net::TcpStream, time};

use async_trait::async_trait;

use crate::{
    negotiators::NegotiatorTrait,
    proxy::models::{Proxy, RuntimeStats},
};

const CONNECTION_LINGER: Duration = Duration::from_secs(30);

pub(crate) type HttpsConnector =
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;
pub(crate) type TlsConnector = tokio_rustls::TlsConnector;

static TLS_CONFIGS: LazyLock<[Arc<rustls::ClientConfig>; 2]> =
    LazyLock::new(|| [build_client_config(false), build_client_config(true)]);

static TLS_CONNECTORS: LazyLock<[TlsConnector; 2]> = LazyLock::new(|| {
    let mut configs = TLS_CONFIGS.iter();
    [
        TlsConnector::from(Arc::clone(configs.next().expect("strict TLS config"))),
        TlsConnector::from(Arc::clone(configs.next().expect("insecure TLS config"))),
    ]
});

fn build_client_config(insecure: bool) -> Arc<rustls::ClientConfig> {
    let verifier: Arc<dyn ServerCertVerifier> = if insecure {
        Arc::new(AcceptAnyServerCert)
    } else {
        let roots = rustls_native_certs::load_native_certs()
            .expect("failed to load native root certificates");
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_parsable_certificates(roots);
        if root_store.is_empty() {
            // Some minimal environments ship no OS store; fall back to the
            // bundled webpki roots so HTTPS targets stay reachable.
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        rustls::client::WebPkiServerVerifier::builder_with_provider(root_store.into(), provider)
            .build()
            .expect("failed to build webpki verifier")
    };
    let config = rustls::ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();
    Arc::new(config)
}

pub(crate) fn tls_connector(insecure: bool) -> TlsConnector {
    TLS_CONNECTORS[insecure as usize].clone()
}

pub fn https_connector() -> HttpsConnector {
    https_connector_with_config(
        hyper_util::client::legacy::connect::HttpConnector::new(),
        false,
    )
}

pub(crate) fn https_connector_with_config(
    mut http: hyper_util::client::legacy::connect::HttpConnector,
    insecure: bool,
) -> HttpsConnector {
    // Disable http-only enforcement so hyper-rustls can dial HTTPS.
    http.enforce_http(false);
    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config((**tls_client_config(insecure)).clone())
        .https_or_http()
        .enable_http1()
        .wrap_connector(http)
}

pub(crate) fn tls_client_config(insecure: bool) -> &'static Arc<rustls::ClientConfig> {
    &TLS_CONFIGS[insecure as usize]
}

pub(crate) async fn tls_connect(
    host: &str,
    stream: TcpStream,
    insecure: bool,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| anyhow::anyhow!("invalid TLS server name `{host}`"))?;
    tls_connector(insecure)
        .connect(server_name, stream)
        .await
        .map_err(|err| anyhow::anyhow!("TLS handshake with {host} failed: {err}"))
}

// Skip certificate validation only via explicit insecure opt-in.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
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
        // Fold single end-to-end sample into proxy stats.
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
        // Disable Nagle to avoid buffering small handshake greetings.
        let _ = tcp_stream.set_nodelay(true);
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
        // Share one deadline across phases to bound total request time.
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

            let sni_host = req
                .uri()
                .host()
                .filter(|host| !host.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("request URI `{}` has no target hostname", req.uri())
                })?;
            let tls_stream = tls_connect(sni_host, stream, opts.insecure)
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
            self.log_response_head(&response);

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
        self.log_response_head(&response);

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

    fn log_response_head(&self, response: &Response<Incoming>) {
        let content_length = response
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("unknown");
        self.log_trace(format!(
            "Received response: {:?} {}, content-length: {}",
            response.version(),
            response.status(),
            content_length
        ));
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
        // Borrow precomputed endpoint text to avoid allocation.
        Cow::Borrowed(self.as_text())
    }

    fn host_arc(&self) -> Arc<str> {
        // Clone precomputed endpoint Arc without reallocating.
        Arc::clone(&self.text)
    }
}
