use std::{
    error::Error,
    fmt::{Debug, Display},
    sync::Arc,
    time::Duration,
};

use fake::{faker::internet::en::UserAgent, Fake};
use http_body_util::{BodyExt, Empty};
use hyper::{
    body::{Body, Bytes, Incoming},
    client::conn::http1::handshake,
    header::USER_AGENT,
    Request, Response,
};
use hyper_util::rt::TokioIo;
use native_tls::TlsConnector;
use tokio::{
    net::TcpStream,
    time::{self, timeout},
};

use crate::{
    negotiators::{HttpNegotiator, NegotiatorTrait},
    proxy::models::{Anonymity, Protocol, Proxy},
};

static HTTP_JUDGES: [&str; 10] = [
    "http://azenv.net/",
    "http://httpheader.net/azenv.php",
    "http://httpbin.org/get?show_env",
    "http://mojeip.net.pl/asdfa/azenv.php",
    "http://proxyjudge.us",
    "http://pascal.hoez.free.fr/azenv.php",
    "http://www.9ravens.com/env.cgi",
    "http://www3.wind.ne.jp/hassii/env.cgi",
    "http://shinh.org/env.cgi",
    "http://www2t.biglobe.ne.jp/~take52/test/env.cgi",
];
static HTTPS_JUDGES: [&str; 4] = [
    "https://httpbin.org/get?show_env",
    "https://www.proxyjudge.info",
    "https://www.proxy-listen.de/azenv.php",
    "https://httpheader.net/azenv.php",
];
static SMTP_JUDGES: [&str; 2] = ["smtp://smtp.gmail.com", "smtp://aspmx.l.google.com"];

/// Represents a client that connects to a proxy server.
pub struct ProxyClient {
    pub proxy: Proxy, // The proxy configuration for the connection.
    max_attempts: usize,
    timeout: u64,
}

impl ProxyClient {
    pub async fn try_http(&mut self) -> anyhow::Result<Option<Anonymity>> {
        for (attempt, judge) in HTTP_JUDGES.into_iter().cycle().enumerate() {
            let ua = UserAgent().fake::<&str>();
            let req = Request::builder()
                .uri(judge)
                .header(USER_AGENT, ua)
                .body(Empty::<Bytes>::new())?;

            let result = timeout(
                Duration::from_secs(self.timeout),
                self.send_request(req, Some(HttpNegotiator)),
            )
            .await;

            if let Ok(Ok(response)) = result {
                if !response.status().is_success() {
                    return Ok(None);
                }
                let mut content = String::new();
                for (k, v) in response.headers() {
                    content.push_str(k.as_str());
                    content.push_str(": ");
                    content.push_str(v.to_str()?);
                    content.push('\n');
                }
                content.push_str("\n\n");
                if let Ok(bytes) = response.collect().await.map(|body| body.to_bytes()) {
                    let body = String::from_utf8_lossy(&bytes);
                    content.push_str(&body);
                }
                println!("{}", content);
            }

            if attempt + 1 >= self.max_attempts {
                break;
            }
        }
        Ok(None)
    }

    pub async fn check_all(&mut self) {
        while let Some(proxytype) = self.proxy.types.pop() {
            match proxytype.protocol {
                Protocol::Http(_) => {
                    self.try_http().await;
                }
                Protocol::Https => {}
                Protocol::Socks4 => {}
                Protocol::Socks5 => {}
                Protocol::Connect(_) => {}
                _ => {}
            }
        }
    }
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
        Self {
            proxy,
            max_attempts: 1,
            timeout: 3,
        }
    }

    pub fn set_max_attempts(&mut self, max_attempts: usize) {
        self.max_attempts = max_attempts;
    }

    pub fn set_timeout(&mut self, timeout: u64) {
        self.timeout = timeout;
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
        negotiator: Option<N>,
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
