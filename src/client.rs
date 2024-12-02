use std::{
    error::Error,
    fmt::{Debug, Display},
    time::Duration,
};

use hyper::{
    body::{Body, Incoming},
    client::conn::http1::handshake,
    Request, Response,
};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};

use crate::models::Proxy;

#[derive(Debug)]
pub struct ProxyClient {
    pub proxy: Proxy,
    timer: time::Instant,
}

impl ProxyClient {
    pub fn new(proxy: Proxy, timeout: Duration) -> Self {
        let timer = time::Instant::now() + timeout;
        Self { proxy, timer }
    }

    async fn connect(&mut self) -> anyhow::Result<TcpStream> {
        let time_start = time::Instant::now();
        self.log_trace("Connecting to server");
        let result =
            time::timeout_at(self.timer, TcpStream::connect(self.proxy.as_text()))
                .await??;
        let elapsed = time_start.elapsed();
        self.log_trace(format!("Connected in {:?}", elapsed));
        self.proxy.runtimes.push(elapsed.as_secs_f64());

        Ok(result)
    }

    fn generate_connect_request(&self, host: &str) -> Vec<u8> {
        let data = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n");
        data.as_bytes().to_vec()
    }

    pub async fn send_request<B>(
        &mut self, req: Request<B>,
    ) -> anyhow::Result<Response<Incoming>>
    where
        B: Body + 'static + Debug + Send,
        B::Data: Send,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let mut stream = self.connect().await?;

        if req
            .uri()
            .scheme()
            .map(|scheme| scheme.as_str() == "https")
            .unwrap_or(false)
        {
            let host = req.uri().authority().map(|v| v.as_str()).unwrap();
            self.log_trace(format!("Sending a connection request to {}", host));

            let time_start = time::Instant::now();
            time::timeout_at(
                self.timer,
                stream.write_all(&self.generate_connect_request(host)),
            )
            .await??;
            self.proxy.runtimes.push(time_start.elapsed().as_secs_f64());

            let mut buf = [0; 1024];
            time::timeout_at(self.timer, stream.read(&mut buf)).await??;

            let mut header = [httparse::EMPTY_HEADER; 32];
            let mut response = httparse::Response::new(&mut header);
            response.parse(&buf)?;

            let code = response.code.unwrap_or_default();
            if code != 200 {
                anyhow::bail!(
                    "Got response code {} {}. Expecting 200 OK",
                    code,
                    response.reason.unwrap_or_default()
                );
            }
            self.log_trace("Connection successfully stabilized");
            self.proxy.runtimes.push(time_start.elapsed().as_secs_f64());
        }

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
        let response = time::timeout_at(self.timer, sender.send_request(req)).await??;
        self.proxy.runtimes.push(time_start.elapsed().as_secs_f64());
        handler.abort();
        Ok(response)
    }

    pub fn log_trace<S>(&self, msg: S)
    where
        S: Display,
    {
        #[cfg(feature = "log")]
        log::trace!("{}: {}", self.proxy.as_text(), msg);
    }

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
