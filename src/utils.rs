use std::{net::Ipv4Addr, str::FromStr};

use async_trait::async_trait;
use cached::proc_macro::cached;
use http_body_util::{BodyExt, Empty};
use hyper::{
    body::{Bytes, Incoming},
    Request, Response,
};
use hyper_tls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};

#[cached]
pub async fn my_ip() -> String {
    let client = Client::builder(TokioExecutor::new()).build(HttpsConnector::new());
    if let Ok(req) = Request::get("https://api64.ipify.org/").body(Empty::<Bytes>::new()) {
        if let Ok(response) = client.request(req).await {
            if let Ok(body) = response.collect().await {
                let data = body.to_bytes();
                let ip = String::from_utf8_lossy(&data);
                if Ipv4Addr::from_str(&ip).is_ok() {
                    return ip.to_string();
                }
            }
        }
    }
    let msg = "Failed to get public IP, please check internet connection or create an issue if necessary.";
    #[cfg(feature = "log")]
    log::warn!("{}", msg);
    #[cfg(not(feature = "log"))]
    eprintln!("Warning: {}", msg);
    std::process::exit(0)
}
