#![allow(unused, dead_code)]

use std::time::Duration;

use async_trait::async_trait;
use fake::{faker::internet::en::UserAgent, Fake};
use http_body_util::{BodyExt, Empty};
use hyper::{
    body::{Bytes, Incoming},
    header::USER_AGENT,
    Request, Response,
};

use crate::{
    negotiators::{HttpNegotiator, HttpsNegotiator},
    proxy::{
        client::{ProxyClient, ProxyRuntimes},
        models::{Anonymity, Protocol, Proxy},
    },
    resolver::my_ip,
};

static ANON_INTEREST: [&str; 15] = [
    "X-REAL-IP",
    "X-FORWARDED-FOR",
    "X-PROXY-ID",
    "VIA",
    "FORWARDED-FOR",
    "X-FORWARDED",
    "HTTP-FORWARDED",
    "CLIENT-IP",
    "FORWARDED-FOR-IP",
    "FORWARDED_FOR",
    "X_FORWARDED FORWARDED",
    "CLIENT_IP",
    "PROXY-CONNECTION",
    "X-PROXY-CONNECTION",
    "X-IMFORWARDS",
];

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

async fn to_raw_response(response: Response<Incoming>) -> anyhow::Result<String> {
    let mut content = String::new();
    for (k, v) in response.headers() {
        content.push_str(&k.as_str().to_uppercase());
        content.push_str(": ");
        content.push_str(v.to_str()?);
        content.push('\n');
    }
    content.push_str("\n\n");
    if let Ok(bytes) = response.collect().await.map(|body| body.to_bytes()) {
        let body = String::from_utf8_lossy(&bytes);
        content.push_str(&body);
    }
    Ok(content)
}

pub async fn support_http(
    proxy: &mut Proxy,
    timeout: Duration,
    max_attempts: usize,
) -> Option<ProxyRuntimes<Protocol>> {
    let useragent = UserAgent().fake::<&str>();
    for judge_url in HTTP_JUDGES.iter().cycle().take(max_attempts) {
        if let Ok(req) = Request::get(*judge_url)
            .header(USER_AGENT, useragent)
            .body(Empty::<Bytes>::new())
        {
            if let Ok(response) = proxy.send_request(req, Some(HttpNegotiator), timeout).await {
                if let Ok(bytes) = response.inner.collect().await.map(|body| body.to_bytes()) {
                    let body = String::from_utf8_lossy(&bytes);
                    if !body.contains(useragent) {
                        continue;
                    }
                    if body.contains(&my_ip().await) {
                        return Some(ProxyRuntimes {
                            inner: Protocol::Http(Anonymity::Transparent),
                            runtimes: response.runtimes,
                        });
                    }

                    let body_uppercase = body.to_uppercase();
                    if ANON_INTEREST.iter().any(|&v| body_uppercase.contains(v))
                        || body_uppercase.contains(&proxy.ip.to_string())
                    {
                        return Some(ProxyRuntimes {
                            inner: Protocol::Http(Anonymity::Anonymous),
                            runtimes: response.runtimes,
                        });
                    }

                    return Some(ProxyRuntimes {
                        inner: Protocol::Http(Anonymity::Elite),
                        runtimes: response.runtimes,
                    });
                }
            }
        }
    }
    None
}
