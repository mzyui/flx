pub mod client;
pub mod models;

/*

static HTTPS_JUDGES: [&str; 4] = [
    "https://httpbin.org/get?show_env",
    "https://www.proxyjudge.info",
    "https://www.proxy-listen.de/azenv.php",
    "https://httpheader.net/azenv.php",
];
static SMTP_JUDGES: [&str; 2] = ["smtp://smtp.gmail.com", "smtp://aspmx.l.google.com"];


/// Represents a client that connects to a proxy server.
pub struct ProxyClient {
    /// The proxy configuration for the connection.
    pub proxy: Proxy,
    max_attempts: usize,
    timeout: u64,
}

impl ProxyClient {
    pub async fn try_http(&mut self) -> Option<Protocol> {
        for judge in HTTP_JUDGES.into_iter().cycle().take(self.max_attempts) {
            let ua = UserAgent().fake::<&str>();
            let req = Request::builder()
                .uri(judge)
                .header(USER_AGENT, ua)
                .body(Empty::<Bytes>::new())
                .unwrap();

            let result = timeout(
                Duration::from_secs(self.timeout),
                self.send_request(req, Some(HttpNegotiator)),
            )
            .await;

            if let Ok(Ok(response)) = result {
                if !response.status().is_success() {
                    return None;
                }

                if let Ok(content) = self.to_raw_response(response).await {
                   if content.contains(&my_ip) {
                        return Some(Protocol::Http(Anonymity::Transparent));
                    } else if ANON_INTEREST.iter().any(|&header| content.contains(header))
                        || content.contains(&self.proxy.ip.to_string())
                    {
                        return Some(Protocol::Http(Anonymity::Anonymous));
                    } else {
                        return Some(Protocol::Http(Anonymity::Elite));
                   }
                }
            }
        }
        None
    }

    pub async fn check_all(&mut self) {
        let mut proxytype = self.proxy.types.drain(..).collect::<Vec<_>>();
    }
}


*/
