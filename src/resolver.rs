use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU16, Ordering},
    time::{Duration, Instant, SystemTime},
};

use anyhow::Context;
use futures_util::{stream::FuturesUnordered, FutureExt, StreamExt};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tokio::sync::OnceCell;
use tokio::time;

static HTTP_IP_ENDPOINTS: [&str; 3] = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
];

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IP_BODY_BYTES: usize = 64;

// Bounds DNS plus HTTPS fallback within a fixed budget.
const MY_IP_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

const PUBLIC_IP_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// DNS sources for public-IP discovery: (server, domain, qtype).
///
/// `whoami.akamai.net` answers A with the requester's address; Google's
/// `o-o.myaddr.l.google.com` answers TXT with it. Both are queried directly
/// so no system resolver is involved.
const DNS_IP_SOURCES: [(Ipv4Addr, &str, u16); 2] = [
    (Ipv4Addr::new(8, 8, 8, 8), "whoami.akamai.net", DNS_TYPE_A),
    (
        Ipv4Addr::new(216, 239, 32, 10),
        "o-o.myaddr.l.google.com",
        DNS_TYPE_TXT,
    ),
];
const DNS_PORT: u16 = 53;
const DNS_QUERY_BUFFER_LEN: usize = DNS_HEADER_LEN + DNS_MAX_NAME_LEN + DNS_QUESTION_TAIL_LEN;
const DNS_RESPONSE_BUFFER_LEN: usize = 512;
const DNS_HEADER_LEN: usize = 12;
const DNS_QUESTION_TAIL_LEN: usize = 4;
const DNS_ANSWER_FIXED_LEN: usize = 10;
const DNS_QUERY_FLAGS: u16 = 0x0100; // RD (QR must be 0 in a query)
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_TXT: u16 = 16;
const DNS_CLASS_IN: u16 = 1;
const DNS_FLAG_QR: u16 = 0x8000;
const DNS_FLAG_TC: u16 = 0x0200;
const DNS_RCODE_MASK: u16 = 0x000F;
const DNS_MAX_NAME_LEN: usize = 255;
const DNS_MAX_LABEL_LEN: usize = 63;

fn public_ip_cache_path() -> Option<PathBuf> {
    let mut path = crate::geolookup::data_dir().ok()?;
    path.push("public-ip");
    Some(path)
}

async fn load_cached_public_ip(path: &Path) -> Option<String> {
    let modified = tokio::fs::metadata(path).await.ok()?.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?;
    if age > PUBLIC_IP_CACHE_TTL {
        return None;
    }
    let body = tokio::fs::read_to_string(path).await.ok()?;
    let ip = body.trim();
    if ip.parse::<IpAddr>().is_ok() {
        Some(ip.to_string())
    } else {
        None
    }
}

async fn store_public_ip(path: &Path, ip: &str) {
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("public-ip");
    let tmp = path.with_file_name(format!(".{name}.tmp-{}", std::process::id()));
    if tokio::fs::write(&tmp, format!("{ip}\n")).await.is_err() {
        return;
    }
    if tokio::fs::rename(&tmp, path).await.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
}

fn parse_ip_body(body: &[u8]) -> anyhow::Result<String> {
    if body.len() > MAX_IP_BODY_BYTES {
        anyhow::bail!("public-IP response exceeds {MAX_IP_BODY_BYTES} bytes");
    }
    let text = std::str::from_utf8(body).context("public-IP response is not valid UTF-8")?;
    let ip: IpAddr = text
        .trim()
        .parse()
        .with_context(|| format!("endpoint did not return a valid IP: {text:?}"))?;
    Ok(ip.to_string())
}

async fn fetch_ip_endpoint(
    client: Client<crate::proxy::client::HttpsConnector, Empty<Bytes>>,
    endpoint: &'static str,
    deadline: time::Instant,
) -> anyhow::Result<String> {
    let response = time::timeout_at(deadline, client.get(endpoint.parse()?))
        .await
        .with_context(|| format!("request to {endpoint} timed out"))?
        .with_context(|| format!("request to {endpoint} failed"))?;
    if !response.status().is_success() {
        anyhow::bail!("{endpoint} returned status {}", response.status());
    }

    let mut body = response.into_body();
    let mut bytes = Vec::with_capacity(32);
    while let Some(frame) = time::timeout_at(deadline, body.frame())
        .await
        .with_context(|| format!("body from {endpoint} timed out"))?
    {
        let chunk = frame
            .with_context(|| format!("body from {endpoint} was interrupted"))?
            .into_data()
            .unwrap_or_default();
        if bytes.len().saturating_add(chunk.len()) > MAX_IP_BODY_BYTES {
            anyhow::bail!("{endpoint} response exceeds {MAX_IP_BODY_BYTES} bytes");
        }
        bytes.extend_from_slice(&chunk);
    }
    parse_ip_body(&bytes).with_context(|| format!("invalid response from {endpoint}"))
}

/// Resolves the public IP via DNS, racing every [`DNS_IP_SOURCES`] entry.
///
/// No sticky kill-switch: a transient failure only fails this call, the next
/// one retries all sources fresh.
async fn my_ip_via_dns() -> anyhow::Result<String> {
    let mut pending = DNS_IP_SOURCES
        .into_iter()
        .map(|(server, domain, qtype)| dns_ip_lookup(server, domain, qtype))
        .collect::<FuturesUnordered<_>>();
    let mut errors = Vec::new();
    while let Some(result) = pending.next().await {
        match result {
            Ok(ip) => return Ok(ip),
            Err(error) => errors.push(format!("{error:#}")),
        }
    }
    anyhow::bail!("all DNS public-IP sources failed: {}", errors.join("; "))
}

static DNS_QUERY_ID: AtomicU16 = AtomicU16::new(0);

fn next_dns_query_id() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|elapsed| elapsed.subsec_nanos() as u16)
        .unwrap_or(0);
    DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed) ^ nanos
}

async fn dns_ip_lookup(server: Ipv4Addr, domain: &str, qtype: u16) -> anyhow::Result<String> {
    let query_id = next_dns_query_id();
    let mut query = [0u8; DNS_QUERY_BUFFER_LEN];
    let query_len = build_dns_query(domain, qtype, query_id, &mut query)?;

    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("failed to bind UDP socket for DNS lookup")?;
    socket
        .send_to(&query[..query_len], SocketAddr::from((server, DNS_PORT)))
        .await
        .context("failed to send DNS query")?;

    let mut response = [0u8; DNS_RESPONSE_BUFFER_LEN];
    let response_len = time::timeout(LOOKUP_TIMEOUT, socket.recv(&mut response))
        .await
        .context("DNS lookup timed out")?
        .context("DNS recv failed")?;
    let message = &response[..response_len];
    match qtype {
        DNS_TYPE_A => parse_dns_a_response(message, query_id).map(|ip| ip.to_string()),
        DNS_TYPE_TXT => parse_dns_txt_response(message, query_id),
        other => anyhow::bail!("unsupported DNS query type {other} for `{domain}`"),
    }
    .with_context(|| format!("invalid DNS response for `{domain}`"))
}

fn build_dns_query(
    domain: &str,
    qtype: u16,
    query_id: u16,
    out: &mut [u8; DNS_QUERY_BUFFER_LEN],
) -> anyhow::Result<usize> {
    out[..2].copy_from_slice(&query_id.to_be_bytes());
    out[2..4].copy_from_slice(&DNS_QUERY_FLAGS.to_be_bytes());
    out[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT

    let mut len = DNS_HEADER_LEN;
    let mut labels = 0usize;
    for label in domain.split('.') {
        let label = label.as_bytes();
        if label.is_empty() {
            anyhow::bail!("empty DNS label in `{domain}`");
        }
        if label.len() > DNS_MAX_LABEL_LEN {
            anyhow::bail!("DNS label exceeds {DNS_MAX_LABEL_LEN} bytes in `{domain}`");
        }
        let end = len + 1 + label.len();
        // Reserve the trailing root label plus TYPE/CLASS, not just the tail.
        if end + 1 + DNS_QUESTION_TAIL_LEN > out.len() {
            anyhow::bail!("DNS name `{domain}` exceeds the {DNS_MAX_NAME_LEN}-byte wire limit");
        }
        out[len] = label.len() as u8;
        out[len + 1..end].copy_from_slice(label);
        len = end;
        labels += 1;
    }
    if labels == 0 {
        anyhow::bail!("empty DNS name");
    }
    out[len] = 0;
    len += 1;
    out[len..len + 2].copy_from_slice(&qtype.to_be_bytes());
    out[len + 2..len + 4].copy_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(len + DNS_QUESTION_TAIL_LEN)
}

// Reads only A records; avoids AAAA-query failure modes.
fn parse_dns_a_response(message: &[u8], query_id: u16) -> anyhow::Result<Ipv4Addr> {
    if message.len() < DNS_HEADER_LEN {
        anyhow::bail!("DNS response is shorter than its header");
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    if id != query_id {
        anyhow::bail!("DNS response id {id} does not match query id {query_id}");
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & DNS_FLAG_QR == 0 {
        anyhow::bail!("DNS reply is not a response");
    }
    if flags & DNS_FLAG_TC != 0 {
        anyhow::bail!("DNS response was truncated");
    }
    let rcode = flags & DNS_RCODE_MASK;
    if rcode != 0 {
        anyhow::bail!("DNS server returned rcode {rcode}");
    }
    let question_count = u16::from_be_bytes([message[4], message[5]]);
    let answer_count = u16::from_be_bytes([message[6], message[7]]);

    let mut offset = DNS_HEADER_LEN;
    for _ in 0..question_count {
        offset = skip_dns_name(message, offset).context("malformed name in question")?;
        offset += DNS_QUESTION_TAIL_LEN;
        if offset > message.len() {
            anyhow::bail!("question section overruns the response");
        }
    }
    for _ in 0..answer_count {
        offset = skip_dns_name(message, offset).context("malformed name in answer")?;
        let Some(record) = message.get(offset..offset + DNS_ANSWER_FIXED_LEN) else {
            anyhow::bail!("answer header overruns the response");
        };
        let record_type = u16::from_be_bytes([record[0], record[1]]);
        let rdlength = u16::from_be_bytes([record[8], record[9]]) as usize;
        let rdata = offset + DNS_ANSWER_FIXED_LEN;
        let rdata_end = rdata + rdlength;
        if rdata_end > message.len() {
            anyhow::bail!("answer record overruns the response");
        }
        if record_type == DNS_TYPE_A && rdlength == 4 {
            return Ok(Ipv4Addr::new(
                message[rdata],
                message[rdata + 1],
                message[rdata + 2],
                message[rdata + 3],
            ));
        }
        offset = rdata_end;
    }
    anyhow::bail!("DNS response carried no A record")
}

fn skip_dns_name(message: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = *message.get(offset)? as usize;
        if length & 0xC0 == 0xC0 {
            return offset.checked_add(2);
        }
        if length == 0 {
            return Some(offset + 1);
        }
        offset += 1 + length;
    }
}

/// Validates the header and returns the answer section offset plus count.
fn answers_offset(message: &[u8], query_id: u16) -> anyhow::Result<(usize, u16)> {
    if message.len() < DNS_HEADER_LEN {
        anyhow::bail!("DNS response is shorter than its header");
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    if id != query_id {
        anyhow::bail!("DNS response id {id} does not match query id {query_id}");
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & DNS_FLAG_QR == 0 {
        anyhow::bail!("DNS reply is not a response");
    }
    if flags & DNS_FLAG_TC != 0 {
        anyhow::bail!("DNS response was truncated");
    }
    let rcode = flags & DNS_RCODE_MASK;
    if rcode != 0 {
        anyhow::bail!("DNS server returned rcode {rcode}");
    }
    let question_count = u16::from_be_bytes([message[4], message[5]]);
    let answer_count = u16::from_be_bytes([message[6], message[7]]);

    let mut offset = DNS_HEADER_LEN;
    for _ in 0..question_count {
        offset = skip_dns_name(message, offset).context("malformed name in question")?;
        offset += DNS_QUESTION_TAIL_LEN;
        if offset > message.len() {
            anyhow::bail!("question section overruns the response");
        }
    }
    Ok((offset, answer_count))
}

/// Reads the first TXT record as the public IP (Google's `o-o.myaddr.l.google.com`).
fn parse_dns_txt_response(message: &[u8], query_id: u16) -> anyhow::Result<String> {
    let (mut offset, answer_count) = answers_offset(message, query_id)?;
    for _ in 0..answer_count {
        offset = skip_dns_name(message, offset).context("malformed name in answer")?;
        let Some(record) = message.get(offset..offset + DNS_ANSWER_FIXED_LEN) else {
            anyhow::bail!("answer header overruns the response");
        };
        let record_type = u16::from_be_bytes([record[0], record[1]]);
        let rdlength = u16::from_be_bytes([record[8], record[9]]) as usize;
        let rdata = offset + DNS_ANSWER_FIXED_LEN;
        let rdata_end = rdata + rdlength;
        if rdata_end > message.len() {
            anyhow::bail!("answer record overruns the response");
        }
        if record_type == DNS_TYPE_TXT && rdlength >= 1 {
            let text_len = message[rdata] as usize;
            let text_end = rdata + 1 + text_len;
            if text_end <= rdata_end {
                let text = std::str::from_utf8(&message[rdata + 1..text_end])
                    .context("TXT record is not valid UTF-8")?;
                let ip: std::net::IpAddr = text
                    .trim()
                    .parse()
                    .with_context(|| format!("TXT record is not a valid IP: {text:?}"))?;
                return Ok(ip.to_string());
            }
        }
        offset = rdata_end;
    }
    anyhow::bail!("DNS response carried no TXT record")
}

async fn my_ip_via_https() -> anyhow::Result<String> {
    let client = Client::builder(TokioExecutor::new())
        .build::<_, Empty<Bytes>>(crate::proxy::client::https_connector());
    let deadline = time::Instant::now() + LOOKUP_TIMEOUT;
    let mut requests = HTTP_IP_ENDPOINTS
        .into_iter()
        .map(|endpoint| fetch_ip_endpoint(client.clone(), endpoint, deadline))
        .collect::<FuturesUnordered<_>>();
    let mut errors = Vec::new();
    while let Some(result) = requests.next().await {
        match result {
            Ok(ip) => return Ok(ip),
            Err(error) => errors.push(format!("{error:#}")),
        }
    }
    anyhow::bail!("all HTTPS IP endpoints failed: {}", errors.join("; "))
}

static MY_IP_CACHE: OnceCell<String> = OnceCell::const_new();

/// Returns the cached public IP when [`my_ip`] already resolved it.
pub fn cached_my_ip() -> Option<String> {
    MY_IP_CACHE.get().cloned()
}

/// Resolves the public IP, caching successes for the process lifetime.
///
/// Races DNS plus HTTPS endpoints within a fixed budget.
///
/// # Errors
///
/// Returns an error when every source fails or the lookup times out.
pub async fn my_ip() -> anyhow::Result<String> {
    // Caches successes only; retries transient failures.
    MY_IP_CACHE
        .get_or_try_init(|| async {
            time::timeout(MY_IP_LOOKUP_TIMEOUT, resolve_public_ip())
                .await
                .context("public-IP lookup timed out")?
        })
        .await
        .cloned()
}

async fn resolve_public_ip() -> anyhow::Result<String> {
    let start_time = Instant::now();

    // Races live sources; consults disk cache only as last resort.
    let live = race_live_ip_sources().await;
    let ip = match live {
        Ok(ip) => {
            #[cfg(feature = "log")]
            log::debug!(
                "My IP: {} (resolved via live sources in {:?})",
                ip,
                start_time.elapsed()
            );
            ip
        }
        Err(live_error) => {
            if let Some(path) = public_ip_cache_path() {
                if let Some(cached) = load_cached_public_ip(&path).await {
                    #[cfg(feature = "log")]
                    log::warn!(
                        "live public-IP lookup failed ({live_error:#}); using cached IP {cached} as last resort"
                    );
                    #[cfg(not(feature = "log"))]
                    let _ = &live_error;
                    return Ok(cached);
                }
            }
            return Err(live_error
                .context("all live public-IP sources failed and no cached IP is available"));
        }
    };

    if let Some(path) = public_ip_cache_path() {
        store_public_ip(&path, &ip).await;
    }
    let _ = start_time;
    Ok(ip)
}

async fn race_live_ip_sources() -> anyhow::Result<String> {
    let mut pending = FuturesUnordered::new();
    pending.push(async { my_ip_via_dns().await }.boxed());
    pending.push(async { my_ip_via_https().await }.boxed());
    let mut errors = Vec::new();
    while let Some(result) = pending.next().await {
        match result {
            Ok(ip) => return Ok(ip),
            Err(error) => errors.push(format!("{error:#}")),
        }
    }
    anyhow::bail!("all live public-IP sources failed: {}", errors.join("; "))
}

#[cfg(test)]
mod tests {
    use super::{
        build_dns_query, load_cached_public_ip, parse_dns_a_response, parse_dns_txt_response,
        parse_ip_body, skip_dns_name, store_public_ip, Ipv4Addr, DNS_CLASS_IN, DNS_FLAG_QR,
        DNS_HEADER_LEN, DNS_QUERY_BUFFER_LEN, DNS_QUERY_FLAGS, DNS_QUESTION_TAIL_LEN, DNS_TYPE_A,
        DNS_TYPE_TXT, MAX_IP_BODY_BYTES,
    };
    use std::{
        fs::File,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, SystemTime},
    };

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn temp_cache_path() -> PathBuf {
        let unique = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "flx_public_ip_test_{}_{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn public_ip_body_is_bounded_and_validated() {
        assert_eq!(parse_ip_body(b"203.0.113.7\n").unwrap(), "203.0.113.7");
        assert!(parse_ip_body(&[b'x'; MAX_IP_BODY_BYTES + 1]).is_err());
        assert!(parse_ip_body(b"not-an-ip").is_err());
    }

    #[tokio::test]
    async fn public_ip_cache_round_trips_fresh_ip() {
        let path = temp_cache_path();
        store_public_ip(&path, "203.0.113.7").await;
        assert_eq!(
            load_cached_public_ip(&path).await.as_deref(),
            Some("203.0.113.7")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn expired_public_ip_cache_is_ignored() {
        let path = temp_cache_path();
        store_public_ip(&path, "203.0.113.7").await;
        let file = File::open(&path).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(25 * 60 * 60))
            .unwrap();
        drop(file);
        assert!(load_cached_public_ip(&path).await.is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn corrupt_public_ip_cache_is_ignored() {
        let path = temp_cache_path();
        tokio::fs::write(&path, "not-an-ip").await.unwrap();
        assert!(load_cached_public_ip(&path).await.is_none());
        let _ = std::fs::remove_file(&path);
    }

    fn sample_query_id() -> u16 {
        0x00AA
    }

    fn sample_question_name() -> Vec<u8> {
        let mut query = [0u8; DNS_QUERY_BUFFER_LEN];
        let len = build_dns_query(
            "whoami.akamai.net",
            DNS_TYPE_A,
            sample_query_id(),
            &mut query,
        )
        .unwrap();
        query[DNS_HEADER_LEN..len - DNS_QUESTION_TAIL_LEN].to_vec()
    }

    fn sample_a_response() -> Vec<u8> {
        let name = sample_question_name();
        let mut message = Vec::new();
        message.extend_from_slice(&sample_query_id().to_be_bytes());
        message.extend_from_slice(&0x8180u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&[0, 0, 0, 0]);
        message.extend_from_slice(&name);
        message.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        message.extend_from_slice(&[0xC0, 0x0C]);
        message.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        message.extend_from_slice(&[0, 0, 0, 42]);
        message.extend_from_slice(&4u16.to_be_bytes());
        message.extend_from_slice(&[192, 0, 2, 7]);
        message
    }

    #[test]
    fn a_query_encodes_name_and_question() {
        // Regression: QR must be 0 in a query; only RD is set.
        assert_eq!(DNS_QUERY_FLAGS, 0x0100);
        assert_eq!(DNS_QUERY_FLAGS & DNS_FLAG_QR, 0);
        let mut buffer = [0u8; DNS_QUERY_BUFFER_LEN];
        let len = build_dns_query("whoami.akamai.net", DNS_TYPE_A, 0x1234, &mut buffer).unwrap();
        assert_eq!(&buffer[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(&buffer[2..4], &DNS_QUERY_FLAGS.to_be_bytes());
        assert_eq!(&buffer[4..6], &1u16.to_be_bytes());
        let expected_name = [
            6, b'w', b'h', b'o', b'a', b'm', b'i', 6, b'a', b'k', b'a', b'm', b'a', b'i', 3, b'n',
            b'e', b't', 0,
        ];
        assert_eq!(
            &buffer[DNS_HEADER_LEN..len - DNS_QUESTION_TAIL_LEN],
            &expected_name
        );
        let tail = &buffer[len - DNS_QUESTION_TAIL_LEN..len];
        assert_eq!(&tail[..2], &DNS_TYPE_A.to_be_bytes());
        assert_eq!(&tail[2..], &DNS_CLASS_IN.to_be_bytes());
    }

    #[test]
    fn txt_query_encodes_txt_type() {
        let mut buffer = [0u8; DNS_QUERY_BUFFER_LEN];
        let len =
            build_dns_query("o-o.myaddr.l.google.com", DNS_TYPE_TXT, 0x1234, &mut buffer).unwrap();
        let tail = &buffer[len - DNS_QUESTION_TAIL_LEN..len];
        assert_eq!(&tail[..2], &DNS_TYPE_TXT.to_be_bytes());
        assert_eq!(&tail[2..], &DNS_CLASS_IN.to_be_bytes());
    }

    #[test]
    fn a_query_rejects_bad_names() {
        let mut buffer = [0u8; DNS_QUERY_BUFFER_LEN];
        assert!(build_dns_query("", DNS_TYPE_A, 1, &mut buffer).is_err());
        assert!(build_dns_query("a..b", DNS_TYPE_A, 1, &mut buffer).is_err());
        let long_label = "a".repeat(64);
        assert!(build_dns_query(&long_label, DNS_TYPE_A, 1, &mut buffer).is_err());
        let long_name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63)
        );
        assert!(build_dns_query(&long_name, DNS_TYPE_A, 1, &mut buffer).is_err());
    }

    #[test]
    fn a_query_rejects_a_name_exactly_filling_the_buffer() {
        let mut buffer = [0u8; DNS_QUERY_BUFFER_LEN];
        // 63+63+63+62 payload bytes land the last label end at 267, the old
        // guard's off-by-one boundary that then wrote past the buffer.
        let name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        assert!(build_dns_query(&name, DNS_TYPE_A, 1, &mut buffer).is_err());
    }

    #[test]
    fn a_response_yields_the_first_a_record() {
        let response = sample_a_response();
        assert_eq!(
            parse_dns_a_response(&response, sample_query_id()).unwrap(),
            Ipv4Addr::new(192, 0, 2, 7)
        );
    }

    #[test]
    fn a_response_skips_non_a_answers_before_the_record() {
        let name = sample_question_name();
        let mut message = Vec::new();
        message.extend_from_slice(&sample_query_id().to_be_bytes());
        message.extend_from_slice(&0x8180u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&2u16.to_be_bytes());
        message.extend_from_slice(&[0, 0, 0, 0]);
        message.extend_from_slice(&name);
        message.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        // Skips CNAME answers carrying compressed names.
        message.extend_from_slice(&[0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 1, 0, 2, 0xC0, 0x0C]);
        message.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 10, 1, 2, 3]);
        assert_eq!(
            parse_dns_a_response(&message, sample_query_id()).unwrap(),
            Ipv4Addr::new(10, 1, 2, 3)
        );
    }

    #[test]
    fn a_response_rejections() {
        let response = sample_a_response();
        assert!(parse_dns_a_response(&response, 0x00BB).is_err());
        assert!(parse_dns_a_response(&[], 1).is_err());
        assert!(parse_dns_a_response(&[0, 1, 2], 1).is_err());

        let mut bad_rcode = response.clone();
        bad_rcode[3] = 0x83;
        assert!(parse_dns_a_response(&bad_rcode, sample_query_id()).is_err());

        let mut not_a_response = response.clone();
        not_a_response[2] = 0x01;
        assert!(parse_dns_a_response(&not_a_response, sample_query_id()).is_err());

        let name_len = sample_question_name().len();
        let truncated = response[..DNS_HEADER_LEN + name_len + 2].to_vec();
        assert!(parse_dns_a_response(&truncated, sample_query_id()).is_err());

        let mut non_a_record = response.clone();
        let answer_type = DNS_HEADER_LEN + name_len + DNS_QUESTION_TAIL_LEN + 2;
        non_a_record[answer_type + 1] = 16;
        assert!(parse_dns_a_response(&non_a_record, sample_query_id()).is_err());
    }

    #[test]
    fn txt_response_yields_the_first_txt_ip() {
        let response = sample_txt_response(b"203.0.113.7");
        assert_eq!(
            parse_dns_txt_response(&response, sample_query_id()).unwrap(),
            "203.0.113.7"
        );
    }

    #[test]
    fn txt_response_rejects_garbage() {
        assert!(
            parse_dns_txt_response(&sample_txt_response(b"not-an-ip"), sample_query_id()).is_err()
        );
        assert!(parse_dns_txt_response(&sample_a_response(), sample_query_id()).is_err());
        assert!(parse_dns_txt_response(&[], 1).is_err());
    }

    fn sample_txt_response(text: &[u8]) -> Vec<u8> {
        let name = sample_question_name();
        let mut message = Vec::new();
        message.extend_from_slice(&sample_query_id().to_be_bytes());
        message.extend_from_slice(&0x8180u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&[0, 0, 0, 0]);
        message.extend_from_slice(&name);
        message.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
        message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        message.extend_from_slice(&[0xC0, 0x0C]);
        message.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
        message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        message.extend_from_slice(&[0, 0, 0, 42]);
        message.extend_from_slice(&(1 + text.len() as u16).to_be_bytes());
        message.push(text.len() as u8);
        message.extend_from_slice(text);
        message
    }

    #[test]
    fn skip_name_handles_labels_pointers_and_root() {
        let plain = [1, b'a', 2, b'b', b'c', 0, 9];
        assert_eq!(skip_dns_name(&plain, 0), Some(6));
        assert_eq!(skip_dns_name(&plain, 5), Some(6));
        assert_eq!(skip_dns_name(&plain, 6), None);
        assert_eq!(skip_dns_name(&plain, 100), None);
        let pointer = [3, b'w', b'w', b'w', 0xC0, 0x0C];
        assert_eq!(skip_dns_name(&pointer, 0), Some(6));
    }
}
