//! Cache parsed proxy rows on disk.

use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use anyhow::Context;

use crate::{
    providers::parsers::ParsedProxy,
    proxy::models::{Anonymity, Protocol},
};

const ORPHANED_TMP_MAX_AGE: Duration = Duration::from_secs(60 * 60);
// Bump on encoding or parser changes to reject stale rows.
const CACHE_MAGIC: &[u8; 8] = b"FLXPCW02";

pub struct Cache {
    dir: PathBuf,
    ttl: Duration,
    refresh: bool,
}

fn clean_orphaned_tmp(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().contains(".tmp-") {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let modified = metadata.modified().unwrap_or(SystemTime::now());
        let Ok(age) = SystemTime::now().duration_since(modified) else {
            continue;
        };
        if age > ORPHANED_TMP_MAX_AGE {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

impl Cache {
    pub fn new(ttl: Duration, refresh: bool) -> anyhow::Result<Self> {
        let mut dir = crate::geolookup::data_dir()?;
        dir.push("cache");
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create cache directory {}", dir.display()))?;
        clean_orphaned_tmp(&dir);
        Ok(Self::new_at(dir, ttl, refresh))
    }

    pub(crate) fn new_at(dir: PathBuf, ttl: Duration, refresh: bool) -> Self {
        Self { dir, ttl, refresh }
    }

    pub async fn load_rows(&self, url: &str) -> Option<Vec<ParsedProxy>> {
        if self.refresh {
            return None;
        }
        let path = self.dir.join(cache_file_name(url));
        let modified = tokio::fs::metadata(&path).await.ok()?.modified().ok()?;
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or(Duration::ZERO);
        if age > self.ttl {
            return None;
        }
        let body = tokio::fs::read(path).await.ok()?;
        let rows = decode_rows(&body)?;
        if rows.is_empty() {
            return None;
        }
        Some(rows)
    }

    pub async fn store_rows(&self, url: &str, rows: &[ParsedProxy]) {
        if rows.is_empty() {
            return;
        }
        let mut body = Vec::with_capacity(8 + 4 + rows.len() * 7);
        body.extend_from_slice(CACHE_MAGIC);
        body.extend_from_slice(&(rows.len() as u32).to_le_bytes());
        for (ip, port, protocol) in rows {
            body.extend_from_slice(&ip.octets());
            body.extend_from_slice(&port.to_le_bytes());
            match protocol {
                None => body.push(0),
                Some(Protocol::Connect(p)) => {
                    body.push(11);
                    body.extend_from_slice(&p.to_le_bytes());
                }
                Some(p) => body.push(protocol_code(Some(*p)).unwrap_or(0)),
            }
        }
        let name = cache_file_name(url);
        let path = self.dir.join(&name);
        let tmp = self.dir.join(format!(".{name}.tmp-{}", std::process::id()));
        if let Err(error) = tokio::fs::write(&tmp, &body).await {
            #[cfg(feature = "log")]
            log::debug!("failed to write cache for {url}: {error}");
            let _ = error;
            return;
        }
        if let Err(error) = tokio::fs::rename(&tmp, &path).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            #[cfg(feature = "log")]
            log::debug!("failed to install cache for {url}: {error}");
            let _ = error;
        }
    }
}

// Row layout: IP(4) + port(2 LE) + proto code(1) + optional CONNECT port(2).

fn anon_code(anonymity: Anonymity) -> u8 {
    match anonymity {
        Anonymity::Elite => 0,
        Anonymity::Transparent => 1,
        Anonymity::Anonymous => 2,
        Anonymity::Unknown => 3,
    }
}

fn anon_from_code(code: u8) -> Option<Anonymity> {
    match code {
        0 => Some(Anonymity::Elite),
        1 => Some(Anonymity::Transparent),
        2 => Some(Anonymity::Anonymous),
        3 => Some(Anonymity::Unknown),
        _ => None,
    }
}

fn protocol_code(protocol: Option<Protocol>) -> Option<u8> {
    match protocol? {
        Protocol::Http(a) => Some(1 + anon_code(a)),
        Protocol::Https(a) => Some(5 + anon_code(a)),
        Protocol::Socks4 => Some(9),
        Protocol::Socks5 => Some(10),
        Protocol::Connect(_) => Some(11),
    }
}

fn protocol_from_code(code: u8) -> Option<Protocol> {
    match code {
        1..=4 => Some(Protocol::Http(anon_from_code(code - 1)?)),
        5..=8 => Some(Protocol::Https(anon_from_code(code - 5)?)),
        9 => Some(Protocol::Socks4),
        10 => Some(Protocol::Socks5),
        _ => None,
    }
}

fn decode_rows(body: &[u8]) -> Option<Vec<ParsedProxy>> {
    if body.len() < 12 || !body.starts_with(&CACHE_MAGIC[..]) {
        return None;
    }
    let n = u32::from_le_bytes(body[8..12].try_into().ok()?) as usize;
    let mut rows = Vec::with_capacity(n);
    let mut cursor = 12;
    for _ in 0..n {
        if cursor + 7 > body.len() {
            return None;
        }
        let ip = Ipv4Addr::new(
            body[cursor],
            body[cursor + 1],
            body[cursor + 2],
            body[cursor + 3],
        );
        let port = u16::from_le_bytes([body[cursor + 4], body[cursor + 5]]);
        let code = body[cursor + 6];
        cursor += 7;
        let protocol = match code {
            0 => None,
            11 => {
                if cursor + 2 > body.len() {
                    return None;
                }
                let p = u16::from_le_bytes([body[cursor], body[cursor + 1]]);
                cursor += 2;
                Some(Protocol::Connect(p))
            }
            code => protocol_from_code(code),
        };
        rows.push((ip, port, protocol));
    }
    Some(rows)
}

fn cache_file_name(url: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in url.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::{
        cache_file_name, decode_rows, protocol_code, protocol_from_code, Cache, CACHE_MAGIC,
    };
    use crate::proxy::models::Protocol;
    use std::{
        net::Ipv4Addr,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn temp_cache(ttl: Duration, refresh: bool) -> (Cache, PathBuf) {
        let mut dir = std::env::temp_dir();
        let unique = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        dir.push(format!("flx_cache_test_{}_{unique}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.clone();
        (Cache::new_at(dir, ttl, refresh), path)
    }

    fn cleanup(dir: &PathBuf) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn load_rows_misses_when_file_absent() {
        let (cache, dir) = temp_cache(Duration::from_secs(60), false);
        assert!(cache.load_rows("http://example.com/list").await.is_none());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn store_then_load_rows_round_trips_within_ttl() {
        let (cache, dir) = temp_cache(Duration::from_secs(60), false);
        cache
            .store_rows(
                "http://example.com/list",
                &[
                    (Ipv4Addr::new(1, 2, 3, 4), 8080, None),
                    (
                        Ipv4Addr::new(5, 6, 7, 8),
                        3128,
                        Some(Protocol::Http(crate::proxy::models::Anonymity::Elite)),
                    ),
                ],
            )
            .await;
        let rows = cache.load_rows("http://example.com/list").await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], (Ipv4Addr::new(1, 2, 3, 4), 8080, None));
        assert_eq!(
            rows[1],
            (
                Ipv4Addr::new(5, 6, 7, 8),
                3128,
                Some(Protocol::Http(crate::proxy::models::Anonymity::Elite))
            )
        );
        cleanup(&dir);
    }

    #[tokio::test]
    async fn load_rows_expires_after_ttl() {
        let (cache, dir) = temp_cache(Duration::from_millis(50), false);
        cache
            .store_rows(
                "http://example.com/list",
                &[(Ipv4Addr::new(1, 2, 3, 4), 8080, None)],
            )
            .await;
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(cache.load_rows("http://example.com/list").await.is_none());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn refresh_bypasses_cache_but_keeps_store() {
        let (cache, dir) = temp_cache(Duration::from_secs(60), true);
        cache
            .store_rows(
                "http://example.com/list",
                &[(Ipv4Addr::new(1, 2, 3, 4), 8080, None)],
            )
            .await;
        assert!(cache.load_rows("http://example.com/list").await.is_none());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn empty_parses_are_never_cached() {
        let (cache, dir) = temp_cache(Duration::from_secs(60), false);
        cache.store_rows("http://example.com/list", &[]).await;
        assert!(cache.load_rows("http://example.com/list").await.is_none());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn foreign_magic_is_treated_as_miss() {
        let (cache, dir) = temp_cache(Duration::from_secs(60), false);
        let path = dir.join(cache_file_name("http://example.com/list"));
        std::fs::write(&path, "<html>1.2.3.4:8080</html>\n").unwrap();
        assert!(cache.load_rows("http://example.com/list").await.is_none());
        cleanup(&dir);
    }

    fn binary_rows(rows: &[(Ipv4Addr, u16, Option<Protocol>)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(CACHE_MAGIC);
        body.extend_from_slice(&(rows.len() as u32).to_le_bytes());
        for (ip, port, protocol) in rows {
            body.extend_from_slice(&ip.octets());
            body.extend_from_slice(&port.to_le_bytes());
            match protocol {
                None => body.push(0),
                Some(Protocol::Connect(p)) => {
                    body.push(protocol_code(*protocol).unwrap());
                    body.extend_from_slice(&p.to_le_bytes());
                }
                Some(p) => body.push(protocol_code(Some(*p)).unwrap()),
            }
        }
        body
    }

    #[test]
    fn binary_round_trips_all_protocol_variants() {
        let rows = [
            (Ipv4Addr::new(1, 2, 3, 4), 8080, None),
            (
                Ipv4Addr::new(5, 6, 7, 8),
                3128,
                Some(Protocol::Http(crate::proxy::models::Anonymity::Elite)),
            ),
            (Ipv4Addr::new(9, 9, 9, 9), 1080, Some(Protocol::Socks5)),
            (
                Ipv4Addr::new(10, 0, 0, 1),
                443,
                Some(Protocol::Connect(443)),
            ),
            (
                Ipv4Addr::new(10, 0, 0, 2),
                8443,
                Some(Protocol::Https(
                    crate::proxy::models::Anonymity::Transparent,
                )),
            ),
        ];
        let parsed = decode_rows(&binary_rows(&rows)).expect("valid binary cache");
        assert_eq!(parsed, rows.to_vec());
    }

    #[test]
    fn truncated_binary_cache_is_rejected() {
        let rows = [(
            Ipv4Addr::new(1, 2, 3, 4),
            8080,
            Some(Protocol::Connect(443)),
        )];
        let full = binary_rows(&rows);
        assert!(decode_rows(&full[..full.len() - 1]).is_none());
    }

    #[test]
    fn protocol_codes_round_trip() {
        for protocol in [
            Protocol::Http(crate::proxy::models::Anonymity::Elite),
            Protocol::Http(crate::proxy::models::Anonymity::Transparent),
            Protocol::Http(crate::proxy::models::Anonymity::Anonymous),
            Protocol::Http(crate::proxy::models::Anonymity::Unknown),
            Protocol::Https(crate::proxy::models::Anonymity::Elite),
            Protocol::Https(crate::proxy::models::Anonymity::Unknown),
            Protocol::Socks4,
            Protocol::Socks5,
        ] {
            let code = protocol_code(Some(protocol)).unwrap();
            assert_eq!(protocol_from_code(code), Some(protocol));
        }
    }

    #[test]
    fn cache_file_name_is_stable_and_hashed() {
        assert_eq!(
            cache_file_name("http://example.com/list"),
            cache_file_name("http://example.com/list")
        );
        assert_ne!(
            cache_file_name("http://example.com/list"),
            cache_file_name("http://example.com/other")
        );
    }

    #[test]
    fn cache_file_name_is_deterministic_fnv1a() {
        assert_eq!(
            cache_file_name("http://example.com/list"),
            "ffb9dd630c1e02bd"
        );
        assert_eq!(
            cache_file_name("http://example.com/other"),
            "e2eae3c2756ad9b1"
        );
    }

    #[test]
    fn clean_orphaned_tmp_removes_only_stale_scratch_files() {
        use super::clean_orphaned_tmp;
        use std::time::SystemTime;

        let dir = std::env::temp_dir().join(format!(
            "flx_cache_tmp_test_{}_{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let stale_tmp = dir.join(".abcdef.tmp-99999");
        std::fs::write(&stale_tmp, "partial").unwrap();
        let file = std::fs::File::open(&stale_tmp).unwrap();
        file.set_modified(SystemTime::now() - super::ORPHANED_TMP_MAX_AGE - Duration::from_secs(1))
            .unwrap();
        drop(file);

        let fresh_tmp = dir.join(".012345.tmp-1");
        std::fs::write(&fresh_tmp, "in-progress").unwrap();
        let real = dir.join("0123456789abcdef");
        std::fs::write(&real, "cached body").unwrap();

        clean_orphaned_tmp(&dir);

        assert!(!stale_tmp.exists(), "stale scratch file must be removed");
        assert!(fresh_tmp.exists(), "live scratch file must be kept");
        assert!(real.exists(), "real cache entry must be kept");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
