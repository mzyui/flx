//! Local cache of raw provider response bodies.

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use anyhow::Context;

const ORPHANED_TMP_MAX_AGE: Duration = Duration::from_secs(60 * 60);

/// Local cache of provider response bodies.
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

    pub async fn load(&self, url: &str) -> Option<String> {
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
        let body = tokio::fs::read_to_string(path).await.ok()?;
        if body.is_empty() {
            return None;
        }
        Some(body)
    }

    pub async fn store(&self, url: &str, body: &str) {
        if body.is_empty() {
            return;
        }
        let name = cache_file_name(url);
        let path = self.dir.join(&name);
        let tmp = self.dir.join(format!(".{name}.tmp-{}", std::process::id()));
        if let Err(error) = tokio::fs::write(&tmp, body).await {
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
    use super::{cache_file_name, Cache};
    use std::{
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
    async fn load_misses_when_file_absent() {
        let (cache, dir) = temp_cache(Duration::from_secs(60), false);
        assert!(cache.load("http://example.com/list").await.is_none());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn store_then_load_round_trips_within_ttl() {
        let (cache, dir) = temp_cache(Duration::from_secs(60), false);
        cache
            .store("http://example.com/list", "1.2.3.4:8080\n")
            .await;
        assert_eq!(
            cache.load("http://example.com/list").await.as_deref(),
            Some("1.2.3.4:8080\n")
        );
        cleanup(&dir);
    }

    #[tokio::test]
    async fn load_expires_after_ttl() {
        let (cache, dir) = temp_cache(Duration::from_millis(50), false);
        cache
            .store("http://example.com/list", "1.2.3.4:8080\n")
            .await;
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(cache.load("http://example.com/list").await.is_none());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn refresh_bypasses_cache_but_keeps_store() {
        let (cache, dir) = temp_cache(Duration::from_secs(60), true);
        cache
            .store("http://example.com/list", "1.2.3.4:8080\n")
            .await;
        assert!(cache.load("http://example.com/list").await.is_none());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn empty_bodies_are_never_cached() {
        let (cache, dir) = temp_cache(Duration::from_secs(60), false);
        cache.store("http://example.com/list", "").await;
        assert!(cache.load("http://example.com/list").await.is_none());
        cleanup(&dir);
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
        use super::{clean_orphaned_tmp, ORPHANED_TMP_MAX_AGE};
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
        file.set_modified(SystemTime::now() - ORPHANED_TMP_MAX_AGE - Duration::from_secs(1))
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
