//! Local cache of raw provider response bodies.
//!
//! Fetching a proxy list is the slowest part of startup: dozens of source URLs,
//! each with a multi-second timeout. Bodies change on the order of minutes, so
//! a fresh cache hit skips the network entirely (and the network semaphore)
//! and re-runs the cheap CPU-side scrape on the stored body.

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    path::PathBuf,
    time::{Duration, SystemTime},
};

use anyhow::Context;

/// Local cache of provider response bodies, keyed by source URL.
pub struct Cache {
    dir: PathBuf,
    ttl: Duration,
    refresh: bool,
}

impl Cache {
    /// Opens (creating if needed) the cache directory under the platform data
    /// dir. Bodies younger than `ttl` are reused; `refresh` forces a refetch.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform data dir is unavailable or the cache
    /// directory cannot be created. Callers treat failure as "no caching".
    pub fn new(ttl: Duration, refresh: bool) -> anyhow::Result<Self> {
        let mut dir = crate::geolookup::data_dir()?;
        dir.push("cache");
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create cache directory {}", dir.display()))?;
        Ok(Self::new_at(dir, ttl, refresh))
    }

    fn new_at(dir: PathBuf, ttl: Duration, refresh: bool) -> Self {
        Self { dir, ttl, refresh }
    }

    /// Returns the cached body for `url` when present, younger than `ttl`, and
    /// non-empty; `None` otherwise. Bypassed entirely under `refresh`.
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

    /// Best-effort store of `body` for `url`. Empty bodies are skipped so a
    /// source that answered nothing cannot shadow a future fetch. Writes go to
    /// a process-unique temp file and are atomically renamed into place, so a
    /// crash or a concurrent writer never leaves a corrupt entry.
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

/// Stable per-URL cache file name (16 hex digits of the URL's hash).
fn cache_file_name(url: &str) -> String {
    let mut hasher = DefaultHasher::new();
    url.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
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
        dir.push(format!("fluxy_cache_test_{}_{unique}", std::process::id()));
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
}
