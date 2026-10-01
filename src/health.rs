//! Persistent proxy health history and score calculation.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::{Anonymity, Protocol};

const SCHEMA_VERSION: u8 = 1;
const DEFAULT_FILE_NAME: &str = "health.jsonl";
const MAX_RECORD_BYTES: usize = 16 * 1024;

/// Persistent health history for proxy endpoints.
#[derive(Clone)]
pub struct HealthStore {
    path: Arc<PathBuf>,
    state: Arc<Mutex<HashMap<Endpoint, HealthStats>>>,
    writer: Arc<tokio::sync::Mutex<tokio::fs::File>>,
}

/// Aggregated health statistics for one endpoint.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HealthStats {
    /// Number of successful probes.
    pub successes: u64,
    /// Number of failed probes.
    pub failures: u64,
    /// Total successful probe latency in seconds.
    pub latency_total: f64,
    /// Best HTTP(S) anonymity observed.
    pub anonymity: Option<Anonymity>,
    /// Unix timestamp of the latest recorded event.
    pub last_checked: f64,
}

/// A score calculated from persistent endpoint health.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HealthScore {
    /// Reliability component in the range 0–100.
    pub reliability: f64,
    /// Speed component in the range 0–100.
    pub speed: f64,
    /// Anonymity component in the range 0–100.
    pub anonymity: f64,
    /// Weighted final score in the range 0–100.
    pub total: f64,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct Endpoint {
    ip: Ipv4Addr,
    port: u16,
}

#[derive(Debug, Serialize)]
struct HealthRecord {
    schema: u8,
    timestamp: f64,
    ip: Ipv4Addr,
    port: u16,
    protocol: String,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_secs: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    anonymity: Option<Anonymity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StoredRecord {
    schema: u8,
    timestamp: f64,
    ip: Ipv4Addr,
    port: u16,
    protocol: String,
    success: bool,
    latency_secs: Option<f64>,
    anonymity: Option<Anonymity>,
}

impl HealthStore {
    /// Opens the default persistent health store.
    pub async fn open_default() -> Result<Self> {
        let path = crate::geolookup::data_dir()?
            .join("health")
            .join(DEFAULT_FILE_NAME);
        Self::open(path).await
    }

    /// Opens a persistent health store at `path`.
    pub async fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("failed to create health directory {}", parent.display())
            })?;
        }
        let state = load_state(&path).await?;
        let writer = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("failed to open health store {}", path.display()))?;
        Ok(Self {
            path: Arc::new(path),
            state: Arc::new(Mutex::new(state)),
            writer: Arc::new(tokio::sync::Mutex::new(writer)),
        })
    }

    /// Returns the backing file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Records one successful probe.
    pub async fn record_success(
        &self,
        ip: Ipv4Addr,
        port: u16,
        protocol: Protocol,
        latency_secs: f64,
        anonymity: Option<Anonymity>,
    ) -> Result<()> {
        self.record(HealthRecord {
            schema: SCHEMA_VERSION,
            timestamp: now(),
            ip,
            port,
            protocol: protocol.to_string(),
            success: true,
            latency_secs: Some(latency_secs),
            anonymity,
            reason: None,
        })
        .await
    }

    /// Records one failed probe.
    pub async fn record_failure(
        &self,
        ip: Ipv4Addr,
        port: u16,
        protocol: Protocol,
        reason: &str,
    ) -> Result<()> {
        self.record(HealthRecord {
            schema: SCHEMA_VERSION,
            timestamp: now(),
            ip,
            port,
            protocol: protocol.to_string(),
            success: false,
            latency_secs: None,
            anonymity: None,
            reason: Some(reason.to_owned()),
        })
        .await
    }

    /// Returns aggregated statistics for an endpoint.
    pub fn stats(&self, ip: Ipv4Addr, port: u16) -> Option<HealthStats> {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&Endpoint { ip, port })
            .cloned()
    }

    /// Calculates the score for an endpoint, if it has history.
    pub fn score(&self, ip: Ipv4Addr, port: u16) -> Option<HealthScore> {
        self.stats(ip, port).map(score_stats)
    }

    async fn record(&self, record: HealthRecord) -> Result<()> {
        let mut body = serde_json::to_vec(&record).context("failed to serialize health record")?;
        if body.len() > MAX_RECORD_BYTES {
            anyhow::bail!("health record exceeds {MAX_RECORD_BYTES} bytes");
        }
        body.push(b'\n');
        {
            let mut writer = self.writer.lock().await;
            writer
                .write_all(&body)
                .await
                .context("failed to append health record")?;
            writer
                .flush()
                .await
                .context("failed to flush health record")?;
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        apply_record(&mut state, &record);
        Ok(())
    }
}

fn score_stats(stats: HealthStats) -> HealthScore {
    let total = stats.successes.saturating_add(stats.failures);
    let reliability = if total == 0 {
        0.0
    } else {
        stats.successes as f64 / total as f64 * 100.0
    };
    let avg_latency = if stats.successes == 0 {
        5.0
    } else {
        stats.latency_total / stats.successes as f64
    };
    let speed = (100.0 * (1.0 - avg_latency / 5.0)).clamp(0.0, 100.0);
    let anonymity = stats
        .anonymity
        .map(|level| match level {
            Anonymity::Transparent => 0.0,
            Anonymity::Anonymous => 50.0,
            Anonymity::Elite => 100.0,
            Anonymity::Unknown => 0.0,
        })
        .unwrap_or(0.0);
    HealthScore {
        reliability,
        speed,
        anonymity,
        total: (reliability * 0.60 + speed * 0.25 + anonymity * 0.15).clamp(0.0, 100.0),
    }
}

fn apply_record(state: &mut HashMap<Endpoint, HealthStats>, record: &HealthRecord) {
    let entry = state
        .entry(Endpoint {
            ip: record.ip,
            port: record.port,
        })
        .or_default();
    if record.success {
        entry.successes = entry.successes.saturating_add(1);
        if let Some(latency) = record
            .latency_secs
            .filter(|value| value.is_finite() && *value >= 0.0)
        {
            entry.latency_total += latency;
        }
        if let Some(anonymity) = record.anonymity {
            if entry
                .anonymity
                .is_none_or(|current| anonymity.rank() > current.rank())
            {
                entry.anonymity = Some(anonymity);
            }
        }
    } else {
        entry.failures = entry.failures.saturating_add(1);
    }
    entry.last_checked = record.timestamp;
}

async fn load_state(path: &Path) -> Result<HashMap<Endpoint, HealthStats>> {
    let body = match tokio::fs::read_to_string(path).await {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read health store {}", path.display()))
        }
    };
    let mut state = HashMap::new();
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<StoredRecord>(line) {
            Ok(record) if record.schema == SCHEMA_VERSION => {
                let record = HealthRecord {
                    schema: record.schema,
                    timestamp: record.timestamp,
                    ip: record.ip,
                    port: record.port,
                    protocol: record.protocol,
                    success: record.success,
                    latency_secs: record.latency_secs,
                    anonymity: record.anonymity,
                    reason: None,
                };
                apply_record(&mut state, &record);
            }
            Ok(_) => warn_corrupt_record("unknown schema"),
            Err(_) => warn_corrupt_record("invalid JSON"),
        }
    }
    Ok(state)
}

fn warn_corrupt_record(reason: &str) {
    #[cfg(feature = "log")]
    log::warn!("ignored health record: {reason}");
    #[cfg(not(feature = "log"))]
    let _ = reason;
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn path(stem: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "flx_health_{stem}_{}_{}.jsonl",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[tokio::test]
    async fn empty_store_has_no_score() {
        let store = HealthStore::open(path("empty")).await.unwrap();
        assert!(store.score(Ipv4Addr::LOCALHOST, 8080).is_none());
    }

    #[tokio::test]
    async fn repeated_events_reload_and_calculate_score() {
        let file = path("reload");
        let store = HealthStore::open(&file).await.unwrap();
        store
            .record_success(
                Ipv4Addr::LOCALHOST,
                8080,
                Protocol::Http(Anonymity::Elite),
                0.5,
                Some(Anonymity::Elite),
            )
            .await
            .unwrap();
        store
            .record_failure(Ipv4Addr::LOCALHOST, 8080, Protocol::Socks5, "timeout")
            .await
            .unwrap();
        let score = store.score(Ipv4Addr::LOCALHOST, 8080).unwrap();
        assert_eq!(score.reliability, 50.0);
        assert_eq!(score.speed, 90.0);
        assert_eq!(score.anonymity, 100.0);
        assert_eq!(score.total, 67.5);

        let reloaded = HealthStore::open(file).await.unwrap();
        assert_eq!(
            reloaded.stats(Ipv4Addr::LOCALHOST, 8080).unwrap().failures,
            1
        );
    }

    #[tokio::test]
    async fn invalid_lines_are_ignored() {
        let file = path("corrupt");
        tokio::fs::write(&file, b"not-json\n").await.unwrap();
        let store = HealthStore::open(file).await.unwrap();
        assert!(store.score(Ipv4Addr::LOCALHOST, 8080).is_none());
    }

    #[test]
    fn speed_is_clamped_at_zero_for_slow_proxies() {
        let score = score_stats(HealthStats {
            successes: 1,
            latency_total: 10.0,
            ..HealthStats::default()
        });
        assert_eq!(score.speed, 0.0);
    }
}
