//! High-level library entry point.
//!
//! [`Fluxy`] is a small builder facade over the lower-level pieces
//! ([`ProxySource`], [`ProxyFetcher`], [`ProxyValidator`]) that covers the
//! common workflows: fetch from the built-in providers, optionally validate,
//! and collect the survivors into a `Vec` or a stream.
//!
//! See the crate-level documentation for a full example.

use std::{path::PathBuf, sync::Arc, time::Duration};

use futures_util::{stream, Stream, StreamExt};

use crate::{
    proxy::models::{Protocol, Proxy},
    FetcherConfig, ProxySource, ProxyValidator, ValidatorConfig,
};

/// Owned, boxed, `Send` stream of proxies. The concrete source type
/// (`ProxyFetcher` or a file-backed iterator) is erased so [`Fluxy::stream`]
/// can hand callers a single uniform stream.
type BoxStream = std::pin::Pin<Box<dyn Stream<Item = Proxy> + Send>>;

/// Where the proxies come from.
enum SourceKind {
    /// The built-in provider set (see [`crate::all_providers`]).
    Fetcher,
    /// A plaintext `ip:port` file, opened eagerly in [`Fluxy::from_file`].
    File(ProxySource),
}

/// Builder facade for fetching and optionally validating proxies.
///
/// The builder combines a [`FetcherConfig`] (how the built-in providers are
/// scraped) and a [`ValidatorConfig`] (how candidates are checked). Validation
/// runs whenever [`Fluxy::types`] has been called; otherwise the proxies are
/// handed through unvalidated.
///
/// # Examples
///
/// Fetch from the built-in providers and validate them as HTTP proxies:
///
/// ```no_run
/// use fluxy::{Anonymity, Fluxy, Protocol};
///
/// # async fn example() -> anyhow::Result<()> {
/// let proxies = Fluxy::fetch()
///     .types([Protocol::Http(Anonymity::Elite)])
///     .limit(20)
///     .collect()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// Validate an existing `ip:port` file:
///
/// ```no_run
/// use fluxy::{Fluxy, Protocol};
///
/// # async fn example() -> anyhow::Result<()> {
/// let proxies = Fluxy::from_file("proxies.txt")?
///     .types([Protocol::Socks5])
///     .collect()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Fluxy {
    source: SourceKind,
    fetcher_config: FetcherConfig,
    validator_config: ValidatorConfig,
    limit: usize,
}

impl Default for Fluxy {
    fn default() -> Self {
        Self {
            source: SourceKind::Fetcher,
            fetcher_config: FetcherConfig::default(),
            validator_config: ValidatorConfig::default(),
            limit: 0,
        }
    }
}

impl Fluxy {
    /// Starts a builder that scrapes the built-in provider set.
    pub fn fetch() -> Self {
        Self::default()
    }

    /// Starts a builder that reads `ip:port` lines from `path`.
    ///
    /// The file is opened immediately so a bad path fails fast.
    ///
    /// # Errors
    ///
    /// Returns an error if `path` cannot be opened.
    pub fn from_file(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let source = ProxySource::from_file(path.into())?;
        Ok(Self {
            source: SourceKind::File(source),
            ..Self::default()
        })
    }

    /// Protocols to validate (and match) against every candidate.
    ///
    /// When empty (the default) the pipeline skips validation and yields every
    /// fetched proxy unchanged.
    pub fn types(mut self, types: impl Into<Vec<Protocol>>) -> Self {
        self.validator_config.types = types.into();
        self
    }

    /// Maximum number of proxies validated concurrently.
    ///
    /// Mirrors the CLI's `--max-connections`.
    pub fn concurrency(mut self, concurrency: usize) -> Self {
        self.validator_config.concurrency_limit = concurrency;
        self
    }

    /// Maximum number of provider sources fetched concurrently.
    ///
    /// Mirrors the CLI's `--fetch-concurrency`.
    pub fn fetch_concurrency(mut self, concurrency: usize) -> Self {
        self.fetcher_config.concurrency_limit = concurrency;
        self
    }

    /// Per-validation timeout in seconds.
    ///
    /// Mirrors the CLI's `--timeout`.
    pub fn timeout(mut self, seconds: u64) -> Self {
        self.validator_config.request_timeout = seconds;
        self
    }

    /// Maximum validation attempts per advertised protocol before giving up.
    ///
    /// Mirrors the CLI's `--max-attempts`.
    pub fn max_attempts(mut self, attempts: usize) -> Self {
        self.validator_config.max_attempts = attempts;
        self
    }

    /// Disable TLS certificate validation for judge connections.
    ///
    /// Mirrors the CLI's `--insecure`; off by default. See
    /// [`ValidatorConfig::insecure`] for the security implications.
    pub fn insecure(mut self, insecure: bool) -> Self {
        self.validator_config.insecure = insecure;
        self
    }

    /// Annotate every fetched proxy with its country from the GeoLite2
    /// database, downloading it on first use.
    ///
    /// Mirrors the CLI's `--with-geo`.
    pub fn with_geo(mut self) -> Self {
        self.fetcher_config.enable_geo_lookup = true;
        self
    }

    /// Filter fetched proxies by ISO country code.
    ///
    /// Implies GeoIP lookup. Mirrors the CLI's `--countries`.
    pub fn countries(mut self, countries: impl Into<Vec<String>>) -> Self {
        self.fetcher_config.enable_geo_lookup = true;
        self.fetcher_config.countries = Arc::from(countries.into());
        self
    }

    /// Freshness window for the provider-source cache, in minutes.
    ///
    /// `0` disables the cache. Mirrors the CLI's `--cache-ttl`.
    pub fn cache_ttl(mut self, minutes: u64) -> Self {
        self.fetcher_config.cache_ttl =
            (minutes > 0).then(|| Duration::from_secs(minutes.saturating_mul(60)));
        self
    }

    /// Bypass the provider-source cache and refetch every source.
    ///
    /// Mirrors the CLI's `--refresh-cache`.
    pub fn refresh_cache(mut self) -> Self {
        self.fetcher_config.refresh_cache = true;
        self
    }

    /// Custom online judges for plain HTTP validation.
    ///
    /// Mirrors the CLI's `--http-judge-urls`.
    pub fn http_judges(mut self, urls: impl Into<Vec<String>>) -> Self {
        self.validator_config.http_judge_urls = urls.into();
        self
    }

    /// Custom online judges for HTTPS, CONNECT and SOCKS tunnels.
    ///
    /// Mirrors the CLI's `--https-judge-urls`.
    pub fn https_judges(mut self, urls: impl Into<Vec<String>>) -> Self {
        self.validator_config.https_judge_urls = urls.into();
        self
    }

    /// Stop after at most `limit` proxies. `0` (the default) means unlimited.
    ///
    /// The limit bounds the *output* of the pipeline, matching the CLI's
    /// `-l/--limit`: when validation is enabled the pipeline keeps validating
    /// candidates until `limit` proxies pass, instead of capping the number of
    /// candidates before the check.
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Runs the configured pipeline and yields validated proxies as a stream.
    ///
    /// Prefer [`Fluxy::collect`] when the pool fits in memory. Streams are
    /// useful for large pools that should not be buffered.
    ///
    /// # Errors
    ///
    /// Returns an error when the fetcher or validator cannot start.
    pub async fn stream(self) -> anyhow::Result<BoxStream> {
        let Fluxy {
            source,
            fetcher_config,
            validator_config,
            limit,
        } = self;

        let source = match source {
            SourceKind::Fetcher => {
                Box::pin(ProxySource::from_fetcher(fetcher_config).await?) as BoxStream
            }
            SourceKind::File(source) => Box::pin(stream::iter(source)) as BoxStream,
        };

        let output = if validator_config.types.is_empty() {
            source
        } else {
            Box::pin(ProxyValidator::validate(source, validator_config).await?) as BoxStream
        };

        // Cap the final output. Dropping the stream when the limit is reached
        // propagates the early stop down the chain (validator → fetcher), so
        // production shuts down promptly, exactly like the CLI.
        Ok(if limit > 0 {
            Box::pin(output.take(limit)) as BoxStream
        } else {
            output
        })
    }

    /// Runs the configured pipeline and collects the validated proxies.
    ///
    /// # Errors
    ///
    /// Returns an error when the fetcher or validator cannot start.
    pub async fn collect(self) -> anyhow::Result<Vec<Proxy>> {
        let stream = self.stream().await?;
        Ok(stream.collect::<Vec<_>>().await)
    }
}

#[cfg(test)]
mod tests {
    use super::Fluxy;
    use crate::proxy::models::{Anonymity, Protocol};

    #[test]
    fn fetch_defaults_to_no_validation() {
        assert!(Fluxy::fetch().validator_config.types.is_empty());
    }

    #[test]
    fn types_land_in_validator_config() {
        let fluxy = Fluxy::fetch().types([Protocol::Http(Anonymity::Elite)]);
        assert_eq!(
            fluxy.validator_config.types,
            vec![Protocol::Http(Anonymity::Elite)]
        );
    }

    #[test]
    fn concurrency_touches_only_the_validator() {
        let fluxy = Fluxy::fetch().concurrency(99);
        assert_eq!(fluxy.validator_config.concurrency_limit, 99);
        assert_eq!(fluxy.fetcher_config.concurrency_limit, 25);
    }

    #[test]
    fn fetch_concurrency_touches_only_the_fetcher() {
        let fluxy = Fluxy::fetch().fetch_concurrency(42);
        assert_eq!(fluxy.fetcher_config.concurrency_limit, 42);
        assert_eq!(fluxy.validator_config.concurrency_limit, 500);
    }

    #[test]
    fn facade_defaults_match_cli_defaults() {
        let fluxy = Fluxy::fetch();
        assert_eq!(
            fluxy.fetcher_config.concurrency_limit,
            crate::fetcher::DEFAULT_CONCURRENCY_LIMIT
        );
        assert_eq!(
            fluxy.validator_config.concurrency_limit,
            crate::validator::DEFAULT_CONCURRENCY_LIMIT
        );
        assert_eq!(
            fluxy.fetcher_config.cache_ttl,
            Some(std::time::Duration::from_secs(15 * 60))
        );
    }

    #[test]
    fn countries_imply_geo_lookup() {
        let fluxy = Fluxy::fetch().countries(["ID".to_owned()]);
        assert!(fluxy.fetcher_config.enable_geo_lookup);
        assert_eq!(fluxy.fetcher_config.countries.as_ref(), ["ID".to_owned()]);
    }

    #[test]
    fn with_geo_enables_lookup_without_filtering() {
        let fluxy = Fluxy::fetch().with_geo();
        assert!(fluxy.fetcher_config.enable_geo_lookup);
        assert!(fluxy.fetcher_config.countries.is_empty());
    }

    #[test]
    fn cache_ttl_zero_disables_cache() {
        let disabled = Fluxy::fetch().cache_ttl(0);
        assert!(disabled.fetcher_config.cache_ttl.is_none());

        let enabled = Fluxy::fetch().cache_ttl(10);
        assert_eq!(
            enabled.fetcher_config.cache_ttl,
            Some(std::time::Duration::from_secs(600))
        );
    }

    #[test]
    fn limit_is_stored() {
        assert_eq!(Fluxy::fetch().limit(5).limit, 5);
    }

    #[tokio::test]
    async fn from_file_collects_proxies_without_validation() {
        let path = std::env::temp_dir().join(format!(
            "fluxy_lib_test_{}_{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "192.0.2.1:8080\n192.0.2.2:3128\ngarbage\n").unwrap();

        let proxies = Fluxy::from_file(&path).unwrap().collect().await.unwrap();

        let _ = std::fs::remove_file(&path);
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].as_text(), "192.0.2.1:8080");
        assert_eq!(proxies[1].as_text(), "192.0.2.2:3128");
    }

    #[tokio::test]
    async fn from_file_limit_truncates_the_output() {
        let path = std::env::temp_dir().join(format!(
            "fluxy_lib_test_limit_{}_{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "192.0.2.1:8080\n192.0.2.2:3128\n192.0.2.3:80\n").unwrap();

        let proxies = Fluxy::from_file(&path)
            .unwrap()
            .limit(2)
            .collect()
            .await
            .unwrap();

        let _ = std::fs::remove_file(&path);
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].as_text(), "192.0.2.1:8080");
        assert_eq!(proxies[1].as_text(), "192.0.2.2:3128");
    }
}
