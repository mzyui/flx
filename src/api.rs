//! High-level [`Flx`] builder facade.

use std::{path::PathBuf, sync::Arc, time::Duration};

use futures_util::{stream, Stream, StreamExt};

use crate::{
    error::FlxError,
    proxy::models::{Protocol, Proxy},
    FetcherConfig, ProxySource, ProxyValidator, ValidationProgress, ValidatorConfig,
};

/// Uniform proxy stream type.
type BoxStream = std::pin::Pin<Box<dyn Stream<Item = Proxy> + Send>>;

/// Where the proxies come from.
enum SourceKind {
    Fetcher,
    File(ProxySource),
}

/// Builder for fetching and optionally validating proxies.
///
/// # Examples
///
/// Fetch from the built-in providers and validate them as HTTP proxies:
///
/// ```no_run
/// use flx::{Anonymity, Flx, Protocol};
///
/// # async fn example() -> anyhow::Result<()> {
/// let proxies = Flx::fetch()
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
/// use flx::{Flx, Protocol};
///
/// # async fn example() -> anyhow::Result<()> {
/// let proxies = Flx::from_file("proxies.txt")?
///     .types([Protocol::Socks5])
///     .collect()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Flx {
    source: SourceKind,
    fetcher_config: FetcherConfig,
    validator_config: ValidatorConfig,
    limit: usize,
}

impl Default for Flx {
    fn default() -> Self {
        Self {
            source: SourceKind::Fetcher,
            fetcher_config: FetcherConfig::default(),
            validator_config: ValidatorConfig::default(),
            limit: 0,
        }
    }
}

impl Flx {
    /// Starts a builder that scrapes the built-in provider set.
    pub fn fetch() -> Self {
        Self::default()
    }

    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self, FlxError> {
        let source = ProxySource::from_file(path.into()).map_err(|e| {
            e.downcast::<std::io::Error>()
                .map(FlxError::Io)
                .unwrap_or_else(|other| FlxError::Io(std::io::Error::other(other)))
        })?;
        Ok(Self {
            source: SourceKind::File(source),
            ..Self::default()
        })
    }

    /// Protocols to validate against every candidate.
    pub fn types(mut self, types: impl Into<Vec<Protocol>>) -> Self {
        self.validator_config.types = types.into();
        self
    }

    /// AND groups of protocols to validate.
    pub fn groups(mut self, groups: impl Into<Vec<Vec<Protocol>>>) -> Self {
        self.validator_config.groups = groups.into();
        self
    }

    /// Maximum number of proxies validated concurrently.
    pub fn concurrency(mut self, concurrency: usize) -> Self {
        self.validator_config.concurrency_limit = concurrency;
        self
    }

    /// Maximum number of provider sources fetched concurrently.
    pub fn fetch_concurrency(mut self, concurrency: usize) -> Self {
        self.fetcher_config.concurrency_limit = concurrency;
        self
    }

    /// Per-validation timeout in seconds.
    pub fn timeout(mut self, seconds: u64) -> Self {
        self.validator_config.request_timeout = seconds;
        self
    }

    /// Maximum validation attempts per advertised protocol.
    pub fn max_attempts(mut self, attempts: usize) -> Self {
        self.validator_config.max_attempts = attempts;
        self
    }

    /// Disable TLS certificate validation for judge connections.
    pub fn insecure(mut self, insecure: bool) -> Self {
        self.validator_config.insecure = insecure;
        self
    }

    /// Require proxies to forward cookie headers to the judge.
    pub fn support_cookies(mut self) -> Self {
        self.validator_config.support_cookies = true;
        self
    }

    /// Require proxies to forward referer headers to the judge.
    pub fn support_referer(mut self) -> Self {
        self.validator_config.support_referer = true;
        self
    }

    /// Annotate fetched proxies with GeoIP country data.
    pub fn with_geo(mut self) -> Self {
        self.fetcher_config.enable_geo_lookup = true;
        self
    }

    /// Annotate fetched proxies with their IP class (residential, datacenter,
    /// mobile, unknown).
    pub fn with_ip_type(mut self) -> Self {
        self.fetcher_config.enable_geo_lookup = true;
        self.fetcher_config.enable_ip_type = true;
        self
    }

    /// Keep only fetched proxies whose IP class matches `ip_type`.
    pub fn ip_type(mut self, ip_type: crate::geolookup::IpType) -> Self {
        self.fetcher_config.enable_geo_lookup = true;
        self.fetcher_config.enable_ip_type = true;
        self.fetcher_config.ip_type_filter = Some(ip_type);
        self
    }

    /// Filter fetched proxies by ISO country code.
    pub fn countries(mut self, countries: impl Into<Vec<String>>) -> Self {
        self.fetcher_config.enable_geo_lookup = true;
        self.fetcher_config.countries = Arc::from(countries.into());
        self
    }

    /// Freshness window for the source cache, in minutes.
    pub fn cache_ttl(mut self, minutes: u64) -> Self {
        self.fetcher_config.cache_ttl =
            (minutes > 0).then(|| Duration::from_secs(minutes.saturating_mul(60)));
        self
    }

    /// Bypass the source cache and refetch.
    pub fn refresh_cache(mut self) -> Self {
        self.fetcher_config.refresh_cache = true;
        self
    }

    /// Serve providers only from the local cache, skipping uncached sources.
    pub fn offline(mut self) -> Self {
        self.fetcher_config.offline = true;
        self
    }

    /// Minimum delay in milliseconds between requests to the same host.
    pub fn fetch_delay(mut self, milliseconds: u64) -> Self {
        self.fetcher_config.fetch_delay =
            (milliseconds > 0).then(|| Duration::from_millis(milliseconds));
        self
    }

    /// Custom HTTP judges for plain HTTP validation.
    pub fn http_judges(mut self, urls: impl Into<Vec<String>>) -> Self {
        self.validator_config.http_judge_urls = urls.into();
        self
    }

    /// Custom online judges for HTTPS and tunnel validation.
    pub fn https_judges(mut self, urls: impl Into<Vec<String>>) -> Self {
        self.validator_config.https_judge_urls = urls.into();
        self
    }

    /// Probe requested types that the proxy's advertised set does not cover.
    pub fn probe_missed_types(mut self, enable: bool) -> Self {
        self.validator_config.probe_missed_types = enable;
        self
    }

    /// Stop after at most `limit` validated proxies.
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Runs the pipeline and yields validated proxies as a stream.
    pub async fn stream(self) -> Result<BoxStream, FlxError> {
        let (stream, _progress) = self.stream_with_progress().await?;
        Ok(stream)
    }

    /// Runs the pipeline with live validation counters.
    pub async fn stream_with_progress(self) -> Result<(BoxStream, ValidationProgress), FlxError> {
        let Flx {
            source,
            fetcher_config,
            validator_config,
            limit,
        } = self;

        let source = match source {
            SourceKind::Fetcher => Box::pin(
                ProxySource::from_fetcher(fetcher_config)
                    .await
                    .map_err(FlxError::Fetch)?,
            ) as BoxStream,
            SourceKind::File(source) => Box::pin(stream::iter(source)) as BoxStream,
        };

        let (output, progress) =
            if validator_config.types.is_empty() && validator_config.groups.is_empty() {
                (source, ValidationProgress::default())
            } else {
                let validator = ProxyValidator::validate(source, validator_config)
                    .await
                    .map_err(FlxError::Validate)?;
                let progress = validator.progress();
                (Box::pin(validator) as BoxStream, progress)
            };

        let output = if limit > 0 {
            Box::pin(output.take(limit)) as BoxStream
        } else {
            output
        };

        Ok((output, progress))
    }
    /// Runs the pipeline and collects validated proxies.
    pub async fn collect(self) -> Result<Vec<Proxy>, FlxError> {
        let stream = self.stream().await?;
        Ok(stream.collect::<Vec<_>>().await)
    }
}

#[cfg(test)]
mod tests {
    use super::Flx;
    use crate::error::FlxError;
    use crate::proxy::models::{Anonymity, Protocol};
    use futures_util::StreamExt;

    #[test]
    fn fetch_defaults_to_no_validation() {
        assert!(Flx::fetch().validator_config.types.is_empty());
    }

    #[test]
    fn types_land_in_validator_config() {
        let flx = Flx::fetch().types([Protocol::Http(Anonymity::Elite)]);
        assert_eq!(
            flx.validator_config.types,
            vec![Protocol::Http(Anonymity::Elite)]
        );
    }

    #[test]
    fn groups_land_in_validator_config() {
        let flx = Flx::fetch().groups(vec![vec![
            Protocol::Http(Anonymity::Unknown),
            Protocol::Https(Anonymity::Unknown),
        ]]);
        assert_eq!(
            flx.validator_config.groups,
            vec![vec![
                Protocol::Http(Anonymity::Unknown),
                Protocol::Https(Anonymity::Unknown)
            ]]
        );
        assert!(flx.validator_config.types.is_empty());
    }

    #[test]
    fn concurrency_touches_only_the_validator() {
        let flx = Flx::fetch().concurrency(99);
        assert_eq!(flx.validator_config.concurrency_limit, 99);
        assert_eq!(flx.fetcher_config.concurrency_limit, 25);
    }

    #[test]
    fn fetch_concurrency_touches_only_the_fetcher() {
        let flx = Flx::fetch().fetch_concurrency(42);
        assert_eq!(flx.fetcher_config.concurrency_limit, 42);
        assert_eq!(flx.validator_config.concurrency_limit, 500);
    }

    #[test]
    fn facade_defaults_match_cli_defaults() {
        let flx = Flx::fetch();
        assert_eq!(
            flx.fetcher_config.concurrency_limit,
            crate::fetcher::DEFAULT_CONCURRENCY_LIMIT
        );
        assert_eq!(
            flx.validator_config.concurrency_limit,
            crate::validator::DEFAULT_CONCURRENCY_LIMIT
        );
        assert_eq!(
            flx.fetcher_config.cache_ttl,
            Some(std::time::Duration::from_secs(15 * 60))
        );
    }

    #[test]
    fn countries_imply_geo_lookup() {
        let flx = Flx::fetch().countries(["ID".to_owned()]);
        assert!(flx.fetcher_config.enable_geo_lookup);
        assert_eq!(flx.fetcher_config.countries.as_ref(), ["ID".to_owned()]);
    }

    #[test]
    fn with_geo_enables_lookup_without_filtering() {
        let flx = Flx::fetch().with_geo();
        assert!(flx.fetcher_config.enable_geo_lookup);
        assert!(flx.fetcher_config.countries.is_empty());
    }

    #[test]
    fn support_header_builders_touch_only_the_validator() {
        let flx = Flx::fetch();
        assert!(!flx.validator_config.support_cookies);
        assert!(!flx.validator_config.support_referer);

        let flx = flx.support_cookies().support_referer();
        assert!(flx.validator_config.support_cookies);
        assert!(flx.validator_config.support_referer);
    }

    #[test]
    fn with_ip_type_enables_lookup_and_detection() {
        let flx = Flx::fetch().with_ip_type();
        assert!(flx.fetcher_config.enable_geo_lookup);
        assert!(flx.fetcher_config.enable_ip_type);
        assert_eq!(flx.fetcher_config.ip_type_filter, None);
    }

    #[test]
    fn ip_type_filter_implies_lookup_and_detection() {
        let flx = Flx::fetch().ip_type(crate::geolookup::IpType::Residential);
        assert!(flx.fetcher_config.enable_geo_lookup);
        assert!(flx.fetcher_config.enable_ip_type);
        assert_eq!(
            flx.fetcher_config.ip_type_filter,
            Some(crate::geolookup::IpType::Residential)
        );
    }

    #[test]
    fn cache_ttl_zero_disables_cache() {
        let disabled = Flx::fetch().cache_ttl(0);
        assert!(disabled.fetcher_config.cache_ttl.is_none());

        let enabled = Flx::fetch().cache_ttl(10);
        assert_eq!(
            enabled.fetcher_config.cache_ttl,
            Some(std::time::Duration::from_secs(600))
        );
    }

    #[test]
    fn limit_is_stored() {
        assert_eq!(Flx::fetch().limit(5).limit, 5);
    }

    #[test]
    fn offline_mode_is_stored() {
        assert!(!Flx::fetch().fetcher_config.offline);
        assert!(Flx::fetch().offline().fetcher_config.offline);
    }

    #[test]
    fn fetch_delay_zero_disables_throttling() {
        let disabled = Flx::fetch().fetch_delay(0);
        assert!(disabled.fetcher_config.fetch_delay.is_none());

        let enabled = Flx::fetch().fetch_delay(250);
        assert_eq!(
            enabled.fetcher_config.fetch_delay,
            Some(std::time::Duration::from_millis(250))
        );
    }

    #[tokio::test]
    async fn from_file_collects_proxies_without_validation() {
        let path = std::env::temp_dir().join(format!(
            "flx_lib_test_{}_{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "192.0.2.1:8080\n192.0.2.2:3128\ngarbage\n").unwrap();

        let proxies = Flx::from_file(&path).unwrap().collect().await.unwrap();

        let _ = std::fs::remove_file(&path);
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].as_text(), "192.0.2.1:8080");
        assert_eq!(proxies[1].as_text(), "192.0.2.2:3128");
    }

    #[tokio::test]
    async fn from_file_limit_truncates_the_output() {
        let path = std::env::temp_dir().join(format!(
            "flx_lib_test_limit_{}_{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "192.0.2.1:8080\n192.0.2.2:3128\n192.0.2.3:80\n").unwrap();

        let proxies = Flx::from_file(&path)
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

    #[tokio::test]
    async fn stream_with_progress_without_validation_returns_zeroed_counters() {
        let path = std::env::temp_dir().join(format!(
            "flx_lib_test_progress_{}_{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "192.0.2.1:8080\n").unwrap();

        let (mut stream, progress) = Flx::from_file(&path)
            .unwrap()
            .stream_with_progress()
            .await
            .unwrap();

        assert!(stream.next().await.is_some());
        assert!(stream.next().await.is_none());
        let _ = std::fs::remove_file(&path);

        // Without validation there is nothing to count; the handle is zeroed.
        assert_eq!(progress.total(), 0);
        assert_eq!(progress.done(), 0);
        assert_eq!(progress.passed(), 0);
    }
    #[test]
    fn from_file_nonexistent_yields_io_error() {
        let result = Flx::from_file("/nonexistent/path/for/testing");
        assert!(
            matches!(result, Err(FlxError::Io(_))),
            "expected FlxError::Io"
        );
    }

    #[tokio::test]
    async fn invalid_fetch_config_yields_fetch_error() {
        let result = Flx::fetch().fetch_concurrency(0).stream().await;
        assert!(
            matches!(result, Err(FlxError::Fetch(_))),
            "expected FlxError::Fetch"
        );
    }
}
