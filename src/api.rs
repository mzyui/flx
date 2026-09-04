//! High-level [`Flx`] builder facade.

use std::{
    fs::File,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::Context as _;
use futures_util::{stream, Stream, StreamExt};
use tokio::sync::mpsc;

use crate::{
    error::FlxError,
    proxy::models::{Anonymity, Protocol, Proxy},
    FetcherConfig, ProxySource, ProxyValidator, ValidationProgress, ValidatorConfig,
};

/// Path token that reads proxies from standard input.
const STDIN_PATH: &str = "-";

/// Uniform proxy stream type.
type BoxStream = std::pin::Pin<Box<dyn Stream<Item = Proxy> + Send>>;

/// Where the proxies come from.
enum SourceKind {
    Fetcher,
    Files(Vec<PathBuf>),
}

/// Whether the caller picked a validation target; the terminal calls refuse
/// to guess one silently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValidationChoice {
    Unset,
    Explicit,
    Skip,
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
    validation_choice: ValidationChoice,
    limit: usize,
}

impl Default for Flx {
    fn default() -> Self {
        Self {
            source: SourceKind::Fetcher,
            fetcher_config: FetcherConfig::default(),
            validator_config: ValidatorConfig::default(),
            validation_choice: ValidationChoice::Unset,
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
        Self::from_files([path.into()])
    }

    /// Reads candidates from one or more `ip:port` files; the path `-` reads
    /// standard input. Files are parsed on the blocking thread pool, so slow
    /// input never stalls an async executor.
    pub fn from_files(
        paths: impl IntoIterator<Item = impl Into<PathBuf>>,
    ) -> Result<Self, FlxError> {
        let paths: Vec<PathBuf> = paths.into_iter().map(Into::into).collect();
        for path in &paths {
            if path.as_os_str() == STDIN_PATH {
                continue;
            }
            File::open(path).map_err(FlxError::Io)?;
        }
        Ok(Self {
            source: SourceKind::Files(paths),
            ..Self::default()
        })
    }

    /// Protocols to validate against every candidate.
    pub fn types(mut self, types: impl Into<Vec<Protocol>>) -> Self {
        self.validator_config.types = types.into();
        self.validation_choice = ValidationChoice::Explicit;
        self
    }

    /// AND groups of protocols to validate.
    pub fn groups(mut self, groups: impl Into<Vec<Vec<Protocol>>>) -> Self {
        self.validator_config.groups = groups.into();
        self.validation_choice = ValidationChoice::Explicit;
        self
    }

    /// Validates every candidate as a plain HTTP proxy; the same default the
    /// CLI applies when `TYPES` is omitted.
    pub fn validate_http(self) -> Self {
        self.types([Protocol::Http(Anonymity::Unknown)])
    }

    /// Streams candidates without validating them.
    ///
    /// Clears any protocols or groups configured earlier: the last explicit
    /// validation choice wins.
    pub fn no_validate(mut self) -> Self {
        self.validator_config.types.clear();
        self.validator_config.groups.clear();
        self.validation_choice = ValidationChoice::Skip;
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

    /// Pause in milliseconds between validation attempts of the same proxy.
    pub fn retry_delay(mut self, milliseconds: u64) -> Self {
        self.validator_config.retry_delay = Duration::from_millis(milliseconds);
        self
    }

    /// Emit a machine-readable record for every failed probe.
    pub fn report_failures(mut self) -> Self {
        self.validator_config.report_failures = true;
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

    /// Restrict scraping to these named providers; empty keeps all of them.
    pub fn providers(mut self, names: impl Into<Vec<String>>) -> Self {
        self.fetcher_config.providers = Arc::from(names.into());
        self
    }

    /// Skip these providers even when included by name.
    pub fn exclude_providers(mut self, names: impl Into<Vec<String>>) -> Self {
        self.fetcher_config.excluded_providers = Arc::from(names.into());
        self
    }

    /// Additional raw source URLs scraped alongside the built-in providers.
    pub fn source_urls(mut self, urls: impl Into<Vec<String>>) -> Self {
        self.fetcher_config.custom_sources = Arc::from(urls.into());
        self
    }

    /// Skip fallback providers once this many proxies are already collected.
    pub fn fallback_threshold(mut self, threshold: usize) -> Self {
        self.fetcher_config.fallback_threshold = Some(threshold);
        self
    }

    /// Cap the fallback provider phase in seconds (0 = unbounded).
    pub fn fetch_phase_timeout(mut self, seconds: u64) -> Self {
        self.fetcher_config.fallback_phase_timeout =
            (seconds > 0).then(|| Duration::from_secs(seconds));
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

    /// Override the per-source fetch timeout in seconds.
    pub fn provider_timeout(mut self, seconds: u64) -> Self {
        self.fetcher_config.provider_timeout = (seconds > 0).then(|| Duration::from_secs(seconds));
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
        Ok(self.stream_with_progress().await?.stream)
    }

    /// Runs the pipeline with live validation counters.
    ///
    /// The returned [`ValidationRun`] is itself a `Stream`; it also carries
    /// the progress handle and, when `.report_failures()` was requested, the
    /// feed of failed probes.
    pub async fn stream_with_progress(self) -> Result<ValidationRun, FlxError> {
        let Flx {
            source,
            fetcher_config,
            validator_config,
            validation_choice,
            limit,
        } = self;

        if validation_choice == ValidationChoice::Unset {
            return Err(FlxError::Config(
                "no validation target selected; call .types(..), .groups(..), \
                 .validate_http(), or .no_validate()"
                    .to_owned(),
            ));
        }

        let source = match source {
            SourceKind::Fetcher => Box::pin(
                ProxySource::from_fetcher(fetcher_config)
                    .await
                    .map_err(FlxError::Fetch)?,
            ) as BoxStream,
            SourceKind::Files(paths) => {
                let proxies = load_proxy_files(paths)
                    .await
                    .map_err(|error| FlxError::Io(std::io::Error::other(error)))?;
                Box::pin(stream::iter(proxies)) as BoxStream
            }
        };

        let (mut output, progress, failures) =
            if validator_config.types.is_empty() && validator_config.groups.is_empty() {
                (source, ValidationProgress::default(), None)
            } else {
                let mut validator = ProxyValidator::validate(source, validator_config)
                    .await
                    .map_err(FlxError::Validate)?;
                let progress = validator.progress();
                // Take before boxing: once erased behind the stream trait the
                // concrete validator is unreachable, and an undrained receiver
                // would silently drop failures past the channel capacity.
                let failures = validator.take_failures();
                (Box::pin(validator) as BoxStream, progress, failures)
            };

        if limit > 0 {
            output = Box::pin(output.take(limit));
        }

        Ok(ValidationRun {
            stream: output,
            progress,
            failures,
        })
    }

    /// Runs the pipeline and collects validated proxies.
    pub async fn collect(self) -> Result<Vec<Proxy>, FlxError> {
        let stream = self.stream().await?;
        Ok(stream.collect::<Vec<_>>().await)
    }

    /// Exposes the validated pool through a local rotating endpoint that runs
    /// until the caller's runtime cancels it. The pool fills from the fetch and
    /// validation pipeline; the endpoint goes live once `options.min_ready`
    /// proxies are validated. See [`crate::rotator::Rotator`] for manual setups.
    pub async fn serve(self, options: crate::rotator::ServeOptions) -> Result<(), FlxError> {
        let stream = self.stream().await?;
        let rotator = Arc::new(crate::rotator::Rotator::new(options));
        let pool = rotator.pool();
        let server = tokio::spawn({
            let rotator = Arc::clone(&rotator);
            async move { rotator.run().await }
        });
        tokio::pin!(stream);
        while let Some(proxy) = stream.next().await {
            pool.add(proxy);
        }
        let _ = server.await;
        Ok(())
    }
}

/// Handle to a started pipeline: the result stream plus live counters and the
/// optional failure feed enabled by `.report_failures()`.
pub struct ValidationRun {
    stream: BoxStream,
    progress: ValidationProgress,
    failures: Option<mpsc::Receiver<crate::ProxyFailure>>,
}

impl ValidationRun {
    /// Live validation counters.
    pub fn progress(&self) -> ValidationProgress {
        self.progress.clone()
    }

    /// Takes the receiver for machine-readable probe failures. Returns `None`
    /// unless `.report_failures()` was set; skipping the drain silently drops
    /// failures once the channel buffer fills.
    pub fn take_failures(&mut self) -> Option<mpsc::Receiver<crate::ProxyFailure>> {
        self.failures.take()
    }
}

impl Stream for ValidationRun {
    type Item = Proxy;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }
}

/// Reads every proxy from `paths` (`-` = stdin) on the blocking thread pool,
/// so slow input never stalls an async executor.
pub async fn load_proxy_files(paths: Vec<PathBuf>) -> anyhow::Result<Vec<Proxy>> {
    tokio::task::spawn_blocking(move || {
        let mut proxies = Vec::new();
        for path in paths {
            let parsed = if path.as_os_str() == STDIN_PATH {
                ProxySource::from_stdin().context("failed to read proxies from stdin")?
            } else {
                ProxySource::from_file(path.clone())
                    .with_context(|| format!("failed to read proxies from {}", path.display()))?
            };
            proxies.extend(parsed);
        }
        Ok::<_, anyhow::Error>(proxies)
    })
    .await
    .context("proxy file reader task failed")?
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use futures_util::StreamExt;

    use super::Flx;
    use crate::error::FlxError;
    use crate::proxy::models::{Anonymity, Protocol};

    #[test]
    fn fetch_defaults_to_no_validation_choice() {
        let flx = Flx::fetch();
        assert!(flx.validator_config.types.is_empty());
        assert_eq!(flx.validation_choice, super::ValidationChoice::Unset);
    }

    #[test]
    fn validate_http_matches_the_cli_default() {
        let flx = Flx::fetch().validate_http();
        assert_eq!(
            flx.validator_config.types,
            vec![Protocol::Http(Anonymity::Unknown)]
        );
        assert_eq!(flx.validation_choice, super::ValidationChoice::Explicit);
    }

    #[test]
    fn no_validate_clears_earlier_choices() {
        let flx = Flx::fetch()
            .types([Protocol::Http(Anonymity::Elite)])
            .groups(vec![vec![Protocol::Socks5]])
            .no_validate();
        assert!(flx.validator_config.types.is_empty());
        assert!(flx.validator_config.groups.is_empty());
        assert_eq!(flx.validation_choice, super::ValidationChoice::Skip);
    }

    #[tokio::test]
    async fn unset_validation_choice_fails_fast() {
        let error = match Flx::fetch().stream().await {
            Err(error) => error,
            Ok(_) => panic!("expected FlxError::Config"),
        };
        assert!(
            matches!(error, FlxError::Config(_)),
            "expected FlxError::Config"
        );
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
        let serve = crate::rotator::ServeOptions::default();
        assert_eq!(serve.pool_size, crate::rotator::DEFAULT_POOL_SIZE);
        assert_eq!(serve.min_ready, crate::rotator::DEFAULT_MIN_READY);
        assert_eq!(serve.refresh_secs, crate::rotator::DEFAULT_REFRESH_SECS);
        assert_eq!(
            serve.request_timeout,
            crate::rotator::DEFAULT_REQUEST_TIMEOUT
        );
        assert_eq!(serve.bind, crate::rotator::DEFAULT_BIND);
        assert_eq!(serve.port, crate::rotator::DEFAULT_PORT);
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

    #[test]
    fn provider_selection_lands_in_fetcher_config() {
        let flx = Flx::fetch()
            .providers(["a".to_owned(), "b".to_owned()])
            .exclude_providers(["c".to_owned()])
            .source_urls(["https://example.test/list".to_owned()]);
        assert_eq!(flx.fetcher_config.providers.as_ref(), ["a", "b"]);
        assert_eq!(flx.fetcher_config.excluded_providers.as_ref(), ["c"]);
        assert_eq!(
            flx.fetcher_config.custom_sources.as_ref(),
            ["https://example.test/list"]
        );
    }

    #[test]
    fn fetch_phase_knobs_land_in_fetcher_config() {
        let flx = Flx::fetch().fallback_threshold(500).fetch_phase_timeout(45);
        assert_eq!(flx.fetcher_config.fallback_threshold, Some(500));
        assert_eq!(
            flx.fetcher_config.fallback_phase_timeout,
            Some(std::time::Duration::from_secs(45))
        );
        let unbounded = Flx::fetch().fetch_phase_timeout(0);
        assert_eq!(unbounded.fetcher_config.fallback_phase_timeout, None);
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

        let proxies = Flx::from_file(&path)
            .unwrap()
            .no_validate()
            .collect()
            .await
            .unwrap();

        let _ = std::fs::remove_file(&path);
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].as_text(), "192.0.2.1:8080");
        assert_eq!(proxies[1].as_text(), "192.0.2.2:3128");
    }

    #[tokio::test]
    async fn from_files_reads_every_file_in_order() {
        let stamp = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let first = std::env::temp_dir().join(format!("flx_lib_test_files_a_{stamp}.txt"));
        let second = std::env::temp_dir().join(format!("flx_lib_test_files_b_{stamp}.txt"));
        std::fs::write(&first, "socks5://192.0.2.1:1080\n").unwrap();
        std::fs::write(&second, "192.0.2.2:3128\nbroken-line\n").unwrap();

        let proxies = Flx::from_files([&first, &second])
            .unwrap()
            .no_validate()
            .collect()
            .await
            .unwrap();

        let _ = std::fs::remove_file(&first);
        let _ = std::fs::remove_file(&second);
        assert_eq!(proxies.len(), 2);
        assert_eq!(
            proxies[0].expected_types.as_ref(),
            &[Protocol::Socks5],
            "scheme-prefixed lines keep pinning their protocol"
        );
        assert_eq!(proxies[1].as_text(), "192.0.2.2:3128");
    }

    #[tokio::test]
    async fn from_files_fails_fast_on_a_missing_file() {
        let missing = std::env::temp_dir().join("flx_lib_test_files_missing.txt");
        let _ = std::fs::remove_file(&missing);
        let error = Flx::from_files([&missing]).err().unwrap();
        assert!(matches!(error, FlxError::Io(_)));
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
            .no_validate()
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

        let mut run = Flx::from_file(&path)
            .unwrap()
            .no_validate()
            .stream_with_progress()
            .await
            .unwrap();

        assert!(run.next().await.is_some());
        assert!(run.next().await.is_none());
        let _ = std::fs::remove_file(&path);

        // Without validation there is nothing to count; the handle is zeroed.
        let progress = run.progress();
        assert_eq!(progress.total(), 0);
        assert_eq!(progress.done(), 0);
        assert_eq!(progress.passed(), 0);
        assert!(run.take_failures().is_none());
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
        let error = match Flx::fetch()
            .fetch_concurrency(0)
            .no_validate()
            .stream()
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("expected FlxError::Fetch"),
        };
        assert!(
            matches!(error, FlxError::Fetch(_)),
            "expected FlxError::Fetch"
        );
    }

    // Offline echo judge: answers the preflight with the request token, so a
    // full validation run needs no external network.
    async fn spawn_echo_judge() -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let mut received = Vec::new();
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    received.extend_from_slice(&buf[..n]);
                    if received.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let mut token = String::new();
                for line in received.split(|&b| b == b'\n') {
                    let line = String::from_utf8_lossy(line);
                    let (name, value) = line.split_once(':').unwrap_or(("", ""));
                    if name.trim().eq_ignore_ascii_case("x-fluxy-token") {
                        token = value.trim().to_owned();
                        break;
                    }
                }
                let body = format!("HTTP_X_FLUXY_TOKEN = {token}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        format!("http://{address}/azenv.php")
    }

    async fn write_candidate_file(stem: &str, count: u16) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "flx_lib_test_{stem}_{}_{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Privileged ports are effectively never bound locally, so every
        // candidate fails fast without external network.
        let body: String = (1..=count)
            .map(|port| format!("127.0.0.1:{port}\n"))
            .collect();
        std::fs::write(&path, body).unwrap();
        path
    }

    #[tokio::test]
    async fn failure_feed_survives_the_facade_run() {
        const CANDIDATES: u16 = 4;

        let judge = spawn_echo_judge().await;
        let path = write_candidate_file("failures", CANDIDATES).await;

        let mut run = Flx::from_file(&path)
            .unwrap()
            .validate_http()
            .http_judges([judge])
            .report_failures()
            .concurrency(2)
            .stream_with_progress()
            .await
            .unwrap();

        let mut failures = run.take_failures().expect("failures enabled");
        while futures_util::StreamExt::next(&mut run).await.is_some() {}

        let mut reasons = Vec::new();
        while let Some(failure) = failures.recv().await {
            reasons.push(failure.reason);
        }

        let _ = std::fs::remove_file(&path);
        assert_eq!(
            reasons.len(),
            usize::from(CANDIDATES),
            "every failed probe must reach the facade consumer"
        );
    }

    #[tokio::test]
    async fn dropping_a_run_mid_flight_keeps_the_runtime_responsive() {
        let judge = spawn_echo_judge().await;
        let path = write_candidate_file("drop", 8).await;

        {
            let mut run = Flx::from_file(&path)
                .unwrap()
                .validate_http()
                .http_judges([judge])
                .concurrency(2)
                .stream_with_progress()
                .await
                .unwrap();
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                futures_util::StreamExt::next(&mut run),
            )
            .await
            .expect("first item must arrive promptly");
            // Abandon the remaining work mid-stream.
        }

        // A fresh pipeline must complete afterwards: the aborted run may not
        // wedge the shared runtime or leak blocking state.
        let judge = spawn_echo_judge().await;
        let second_path = write_candidate_file("drop-second", 2).await;
        let started = std::time::Instant::now();
        let proxies = Flx::from_file(&second_path)
            .unwrap()
            .validate_http()
            .http_judges([judge])
            .concurrency(2)
            .collect()
            .await
            .unwrap();
        let elapsed = started.elapsed();

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&second_path);
        assert_eq!(proxies.len(), 0, "closed local ports must fail validation");
        assert!(
            elapsed < Duration::from_secs(10),
            "post-drop pipeline stalled for {elapsed:?}"
        );
    }
}
