//! Config file support: TOML defaults layered over CLI flags.
//!
//! A config file is a **patch** — it fills values the CLI didn't explicitly
//! set.  CLI flags always win.  Project `.flx.toml` overrides the user XDG
//! config key-by-key.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ── Section patch structs ─────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GlobalSection {
    pub log_level: Option<String>,
    pub quiet: Option<bool>,
    pub no_color: Option<bool>,
    pub skip_version_check: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FetchSection {
    pub providers: Option<Vec<String>>,
    pub exclude_providers: Option<Vec<String>>,
    pub source_urls: Option<Vec<String>>,
    pub with_geo: Option<bool>,
    pub with_ip_type: Option<bool>,
    pub ip_type: Option<String>,
    pub countries: Option<Vec<String>>,
    pub exclude_countries: Option<Vec<String>>,
    pub concurrency: Option<usize>,
    pub cache_ttl: Option<u64>,
    pub refresh_cache: Option<bool>,
    pub offline: Option<bool>,
    pub delay_ms: Option<u64>,
    pub fallback_threshold: Option<usize>,
    pub phase_timeout: Option<u64>,
    pub no_dedup: Option<bool>,
    pub provider_timeout: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutputSection {
    pub format: Option<String>,
    pub limit: Option<usize>,
    pub output_file: Option<PathBuf>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub min_anonymity: Option<String>,
    pub levels: Option<Vec<String>>,
    pub max_response_time: Option<f64>,
    pub min_response_time: Option<f64>,
    pub exclude_types: Option<Vec<String>>,
    pub shuffle: Option<bool>,
    pub append: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ValidateSection {
    pub types: Option<Vec<String>>,
    pub concurrency: Option<usize>,
    pub max_attempts: Option<usize>,
    pub retry_delay_ms: Option<u64>,
    pub timeout: Option<u64>,
    pub http_judges: Option<Vec<String>>,
    pub https_judges: Option<Vec<String>>,
    pub insecure: Option<bool>,
    pub support_cookies: Option<bool>,
    pub support_referer: Option<bool>,
    pub report_failures: Option<PathBuf>,
}

// ── Top-level config ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize)]
pub struct FileConfig {
    pub global: Option<GlobalSection>,
    pub fetch: Option<FetchSection>,
    pub output: Option<OutputSection>,
    pub validate: Option<ValidateSection>,
    #[serde(skip)]
    pub unknown_sections: Vec<String>,
    #[serde(skip)]
    pub source: Option<PathBuf>,
}

// ── Discovery ─────────────────────────────────────────────────────────

pub struct Discovery {
    pub project: Option<PathBuf>,
    pub user: Option<PathBuf>,
}

/// The config files that would be read, in precedence order.
pub struct EffectivePaths {
    pub primary: Option<PathBuf>,
    pub project: Option<PathBuf>,
    pub user: Option<PathBuf>,
}

/// Resolves the files `load` would read, without reading them.
pub fn paths_in_effect(
    config_flag: Option<&Path>,
    env_path: Option<&str>,
    no_config: bool,
    config_home: &Path,
    cwd: &Path,
) -> EffectivePaths {
    if no_config {
        return EffectivePaths {
            primary: None,
            project: None,
            user: None,
        };
    }
    if let Some(path) = config_flag.or_else(|| env_path.map(Path::new)) {
        return EffectivePaths {
            primary: Some(path.to_owned()),
            project: None,
            user: None,
        };
    }
    let discovery = discover(config_home, cwd);
    EffectivePaths {
        primary: None,
        project: discovery.project,
        user: discovery.user,
    }
}

/// Scans the standard locations for config files without touching the filesystem.
///
/// `config_home` is the XDG config directory (`~/.config`); `cwd` is the
/// current working directory where `.flx.toml` is checked.
pub fn discover(config_home: &Path, cwd: &Path) -> Discovery {
    let project = cwd.join(".flx.toml");
    let user = config_home.join("flx").join("config.toml");
    Discovery {
        project: project.is_file().then_some(project),
        user: user.is_file().then_some(user),
    }
}

// ── Parse ─────────────────────────────────────────────────────────────

/// Parses a TOML config string, validating every known value.
///
/// Unknown top-level **sections** are collected (not rejected) so future
/// extensions like `[serve]` do not break; unknown **keys** inside a known
/// section are rejected (`deny_unknown_fields`).
pub fn parse(text: &str) -> Result<FileConfig, ConfigError> {
    let value: toml::Value = toml::from_str(text).map_err(ConfigError::parse)?;
    let table = match value {
        toml::Value::Table(ref t) => t,
        _ => return Err(ConfigError::message("config must be a TOML table")),
    };

    let mut cfg = FileConfig::default();
    for (key, value) in table {
        match key.as_str() {
            "global" => cfg.global = Some(deser_section(value, "global")?),
            "fetch" => cfg.fetch = Some(deser_section(value, "fetch")?),
            "output" => cfg.output = Some(deser_section(value, "output")?),
            "validate" => cfg.validate = Some(deser_section(value, "validate")?),
            other => cfg.unknown_sections.push(other.to_owned()),
        }
    }
    validate_enum_values(&cfg)?;
    Ok(cfg)
}

fn deser_section<T: serde::de::DeserializeOwned>(
    value: &toml::Value,
    section: &str,
) -> Result<T, ConfigError> {
    value
        .clone()
        .try_into()
        .map_err(|e: toml::de::Error| ConfigError::message(format!("[{section}] {e}")))
}

// ── Value validation ──────────────────────────────────────────────────

const LOG_LEVELS: &[&str] = &["off", "error", "warn", "info", "debug", "trace"];
const IP_TYPES: &[&str] = &["residential", "datacenter", "mobile", "unknown"];
pub(crate) const FORMATS: &[&str] = &[
    "default",
    "text",
    "json",
    "json-lines",
    "pretty-json",
    "csv",
    "prefix",
    "pac",
    "proxychains",
];
const SORTS: &[&str] = &["avg-response", "response-time", "country", "anonymity"];
const ORDERS: &[&str] = &["asc", "desc"];
pub(crate) const ANONYMITY_LEVELS: &[&str] = &["transparent", "anonymous", "elite", "unknown"];

fn validate_enum_values(cfg: &FileConfig) -> Result<(), ConfigError> {
    if let Some(g) = &cfg.global {
        ensure_member(g.log_level.as_deref(), LOG_LEVELS, "global.log_level")?;
    }
    if let Some(f) = &cfg.fetch {
        ensure_member(f.ip_type.as_deref(), IP_TYPES, "fetch.ip_type")?;
    }
    if let Some(o) = &cfg.output {
        ensure_member(o.format.as_deref(), FORMATS, "output.format")?;
        ensure_member(o.sort.as_deref(), SORTS, "output.sort")?;
        ensure_member(o.order.as_deref(), ORDERS, "output.order")?;
        ensure_member(
            o.min_anonymity.as_deref(),
            ANONYMITY_LEVELS,
            "output.min_anonymity",
        )?;
        for level in o.levels.iter().flatten() {
            ensure_member(Some(level), ANONYMITY_LEVELS, "output.levels")?;
        }
        for token in o.exclude_types.iter().flatten() {
            ensure_valid_type(token, "output.exclude_types")?;
        }
    }
    if let Some(v) = &cfg.validate {
        for token in v.types.iter().flatten() {
            ensure_valid_type(token, "validate.types")?;
        }
        ensure_judge_urls(&v.http_judges, "validate.http_judges")?;
        ensure_judge_urls(&v.https_judges, "validate.https_judges")?;
    }
    Ok(())
}

fn ensure_member(value: Option<&str>, allowed: &[&str], key: &str) -> Result<(), ConfigError> {
    match value {
        Some(v) if !allowed.contains(&v) => Err(ConfigError::value(key, v, &allowed.join("|"))),
        _ => Ok(()),
    }
}

fn ensure_valid_type(value: &str, key: &str) -> Result<(), ConfigError> {
    if crate::argument::is_valid_type_value(value) {
        Ok(())
    } else {
        Err(ConfigError::value(
            key,
            value,
            "HTTP, HTTPS, SOCKS4, SOCKS5, CONNECT:port, optionally with :Anonymity, joined by +",
        ))
    }
}

fn ensure_judge_urls(urls: &Option<Vec<String>>, key: &str) -> Result<(), ConfigError> {
    for url in urls.iter().flatten() {
        let scheme = url::Url::parse(url)
            .map(|u| u.scheme().to_owned())
            .unwrap_or_default();
        if scheme != "http" && scheme != "https" {
            return Err(ConfigError::value(key, url, "http(s) URL"));
        }
    }
    Ok(())
}

// ── Merge (layering) ──────────────────────────────────────────────────

trait Overlay {
    fn overlay(self, base: Self) -> Self;
}

macro_rules! overlay_section {
    ($name:ident { $($field:ident),+ $(,)? }) => {
        impl Overlay for $name {
            fn overlay(self, base: Self) -> Self {
                Self {
                    $($field: self.$field.or(base.$field),)+
                }
            }
        }
    };
}

overlay_section!(GlobalSection {
    log_level,
    quiet,
    no_color,
    skip_version_check
});
overlay_section!(FetchSection {
    providers,
    exclude_providers,
    source_urls,
    with_geo,
    with_ip_type,
    ip_type,
    countries,
    exclude_countries,
    concurrency,
    cache_ttl,
    refresh_cache,
    offline,
    delay_ms,
    fallback_threshold,
    phase_timeout,
    no_dedup,
    provider_timeout,
});
overlay_section!(OutputSection {
    format,
    limit,
    output_file,
    sort,
    order,
    min_anonymity,
    levels,
    max_response_time,
    min_response_time,
    exclude_types,
    shuffle,
    append,
});
overlay_section!(ValidateSection {
    types,
    concurrency,
    max_attempts,
    retry_delay_ms,
    timeout,
    http_judges,
    https_judges,
    insecure,
    support_cookies,
    support_referer,
    report_failures,
});

/// Merges two configs: `project` values override `user` values per field.
pub fn merge(project: FileConfig, user: FileConfig) -> FileConfig {
    FileConfig {
        global: merge_section(project.global, user.global),
        fetch: merge_section(project.fetch, user.fetch),
        output: merge_section(project.output, user.output),
        validate: merge_section(project.validate, user.validate),
        unknown_sections: {
            let mut all = project.unknown_sections;
            all.extend(user.unknown_sections);
            all
        },
        source: project.source.or(user.source),
    }
}

fn merge_section<T: Overlay>(project: Option<T>, user: Option<T>) -> Option<T> {
    match (project, user) {
        (Some(p), Some(u)) => Some(p.overlay(u)),
        (Some(p), None) => Some(p),
        (None, Some(u)) => Some(u),
        (None, None) => None,
    }
}

// ── Load from disk ────────────────────────────────────────────────────

/// Loads and merges config files following the standard precedence.
///
/// 1. `config_flag` (`--config <path>`) or `env_path` (`$FLX_CONFIG`)
/// 2. `.flx.toml` in `cwd` (project) + `~/.config/flx/config.toml` (user)
/// 3. `no_config` → `Ok(None)`
pub fn load(
    config_flag: Option<&Path>,
    env_path: Option<&str>,
    no_config: bool,
    config_home: &Path,
    cwd: &Path,
) -> Result<Option<FileConfig>, ConfigError> {
    if no_config {
        return Ok(None);
    }
    if let Some(path) = config_flag.or_else(|| env_path.map(Path::new)) {
        return read_file(path).map(Some);
    }
    let discovery = discover(config_home, cwd);
    let project = discovery.project.as_deref().map(read_file).transpose()?;
    let user = discovery.user.as_deref().map(read_file).transpose()?;
    let merged = match (project, user) {
        (Some(p), Some(u)) => merge(p, u),
        (Some(p), None) => p,
        (None, Some(u)) => u,
        (None, None) => return Ok(None),
    };
    warn_unknown_sections(&merged);
    Ok(Some(merged))
}

fn read_file(path: &Path) -> Result<FileConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError {
        path: Some(path.to_owned()),
        message: source.to_string(),
    })?;
    let mut cfg = parse(&text).map_err(|e| e.with_path(path))?;
    cfg.source = Some(path.to_owned());
    Ok(cfg)
}

fn warn_unknown_sections(cfg: &FileConfig) {
    for section in &cfg.unknown_sections {
        #[cfg(feature = "log")]
        log::warn!("unknown config section `{section}` ignored");
        #[cfg(not(feature = "log"))]
        let _ = section;
    }
}

// ── Apply to CLI ──────────────────────────────────────────────────────

use crate::argument::{Cli, Command, FetcherArgs, OutputOptions, ValidatorArgs};
use clap::parser::ValueSource;
use clap::ArgMatches;

/// Applies `cfg` values to `cli` for every field the CLI did **not** set.
pub fn apply_config(cli: &mut Cli, cfg: &FileConfig, matches: &ArgMatches) {
    apply_global(cli, cfg.global.as_ref(), matches);
    let sub = matches.subcommand().map(|(_, m)| m);
    match cli.command.as_mut() {
        Some(Command::Grab(grab)) => {
            apply_fetch(&mut grab.fetcher, cfg.fetch.as_ref(), sub);
            apply_output(&mut grab.output, cfg.output.as_ref(), sub);
        }
        Some(Command::Find(find)) => {
            apply_fetch(&mut find.fetcher, cfg.fetch.as_ref(), sub);
            apply_output(&mut find.output, cfg.output.as_ref(), sub);
            apply_validate(&mut find.validator, cfg.validate.as_ref(), sub);
        }
        Some(Command::GeoUpdate) | Some(Command::Config(_)) | None => {}
    }
}

fn provided(matches: Option<&ArgMatches>, id: &str) -> bool {
    matches!(
        matches.and_then(|m| m.value_source(id)),
        Some(ValueSource::CommandLine) | Some(ValueSource::EnvVariable)
    )
}

macro_rules! apply_field {
    ($provided:expr, $cfg:expr, $target:expr, $wrap:expr) => {
        if !$provided {
            if let Some(ref value) = *$cfg {
                $target = $wrap(value.clone());
            }
        }
    };
}

fn apply_global(cli: &mut Cli, cfg: Option<&GlobalSection>, matches: &ArgMatches) {
    let Some(cfg) = cfg else { return };
    apply_field!(
        provided(Some(matches), "log_level"),
        &cfg.log_level,
        cli.log_level,
        |v| v
    );
    if !provided(Some(matches), "quiet") && !cli.verbose {
        if let Some(value) = cfg.quiet {
            cli.quiet = value;
        }
    }
    apply_field!(
        provided(Some(matches), "no_color"),
        &cfg.no_color,
        cli.no_color,
        |v| v
    );
    apply_field!(
        provided(Some(matches), "skip_version_check"),
        &cfg.skip_version_check,
        cli.skip_version_check,
        |v| v
    );
}

fn apply_fetch(cli: &mut FetcherArgs, cfg: Option<&FetchSection>, sub: Option<&ArgMatches>) {
    let Some(cfg) = cfg else { return };
    apply_field!(
        provided(sub, "countries"),
        &cfg.countries,
        cli.countries,
        |v| v
    );
    apply_field!(
        provided(sub, "exclude_country"),
        &cfg.exclude_countries,
        cli.exclude_country,
        |v| v
    );
    apply_field!(
        provided(sub, "with_geo"),
        &cfg.with_geo,
        cli.with_geo,
        |v| v
    );
    apply_field!(
        provided(sub, "with_ip_type"),
        &cfg.with_ip_type,
        cli.with_ip_type,
        |v| v
    );
    apply_field!(provided(sub, "ip_type"), &cfg.ip_type, cli.ip_type, Some);
    apply_field!(
        provided(sub, "provider"),
        &cfg.providers,
        cli.provider,
        |v| v
    );
    apply_field!(
        provided(sub, "exclude_provider"),
        &cfg.exclude_providers,
        cli.exclude_provider,
        |v| v
    );
    apply_field!(
        provided(sub, "source_url"),
        &cfg.source_urls,
        cli.source_url,
        |v| v
    );
    apply_field!(provided(sub, "offline"), &cfg.offline, cli.offline, |v| v);
    apply_field!(
        provided(sub, "fetch_concurrency"),
        &cfg.concurrency,
        cli.fetch_concurrency,
        |v| v
    );
    apply_field!(
        provided(sub, "cache_ttl"),
        &cfg.cache_ttl,
        cli.cache_ttl,
        |v| v
    );
    apply_field!(
        provided(sub, "refresh_cache"),
        &cfg.refresh_cache,
        cli.refresh_cache,
        |v| v
    );
    apply_field!(
        provided(sub, "fetch_delay_ms"),
        &cfg.delay_ms,
        cli.fetch_delay_ms,
        |v| v
    );
    apply_field!(
        provided(sub, "fallback_threshold"),
        &cfg.fallback_threshold,
        cli.fallback_threshold,
        Some
    );
    apply_field!(
        provided(sub, "fetch_phase_timeout"),
        &cfg.phase_timeout,
        cli.fetch_phase_timeout,
        |v| v
    );
    apply_field!(
        provided(sub, "no_dedup"),
        &cfg.no_dedup,
        cli.no_dedup,
        |v| v
    );
    apply_field!(
        provided(sub, "provider_timeout"),
        &cfg.provider_timeout,
        cli.provider_timeout,
        |v| v
    );
}

fn apply_output(cli: &mut OutputOptions, cfg: Option<&OutputSection>, sub: Option<&ArgMatches>) {
    let Some(cfg) = cfg else { return };
    apply_field!(provided(sub, "format"), &cfg.format, cli.format, |v| v);
    apply_field!(provided(sub, "limit"), &cfg.limit, cli.limit, |v| v);
    apply_field!(
        provided(sub, "output_file"),
        &cfg.output_file,
        cli.output_file,
        Some
    );
    apply_field!(provided(sub, "sort"), &cfg.sort, cli.sort, Some);
    apply_field!(provided(sub, "order"), &cfg.order, cli.order, |v| v);
    apply_field!(
        provided(sub, "min_anonymity"),
        &cfg.min_anonymity,
        cli.min_anonymity,
        Some
    );
    apply_field!(provided(sub, "levels"), &cfg.levels, cli.levels, |v| v);
    apply_field!(
        provided(sub, "max_response_time"),
        &cfg.max_response_time,
        cli.max_response_time,
        Some
    );
    apply_field!(
        provided(sub, "min_response_time"),
        &cfg.min_response_time,
        cli.min_response_time,
        Some
    );
    apply_field!(
        provided(sub, "exclude_type"),
        &cfg.exclude_types,
        cli.exclude_type,
        |v| v
    );
    apply_field!(provided(sub, "shuffle"), &cfg.shuffle, cli.shuffle, |v| v);
    apply_field!(provided(sub, "append"), &cfg.append, cli.append, |v| v);
}

fn apply_validate(
    cli: &mut ValidatorArgs,
    cfg: Option<&ValidateSection>,
    sub: Option<&ArgMatches>,
) {
    let Some(cfg) = cfg else { return };
    apply_field!(provided(sub, "types"), &cfg.types, cli.types, |v| v);
    apply_field!(
        provided(sub, "max_connections"),
        &cfg.concurrency,
        cli.max_connections,
        |v| v
    );
    apply_field!(
        provided(sub, "max_attempts"),
        &cfg.max_attempts,
        cli.max_attempts,
        |v| v
    );
    apply_field!(
        provided(sub, "retry_delay_ms"),
        &cfg.retry_delay_ms,
        cli.retry_delay_ms,
        |v| v
    );
    apply_field!(provided(sub, "timeout"), &cfg.timeout, cli.timeout, |v| v);
    apply_field!(
        provided(sub, "http_judge_urls"),
        &cfg.http_judges,
        cli.http_judge_urls,
        |v| v
    );
    apply_field!(
        provided(sub, "https_judge_urls"),
        &cfg.https_judges,
        cli.https_judge_urls,
        |v| v
    );
    apply_field!(
        provided(sub, "no_verify_tls"),
        &cfg.insecure,
        cli.no_verify_tls,
        |v| v
    );
    apply_field!(
        provided(sub, "support_cookies"),
        &cfg.support_cookies,
        cli.support_cookies,
        |v| v
    );
    apply_field!(
        provided(sub, "support_referer"),
        &cfg.support_referer,
        cli.support_referer,
        |v| v
    );
    apply_field!(
        provided(sub, "report_failures"),
        &cfg.report_failures,
        cli.report_failures,
        Some
    );
}

// ── Template & show ───────────────────────────────────────────────────

/// Static commented template for `flx config init`.
pub fn template() -> &'static str {
    r#"# flx configuration file.
# CLI flags always win over values here.

[global]
# log_level = "info"           # off|error|warn|info|debug|trace
# quiet = true
# no_color = true
# skip_version_check = true

[fetch]
# providers = ["geonode", "proxyscrape"]   # --provider
# exclude_providers = ["github-raw"]       # --exclude-provider
# source_urls = ["https://example.com/proxies.txt"]  # --source-url
# with_geo = true
# with_ip_type = true
# ip_type = "residential"                  # residential|datacenter|mobile|unknown
# countries = ["US", "DE"]                 # --countries
# exclude_countries = ["RU", "CN"]         # --exclude-country
# concurrency = 25                         # --fetch-concurrency
# cache_ttl = 15                           # minutes, --cache-ttl
# refresh_cache = false
# offline = false
# delay_ms = 0                             # --fetch-delay-ms
# fallback_threshold = 500
# phase_timeout = 30                       # seconds, --fetch-phase-timeout
# no_dedup = false
# provider_timeout = 0                     # seconds

[output]
# format = "default"                       # default|text|json|json-lines|pretty-json|csv|prefix|pac|proxychains
# limit = 50
# output_file = "proxies.csv"              # relative to the current directory
# sort = "response-time"                   # avg-response|response-time|country|anonymity
# order = "asc"                            # asc|desc
# shuffle = false
# append = false
# min_anonymity = "anonymous"              # transparent|anonymous|elite|unknown
# levels = ["anonymous", "elite"]
# max_response_time = 5.0
# min_response_time = 0.1
# exclude_types = ["SOCKS4"]               # --exclude-type

[validate]
# types = ["HTTP:Elite", "SOCKS5", "HTTP+HTTPS"]
# concurrency = 500                        # --max-connections
# max_attempts = 1
# retry_delay_ms = 0
# timeout = 3
# http_judges = ["http://azenv.net/"]      # --http-judge-urls
# https_judges = ["https://aranguren.org/azenv.php"]  # --https-judge-urls
# insecure = false                         # --no-verify-tls
# support_cookies = false
# support_referer = false
# report_failures = "failures.jsonl"
"#
}

/// Serialises the merged config back to TOML for `flx config show`.
pub fn to_toml(cfg: &FileConfig) -> String {
    let s = toml::to_string(cfg).unwrap_or_default();
    if s.trim().is_empty() {
        "# no config values set".to_owned()
    } else {
        s
    }
}

// ── Error type ────────────────────────────────────────────────────────

use std::fmt;

#[derive(Debug)]
pub struct ConfigError {
    path: Option<PathBuf>,
    message: String,
}

impl ConfigError {
    fn parse(source: toml::de::Error) -> Self {
        Self {
            path: None,
            message: source.to_string(),
        }
    }
    fn message(message: impl Into<String>) -> Self {
        Self {
            path: None,
            message: message.into(),
        }
    }
    fn value(key: &str, value: &str, allowed: &str) -> Self {
        Self::message(format!(
            "`{key}`: invalid value `{value}` (allowed: {allowed})"
        ))
    }
    fn with_path(mut self, path: &Path) -> Self {
        self.path = Some(path.to_owned());
        self
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(path) => write!(f, "config error in {}: {}", path.display(), self.message),
            None => write!(f, "config error: {}", self.message),
        }
    }
}

impl std::error::Error for ConfigError {}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::argument::{Cli, Command};
    use clap::{CommandFactory, FromArgMatches};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_dir(stem: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "flx_config_{stem}_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn parse_cli(args: &[&str]) -> (Cli, clap::ArgMatches) {
        let mut full = vec!["flx"];
        full.extend_from_slice(args);
        let matches = Cli::command()
            .try_get_matches_from(full)
            .expect("test args must parse");
        let cli = Cli::from_arg_matches(&matches).expect("cli from matches");
        (cli, matches)
    }

    // ── parse ──

    #[test]
    fn parse_empty_config_is_a_no_op() {
        let cfg = parse("").unwrap();
        assert!(cfg.global.is_none());
        assert!(cfg.fetch.is_none());
        assert!(cfg.output.is_none());
        assert!(cfg.validate.is_none());
        assert!(cfg.unknown_sections.is_empty());
        // comment-only
        assert!(parse("# just a comment\n").unwrap().fetch.is_none());
    }

    #[test]
    fn parse_reads_every_section() {
        let text = r#"
[global]
log_level = "info"
quiet = true
skip_version_check = true
[fetch]
providers = ["geonode"]
countries = ["US", "DE"]
concurrency = 10
cache_ttl = 30
[output]
format = "csv"
limit = 50
min_anonymity = "anonymous"
[validate]
types = ["HTTP:Elite", "SOCKS5"]
timeout = 5
http_judges = ["http://azenv.net/"]
"#;
        let cfg = parse(text).unwrap();
        let g = cfg.global.unwrap();
        assert_eq!(g.log_level.as_deref(), Some("info"));
        assert_eq!(g.quiet, Some(true));
        let f = cfg.fetch.unwrap();
        assert_eq!(f.providers.as_deref(), Some(&["geonode".to_owned()][..]));
        let o = cfg.output.unwrap();
        assert_eq!(o.limit, Some(50));
        let v = cfg.validate.unwrap();
        assert_eq!(
            v.types.as_deref(),
            Some(&["HTTP:Elite".to_owned(), "SOCKS5".to_owned()][..])
        );
    }

    #[test]
    fn parse_rejects_unknown_keys_inside_sections() {
        assert!(parse("[fetch]\ncache_tll = 5\n").is_err());
        assert!(parse("[output]\nbogus = 1\n").is_err());
    }

    #[test]
    fn parse_collects_unknown_top_level_sections() {
        let cfg = parse("[serve]\nport = 8080\n[fetch]\nwith_geo = true\n").unwrap();
        assert_eq!(cfg.unknown_sections, vec!["serve".to_owned()]);
        assert!(cfg.fetch.is_some());
    }

    #[test]
    fn parse_rejects_invalid_enum_values() {
        for bad in [
            "[output]\nformat = \"bogus\"\n",
            "[output]\nsort = \"bogus\"\n",
            "[output]\norder = \"sideways\"\n",
            "[output]\nmin_anonymity = \"super\"\n",
            "[output]\nlevels = [\"elite\", \"super\"]\n",
            "[fetch]\nip_type = \"nope\"\n",
            "[global]\nlog_level = \"chatty\"\n",
        ] {
            assert!(parse(bad).is_err(), "must reject: {bad}");
        }
    }

    #[test]
    fn parse_rejects_invalid_types_and_judge_urls() {
        assert!(parse("[validate]\ntypes = [\"BOGUS\"]\n").is_err());
        assert!(parse("[output]\nexclude_types = [\"NOPE\"]\n").is_err());
        assert!(parse("[validate]\nhttp_judges = [\"ftp://x\"]\n").is_err());
        assert!(parse("[validate]\nhttps_judges = [\"not a url\"]\n").is_err());
    }

    // ── merge ──

    #[test]
    fn merge_project_overrides_user_per_field() {
        let user =
            parse("[fetch]\ncountries = [\"US\"]\nconcurrency = 5\n[output]\nformat = \"csv\"\n")
                .unwrap();
        let project = parse("[fetch]\ncountries = [\"DE\"]\n[global]\nquiet = true\n").unwrap();
        let merged = merge(project, user);
        assert_eq!(
            merged.fetch.as_ref().unwrap().countries.as_deref(),
            Some(&["DE".to_owned()][..])
        );
        assert_eq!(merged.fetch.as_ref().unwrap().concurrency, Some(5));
        assert_eq!(merged.global.as_ref().unwrap().quiet, Some(true));
        assert_eq!(
            merged.output.as_ref().unwrap().format.as_deref(),
            Some("csv")
        );
        assert!(merged.unknown_sections.is_empty());
    }

    // ── discover ──

    #[test]
    fn discover_finds_project_and_user_files() {
        let dir = unique_dir("discover");
        let config_home = dir.join("xdg");
        let cwd = dir.join("work");
        std::fs::create_dir_all(config_home.join("flx")).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::write(config_home.join("flx").join("config.toml"), "").unwrap();
        std::fs::write(cwd.join(".flx.toml"), "").unwrap();

        let both = discover(&config_home, &cwd);
        assert_eq!(both.project, Some(cwd.join(".flx.toml")));
        assert_eq!(both.user, Some(config_home.join("flx").join("config.toml")));

        let none = discover(&dir.join("no_xdg"), &dir.join("no_cwd"));
        assert!(none.project.is_none());
        assert!(none.user.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── load ──

    #[test]
    fn load_no_config_returns_none() {
        let loaded = load(None, None, true, Path::new("/nonexistent"), Path::new("/")).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn load_explicit_path_reads_the_file() {
        let dir = unique_dir("explicit");
        let path = dir.join("custom.toml");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "[output]\nformat = \"csv\"\n").unwrap();
        let loaded = load(Some(&path), None, false, &dir, &dir).unwrap().unwrap();
        assert_eq!(
            loaded.output.as_ref().unwrap().format.as_deref(),
            Some("csv")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_explicit_path_fails() {
        let dir = unique_dir("missing");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nope.toml");
        let error = load(Some(&path), None, false, &dir, &dir).unwrap_err();
        assert!(error.to_string().contains("nope.toml"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_merges_project_over_user() {
        let dir = unique_dir("layered");
        let config_home = dir.join("xdg");
        let cwd = dir.join("work");
        std::fs::create_dir_all(config_home.join("flx")).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::write(
            config_home.join("flx").join("config.toml"),
            "[fetch]\ncountries = [\"US\"]\nconcurrency = 5\n",
        )
        .unwrap();
        std::fs::write(cwd.join(".flx.toml"), "[fetch]\ncountries = [\"DE\"]\n").unwrap();
        let cfg = load(None, None, false, &config_home, &cwd)
            .unwrap()
            .unwrap();
        let fetch = cfg.fetch.unwrap();
        assert_eq!(fetch.countries.as_deref(), Some(&["DE".to_owned()][..]));
        assert_eq!(fetch.concurrency, Some(5));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── apply ──

    #[test]
    fn apply_cli_flags_beat_config_values() {
        let cfg = parse("[output]\nformat = \"csv\"\nlimit = 50\n").unwrap();
        let (mut cli, matches) = parse_cli(&["find", "-f", "json"]);
        apply_config(&mut cli, &cfg, &matches);
        let find = match cli.command {
            Some(Command::Find(find)) => find,
            _ => panic!("expected find"),
        };
        assert_eq!(find.output.format, "json");
        assert_eq!(find.output.limit, 50);
    }

    #[test]
    fn apply_fills_scalars_options_and_vectors_from_config() {
        let cfg = parse(
            "[output]\nformat = \"csv\"\nmax_response_time = 2.5\nlevels = [\"elite\"]\n\
             [fetch]\nproviders = [\"geonode\"]\nconcurrency = 9\n\
             [validate]\ntypes = [\"SOCKS5\"]\ntimeout = 7\n",
        )
        .unwrap();
        let (mut cli, matches) = parse_cli(&["find"]);
        apply_config(&mut cli, &cfg, &matches);
        let find = match cli.command {
            Some(Command::Find(find)) => find,
            _ => panic!("expected find"),
        };
        assert_eq!(find.output.format, "csv");
        assert_eq!(find.output.max_response_time, Some(2.5));
        assert_eq!(find.output.levels, vec!["elite".to_owned()]);
        assert_eq!(find.fetcher.provider, vec!["geonode".to_owned()]);
        assert_eq!(find.fetcher.fetch_concurrency, 9);
        assert_eq!(find.validator.types, vec!["SOCKS5".to_owned()]);
        assert_eq!(find.validator.timeout, 7);
    }

    #[test]
    fn apply_skips_sections_absent_from_config() {
        let cfg = parse("[fetch]\nwith_geo = true\n").unwrap();
        let (mut cli, matches) = parse_cli(&["find"]);
        apply_config(&mut cli, &cfg, &matches);
        let find = match cli.command {
            Some(Command::Find(find)) => find,
            _ => panic!("expected find"),
        };
        assert!(find.fetcher.with_geo);
        assert_eq!(find.output.format, "default");
        assert_eq!(find.output.limit, 0);
    }

    #[test]
    fn apply_global_quiet_respects_verbose() {
        let cfg = parse("[global]\nquiet = true\nno_color = true\n").unwrap();
        let (mut cli, matches) = parse_cli(&["--verbose", "find"]);
        apply_config(&mut cli, &cfg, &matches);
        assert!(!cli.quiet, "--verbose must beat config quiet");
        assert!(cli.no_color, "unrelated globals still apply");

        let (mut cli, matches) = parse_cli(&["find"]);
        apply_config(&mut cli, &cfg, &matches);
        assert!(cli.quiet);
    }

    #[test]
    fn apply_config_reaches_library_configs() {
        let cfg = parse(
            "[fetch]\nconcurrency = 9\ncache_ttl = 30\n\
             [validate]\ntimeout = 8\nmax_attempts = 3\n",
        )
        .unwrap();
        let (mut cli, matches) = parse_cli(&["find"]);
        apply_config(&mut cli, &cfg, &matches);
        let find = match cli.command {
            Some(Command::Find(find)) => find,
            _ => panic!("expected find"),
        };
        let fetcher = crate::fetcher_config(&find.fetcher);
        assert_eq!(fetcher.concurrency_limit, 9);
        assert_eq!(
            fetcher.cache_ttl,
            Some(std::time::Duration::from_secs(30 * 60))
        );
        let validator = crate::validator_config(&find.validator, Vec::new(), Vec::new(), false);
        assert_eq!(validator.request_timeout, 8);
        assert_eq!(validator.max_attempts, 3);
    }

    // ── to_toml ──

    #[test]
    fn to_toml_round_trips_set_values() {
        let cfg = parse("[global]\nquiet = true\n[fetch]\nwith_geo = true\n").unwrap();
        let text = to_toml(&cfg);
        assert!(text.contains("quiet = true"), "{text}");
        assert!(text.contains("with_geo = true"), "{text}");
        let reparsed = parse(&text).unwrap();
        assert_eq!(reparsed.global.unwrap().quiet, Some(true));
        assert_eq!(reparsed.fetch.unwrap().with_geo, Some(true));
    }

    // ── template ──

    #[test]
    fn template_mentions_every_section() {
        let text = template();
        for section in &["[global]", "[fetch]", "[output]", "[validate]"] {
            assert!(text.contains(section), "missing {section} in template");
        }
    }
}
