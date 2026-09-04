use clap::builder::PossibleValue;
use clap::builder::TypedValueParser;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::LazyLock;

pub(crate) fn is_valid_type_value(value: &str) -> bool {
    // Accept every token the protocol parser understands (including the
    // `HTTP:Elite`-style anonymity annotations) in any `+` combination.
    value
        .split('+')
        .all(|part| !part.is_empty() && flx::Protocol::from_str(part).is_ok())
}

fn parse_positive_usize(value: &str) -> Result<usize, String> {
    let n: usize = value
        .parse()
        .map_err(|_| format!("{value} is not a valid integer"))?;
    if n == 0 {
        return Err(format!("{value} must be greater than zero"));
    }
    Ok(n)
}

#[derive(Clone)]
struct TypesValueParser;

impl TypedValueParser for TypesValueParser {
    type Value = String;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let raw = value.to_string_lossy();
        if is_valid_type_value(&raw) {
            Ok(raw.into_owned())
        } else {
            let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
            err.insert(
                clap::error::ContextKind::InvalidArg,
                clap::error::ContextValue::String("TYPES".to_owned()),
            );
            err.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(raw.into_owned()),
            );
            Err(err)
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "flx",
    version,
    about = "Proxy scraper and validator",
    after_help = "Suggestions and bug reports: https://github.com/mzyui/flx/issues"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Suppress non-essential output.
    #[arg(short = 'q', long, help_heading = "Global")]
    pub quiet: bool,

    /// Disable colored output.
    #[arg(long, help_heading = "Global")]
    pub no_color: bool,

    /// Log level for application output.
    #[arg(
        long = "log",
        default_value = "off",
        help_heading = "Global",
        value_parser([
            PossibleValue::new("debug").help("Show debug messages"),
            PossibleValue::new("info").help("Show informational messages"),
            PossibleValue::new("warn").help("Show warnings only"),
            PossibleValue::new("error").help("Show errors only"),
            PossibleValue::new("trace").help("Show all messages"),
            PossibleValue::new("off").help("No log output"),
        ])
    )]
    pub log_level: String,

    /// Skip the background check for newer flx releases.
    #[arg(long, help_heading = "Global")]
    pub skip_version_check: bool,

    /// Path to a config file overriding the discovery defaults.
    #[arg(long, global = true, help_heading = "Global")]
    pub config: Option<PathBuf>,

    /// Skip loading any config file.
    #[arg(long, global = true, help_heading = "Global")]
    pub no_config: bool,

    /// Override the `quiet` value set by the config file.
    #[arg(long, global = true, help_heading = "Global")]
    pub verbose: bool,
}

/// The pipeline commands available in the CLI.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scrape proxies from the built-in providers and print them.
    Grab(FetchArgs),
    /// Validate proxies from a file or the built-in providers against online judges.
    Find(FindArgs),
    /// Serve validated proxies through a local rotating endpoint.
    Serve(ServeArgs),
    /// Download and verify the GeoLite2 GeoIP database.
    #[command(name = "geo-update")]
    GeoUpdate,
    /// Manage the flx configuration file.
    Config(ConfigCmd),
}

/// Options shared by every command that render proxies.
#[derive(Args, Debug, Clone)]
pub struct OutputOptions {
    /// Output format for the results.
    #[arg(
        short = 'f',
        long,
        default_value = "default",
        help_heading = "Output",
        value_parser([
            PossibleValue::new("csv").help("Comma-separated ip,port,type,response_time,country,ip_type"),
            PossibleValue::new("default").help("Human-readable summary (json-lines when piped; -o infers format from extension)"),
            PossibleValue::new("json").help("Compact JSON array"),
            PossibleValue::new("json-lines").help("One JSON object per line"),
            PossibleValue::new("pac").help("Proxy Auto-Config JavaScript file"),
            PossibleValue::new("prefix").help("socks5://ip:port one per line"),
            PossibleValue::new("pretty-json").help("Indented JSON array"),
            PossibleValue::new("proxychains").help("proxychains.conf format: type ip port"),
            PossibleValue::new("text").help("ip:port one per line"),
        ])
    )]
    pub format: String,

    /// Maximum number of proxies to retrieve.
    #[arg(short = 'l', long, default_value = "0", help_heading = "Output")]
    pub limit: usize,

    /// File path to save the retrieved proxies.
    #[arg(short = 'o', long, help_heading = "Output")]
    pub output_file: Option<PathBuf>,

    /// Sort the output by this field.
    #[arg(
        short = 's',
        long,
        help_heading = "Output",
        value_parser([
            PossibleValue::new("avg-response").help("Average response time"),
            PossibleValue::new("country").help("Country ISO code"),
            PossibleValue::new("anonymity").help("Anonymity level"),
            PossibleValue::new("response-time").help("Response time"),
        ])
    )]
    pub sort: Option<String>,

    /// Sort direction.
    #[arg(
        long,
        default_value = "asc",
        help_heading = "Output",
        value_parser([
            PossibleValue::new("asc").help("Ascending order"),
            PossibleValue::new("desc").help("Descending order"),
        ])
    )]
    pub order: String,

    /// Only keep proxies whose best anonymity is at least this level.
    #[arg(
        short = 'a',
        long,
        help_heading = "Filtering",
        value_parser([
            PossibleValue::new("transparent").help("No anonymity guarantee"),
            PossibleValue::new("anonymous").help("Hides client IP"),
            PossibleValue::new("elite").help("Hides proxy usage entirely"),
            PossibleValue::new("unknown").help("Anonymity could not be determined"),
        ])
    )]
    pub min_anonymity: Option<String>,

    /// Only keep proxies whose anonymity is one of these levels.
    #[arg(long, num_args(1..), help_heading = "Filtering", value_parser([
        PossibleValue::new("transparent").help("No anonymity guarantee"),
        PossibleValue::new("anonymous").help("Hides client IP"),
        PossibleValue::new("elite").help("Hides proxy usage entirely"),
        PossibleValue::new("unknown").help("Anonymity could not be determined"),
    ]))]
    pub levels: Vec<String>,

    /// Drop proxies slower than this many seconds.
    #[arg(long, help_heading = "Filtering")]
    pub max_response_time: Option<f64>,

    /// Drop proxies faster than this many seconds.
    #[arg(long, help_heading = "Filtering")]
    pub min_response_time: Option<f64>,

    /// Skip proxies supporting one of these protocol types.
    #[arg(long, num_args(1..), value_parser = TypesValueParser, help_heading = "Filtering")]
    pub exclude_type: Vec<String>,

    /// Randomize the order of the results.
    #[arg(long, help_heading = "Output")]
    pub shuffle: bool,

    /// Append to the output file instead of truncating it.
    #[arg(long, help_heading = "Output")]
    pub append: bool,
}

/// Options controlling how proxies are scraped from the built-in providers.
#[derive(Args, Debug, Clone)]
pub struct FetcherArgs {
    /// List of ISO country codes to filter proxies by location.
    #[arg(short = 'c', long, num_args(1..), help_heading = "Fetching")]
    pub countries: Vec<String>,

    /// Skip proxies located in these ISO country codes.
    #[arg(long, num_args(1..), help_heading = "Fetching")]
    pub exclude_country: Vec<String>,

    /// Enable GeoIP lookup without filtering by location.
    #[arg(short = 'g', long, help_heading = "Fetching")]
    pub with_geo: bool,

    /// Annotate fetched proxies with their IP class.
    #[arg(long, help_heading = "Fetching")]
    pub with_ip_type: bool,

    /// Keep only proxies classified as this IP type.
    #[arg(
        long,
        help_heading = "Fetching",
        value_parser = [
            PossibleValue::new("residential").help("Home and local ISP networks"),
            PossibleValue::new("datacenter").help("Cloud and hosting providers"),
            PossibleValue::new("mobile").help("Mobile carrier networks"),
            PossibleValue::new("unknown").help("IP type could not be determined"),
        ]
    )]
    pub ip_type: Option<String>,

    /// Scrape only the named providers.
    #[arg(short = 'p', long, help_heading = "Fetching")]
    pub provider: Vec<String>,

    /// Skip the named providers.
    #[arg(long, help_heading = "Fetching")]
    pub exclude_provider: Vec<String>,

    /// Fetch an additional proxy list from this plaintext URL.
    #[arg(long, help_heading = "Fetching")]
    pub source_url: Vec<String>,

    /// Serve providers only from the local cache.
    #[arg(long, help_heading = "Fetching")]
    pub offline: bool,

    /// List the providers and sources that would be fetched, then exit.
    #[arg(long, help_heading = "Fetching")]
    pub dry_run: bool,

    /// List the available proxy providers and their sources, then exit.
    #[arg(long, help_heading = "Fetching")]
    pub list_providers: bool,

    /// Maximum number of proxy sources fetched concurrently.
    #[arg(long, default_value_t = flx::fetcher::DEFAULT_CONCURRENCY_LIMIT, help_heading = "Fetching")]
    pub fetch_concurrency: usize,

    /// Freshness in minutes for the local provider-source cache.
    #[arg(long, default_value_t = flx::fetcher::DEFAULT_CACHE_TTL_MINUTES, help_heading = "Fetching")]
    pub cache_ttl: u64,

    /// Ignore the local provider-source cache and fetch every source again.
    #[arg(long, help_heading = "Fetching")]
    pub refresh_cache: bool,

    /// Minimum delay in milliseconds between requests to the same host.
    #[arg(long, default_value_t = 0, help_heading = "Fetching")]
    pub fetch_delay_ms: u64,

    /// Skip fallback providers once this many proxies are already collected.
    #[arg(long, help_heading = "Fetching")]
    pub fallback_threshold: Option<usize>,

    /// Maximum seconds to wait for the fallback provider phase (0 = unbounded).
    #[arg(long, default_value_t = flx::fetcher::PRIMARY_PHASE_TIMEOUT.as_secs(), help_heading = "Fetching")]
    pub fetch_phase_timeout: u64,

    /// Disable deduplication of identical endpoints across sources.
    #[arg(long, help_heading = "Fetching")]
    pub no_dedup: bool,

    /// Override the per-source fetch timeout in seconds (0 = provider default).
    #[arg(long, default_value_t = 0, help_heading = "Fetching")]
    pub provider_timeout: u64,
}

/// `flx grab`: scrape proxies from the built-in providers and print them.
#[derive(Args, Debug)]
pub struct FetchArgs {
    #[command(flatten)]
    pub fetcher: FetcherArgs,

    #[command(flatten)]
    pub output: OutputOptions,
}

/// Judge defaults joined once for clap's `default_value`, so the CLI and the
/// library cannot drift apart.
static HTTP_JUDGE_DEFAULTS: LazyLock<String> =
    LazyLock::new(|| flx::validator::DEFAULT_HTTP_JUDGE_URLS.join(","));
static HTTPS_JUDGE_DEFAULTS: LazyLock<String> =
    LazyLock::new(|| flx::validator::DEFAULT_HTTPS_JUDGE_URLS.join(","));

/// Options controlling proxy validation against online judges.
#[derive(Args, Debug, Clone)]
pub struct ValidatorArgs {
    /// Proxy types to validate (HTTP, HTTPS, SOCKS4, SOCKS5, CONNECT:80, CONNECT:25).
    #[arg(num_args(1..), value_parser = TypesValueParser, help_heading = "Validation")]
    pub types: Vec<String>,

    /// Maximum number of concurrent proxy checks.
    #[arg(short = 'm', long, default_value_t = flx::validator::DEFAULT_CONCURRENCY_LIMIT, help_heading = "Validation")]
    pub max_connections: usize,

    /// Maximum number of attempts to validate a proxy.
    #[arg(long, default_value = "1", value_parser = parse_positive_usize, help_heading = "Validation")]
    pub max_attempts: usize,

    /// Delay in milliseconds between validation attempts of the same proxy.
    #[arg(long, default_value_t = 0, help_heading = "Validation")]
    pub retry_delay_ms: u64,

    /// Timeout duration in seconds before giving up.
    #[arg(long, default_value_t = 3, help_heading = "Validation")]
    pub timeout: u64,

    /// Online judges used to validate plain HTTP proxy forwarding.
    #[arg(
        long,
        default_value = HTTP_JUDGE_DEFAULTS.as_str(),
        value_delimiter = ',',
        help_heading = "Validation"
    )]
    pub http_judge_urls: Vec<String>,

    /// Online judges used for HTTPS, CONNECT and SOCKS tunnels.
    #[arg(
        long,
        default_value = HTTPS_JUDGE_DEFAULTS.as_str(),
        value_delimiter = ',',
        help_heading = "Validation"
    )]
    pub https_judge_urls: Vec<String>,

    /// Disable TLS certificate verification for HTTPS judges.
    #[arg(long, help_heading = "Validation")]
    pub no_verify_tls: bool,

    /// Require proxies to forward cookie headers to the judge.
    #[arg(long, help_heading = "Validation")]
    pub support_cookies: bool,

    /// Require proxies to forward referer headers to the judge.
    #[arg(long, help_heading = "Validation")]
    pub support_referer: bool,

    /// Write a machine-readable JSON-lines report of failed proxies to this path.
    #[arg(long, help_heading = "Validation")]
    pub report_failures: Option<PathBuf>,

    /// Path to a file containing proxy endpoints (ip:port per line).
    #[arg(long, alias = "file", num_args(1..), help_heading = "Validation")]
    pub files: Vec<PathBuf>,
}

/// `flx find`: validate proxies from a file or the built-in providers.
#[derive(Args, Debug)]
pub struct FindArgs {
    #[command(flatten)]
    pub fetcher: FetcherArgs,

    #[command(flatten)]
    pub output: OutputOptions,

    #[command(flatten)]
    pub validator: ValidatorArgs,
}

/// `flx serve`: expose validated proxies through a local rotating endpoint.
#[derive(Args, Debug)]
pub struct ServeArgs {
    #[command(flatten)]
    pub fetcher: FetcherArgs,

    #[command(flatten)]
    pub validator: ValidatorArgs,

    /// Address for the rotating endpoint to bind.
    #[arg(long, default_value = "127.0.0.1", help_heading = "Serve")]
    pub bind: std::net::IpAddr,

    /// Port for the rotating endpoint.
    #[arg(
        long,
        default_value_t = flx::rotator::DEFAULT_PORT,
        help_heading = "Serve"
    )]
    pub port: u16,

    /// Rotation strategy for picking the upstream of each connection.
    #[arg(
        long,
        value_parser(["round-robin", "random"]),
        default_value = "round-robin",
        help_heading = "Serve"
    )]
    pub strategy: String,

    /// Maximum number of validated proxies kept in the rotation pool.
    #[arg(long, help_heading = "Serve")]
    pub pool_size: Option<usize>,

    /// Validated proxies required before the endpoint starts serving.
    #[arg(
        long,
        default_value_t = flx::rotator::DEFAULT_MIN_READY,
        help_heading = "Serve"
    )]
    pub min_ready: usize,

    /// Seconds between pool refill runs against the providers.
    #[arg(long, help_heading = "Serve")]
    pub refresh_secs: Option<u64>,

    /// End-to-end budget per client connection, in seconds.
    #[arg(long, help_heading = "Serve")]
    pub request_timeout: Option<u64>,

    /// Require `user:pass` basic proxy authentication from clients.
    #[arg(long, help_heading = "Serve")]
    pub auth: Option<String>,
}

/// `flx config`: manage the configuration file.
#[derive(Args, Debug)]
pub struct ConfigCmd {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Print the config file path(s) in effect.
    Path,
    /// Write a commented template config file.
    Init {
        /// Write to this path instead of the default location.
        #[arg(long)]
        path: Option<PathBuf>,
        /// Overwrite an existing config file.
        #[arg(long)]
        force: bool,
    },
    /// Print the merged configuration as TOML.
    Show,
    /// Interactively set up a config file.
    Wizard(WizardArgs),
}

/// Options for `flx config wizard`.
#[derive(Args, Debug, Default)]
pub struct WizardArgs {
    /// Write to this path instead of the default location.
    #[arg(long)]
    pub path: Option<PathBuf>,
    /// Write the user config instead of the project one.
    #[arg(long)]
    pub user: bool,
    /// Overwrite an existing config file.
    #[arg(long)]
    pub force: bool,
    /// Non-interactive: answer every question with its default.
    #[arg(short = 'y', long)]
    pub yes: bool,
}
