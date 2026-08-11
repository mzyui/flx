use clap::builder::styling::AnsiColor;
use clap::builder::{PossibleValue, Styles, TypedValueParser};
use clap::Parser;

fn get_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Yellow.on_default())
        .usage(AnsiColor::Green.on_default())
        .literal(AnsiColor::BrightGreen.on_default())
        .placeholder(AnsiColor::Cyan.on_default())
}

fn parse_positive_usize(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| "must be a positive integer".to_owned())?;
    if parsed == 0 {
        Err("must be greater than zero".to_owned())
    } else {
        Ok(parsed)
    }
}

/// Protocol values accepted by `--types`, without the dynamic `CONNECT:<port>`.
const VALID_TYPE_NAMES: &[&str] = &[
    "HTTP",
    "HTTP:Transparent",
    "HTTP:Anonymous",
    "HTTP:Elite",
    "HTTPS",
    "HTTPS:Transparent",
    "HTTPS:Anonymous",
    "HTTPS:Elite",
    "SOCKS4",
    "SOCKS5",
];

/// Validates a single `--types` value against the fixed protocol names plus
/// the dynamic `CONNECT:<port>` form.
fn is_valid_type_value(value: &str) -> bool {
    VALID_TYPE_NAMES.contains(&value)
        || value
            .strip_prefix("CONNECT:")
            .is_some_and(|port| port.parse::<u16>().is_ok())
}

/// `value_parser` for `--types`.
///
/// A static `[PossibleValue]` list cannot express `CONNECT:<port>` (the port is
/// dynamic), so validation is a typed parser over the same documented set.
#[derive(Clone)]
struct TypesValueParser;

impl TypedValueParser for TypesValueParser {
    type Value = String;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value
            .to_str()
            .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::InvalidValue).with_cmd(cmd))?;
        if is_valid_type_value(value) {
            Ok(value.to_owned())
        } else {
            let mut error = clap::Error::new(clap::error::ErrorKind::InvalidValue).with_cmd(cmd);
            error.insert(
                clap::error::ContextKind::InvalidArg,
                clap::error::ContextValue::String(
                    arg.map(|arg| format!("--{}", arg.get_id()))
                        .unwrap_or_else(|| "--types".to_owned()),
                ),
            );
            error.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(value.to_string()),
            );
            error.insert(
                clap::error::ContextKind::ValidValue,
                clap::error::ContextValue::Strings(
                    VALID_TYPE_NAMES
                        .iter()
                        .map(|name| name.to_string())
                        .chain(std::iter::once("CONNECT:<port>".to_string()))
                        .collect(),
                ),
            );
            Err(error)
        }
    }
}

/// Command-line interface definition for the proxy application.
#[derive(Parser, Debug, Clone)]
#[command(
    after_help = "Suggestions and bug reports are greatly appreciated:\nhttps://github.com/zevtyardt/fluxy/issues",
    styles=get_styles()
)]
pub struct Cli {
    /// List of ISO country codes to filter proxies by location.
    #[arg(short, long, num_args(1..))]
    pub countries: Vec<String>,

    /// Enable GeoIP lookup so every proxy carries country information in the
    /// output without filtering by location. Requires downloading GeoLite2-City
    /// on first use; pair with --countries to also filter.
    #[arg(long)]
    pub with_geo: bool,

    /// Maximum number of concurrent proxy checks.
    #[arg(
        short,
        long,
        default_value_t = fluxy::validator::DEFAULT_CONCURRENCY_LIMIT as u64,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub max_connections: u64,

    /// Maximum number of proxy sources fetched concurrently.
    ///
    /// Separate from `--max-connections`: fetching touches a few dozen source
    /// URLs, while validation touches thousands of proxies.
    #[arg(
        long,
        default_value_t = fluxy::fetcher::DEFAULT_CONCURRENCY_LIMIT as u64,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub fetch_concurrency: u64,

    /// Freshness in minutes for the local provider-source cache.
    ///
    /// Fetched source bodies are stored under the platform data dir and reused
    /// within this window, so repeat runs skip most of the network startup cost.
    /// `0` disables the cache entirely.
    #[arg(
        long,
        default_value_t = fluxy::fetcher::DEFAULT_CACHE_TTL_MINUTES,
        value_parser = clap::value_parser!(u64)
    )]
    pub cache_ttl: u64,

    /// Ignore the local provider-source cache and fetch every source again.
    ///
    /// The freshly fetched bodies still repopulate the cache.
    #[arg(long, default_value_t = false)]
    pub refresh_cache: bool,

    /// Timeout duration in seconds before giving up.
    #[arg(long, default_value = "3", value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout: u64,

    /// Log level for application output.
    #[arg(
        long = "log",
        default_value = "off",
        value_parser([
            PossibleValue::new("debug"),
            PossibleValue::new("info"),
            PossibleValue::new("warn"),
            PossibleValue::new("error"),
            PossibleValue::new("trace"),
            PossibleValue::new("off"),
        ])
    )]
    pub log_level: String,

    /// Output format for the results.
    #[arg(
        short,
        long,
        default_value = "default",
        value_parser([
            PossibleValue::new("default"),
            PossibleValue::new("text"),
            PossibleValue::new("json"),
            PossibleValue::new("pretty-json"),
        ])
    )]
    pub format: String,

    /// Maximum number of proxies to retrieve.
    #[arg(short, long, default_value = "0")]
    pub limit: usize,

    /// File path to save the retrieved proxies. If not provided, output will go to the console.
    #[arg(short, long)]
    pub output_file: Option<std::path::PathBuf>,

    /// Proxy types (protocols) to validate. [possible values: HTTP{:Transparent,
    /// :Anonymous,:Elite}, HTTPS{:Transparent,:Anonymous,:Elite}, SOCKS4, SOCKS5,
    /// CONNECT:<port>]
    #[arg(
        short = 't',
        long = "types",
        help_heading = "Validate",
        num_args(1..),
        value_parser = TypesValueParser,
    )]
    pub types: Vec<String>,

    /// File path containing proxies. Overrides providers if specified.
    #[arg(long, help_heading = "Validate", requires("types"))]
    pub file: Option<std::path::PathBuf>,

    /// Maximum number of attempts to validate a proxy.
    #[arg(
        long,
        default_value = "1",
        value_parser = parse_positive_usize,
        help_heading = "Validate",
        requires("types")
    )]
    pub max_attempts: usize,

    /// Online judges used to validate plain HTTP proxy forwarding.
    ///
    /// May be supplied multiple times or as a comma-separated list. Every URL is
    /// preflighted at startup; those that fail are dropped and the survivors are
    /// used round-robin. If all fail, the run aborts with a message.
    #[arg(
        long,
        default_value = "http://azenv.net/,http://wfuchs.de/azenv.php,http://proxyjudge.us/,http://shinh.org/env.cgi",
        value_delimiter = ',',
        help_heading = "Validate",
        requires = "types"
    )]
    pub http_judge_urls: Vec<String>,

    /// Online HTTPS judges used for HTTPS, CONNECT and SOCKS tunnels.
    ///
    /// Same contract as `--http-judge-urls` but reached over a verified TLS
    /// connection to port 443.
    #[arg(
        long,
        default_value = "https://aranguren.org/azenv.php,https://wfuchs.de/azenv.php",
        value_delimiter = ',',
        help_heading = "Validate",
        requires = "types"
    )]
    pub https_judge_urls: Vec<String>,

    /// Disable TLS certificate validation for judge connections.
    ///
    /// Off by default. Enable only for self-hosted judges that use self-signed
    /// certificates; leaving it on for public HTTPS judges lets a MITM on the
    /// judge path forge validation responses.
    #[arg(long, default_value_t = false)]
    pub insecure: bool,
}
