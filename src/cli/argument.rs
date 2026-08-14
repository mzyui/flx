use clap::builder::styling::AnsiColor;
use clap::builder::{PossibleValue, Styles, TypedValueParser};
use clap::{Args, Parser, Subcommand};

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

fn is_valid_type_value(value: &str) -> bool {
    value.split('+').all(|part| {
        VALID_TYPE_NAMES.contains(&part)
            || part
                .strip_prefix("CONNECT:")
                .is_some_and(|port| port.parse::<u16>().is_ok())
    })
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
        let value = value
            .to_str()
            .ok_or_else(|| clap::Error::new(clap::error::ErrorKind::InvalidValue).with_cmd(cmd))?;
        if is_valid_type_value(value) {
            Ok(value.to_owned())
        } else {
            let mut error = clap::Error::new(clap::error::ErrorKind::InvalidValue).with_cmd(cmd);
            error.insert(
                clap::error::ContextKind::InvalidArg,
                clap::error::ContextValue::String("TYPES".to_owned()),
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
                        .chain(std::iter::once("HTTP+HTTPS".to_string()))
                        .collect(),
                ),
            );
            Err(error)
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "flx",
    after_help = "Suggestions and bug reports are greatly appreciated:\nhttps://github.com/zevtyardt/flx/issues",
    styles=get_styles()
)]
pub struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Option<Command>,

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

    /// Generate a shell completion script and exit.
    #[arg(long, value_enum, value_name = "SHELL")]
    pub generate_completions: Option<clap_complete::Shell>,

    /// Generate a man page and exit.
    #[arg(long, default_value_t = false)]
    pub generate_man_page: bool,

    /// Suppress non-essential output, such as the validation progress line.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,

    /// Disable colored output, including colors in the validation progress line.
    #[arg(long, default_value_t = false)]
    pub no_color: bool,
}

/// The pipeline commands available in the CLI.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scrape proxies from the built-in providers and print them.
    Grab(FetchArgs),
    /// Validate proxies from a file or the built-in providers against online
    /// judges, printing the survivors.
    Find(FindArgs),
    /// Download (if missing) and verify the GeoLite2 database used for GeoIP
    /// lookups, then exit.
    GeoUpdate,
}

/// Options shared by every command that render proxies.
#[derive(Args, Debug, Clone, Default)]
pub struct OutputOptions {
    /// Output format for the results.
    #[arg(
        short,
        long,
        default_value = "default",
        value_parser([
            PossibleValue::new("default"),
            PossibleValue::new("text"),
            PossibleValue::new("json"),
            PossibleValue::new("json-lines"),
            PossibleValue::new("pretty-json"),
            PossibleValue::new("csv"),
        ])
    )]
    pub format: String,

    /// Maximum number of proxies to retrieve.
    #[arg(short, long, default_value = "0")]
    pub limit: usize,

    /// File path to save the retrieved proxies; prints to the console otherwise.
    #[arg(short, long)]
    pub output_file: Option<std::path::PathBuf>,
}

/// Options controlling how proxies are scraped from the built-in providers.
#[derive(Args, Debug, Clone, Default)]
pub struct FetcherArgs {
    /// List of ISO country codes to filter proxies by location.
    #[arg(short, long, num_args(1..))]
    pub countries: Vec<String>,

    /// Enable GeoIP lookup so every proxy carries country information in the
    /// output without filtering by location.
    #[arg(long)]
    pub with_geo: bool,

    /// Maximum number of proxy sources fetched concurrently.
    #[arg(
        long,
        help_heading = "Advanced",
        default_value_t = flx::fetcher::DEFAULT_CONCURRENCY_LIMIT as u64,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub fetch_concurrency: u64,

    /// Freshness in minutes for the local provider-source cache; `0` disables
    /// the cache entirely.
    #[arg(
        long,
        help_heading = "Advanced",
        default_value_t = flx::fetcher::DEFAULT_CACHE_TTL_MINUTES,
        value_parser = clap::value_parser!(u64)
    )]
    pub cache_ttl: u64,

    /// Ignore the local provider-source cache and fetch every source again.
    #[arg(long, help_heading = "Advanced", default_value_t = false)]
    pub refresh_cache: bool,

    /// Disable deduplication of identical endpoints across sources.
    #[arg(long, help_heading = "Advanced", default_value_t = false)]
    pub no_dedup: bool,

    /// List the providers and sources that would be fetched, then exit.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

/// `flx grab`: scrape proxies from the built-in providers and print them.
#[derive(Args, Debug, Default)]
pub struct FetchArgs {
    #[command(flatten)]
    pub fetcher: FetcherArgs,
    #[command(flatten)]
    pub output: OutputOptions,
}

/// Options controlling proxy validation against online judges.
#[derive(Args, Debug, Default)]
pub struct ValidatorArgs {
    /// Proxy types (protocols) to validate; combine several with `+` to
    /// require all of them and omit to default to `HTTP`.
    #[arg(num_args(1..), value_parser = TypesValueParser)]
    pub types: Vec<String>,

    /// Maximum number of concurrent proxy checks.
    #[arg(
        short,
        long,
        help_heading = "Advanced",
        default_value_t = flx::validator::DEFAULT_CONCURRENCY_LIMIT as u64,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub max_connections: u64,

    /// Maximum number of attempts to validate a proxy.
    #[arg(
        long,
        help_heading = "Advanced",
        default_value = "1",
        value_parser = parse_positive_usize
    )]
    pub max_attempts: usize,

    /// Timeout duration in seconds before giving up.
    #[arg(
        long,
        help_heading = "Advanced",
        default_value = "3",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub timeout: u64,

    /// Online judges used to validate plain HTTP proxy forwarding.
    #[arg(
        long,
        help_heading = "Advanced",
        default_value = "http://azenv.net/,http://wfuchs.de/azenv.php,http://proxyjudge.us/,http://shinh.org/env.cgi",
        value_delimiter = ','
    )]
    pub http_judge_urls: Vec<String>,

    /// Online judges used for HTTPS, CONNECT and SOCKS tunnels.
    #[arg(
        long,
        help_heading = "Advanced",
        default_value = "https://aranguren.org/azenv.php,https://wfuchs.de/azenv.php",
        value_delimiter = ','
    )]
    pub https_judge_urls: Vec<String>,

    /// Disable TLS certificate validation for judge connections.
    #[arg(long, help_heading = "Advanced", default_value_t = false)]
    pub insecure: bool,
}

/// `flx find`: validate proxies from a file or the built-in providers.
#[derive(Args, Debug, Default)]
pub struct FindArgs {
    #[command(flatten)]
    pub fetcher: FetcherArgs,

    /// File path containing proxies; overrides providers if specified.
    #[arg(long)]
    pub file: Option<std::path::PathBuf>,

    #[command(flatten)]
    pub validator: ValidatorArgs,

    #[command(flatten)]
    pub output: OutputOptions,
}
