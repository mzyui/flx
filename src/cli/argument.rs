use clap::builder::styling::AnsiColor;
use clap::builder::{PossibleValue, Styles};
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
    #[arg(short, long, default_value = "500", value_parser = clap::value_parser!(u64).range(1..))]
    pub max_connections: u64,

    /// Maximum number of proxy sources fetched concurrently.
    ///
    /// Separate from `--max-connections`: fetching touches a few dozen source
    /// URLs, while validation touches thousands of proxies.
    #[arg(long, default_value = "25", value_parser = clap::value_parser!(u64).range(1..))]
    pub fetch_concurrency: u64,

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
