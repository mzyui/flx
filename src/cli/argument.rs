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

    /// Maximum number of concurrent proxy checks.
    #[arg(short, long, default_value = "500", value_parser = clap::value_parser!(u64).range(1..))]
    pub max_connections: u64,

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
    /// :Anonymous,:Elite}, HTTPS, SOCKS4, SOCKS5, CONNECT:<port>]
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
        help_heading = "Validate",
        requires("types")
    )]
    pub max_attempts: usize,
}
