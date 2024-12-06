use clap::builder::styling::AnsiColor;
use clap::builder::{PossibleValue, Styles};
use clap::{Args, Parser, Subcommand};

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
    /// Maximum number of concurrent proxy checks.
    #[arg(long, default_value = "50")]
    pub max_connections: usize,

    /// Timeout duration in seconds before giving up.
    #[arg(short, long, default_value = "8")]
    pub timeout: usize,

    /// Log level for application output.
    #[arg(
        long = "log",
        default_value = "warn",
        value_parser([
            PossibleValue::new("debug"),
            PossibleValue::new("info"),
            PossibleValue::new("warn"),
            PossibleValue::new("error"),
        ])
    )]
    pub log_level: String,

    /// Subcommands available for the proxy application.
    #[command(subcommand)]
    pub command: Commands,
}

/// Subcommands for the proxy application.
#[derive(Subcommand, Debug, Clone)]
#[command(
    after_help = "Suggestions and bug reports are greatly appreciated:\nhttps://github.com/zevtyardt/fluxy/issues",
    styles=get_styles()
)]
pub enum Commands {
    /// Retrieve proxies without performing any checks.
    Fetch(FetchArgs),

    /// Retrieve and validate proxies.
    Find(FindArgs),
}

/// Arguments for the `grab` subcommand.
#[derive(Args, Debug, Clone)]
#[command(
    after_help = "Suggestions and bug reports are greatly appreciated:\nhttps://github.com/zevtyardt/fluxy/issues",
    styles=get_styles()
)]
pub struct FetchArgs {
    /// List of ISO country codes to filter proxies by location.
    #[arg(short, long, num_args(1..))]
    pub countries: Vec<String>,

    /// Maximum number of proxies to retrieve.
    #[arg(short, long, default_value = "0")]
    pub limit: usize,

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

    /// File path to save the retrieved proxies. If not provided, output will go to the console.
    #[arg(short, long)]
    pub output_file: Option<std::path::PathBuf>,
}

/// Arguments for the `find` subcommand.
#[derive(Args, Debug, Clone)]
#[command(
    after_help = "Suggestions and bug reports are greatly appreciated:\nhttps://github.com/zevtyardt/fluxy/issues",
    styles=get_styles()

)]
pub struct FindArgs {
    /// Proxy types (protocols) to validate.
    #[arg(
        long,
        required = true,
        num_args(1..),
        value_parser([
            PossibleValue::new("HTTP"),
            PossibleValue::new("HTTPS"),
            PossibleValue::new("SOCKS4"),
            PossibleValue::new("SOCKS5"),
            PossibleValue::new("CONNECT:80"),
            PossibleValue::new("CONNECT:25"),
        ])
    )]
    pub proxy_types: Vec<String>,

    /// File paths containing proxies. Overrides providers if specified.
    #[arg(long, num_args(1..))]
    pub proxy_files: Vec<std::path::PathBuf>,

    /// Levels of anonymity for HTTP proxies. Defaults to any level.
    #[arg(
        long,
        num_args(1..),
        value_parser([
            PossibleValue::new("Transparent"),
            PossibleValue::new("Anonymous"),
            PossibleValue::new("High"),
        ])
    )]
    pub anonymity_levels: Vec<String>,

    /// Maximum number of attempts to validate a proxy.
    #[arg(long, default_value = "1")]
    pub max_attempts: usize,

    /// Require the proxy to support cookies.
    #[arg(long, default_value = "false")]
    pub supports_cookies: bool,

    /// Require the proxy to support referer headers.
    #[arg(long, default_value = "false")]
    pub supports_referer: bool,

    /// List of ISO country codes to filter proxies by location.
    #[arg(short, long, num_args(1..))]
    pub countries: Vec<String>,

    /// Maximum number of working proxies to retrieve.
    #[arg(short, long, default_value = "0")]
    pub limit: usize,

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

    /// File path to save the validated proxies. If not provided, output will go to the console.
    #[arg(short, long)]
    pub output_file: Option<std::path::PathBuf>,
}
