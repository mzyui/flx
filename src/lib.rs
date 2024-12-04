pub mod client;
mod fetcher;
pub mod geoip;
pub mod models;
pub mod negotiators;
pub mod providers;
mod validator;

pub use fetcher::ProxyFetcher;
pub use validator::ProxyValidator;

/// Sets up logging for the application.
///
/// This function initializes the logging system with the specified log level.
///
/// # Arguments
///
/// * `log_level`: The level of logging verbosity. It determines what log messages will be shown.
///
/// # Returns
///
/// A result indicating success or failure during the logging setup.
#[cfg(feature = "log")]
pub fn setup_log(log_level: log::LevelFilter) -> anyhow::Result<()> {
    #[cfg(feature = "log")]
    stderrlog::new()
        .module(module_path!()) // Sets the module path for log messages.
        .show_module_names(true) // Enables displaying module names in log output.
        .verbosity(log_level) // Sets the specified log level.
        .init()?; // Initializes the logger.
    Ok(())
}
