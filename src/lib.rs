/// Module responsible for fetching proxies from various sources.
pub mod fetcher;

/// Module that handles geographical IP lookups and data.
pub mod geoip;

/// Module defining the data models used throughout the application.
pub mod models;

/// Module containing different proxy providers.
pub mod providers;

/// Module for validating proxy data and configurations.
pub mod validator;

#[cfg(feature = "log")]
/// Sets up logging for the application with the specified log level.
pub fn setup_log(log_level: log::LevelFilter) -> anyhow::Result<()> {
    #[cfg(feature = "log")]
    stderrlog::new()
        .module(module_path!())
        .show_module_names(true)
        .verbosity(log_level)
        .init()?;
    Ok(())
}
