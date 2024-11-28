#![allow(unused, dead_code)]
pub mod fetcher;
pub mod models;
pub mod providers;

#[cfg(feature = "log")]
pub fn setup_log(log_level: log::LevelFilter) -> anyhow::Result<()> {
    #[cfg(feature = "log")]
    stderrlog::new()
        .module(module_path!())
        .show_module_names(true)
        .verbosity(log_level)
        .init()?;
    Ok(())
}
