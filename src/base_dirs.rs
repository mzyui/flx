//! Platform base directories: only the two paths the crate needs, resolved
//! with the same fallbacks as before (XDG variables are honored only when
//! absolute, per the XDG spec).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn resolve_xdg(
    xdg_value: Option<OsString>,
    home: Option<&Path>,
    fallback: &str,
) -> Option<PathBuf> {
    xdg_value
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| home.map(|home| home.join(fallback)))
}

/// `BaseDirs::data_dir()`: XDG data home on Linux, `~/Library/Application
/// Support` on macOS, `%APPDATA%\data` on Windows.
pub fn data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        home_dir().map(|home| home.join("Library/Application Support"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        #[cfg(windows)]
        {
            // The known-folder lookup resolves RoamingAppData via FFI; the
            // env var covers the practical cases without that dependency.
            std::env::var_os("APPDATA")
                .map(PathBuf::from)
                .filter(|base| base.is_absolute())
                .map(|base| base.join("data"))
        }
        #[cfg(not(windows))]
        {
            resolve_xdg(
                std::env::var_os("XDG_DATA_HOME"),
                home_dir().as_deref(),
                ".local/share",
            )
        }
    }
}

/// `BaseDirs::config_dir()`: XDG config home on Linux, `~/Library/Application
/// Support` on macOS, `%APPDATA%\config` on Windows.
pub fn config_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        home_dir().map(|home| home.join("Library/Application Support"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        #[cfg(windows)]
        {
            std::env::var_os("APPDATA")
                .map(PathBuf::from)
                .filter(|base| base.is_absolute())
                .map(|base| base.join("config"))
        }
        #[cfg(not(windows))]
        {
            resolve_xdg(
                std::env::var_os("XDG_CONFIG_HOME"),
                home_dir().as_deref(),
                ".config",
            )
        }
    }
}

#[cfg(all(test, unix, not(target_os = "macos")))]
mod tests {
    use super::resolve_xdg;
    use std::path::{Path, PathBuf};

    #[test]
    fn xdg_variable_wins_when_absolute() {
        assert_eq!(
            resolve_xdg(
                Some("/opt/data".into()),
                Some(Path::new("/home/u")),
                ".local/share"
            ),
            Some(PathBuf::from("/opt/data"))
        );
    }

    #[test]
    fn relative_xdg_variable_is_ignored_per_spec() {
        assert_eq!(
            resolve_xdg(
                Some("relative/dir".into()),
                Some(Path::new("/home/u")),
                ".local/share"
            ),
            Some(PathBuf::from("/home/u/.local/share"))
        );
    }

    #[test]
    fn home_fallback_applies_without_xdg_variable() {
        assert_eq!(
            resolve_xdg(None, Some(Path::new("/home/u")), ".config"),
            Some(PathBuf::from("/home/u/.config"))
        );
        assert_eq!(resolve_xdg(None, None, ".config"), None);
    }
}
