//! Style CLI output with minimal color helpers.

use std::fmt::Display;
use std::sync::atomic::{AtomicU8, Ordering};

const OVERRIDE_UNSET: u8 = 0;
const OVERRIDE_ON: u8 = 1;
const OVERRIDE_OFF: u8 = 2;
const RESET_COLOR: &str = "\x1b[0m";

static COLOR_OVERRIDE: AtomicU8 = AtomicU8::new(OVERRIDE_UNSET);

/// Force the color decision for the whole process.
pub(crate) fn set_override(enabled: bool) {
    let state = if enabled { OVERRIDE_ON } else { OVERRIDE_OFF };
    COLOR_OVERRIDE.store(state, Ordering::Relaxed);
}

fn should_colorize() -> bool {
    use std::io::IsTerminal as _;
    match COLOR_OVERRIDE.load(Ordering::Relaxed) {
        OVERRIDE_ON => true,
        OVERRIDE_OFF => false,
        _ => {
            // Prefer TTY stdout unless NO_COLOR or CLICOLOR=0 disables it.
            std::env::var_os("NO_COLOR").is_none()
                && std::env::var("CLICOLOR").is_ok_and(|value| value != "0")
                && std::io::stdout().is_terminal()
        }
    }
}

struct Styled {
    text: String,
    code: &'static str,
}

impl Display for Styled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if should_colorize() {
            write!(f, "{}{}{}", self.code, self.text, RESET_COLOR)
        } else {
            f.write_str(&self.text)
        }
    }
}

fn style(text: impl Display, code: &'static str) -> Styled {
    Styled {
        text: text.to_string(),
        code,
    }
}

/// Expose color helpers used by call sites.
pub(crate) trait Colorize {
    fn green(self) -> String;
    fn red(self) -> String;
    fn cyan(self) -> String;
    fn bold(self) -> String;
    fn dimmed(self) -> String;
}

macro_rules! impl_colorize {
    ($($method:ident = $code:literal),* $(,)?) => {
        impl Colorize for String {
            $(fn $method(self) -> String {
                style(self, $code).to_string()
            })*
        }
        impl Colorize for &str {
            $(fn $method(self) -> String {
                style(self, $code).to_string()
            })*
        }
    };
}

impl_colorize!(
    green = "\x1b[32m",
    red = "\x1b[31m",
    cyan = "\x1b[36m",
    bold = "\x1b[1m",
    dimmed = "\x1b[2m",
);

#[cfg(test)]
pub(crate) fn color_lock() -> std::sync::MutexGuard<'static, ()> {
    static COLOR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    COLOR_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn styled_output_emits_standard_ansi_sequences() {
        let _guard = color_lock();
        set_override(true);
        assert_eq!("x".green(), "\x1b[32mx\x1b[0m");
        assert_eq!("x".red(), "\x1b[31mx\x1b[0m");
        assert_eq!("x".cyan(), "\x1b[36mx\x1b[0m");
        assert_eq!("x".bold(), "\x1b[1mx\x1b[0m");
        assert_eq!("x".dimmed(), "\x1b[2mx\x1b[0m");
        set_override(false);
        assert_eq!("x".green(), "x");
    }

    #[test]
    fn separate_style_calls_do_not_merge_codes() {
        let _guard = color_lock();
        set_override(true);
        let line = format!("{} {}", "▸".cyan(), "Validating".bold());
        assert!(line.contains("\x1b[36m▸\x1b[0m"));
        assert!(line.contains("\x1b[1mValidating\x1b[0m"));
        assert!(!line.contains("\x1b[1;36m"));
        set_override(false);
    }
}
