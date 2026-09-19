//! Semantic style tokens for the TUI.
//!
//! Call sites name a *meaning* (`status_error`, `text_muted`), never an
//! appearance, so monochrome and ASCII fallbacks stay in one place. Every
//! colored signal is paired with a symbol or word by the caller.
//!
//! Roles follow Material 3 loosely: [`accent_primary`] is M3 `primary`,
//! [`surface_container`] is `surface-container-high` (dialog fill),
//! [`outline`] is `outline-variant`, and `status_*` carry the conventional
//! error/warning/info meanings. No hex is hardcoded: the 16 ANSI colors are
//! theme variables owned by the user's terminal. Overlays use rounded borders;
//! the main list stays borderless.
//!
//! The palette is installed once, before the event loop, from `--no-color` and
//! the environment. A non-empty `NO_COLOR` suppresses color like the flag.

use std::sync::atomic::{AtomicBool, Ordering};

use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::border;

/// Whether color is suppressed (`--no-color` or a non-empty `NO_COLOR`).
static MONOCHROME: AtomicBool = AtomicBool::new(false);

/// Whether glyphs should stay inside the ASCII range.
static ASCII: AtomicBool = AtomicBool::new(false);

/// Border set used when the terminal cannot be trusted with box drawing.
const ASCII_BORDER: border::Set = border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};

/// Installs the palette for this run, before any frame is drawn.
pub(crate) fn configure(no_color_flag: bool, ascii: bool) {
    let environment = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
    MONOCHROME.store(no_color_flag || environment, Ordering::Relaxed);
    ASCII.store(ascii, Ordering::Relaxed);
}

/// Whether color is currently suppressed.
pub(crate) fn monochrome() -> bool {
    MONOCHROME.load(Ordering::Relaxed)
}

/// Whether glyphs should stay inside the ASCII range.
pub(crate) fn ascii() -> bool {
    ASCII.load(Ordering::Relaxed)
}

/// Whether the terminal is likely unable to draw box-drawing glyphs.
///
/// Without a UTF-8 locale in the environment there is no reliable way to know,
/// so assume the worst and stay inside ASCII. `FLX_ASCII` forces it.
pub(crate) fn detect_ascii() -> bool {
    if std::env::var_os("FLX_ASCII").is_some() {
        return true;
    }
    !["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .any(|value| {
            let upper = value.to_ascii_uppercase();
            upper.contains("UTF-8") || upper.contains("UTF8")
        })
}

fn colored(color: Color) -> Color {
    if monochrome() {
        Color::Reset
    } else {
        color
    }
}

/// `status.success` — a pass, a kept row, a completed run.
pub(crate) fn status_success() -> Style {
    Style::default().fg(colored(Color::Green))
}

/// `status.warning` — paused, cancelled, near-cap, overwrite pending.
pub(crate) fn status_warning() -> Style {
    Style::default().fg(colored(Color::Yellow))
}

/// `status.error` — a failed probe, a failed export, an unreachable source.
pub(crate) fn status_error() -> Style {
    Style::default().fg(colored(Color::Red))
}

/// `status.info` — neutral progress facts that are neither good nor bad news.
pub(crate) fn status_info() -> Style {
    Style::default().fg(colored(Color::Blue))
}

/// `text.primary` — ordinary data cells.
pub(crate) fn text_primary() -> Style {
    Style::default().fg(colored(Color::Gray))
}

/// `text.muted` — metadata, separators, secondary hints.
pub(crate) fn text_muted() -> Style {
    Style::default().fg(colored(Color::DarkGray))
}

/// `text.emphasis` — values the user is looking for right now.
pub(crate) fn text_emphasis() -> Style {
    Style::default().fg(colored(Color::White))
}

/// `bg.overlay` — a drill-down overlay's background.
pub(crate) fn bg_overlay() -> Style {
    Style::default().bg(colored(Color::Black))
}

/// `accent.primary` — the mode label, the live phase, the focus ring.
///
/// M3 `primary`. Stays a 16-color ANSI token on purpose: the user's terminal
/// theme owns the hue (`red` may be Material, Solarized, or Catppuccin), so no
/// `#D0BCFF`-style hex is hardcoded here.
pub(crate) fn accent_primary() -> Style {
    Style::default().fg(colored(Color::Cyan))
}

/// M3 `primary-container` needs no separate token: the list selection itself
/// is `selected()` reverse video (the canonical terminal signal), which is the
/// container contrast M3 asks for without filling whole rows.

/// M3 `surface-container-high` — dialog and sheet fill.
///
/// Same fill as `bg_overlay`; kept as a separate name so call sites can say
/// "surface" (M3 meaning) instead of "overlay" (position).
pub(crate) fn surface_container() -> Style {
    bg_overlay()
}

/// M3 `outline-variant` — dividers, gutters, unfocused rules.
pub(crate) fn outline() -> Style {
    text_muted()
}

/// `border.focus` — the one focused panel's border.
pub(crate) fn border_focus() -> Style {
    Style::default().fg(colored(Color::Cyan))
}

/// Bold text, for panel titles and column headers.
pub(crate) fn title() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

/// Reverse video, the canonical selection marker.
pub(crate) fn selected() -> Style {
    Style::default().add_modifier(Modifier::REVERSED)
}

/// The matched part of a filter hit.
pub(crate) fn match_highlight() -> Style {
    Style::default()
        .fg(colored(Color::Black))
        .bg(colored(Color::Yellow))
        .add_modifier(Modifier::BOLD)
}

/// Border set for a panel, honoring the ASCII fallback.
///
/// M3 dialogs use large rounded corners, so overlays draw `ROUNDED`
/// (`╭╮╰╯`). The main list stays borderless and never touches this.
pub(crate) fn border_set() -> border::Set<'static> {
    if ascii() {
        ASCII_BORDER
    } else {
        border::ROUNDED
    }
}

/// Symbols that degrade to ASCII when box drawing cannot be trusted.
pub(crate) const ARROW_UP: (&str, &str) = ("\u{25b2}", "^");
pub(crate) const ARROW_DOWN: (&str, &str) = ("\u{25bc}", "v");
pub(crate) const CHECK: (&str, &str) = ("\u{2713}", "+");
pub(crate) const CROSS: (&str, &str) = ("\u{2717}", "x");
pub(crate) const PAUSED: (&str, &str) = ("\u{25a0}", "#");
pub(crate) const WARNING: (&str, &str) = ("\u{26a0}", "!");
pub(crate) const DOT: (&str, &str) = ("\u{b7}", "-");
pub(crate) const DASH: (&str, &str) = ("\u{2014}", "-");
pub(crate) const TIMES: (&str, &str) = ("\u{d7}", "x");

/// Picks the Unicode glyph, or its ASCII twin in fallback mode.
pub(crate) fn glyph(pair: (&'static str, &'static str)) -> &'static str {
    if ascii() {
        pair.1
    } else {
        pair.0
    }
}

/// Serializes tests that repaint the palette.
///
/// One process owns one terminal, so the palette is configured once before the
/// event loop rather than threaded through every call site. Tests share that
/// process, so they have to take turns.
#[cfg(test)]
pub(crate) fn lock_for_tests() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
