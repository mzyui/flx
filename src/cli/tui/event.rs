//! Key handling: one table that drives dispatch, the footer hints, and `?`.
//!
//! Keeping a single keymap means the footer cannot drift from what the keys do,
//! and the `?` panel cannot drift either: it prints the same rows at greater
//! length. Terminal-reserved combinations (`Ctrl+C`, `Ctrl+Z`, flow control)
//! are deliberately absent: they must stay the shell's.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// Which screen the TUI is showing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Screen {
    Running,
    Done,
}

/// What an active text input is collecting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InputPurpose {
    /// Typing the results filter.
    Filter,
    /// Choosing the export format.
    ExportFormat,
    /// Typing the export destination path.
    ExportPath,
}

/// Everything the key map needs to know about the current UI.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KeyContext {
    pub(crate) screen: Screen,
    pub(crate) purpose: Option<InputPurpose>,
    pub(crate) help: bool,
    pub(crate) confirm: bool,
    /// Whether a `g` is waiting for its second press.
    pub(crate) pending_g: bool,
    /// Digits typed so far, waiting for `G` to use them.
    pub(crate) count: Option<usize>,
}

/// A user intent decoupled from the physical key that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    ToggleHelp,
    /// Esc: close the drill-down, dismiss a prompt, or leave the Done screen.
    Back,
    /// Ctrl+C: cancel a live run, or quit once nothing is running.
    Interrupt,
    Submit,
    Cancel,
    Backspace,
    Text(char),
    PauseToggle,
    CancelRun,
    SortCycle,
    OrderToggle,
    EditFilter,
    ClearFilter,
    Export,
    Rerun,
    /// Enter: open the drill-down.
    DrillIn,
    /// `d`: open or close the drill-down.
    ToggleDetail,
    /// First `g` of `gg`.
    PrefixG,
    GotoTop,
    GotoBottom,
    /// A digit joined the pending count.
    Count(u8),
    /// `G` (or `gg`) with a count in front: go to that row.
    GotoCount,
    ScrollUp,
    ScrollDown,
    PageUp,
    PageDown,
    ConfirmYes,
    ConfirmNo,
}

/// A key as the table writes it down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    Char(char),
    Ctrl(char),
    Up,
    Down,
    PageUp,
    PageDown,
    Enter,
    Esc,
    Backspace,
    /// Any printable character; the text-prompt scope matches on this.
    Printable,
    /// Any ASCII digit; the browse scope accumulates these into a count.
    Digit,
}

/// Which surface a binding belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    /// The browse keymap, active while no prompt or help owns the keyboard.
    Screen,
    Running,
    Done,
    Input,
    Confirm,
    /// The `?` panel: it scrolls, and it closes.
    Help,
}

impl Scope {
    fn applies(self, context: KeyContext) -> bool {
        // Help is modal: only its own bindings apply while it is open.
        if context.help {
            return self == Scope::Help;
        }
        // A confirmation is modal too: only its own two answers apply.
        if context.confirm {
            return self == Scope::Confirm;
        }
        match self {
            Scope::Confirm | Scope::Help => false,
            Scope::Input => context.purpose.is_some(),
            Scope::Screen => context.purpose.is_none(),
            Scope::Running => context.purpose.is_none() && context.screen == Screen::Running,
            Scope::Done => context.purpose.is_none() && context.screen == Screen::Done,
        }
    }
}

/// One row of the keymap.
pub(crate) struct Binding {
    keys: &'static [Key],
    /// How the keys are written, in the footer and in `?`.
    pub(crate) keys_label: &'static str,
    action: Action,
    /// The footer's wording: one short phrase, because the footer is one line.
    pub(crate) label: &'static str,
    /// The `?` panel's wording: what the key does, including where that differs
    /// by screen. Longer than `label`, and never a copy of it.
    pub(crate) detail: &'static str,
    scope: Scope,
    /// Whether the contextual footer advertises this binding.
    hint: bool,
}

/// Builds one keymap row, so the table below stays one line per binding.
const fn row(
    keys: &'static [Key],
    keys_label: &'static str,
    action: Action,
    label: &'static str,
    detail: &'static str,
    scope: Scope,
    hint: bool,
) -> Binding {
    Binding {
        keys,
        keys_label,
        action,
        label,
        detail,
        scope,
        hint,
    }
}

/// Placeholder action for the row that means "any printable key".
const TEXT_ANY: Action = Action::Text('\0');
/// Placeholder action for the row that means "any digit"; the digit itself
/// rides along, exactly as `TEXT_ANY` carries the character.
const COUNT_ANY: Action = Action::Count(0);

/// The footer never shows more than this many keys.
const MAX_HINTS: usize = 5;

// Short aliases, so one binding still fits on one line.
use Action as A;
use Scope as S;

/// The whole keymap.
///
/// Order matters twice: dispatch takes the first match, and the footer keeps the
/// first [`MAX_HINTS`] hints, so the most useful keys come first. Every row
/// carries both wordings — the footer's short one and the help panel's fuller
/// one — so the two can never disagree.
///
/// One row per line is the point of a keymap you can read; rustfmt would break
/// every call into seven lines instead.
#[rustfmt::skip]
static KEYMAP: &[Binding] = &[
    // Global
    row(&[Key::Char('?')], "?", A::ToggleHelp, "help", "open this key table", S::Screen, false),
    row(&[Key::Esc], "esc", A::Back, "back", "close the drill-down, then leave", S::Screen, false),
    row(&[Key::Up, Key::Char('k')], "\u{2191}/k", A::ScrollUp, "up", "move up one row", S::Screen, false),
    row(&[Key::Down, Key::Char('j')], "\u{2193}/j", A::ScrollDown, "down", "move down one row", S::Screen, false),
    row(&[Key::PageUp], "pgup", A::PageUp, "page up", "move up one page", S::Screen, false),
    row(&[Key::PageDown], "pgdn", A::PageDown, "page down", "move down one page", S::Screen, false),
    row(&[Key::Char('g')], "gg/{n}G", A::PrefixG, "top / row n", "top of the list, or row n", S::Screen, false),
    row(&[Key::Char('G')], "G", A::GotoBottom, "bottom", "bottom of the list", S::Screen, false),
    row(&[Key::Digit], "1-9", COUNT_ANY, "then G: row n", "digits, then G: go to that row", S::Screen, false),
    // Running only
    row(&[Key::Char('p')], "p", A::PauseToggle, "pause", "pause or resume probing", S::Running, true),
    row(&[Key::Char('c')], "c", A::CancelRun, "cancel", "cancel the run, after asking", S::Running, true),
    // Results, on either screen
    row(&[Key::Char('s')], "s", A::SortCycle, "sort", "cycle the sort key", S::Screen, true),
    row(&[Key::Char('/')], "/", A::EditFilter, "filter", "live-filter rows (smart-case); Esc restores", S::Screen, true),
    row(&[Key::Char('e')], "e", A::Export, "export", "export the visible rows", S::Screen, true),
    row(&[Key::Char('d')], "d", A::ToggleDetail, "detail", "open or close the drill-down", S::Screen, true),
    row(&[Key::Enter], "enter", A::DrillIn, "open", "open the drill-down", S::Screen, false),
    row(&[Key::Char('S')], "S", A::OrderToggle, "order", "reverse the sort order", S::Screen, false),
    row(&[Key::Char('x')], "x", A::ClearFilter, "clear filter", "clear the filter", S::Screen, false),
    // Done only
    row(&[Key::Char('r')], "r", A::Rerun, "re-run", "run again with the same options", S::Done, true),
    // Text prompts
    row(&[Key::Enter], "enter", A::Submit, "submit", "submit the prompt", S::Input, false),
    row(&[Key::Up], "up", A::ScrollUp, "up", "choose the previous export format", S::Input, false),
    row(&[Key::Down], "down", A::ScrollDown, "down", "choose the next export format", S::Input, false),
    row(&[Key::Esc], "esc", A::Cancel, "cancel", "abandon the prompt", S::Input, true),
    row(&[Key::Backspace], "backspace", A::Backspace, "delete", "delete one character", S::Input, false),
    row(&[Key::Printable], "text", TEXT_ANY, "type", "type text; digits type here too", S::Input, false),
    // Confirmations
    row(&[Key::Char('y'), Key::Char('Y')], "y", A::ConfirmYes, "yes", "yes, go ahead", S::Confirm, true),
    row(&[Key::Char('n'), Key::Char('N')], "n", A::ConfirmNo, "no", "no; any other key declines", S::Confirm, true),
    // The help panel itself, so it can document its own keys
    row(&[Key::Esc, Key::Char('?')], "esc", A::ToggleHelp, "close", "close this help", S::Help, true),
    row(&[Key::Down, Key::Char('j'), Key::PageDown], "\u{2193}/j", A::ScrollDown, "scroll", "scroll down", S::Help, true),
    row(&[Key::Up, Key::Char('k'), Key::PageUp], "\u{2191}/k", A::ScrollUp, "scroll", "scroll back up", S::Help, false),
];

/// Facts the `?` panel states that have no key of their own.
///
/// One short line each, short enough for the narrowest supported panel: they
/// are read as a list, not as prose.
pub(crate) const HELP_NOTES: [&str; 6] = [
    "Row numbers follow the view, not the run.",
    "The filter is smart-case: lowercase ignores case.",
    "The mouse scrolls and clicks; Shift selects text.",
    "Every flag you passed still configures the run.",
    "Judge health shows only when a judge is down.",
    "Ctrl+C cancels, then exits on the next press.",
];

/// Normalizes a terminal event into a table key, or `None` when the key is one
/// the table never claims.
fn resolve_key(event: KeyEvent) -> Option<Key> {
    // Windows delivers both press and release; only presses are actions.
    if event.kind != KeyEventKind::Press {
        return None;
    }
    if event.modifiers.contains(KeyModifiers::CONTROL) {
        return match event.code {
            KeyCode::Char(character) => Some(Key::Ctrl(character.to_ascii_lowercase())),
            _ => None,
        };
    }
    if event
        .modifiers
        .intersects(KeyModifiers::ALT | KeyModifiers::SUPER | KeyModifiers::META)
    {
        return None;
    }
    Some(match event.code {
        KeyCode::Char(character) if !character.is_control() => Key::Char(character),
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Esc,
        KeyCode::Backspace => Key::Backspace,
        _ => return None,
    })
}

fn matches(binding: &Binding, pressed: Key) -> bool {
    binding.keys.iter().any(|candidate| match candidate {
        Key::Printable => matches!(pressed, Key::Char(_)),
        Key::Digit => matches!(pressed, Key::Char(c) if c.is_ascii_digit()),
        candidate => *candidate == pressed,
    })
}

/// The digit a press represents, when it is one.
fn digit_of(pressed: Key) -> Option<u8> {
    match pressed {
        Key::Char(c) => c.to_digit(10).map(|digit| digit as u8),
        _ => None,
    }
}

/// The first binding on an active surface that claims this key.
fn binding_for(pressed: Key, context: KeyContext) -> Option<&'static Binding> {
    KEYMAP
        .iter()
        .find(|binding| binding.scope.applies(context) && matches(binding, pressed))
}

/// Maps a key press to an intent, or `None` when the key is unbound.
pub(crate) fn action_for(event: KeyEvent, context: KeyContext) -> Option<Action> {
    let pressed = resolve_key(event)?;

    // Ctrl+C is reserved for the interrupt path on every surface, so a prompt
    // can never swallow it and no binding can repurpose it.
    if pressed == Key::Ctrl('c') {
        return Some(Action::Interrupt);
    }
    if context.confirm {
        // Default No: only an explicit `y` goes ahead.
        return Some(match pressed {
            Key::Char('y') | Key::Char('Y') => Action::ConfirmYes,
            _ => Action::ConfirmNo,
        });
    }
    if context.help {
        // Scrolling is bound; anything else dismisses, so the panel can never
        // trap someone who does not know the way out.
        return Some(match binding_for(pressed, context) {
            Some(binding) => binding.action,
            None => Action::ToggleHelp,
        });
    }

    // A count in front of `G` (or `gg`) turns "go to the bottom" into "go to
    // that row", which is the vim convention the digits already suggest.
    let has_count = context.count.is_some();
    if has_count && pressed == Key::Char('G') {
        return Some(Action::GotoCount);
    }
    // `gg` is the one binding that needs the previous press to be remembered.
    if context.pending_g && pressed == Key::Char('g') {
        return Some(if has_count {
            Action::GotoCount
        } else {
            Action::GotoTop
        });
    }

    let binding = binding_for(pressed, context)?;
    // Rows that mean "any key of this kind" carry the key itself.
    if binding.action == TEXT_ANY {
        return match pressed {
            Key::Char(character) => Some(Action::Text(character)),
            _ => None,
        };
    }
    if binding.action == COUNT_ANY {
        return digit_of(pressed).map(Action::Count);
    }
    Some(binding.action)
}

/// Contextual footer hints: at most [`MAX_HINTS`] keys for the current surface.
pub(crate) fn hints(context: KeyContext) -> Vec<(&'static str, &'static str)> {
    // A half-typed count takes the line over: the digits and what finishes them
    // are the only thing the user needs to see right now. A bare `g` keeps the
    // usual hints, so `gg` does not blank the footer while it waits.
    if context.count.is_some() {
        return Vec::new();
    }
    KEYMAP
        .iter()
        .filter(|binding| binding.hint && binding.scope.applies(context))
        .take(MAX_HINTS)
        .map(|binding| (binding.keys_label, binding.label))
        .collect()
}

/// The count being typed, with the key that completes it.
///
/// Discoverability for a typed sequence has to be immediate — the footer is
/// where the user is already looking.
pub(crate) fn count_hint(context: KeyContext) -> Option<(String, &'static str)> {
    let count = context.count?;
    Some((format!("{count}"), "G go to row"))
}

/// The surfaces `?` documents, in the order it lists them.
///
/// Titled by *where they apply*, not by an internal scope name: a reader wants
/// to know which keys work right now, and "both screens" is the honest answer
/// for the keys that are not tied to one.
pub(crate) const HELP_GROUPS: [(&str, &str); 6] = [
    ("both screens", "screen"),
    ("while running", "running"),
    ("when done", "done"),
    ("in a prompt", "input"),
    ("in a confirmation", "confirm"),
    ("in this help", "help"),
];

fn scope_of(scope_name: &str) -> Option<Scope> {
    Some(match scope_name {
        "screen" => S::Screen,
        "running" => S::Running,
        "done" => S::Done,
        "input" => S::Input,
        "confirm" => S::Confirm,
        "help" => S::Help,
        _ => return None,
    })
}

/// Every binding on one named surface, as `?` prints it.
pub(crate) fn bindings_on(scope_name: &str) -> Vec<(&'static str, &'static str)> {
    let Some(scope) = scope_of(scope_name) else {
        return Vec::new();
    };
    KEYMAP
        .iter()
        .filter(|binding| binding.scope == scope)
        .map(|binding| (binding.keys_label, binding.detail))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn context(screen: Screen) -> KeyContext {
        KeyContext {
            screen,
            purpose: None,
            help: false,
            confirm: false,
            pending_g: false,
            count: None,
        }
    }

    fn typing(purpose: InputPurpose) -> KeyContext {
        KeyContext {
            purpose: Some(purpose),
            ..context(Screen::Running)
        }
    }

    fn reading_help() -> KeyContext {
        KeyContext {
            help: true,
            ..context(Screen::Done)
        }
    }

    #[test]
    fn ctrl_c_interrupts_whatever_owns_the_keyboard() {
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        for context in [
            context(Screen::Running),
            context(Screen::Done),
            typing(InputPurpose::Filter),
            reading_help(),
        ] {
            assert_eq!(
                action_for(ctrl_c, context),
                Some(Action::Interrupt),
                "Ctrl+C must stay the interrupt path"
            );
        }
    }

    #[test]
    fn typing_takes_over_when_an_input_is_active() {
        let active = typing(InputPurpose::Filter);
        assert_eq!(
            action_for(key(KeyCode::Char('p')), active),
            Some(Action::Text('p')),
            "printable aliases yield to a focused prompt"
        );
        assert_eq!(
            action_for(key(KeyCode::Enter), active),
            Some(Action::Submit)
        );
        assert_eq!(action_for(key(KeyCode::Esc), active), Some(Action::Cancel));
        assert_eq!(
            action_for(key(KeyCode::Backspace), active),
            Some(Action::Backspace)
        );
    }

    #[test]
    fn browsing_keys_are_bound_on_the_done_screen() {
        assert_eq!(
            action_for(key(KeyCode::Char('s')), context(Screen::Done)),
            Some(Action::SortCycle)
        );
        assert_eq!(
            action_for(key(KeyCode::Char('r')), context(Screen::Done)),
            Some(Action::Rerun)
        );
        assert_eq!(
            action_for(key(KeyCode::Char('z')), context(Screen::Done)),
            None
        );
    }

    #[test]
    fn esc_is_the_one_back_key_on_both_screens() {
        // What `Back` means differs per screen; that decision lives in `App`.
        for screen in [Screen::Running, Screen::Done] {
            assert_eq!(
                action_for(key(KeyCode::Esc), context(screen)),
                Some(Action::Back)
            );
        }
    }

    #[test]
    fn p_pauses_only_while_running() {
        assert_eq!(
            action_for(key(KeyCode::Char('p')), context(Screen::Running)),
            Some(Action::PauseToggle)
        );
        assert_eq!(
            action_for(key(KeyCode::Char('p')), context(Screen::Done)),
            None
        );
    }

    #[test]
    fn paging_and_jumping_work_on_both_screens() {
        for screen in [Screen::Running, Screen::Done] {
            assert_eq!(
                action_for(key(KeyCode::PageUp), context(screen)),
                Some(Action::PageUp)
            );
            assert_eq!(
                action_for(key(KeyCode::PageDown), context(screen)),
                Some(Action::PageDown)
            );
            assert_eq!(
                action_for(key(KeyCode::Char('j')), context(screen)),
                Some(Action::ScrollDown)
            );
            assert_eq!(
                action_for(key(KeyCode::Char('G')), context(screen)),
                Some(Action::GotoBottom)
            );
        }
    }

    #[test]
    fn g_needs_a_second_press_to_jump_to_the_top() {
        let done = context(Screen::Done);
        assert_eq!(
            action_for(key(KeyCode::Char('g')), done),
            Some(Action::PrefixG)
        );
        let pending = KeyContext {
            pending_g: true,
            ..done
        };
        assert_eq!(
            action_for(key(KeyCode::Char('g')), pending),
            Some(Action::GotoTop)
        );
        assert_eq!(
            action_for(key(KeyCode::Char('d')), pending),
            Some(Action::ToggleDetail),
            "an unfinished `g` must not swallow the next key"
        );
    }

    #[test]
    fn digits_accumulate_into_a_row_number() {
        let done = context(Screen::Done);
        assert_eq!(
            action_for(key(KeyCode::Char('1')), done),
            Some(Action::Count(1)),
            "digits are a count, not an action"
        );
        assert_eq!(
            action_for(key(KeyCode::Char('0')), done),
            Some(Action::Count(0)),
            "zero is a digit like any other"
        );
    }

    #[test]
    fn a_count_turns_g_into_a_row_jump() {
        let done = context(Screen::Done);
        let counted = KeyContext {
            count: Some(12),
            ..done
        };
        assert_eq!(
            action_for(key(KeyCode::Char('G')), counted),
            Some(Action::GotoCount)
        );
        // `{n}gg` is the same jump, so the count cannot silently mean "top".
        let pending = KeyContext {
            pending_g: true,
            ..counted
        };
        assert_eq!(
            action_for(key(KeyCode::Char('g')), pending),
            Some(Action::GotoCount)
        );

        // Without a count both keys keep their documented meaning.
        assert_eq!(
            action_for(key(KeyCode::Char('G')), done),
            Some(Action::GotoBottom)
        );
    }

    #[test]
    fn digits_still_type_into_a_prompt() {
        assert_eq!(
            action_for(key(KeyCode::Char('7')), typing(InputPurpose::Filter)),
            Some(Action::Text('7')),
            "a filter may well contain digits"
        );
    }

    #[test]
    fn a_pending_count_takes_the_footer_over() {
        let counted = KeyContext {
            count: Some(12),
            ..context(Screen::Done)
        };
        assert!(
            hints(counted).is_empty(),
            "the digits and their key are the whole story while typing them"
        );
        assert_eq!(count_hint(counted), Some(("12".to_owned(), "G go to row")));
        assert_eq!(count_hint(context(Screen::Done)), None);
    }

    #[test]
    fn the_help_panel_scrolls_and_otherwise_dismisses() {
        let help = reading_help();
        for (code, expected) in [
            (KeyCode::Char('j'), Action::ScrollDown),
            (KeyCode::Down, Action::ScrollDown),
            (KeyCode::PageDown, Action::ScrollDown),
            (KeyCode::Char('k'), Action::ScrollUp),
            (KeyCode::Up, Action::ScrollUp),
            (KeyCode::PageUp, Action::ScrollUp),
        ] {
            assert_eq!(action_for(key(code), help), Some(expected), "{code:?}");
        }

        // Leaving is explicit; an unbound key leaves too, so the panel can never
        // trap someone who does not know the way out. A bound browse key is
        // rebound rather than shadowed: `s` closes instead of sorting.
        for code in [
            KeyCode::Esc,
            KeyCode::Char('q'),
            KeyCode::Char('?'),
            KeyCode::Char('z'),
            KeyCode::Char('s'),
        ] {
            assert_eq!(
                action_for(key(code), help),
                Some(Action::ToggleHelp),
                "{code:?} must close the help"
            );
        }
    }

    #[test]
    fn confirmation_defaults_to_no() {
        let confirm = KeyContext {
            confirm: true,
            ..context(Screen::Done)
        };
        assert_eq!(
            action_for(key(KeyCode::Char('y')), confirm),
            Some(Action::ConfirmYes)
        );
        for code in [KeyCode::Char('n'), KeyCode::Esc, KeyCode::Char('q')] {
            assert_eq!(
                action_for(key(code), confirm),
                Some(Action::ConfirmNo),
                "{code:?} must not confirm"
            );
        }
    }

    #[test]
    fn terminal_reserved_keys_stay_unbound() {
        let done = context(Screen::Done);
        for character in ['z', 'h', 's', 'q', '\\'] {
            let event = KeyEvent::new(KeyCode::Char(character), KeyModifiers::CONTROL);
            assert_eq!(
                action_for(event, done),
                None,
                "Ctrl+{character} belongs to the terminal"
            );
        }
    }

    #[test]
    fn key_releases_are_not_actions() {
        let release = KeyEvent::new_with_kind(
            KeyCode::Char('q'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        assert_eq!(action_for(release, context(Screen::Done)), None);
    }

    #[test]
    fn footer_hints_are_contextual_and_bounded() {
        let running = hints(context(Screen::Running));
        let done = hints(context(Screen::Done));

        assert!((3..=MAX_HINTS).contains(&running.len()), "got {running:?}");
        assert!((3..=MAX_HINTS).contains(&done.len()), "got {done:?}");
        assert!(
            running.iter().any(|(keys, _)| *keys == "p"),
            "pausing belongs in the running footer"
        );
        assert!(
            !done.iter().any(|(keys, _)| *keys == "p"),
            "a finished run cannot be paused"
        );
        assert!(
            done.iter().any(|(keys, _)| *keys == "r"),
            "re-running belongs in the done footer"
        );
    }

    #[test]
    fn the_help_footer_says_how_to_leave_and_how_to_scroll() {
        let hints = hints(reading_help());
        assert!(
            hints.iter().any(|(_, label)| *label == "close"),
            "the way out must be visible: {hints:?}"
        );
        assert!(
            hints.iter().any(|(_, label)| *label == "scroll"),
            "the scroll keys must be visible: {hints:?}"
        );
    }

    #[test]
    fn a_prompt_and_a_confirmation_advertise_their_own_keys() {
        let prompt = hints(typing(InputPurpose::ExportPath));
        assert!(
            prompt.iter().any(|(keys, _)| *keys == "esc"),
            "a prompt must show how to leave it: {prompt:?}"
        );

        let confirm = hints(KeyContext {
            confirm: true,
            ..context(Screen::Done)
        });
        assert_eq!(confirm, vec![("y", "yes"), ("n", "no")]);
    }

    #[test]
    fn a_confirmation_hides_the_browse_keys_it_replaces() {
        let confirm = KeyContext {
            confirm: true,
            ..context(Screen::Done)
        };
        assert!(
            !hints(confirm).iter().any(|(keys, _)| *keys == "s"),
            "sorting is unreachable while a prompt is modal"
        );
    }

    #[test]
    fn the_help_table_covers_every_surface() {
        for (_, scope) in HELP_GROUPS {
            assert!(
                !bindings_on(scope).is_empty(),
                "the `{scope}` group would render empty"
            );
        }
        assert_eq!(bindings_on("nonsense"), Vec::new());
    }

    #[test]
    fn every_binding_explains_itself_in_the_help_panel() {
        for (keys, detail) in HELP_GROUPS
            .into_iter()
            .flat_map(|(_, scope)| bindings_on(scope))
        {
            assert!(
                detail.len() > 4,
                "`{keys}` needs a real description, got {detail:?}"
            );
            assert!(
                !detail.ends_with('.'),
                "`{keys}` reads as a label, not a sentence: {detail:?}"
            );
        }
    }

    #[test]
    fn the_help_panel_documents_its_own_keys() {
        let help = bindings_on("help");
        assert!(
            help.iter().any(|(_, detail)| detail.contains("close")),
            "the panel must say how to leave it: {help:?}"
        );
        assert!(
            help.iter().any(|(_, detail)| detail.contains("scroll")),
            "the panel must say how to scroll: {help:?}"
        );
    }

    #[test]
    fn esc_is_documented_on_every_surface_that_binds_it() {
        for scope in ["screen", "input", "help"] {
            assert!(
                bindings_on(scope).iter().any(|(keys, _)| *keys == "esc"),
                "the `{scope}` surface binds Esc but does not document it"
            );
        }
    }

    #[test]
    fn the_footer_word_is_never_longer_than_the_help_text() {
        // They serve different widths; the footer's must stay the shorter one.
        for binding in KEYMAP {
            assert!(
                binding.label.len() <= binding.detail.len(),
                "`{}` has a longer footer word than help text",
                binding.keys_label
            );
        }
    }

    #[test]
    fn every_note_fits_the_narrowest_panel() {
        // Notes render in a single column inside a 60-column terminal.
        for note in HELP_NOTES {
            assert!(
                note.chars().count() <= 52,
                "{note:?} would wrap in the narrowest supported panel"
            );
            assert!(!note.is_empty());
        }
    }
}
