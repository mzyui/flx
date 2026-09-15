# flx TUI Redesign — Design Spec

Date: 2026-09-15
Path: `architectural` (brainstorming) + `tui-design` (full-screen session, Rust)
Status: approved in chat, sections 1–4

## 1. Goal

Redesign the interactive TUI for `flx find --tui` and `flx grab --tui`
(full redesign: visual + layout + interaction) while keeping the existing
product contract: flags configure the run, the TUI starts the pipeline
immediately, reports it live, then hands over to a results browser with
filter, sort, inspect, re-run, and export.

Out of scope: `serve` endpoint UI, config wizard UI, non-terminal output
formats, community theme packs, command palette, multi-select batch
actions, mouse drag-resize.

## 2. Product shape (tui-design classification)

- Full-screen session on the alternate screen. No inline mode.
- Exit contract: restore shell state on every path; leave no dead UI.
  Transient runs erase cleanly; export/re-run print no stdout chrome
  that could corrupt pipes (TUI refuses non-TTY already).
- Workflow shape: single primary + drill-down (not multi-panel,
  not IDE three-panel, not widget dashboard).
  - One primary table full-width is always on screen.
  - Detail is drill-down: `Enter` opens, `Esc` backs up. `d` remains
    as a toggle alias for compatibility.
  - Rationale: degrades best to narrow terminals; fixed grids turn
    to mush at 60 columns while drill-down only shrinks.

## 3. Architecture + upgrade

- Stay on `Ratatui + Crossterm + clap`. Upgrade to `Ratatui 0.30`
  with `crossterm 0.29`.
  - Enable exactly one feature flag: `crossterm_0_29`. Never enable
    both `crossterm_0_28` and `crossterm_0_29`.
  - Verify with `cargo tree -p crossterm` that only one version exists.
    Two majors cause separate event queues and broken raw-mode tracking.
- Lifecycle: migrate `src/cli/tui/term.rs` from manual
  `enable_raw_mode` + `EnterAlternateScreen` + custom panic hook to the
  managed API (`ratatui::init()` / `ratatui::run()` + `ratatui::restore()`).
  - Install reporting hooks before `init()` so Ratatui wraps them.
  - Remove double-wrapping. Keep a minimal guard owning
    `DefaultTerminal` so every exit path (normal, error, panic,
    Ctrl+C event, SIGTERM via runtime quit event) converges on the
    loop boundary and restores raw mode, screen buffer, cursor, and
    input modes.
- State: keep the monolithic `App` struct (right size for this app),
  but enforce `update` (event to state) vs `view` (state to frame)
  separation so update logic is testable without a terminal.
- Engine: keep `mpsc + EventStream + 100ms tick select!` loop.
  No busy-loop redraw. No new async runtime beyond existing Tokio use.
- New dependencies allowed only if small and proven: `unicode-width`
  for cell measurement (if not already via ratatui), `nucleo` or
  `skim` matcher for fuzzy filter. No Cursive/iocraft migration,
  no dashboard config schema, no image protocols.

## 4. Layout + visual system

Current layout for reference: outer `vertical [2, Min(5), 2]`
(header, body, footer); body `vertical [stats, Min(4), detail 7/2]`;
table 8 fixed `Length` columns summing to 77 cells plus borders.

New layout:

- Header (1–2 rows, no border): `flx · find|grab · running|done <elapsed>`.
  Second line is the live/done summary line (phase, gathered,
  checked/total, pass/fail counts, rate, judge health).
- Primary table (fills remainder, single bordered panel): the only
  panel with a border. Title is short:
  `results · <shown>/<rows> · sort <key> <dir>` plus
  `filter "<q>"` only when active and `over cap <n>` only when hit.
- Footer (2 rows max): line 1 is contextual hints (3–5 keys derived
  from the single keymap source); line 2 is ephemeral status
  (`exported N rows → path`, `cancelled`, validation pass) with auto-fade.
- Live progress: remove the boxed `Gauge`. Use one inline progress line
  with block chars (`▏▎▍▌▋▊▉█`) showing `done/total`, percent, and rate.
  Determinate bar only; spinner (Braille `dots` at ~80ms) only after
  150–200ms of indeterminate work; suppressed on non-TTY (already refused).
- Breakpoint ladder:
  - Wide (>120 cols): table 70% + side detail 30%.
  - Standard (80–120): table full-width, detail via `Enter`.
  - Narrow (60–80): single column; hide low-priority columns first in
    order ASN, then N, then TYPE; truncate with reserved ellipsis cell,
    never wrap inside cells.
  - Below minimum (`60×12`): clean message
    `terminal too small — need 60×12`, no garbage, no panic.
- Clutter audit fixes: at most one border between terminal edge and
  content; no outer fullscreen frame; one signal per state (color plus
  one letter/symbol: `✓/✗`, `▲/▼`); no always-on row markers; whitespace
  before new borders; removal test for every decorative element.
- Semantic tokens (function, not appearance): `status.success|warning|
  error|info`, `text.primary|muted|emphasis`, `bg.base|surface|overlay`,
  `accent.primary`, `border.default|focus`. Honor `NO_COLOR` (non-empty
  value suppresses auto color; explicit `--color=always` may override if
  documented). Preserve meaning in 16-color/monochrome and ASCII fallback
  (`─│┌┐└┘├┤┬┴┼` to `- | +`). Selection stays reverse-video (canonical).
  Bold for titles/focused panel, dim for metadata. No blink.
- Tables: numerics right-aligned (RTT, N); text left; dates fixed-width
  ISO-8601 where shown; sort indicator `▲/▼` after header (`Size ▼`);
  filter shows `123/45678` with matched-substring highlight and
  smart-case (lowercase is case-insensitive); updates under 100ms;
  virtualize via existing `window()` (keep O(1), cache string widths
  outside the render closure).

## 5. Interaction + keymap (hybrid)

Philosophy: hybrid — arrows and `hjkl` aliases work together on
navigational surfaces; printable aliases yield when a text field owns input.

Keymap (single source; footer derived from it):

- `q` quit (modeless fullscreen), `?` help, `Esc` cancel/back/dismiss,
  `Enter` confirm/drill-in, `/` filter, `n/N` next/prev match when
  search-match navigation exists, `Space` reserved for future multi-select
  (not implemented now), `r` refresh/re-run (Done screen), `1–9` reserved
  (no numeric jumps while single-panel).
- Running: `q` quit, `?` help, `p` pause/resume, `c` cancel run,
  `s` cycle sort, `S` toggle order, `/` filter, `x` clear filter,
  `d` detail alias, `Enter` detail drill-in, `e` export,
  `↑/↓/j/k` move, `PgUp/PgDn` page (added to Running; currently Done only),
  `gg/G` top/bottom.
- Done: `q/Esc` quit, `?` help, `s/S` sort, `/` filter, `x` clear,
  `d` detail, `Enter` detail, `e` export, `r` re-run same options,
  navigation same as Running. `y` is reserved and unbound in this
  redesign (clipboard yank via OSC 52 is explicitly out of scope).
- Input (filter/export): `Enter` submit, `Esc` cancel, `Backspace` delete,
  printable text. Validation on submit/blur, never per-keystroke error.
- Reserved: never bind `Ctrl+C` (SIGINT quit path), `Ctrl+Z` (suspend),
  `Ctrl+\`, `Ctrl+S/Q` (flow control). `Ctrl+C` during Running cancels
  the run then quits cleanly on second press or when idle; on Done it
  quits. `Ctrl+H` left unbound until tested per terminal.
- Discoverability: Layer 1 footer hints (contextual, 3–5 keys);
  Layer 2 `?` full key table grouped by global/running/results/input.
  No leader/which-key and no command palette (action set under 20).
- Focus: single primary panel so no Tab cycle now; drill-down overlay
  traps focus with `Esc` escape; focused border uses accent color plus
  bold title; selection is reverse-video in focused view only.
- Mouse: augment only (click to select, scroll lists, click tabs where
  present). Every mouse action keeps a keyboard equivalent. Document
  Shift-bypass for terminal text selection. No mouse-only critical path;
  must work over restricted SSH.
- Confirmation: `y/N` (default No) for export overwrite and cancel
  in-flight run. No typed-name confirmation (no nuclear action).
- Forms: filter/export are single-field prompts centered with `Clear`
  hole-punch; no multi-field settings form in TUI.

## 6. Data flow + error handling

- `begin_run` clears results/visible/overflow/health/failures/summary,
  resets selection, records start time, spawns engine with cloned
  `RunSpec` over bounded `mpsc`, sets `Screen::Running`.
- Engine events: `Proxy` (push until 20k cap, then `overflow += 1`),
  `JudgeHealth` (`H/C judges healthy`), `PassChanged`
  (`validating pass N`), `Failure` (ring buffer 64, `ip:port proto — reason`),
  `Finished(summary)` (screen Done), `Error(text)` (screen Done + message).
- Tick (100ms): `refresh_visible()` plus `clamp_selection` plus rate
  update from `progress.done()` sampled at 0.5s granularity.
- `visible()` is pure filter plus stable sort; `window()` keeps selection
  on screen; `compute_layout(area)` is pure for per-size tests.
- Export writes only `visible` rows in the spec output format; empty path
  cancels with message; overwrite prompts `y/N`; result is a status-line
  receipt, not stdout paint.
- All terminal I/O stays in the event/render loop; disk/net/subprocess
  work never blocks it (commands/messages/channels only). Cell width via
  `unicode_width`, not `len()`. Collections over a few hundred rows stay
  virtualized. Logs go to a file (ANSI disabled) or in-app console,
  never `println!` into raw/alt-screen. `insert_before` style scrollback
  pollution is out of scope while fullscreen-only.

## 7. Responsive, accessibility, streams

- 80×24 is the compatibility baseline; 60-column tmux split is the
  narrow test rig; ultrawide is opportunistic side-detail only.
- Keyboard-reachable everything; help accurate; focus visible.
- `NO_COLOR`, 16-color/monochrome, ASCII fallback, and non-TTY refusal
  already in guard; keep and test. No color-alone signaling.
- Wide characters, combining marks, emoji truncation covered in tests.
- Streams: TUI owns the screen; result data leaves only via export file
  or post-TUI stdout receipt. No stdout corruption from render path.

## 8. Verification plan

Bottom-heavy pyramid:

1. Unit: `visible`, `compare`, `window`, `clamp_selection`,
   `cycle_sort`, `action_for` keymap, rate sampling, export path default.
2. Golden frames (`TestBackend` plus `insta` snapshots, size-suffixed):
   `120×30`, `80×24`, `60×20`, minimum message. Snapshots assert text;
   separate `Buffer` equality asserts assert color/style regions
   (selected row reverse, error red, focus accent).
3. PTY smoke (1–2 flows max): normal run to Done plus quit; interrupt
   plus resize plus too-small message. Covers startup first-draw (no blank
   first tick after loop refactor), normal exit, error exit, panic restore.

Checklist before merge: normal/interrupt/error/panic cleanup; resize,
too-small, suspend/resume where supported; empty, loading, partial,
error, disconnected, large-data (20k cap) states; keyboard reachability
and help accuracy; `NO_COLOR`/monochrome/ASCII/non-TTY; CJK/combining/
emoji widths; sorting/virtualization; no blocking I/O in render path.

## 9. Rollout

1. Upgrade crate (`Ratatui 0.30`, `crossterm 0.29`, single flag) plus
   `cargo tree` check and lifecycle migration behind no behavior change.
2. Layout pass (header/inline progress/table/footer, drill-down detail,
   breakpoints, tokens, clutter cuts).
3. Interaction pass (hybrid aliases, `PgUp/PgDn`+`gg/G` everywhere,
   footer-from-keymap, `?` regroup, export-overwrite confirm).
4. Golden snapshots plus PTY smoke plus checklist above.
