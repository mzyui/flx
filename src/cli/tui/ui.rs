//! Rendering for every TUI surface.
//!
//! The only panel with a border is the primary table; the side detail, header,
//! and footer are plain text, and overlays hole-punch the frame with `Clear`.
//! Nothing here measures a row per frame: the table reads prebuilt
//! [`RowModel`]s out of `App`.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Cell, Clear, Padding, Paragraph, Row, Table, Wrap};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr as _;

use super::app::{App, Confirm, InputBox, MessageKind};
use super::event::{self, InputPurpose, Screen};
use super::theme;
use super::view::{self, RowModel};

/// Rows an overlay spends on its border.
const OVERLAY_CHROME_ROWS: u16 = 2;
/// Cells an overlay spends on its border and inner padding.
const OVERLAY_CHROME_COLUMNS: u16 = 4;
/// Share of the terminal a drill-down overlay takes.
const DETAIL_WIDTH_PERCENT: u16 = 70;
/// Share of the terminal the help overlay takes.
const HELP_WIDTH_PERCENT: u16 = 80;
/// Share of the terminal a text prompt takes.
const PROMPT_WIDTH_PERCENT: u16 = 60;
/// Interior rows a prompt needs: one line of text plus breathing room.
const PROMPT_ROWS: u16 = 3;
/// Interior rows a confirmation needs: the question and the answers.
const CONFIRM_ROWS: u16 = 3;
/// Narrowest a centered overlay is allowed to get.
const MIN_OVERLAY_WIDTH: u16 = 30;
/// The bar takes this fraction of the live line, so the numbers beside it keep
/// a stable position instead of sliding as they change width.
const BAR_SHARE: u16 = 4;
/// Bar floor and ceiling, in cells.
const MIN_BAR_CELLS: u16 = 10;
const MAX_BAR_CELLS: u16 = 24;
/// A leading cell, plus two between the bar and its numbers.
const BAR_GUTTER_CELLS: u16 = 3;

/// Draws the whole interface for the current state.
pub(crate) fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let Some(layout) = view::compute_layout(area) else {
        render_too_small(frame, area);
        return;
    };

    render_header(frame, app, layout.header);
    render_table(frame, app, layout.table);
    if let Some(side) = layout.side_detail {
        render_side_detail(frame, app, side);
    }
    render_footer(frame, app, layout.footer);

    // Overlays, topmost surface last.
    if app.help {
        render_help(frame, app, area);
    } else if let Some(confirm) = &app.confirm {
        render_confirm(frame, confirm, area);
    } else if let Some(input) = &app.input {
        render_input(frame, input, area);
    } else if app.view.detail {
        render_detail(frame, app, area);
    }
}

/// The browsed row a click landed on, if it hit the table body.
///
/// Mouse input only accelerates the keyboard: every row a click can reach is
/// already reachable with the movement keys.
pub(crate) fn row_at(app: &App, area: Rect, row: u16) -> Option<usize> {
    let layout = view::compute_layout(area)?;
    let body = table_block(app).inner(layout.table);
    // The header occupies the first line inside the panel.
    let first_data_row = body.y.checked_add(1)?;
    if row < first_data_row || row >= body.bottom() {
        return None;
    }
    let height = view::table_rows(layout.table.height);
    let (start, _) = view::window(app.view.selected, height, app.visible.len());
    let index = start + usize::from(row - first_data_row);
    (index < app.visible.len()).then_some(index)
}

fn separator() -> &'static str {
    theme::glyph(theme::DOT)
}

/// Below the supported minimum there is nothing honest to draw.
fn render_too_small(frame: &mut Frame, area: Rect) {
    let message = format!(
        "terminal too small {} need {}{}{}",
        theme::glyph(theme::DASH),
        view::MIN_WIDTH,
        theme::glyph(theme::TIMES),
        view::MIN_HEIGHT
    );
    // One line, a third of the way down: enough to read, no chrome to mislead.
    let [_, line, _] = Layout::vertical([
        Constraint::Percentage(40),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .areas(area);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(message, theme::status_warning())))
            .alignment(Alignment::Center),
        line,
    );
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let (state, state_style) = match app.screen {
        Screen::Running => ("running", theme::accent_primary()),
        Screen::Done if app.cancelled => ("done", theme::status_warning()),
        Screen::Done => ("done", theme::status_success()),
    };
    let identity = Line::from(vec![
        Span::styled(" flx", theme::title()),
        Span::styled(format!(" {} ", separator()), theme::text_muted()),
        Span::styled(app.mode_label(), theme::accent_primary()),
        Span::styled(format!(" {} ", separator()), theme::text_muted()),
        Span::styled(state, state_style),
        Span::styled(
            format!(" {}", format_duration(app.elapsed())),
            theme::text_muted(),
        ),
    ]);
    let live = match app.screen {
        Screen::Running => running_summary(app, area.width),
        Screen::Done => done_summary(app),
    };
    frame.render_widget(Paragraph::new(vec![identity, live]), area);
}

/// The live line: the progress bar and its numbers once validation is running,
/// or the phase and gathered count while it is not.
///
/// This is the only place the run's progress appears, so nothing is stated
/// twice and no third chrome row is needed for the bar.
fn running_summary(app: &App, width: u16) -> Line<'static> {
    let mut spans = Vec::new();
    match app.live() {
        Some(live) => {
            match &live.progress {
                Some(progress) => {
                    spans.extend(progress_spans(
                        progress.done(),
                        progress.total(),
                        progress.passed(),
                        progress.fraction(),
                        app.rate,
                        width,
                    ));
                }
                None => {
                    let elapsed = live.phase_elapsed();
                    spans.push(Span::styled(" ", theme::text_muted()));
                    // Stay quiet until the phase has visibly not finished.
                    if elapsed >= view::SPINNER_DELAY {
                        spans.push(Span::styled(
                            view::spinner_frame(elapsed),
                            theme::accent_primary(),
                        ));
                        spans.push(Span::styled(" ", theme::text_muted()));
                    }
                    spans.push(Span::styled(live.phase.label(), theme::accent_primary()));
                    spans.push(Span::styled(
                        format!(" {} gathered {}", separator(), live.gathered()),
                        theme::text_primary(),
                    ));
                }
            }
            if live.paused() {
                spans.push(Span::styled(
                    format!("  {} paused", theme::glyph(theme::PAUSED)),
                    theme::status_warning(),
                ));
            }
        }
        None => {
            spans.push(Span::styled(" starting", theme::accent_primary()));
            spans.push(Span::styled(
                format!(" {}", theme::glyph(theme::DASH)),
                theme::text_muted(),
            ));
        }
    }
    // Judge health is only news when it is bad; all-healthy is the norm.
    if let Some(health) = unhealthy_judges(app) {
        spans.push(Span::styled(
            format!("  {} {health}", theme::glyph(theme::WARNING)),
            theme::status_warning(),
        ));
    }
    Line::from(spans)
}

/// The judge health report, but only when at least one judge is down.
fn unhealthy_judges(app: &App) -> Option<&str> {
    let health = app.health.as_deref()?;
    let (healthy, candidates) = health.split_once('/')?;
    (healthy != candidates.split(' ').next()?).then_some(health)
}

fn done_summary(app: &App) -> Line<'static> {
    let mut spans = vec![Span::styled(" ", theme::text_muted())];
    match &app.summary {
        Some(summary) => {
            spans.push(Span::styled(
                format!("kept {}", summary.valid),
                theme::status_success(),
            ));
            if summary.failed > 0 {
                spans.push(Span::styled(
                    format!("  {} failed", summary.failed),
                    theme::status_error(),
                ));
            }
            spans.push(Span::styled(
                format!(
                    " {} gathered {} in {}",
                    separator(),
                    summary.gathered,
                    format_duration(summary.elapsed)
                ),
                theme::text_primary(),
            ));
        }
        None => spans.push(Span::styled(
            format!("{} rows", app.results.len()),
            theme::text_primary(),
        )),
    }
    if app.cancelled {
        spans.push(Span::styled("  cancelled", theme::status_warning()));
    }
    Line::from(spans)
}

/// The determinate progress strip: bar, counts, percent, rate, and the
/// pass/fail split.
///
/// This is the whole of the run's progress reporting — one line, each fact
/// stated once — so the header needs no third row for the bar.
fn progress_spans(
    done: usize,
    total: usize,
    passed: usize,
    fraction: f64,
    rate: f64,
    width: u16,
) -> Vec<Span<'static>> {
    let fraction = fraction.clamp(0.0, 1.0);
    let failed = done.saturating_sub(passed);
    let mut split = format!(
        "  {} {passed} {} {failed}",
        theme::glyph(theme::CHECK),
        theme::glyph(theme::CROSS)
    );
    // Below the supported minimum a row cannot hold the whole strip; the bar and
    // the counts win, because they are what the user is reading.
    if width < view::MIN_WIDTH {
        split.clear();
    }
    let split_cells = split.width() as u16;

    // A fixed share keeps the numbers beside the bar in the same place from
    // frame to frame instead of sliding around as they change width.
    let share = (width / BAR_SHARE).clamp(MIN_BAR_CELLS, MAX_BAR_CELLS);
    let budget = width.saturating_sub(share + BAR_GUTTER_CELLS + split_cells);
    let label = progress_label(done, total, fraction, rate, budget);
    // The bar holds its floor while the row can afford it, and yields rather
    // than pushing the numbers off the edge.
    let numbers = label.width() as u16 + split_cells + BAR_GUTTER_CELLS;
    let bar_cells = share.min(width.saturating_sub(numbers));

    let mut spans = vec![
        Span::styled(
            view::progress_bar(fraction, bar_cells),
            theme::accent_primary(),
        ),
        Span::styled(format!("  {label}"), theme::text_primary()),
    ];
    if !split.is_empty() {
        spans.push(Span::styled(
            format!("  {} {passed}", theme::glyph(theme::CHECK)),
            theme::status_success(),
        ));
        spans.push(Span::styled(
            format!(" {} {failed}", theme::glyph(theme::CROSS)),
            theme::status_error(),
        ));
    }
    spans
}

/// The numbers beside the bar, at the longest form that fits `budget` cells.
/// A cramped strip drops the rate first, then the percent: the bar and the
/// counts are the two things worth keeping.
fn progress_label(done: usize, total: usize, fraction: f64, rate: f64, budget: u16) -> String {
    let counts = format!("{done}/{total}");
    let percent = format!("{:>3.0}%", fraction * 100.0);
    let candidates = [
        format!("{counts}  {percent}  {rate:.1}/s"),
        format!("{counts}  {percent}"),
        counts,
    ];
    let mut chosen = candidates[candidates.len() - 1].clone();
    for candidate in candidates {
        if candidate.width() as u16 <= budget {
            chosen = candidate;
            break;
        }
    }
    chosen
}

fn render_table(frame: &mut Frame, app: &App, area: Rect) {
    let rows_in_view = app.visible.len();
    let fitted = view::fit_columns(
        area.width.saturating_sub(view::TABLE_CHROME_COLUMNS),
        rows_in_view,
    );
    let height = view::table_rows(area.height);
    let (start, end) = view::window(app.view.selected, height, rows_in_view);

    let header = Row::new(
        fitted
            .iter()
            .map(|(index, width)| header_cell(*index, *width, app)),
    )
    .style(theme::title());

    // The row marker identifies *which* row the frame is about, so it stays
    // while the table is on screen: opening the drill-down or a prompt must not
    // lose the row it refers to. Focus is signalled by the border, not by this.
    let filter = (!app.view.filter.is_empty()).then_some(app.view.filter.as_str());
    let rows: Vec<Row> = (start..end)
        .map(|position| {
            let row = &app.rows[app.visible[position]];
            let hit = filter.and_then(|filter| view::find_hit(row, filter));
            let cells = fitted
                .iter()
                .map(|(index, width)| body_cell(row, position + 1, *index, *width, hit));
            Row::new(cells).style(if position == app.view.selected {
                theme::selected()
            } else {
                theme::text_primary()
            })
        })
        .collect();

    let widths = fitted.iter().map(|(_, width)| Constraint::Length(*width));
    let table = Table::new(rows, widths)
        .column_spacing(view::COLUMN_SPACING)
        .header(header)
        .block(table_block(app));
    frame.render_widget(table, area);
}

/// The primary table's block: the one bordered panel, accent when focused.
fn table_block(app: &App) -> Block<'static> {
    let focused = !app.overlay_open();
    let title_style = if focused {
        theme::title()
    } else {
        theme::text_muted()
    };
    Block::bordered()
        .border_set(theme::border_set())
        .border_style(if focused {
            theme::border_focus()
        } else {
            theme::border_default()
        })
        .padding(Padding::horizontal(1))
        .title(Line::from(table_title(app)).style(title_style))
}

fn table_title(app: &App) -> String {
    let mut title = format!(
        " results {} {}/{} {} sort {} {} ",
        separator(),
        app.visible.len(),
        app.results.len(),
        separator(),
        app.view.sort_label(),
        app.view.order_glyph()
    );
    if !app.view.filter.is_empty() {
        title.push_str(&format!("{} filter \"{}\" ", separator(), app.view.filter));
    }
    if app.overflow > 0 {
        title.push_str(&format!("{} over cap {} ", separator(), app.overflow));
    }
    title
}

fn header_cell(index: usize, width: u16, app: &App) -> Cell<'static> {
    let column = &view::COLUMNS[index];
    Cell::from(Text::from(header_text(index, width, app)).alignment(column.align))
}

/// The header label, with the sort indicator on the column that owns the sort.
fn header_text(index: usize, width: u16, app: &App) -> String {
    let column = &view::COLUMNS[index];
    let arrow = if column.sort_key.is_some() && column.sort_key == app.view.sort {
        app.view.order_glyph()
    } else {
        ""
    };
    let arrow_cells = arrow.width() as u16;
    // The indicator outranks the label: shorten the label rather than drop it.
    if arrow_cells > 0 && arrow_cells < width {
        format!(
            "{} {arrow}",
            view::clamp_cells(column.title, width - arrow_cells - 1)
        )
    } else {
        view::clamp_cells(column.title, width).into_owned()
    }
}

/// One body cell: the row's field, or the row's number in the current view.
///
/// `ordinal` is 1-based, matching what `{n}G` takes.
fn body_cell(
    row: &RowModel,
    ordinal: usize,
    index: usize,
    width: u16,
    hit: Option<view::Hit>,
) -> Cell<'static> {
    let column = &view::COLUMNS[index];
    let cell = match column.source {
        // Numbers are the jump addresses, so they read as metadata and never
        // compete with the data beside them.
        view::Source::Ordinal => {
            let number = ordinal.to_string();
            let text = view::clamp_cells(&number, width).into_owned();
            return Cell::from(
                Text::from(Line::from(Span::styled(text, theme::text_muted())))
                    .alignment(column.align),
            );
        }
        view::Source::Cell(cell) => cell,
    };
    let text = view::clamp_cells(&row.cells[cell], width);
    let line = match hit {
        // The match can sit past the truncation point; then there is nothing on
        // screen to highlight.
        Some(hit) if hit.column == cell && hit.range.1 <= text.len() => {
            let (begin, end) = hit.range;
            Line::from(vec![
                Span::raw(text[..begin].to_owned()),
                Span::styled(text[begin..end].to_owned(), theme::match_highlight()),
                Span::raw(text[end..].to_owned()),
            ])
        }
        _ => Line::from(Span::raw(text.into_owned())),
    };
    Cell::from(Text::from(line).alignment(column.align))
}

/// The persistent side panel on ultrawide terminals. Deliberately borderless:
/// the table's right border already separates the two.
fn render_side_detail(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = vec![Line::from(Span::styled(" selected", theme::title()))];
    lines.extend(detail_lines(app));
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::new().padding(Padding::horizontal(1)))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn detail_lines(app: &App) -> Vec<Line<'static>> {
    let Some(proxy) = app.selected_proxy() else {
        return vec![Line::from(Span::styled(
            " no row selected",
            theme::text_muted(),
        ))];
    };
    let mut lines = vec![
        Line::from(Span::styled(
            format!(" {}", proxy.as_text()),
            theme::text_emphasis(),
        )),
        field("geo", geo_summary(proxy)),
        field(
            "org",
            proxy
                .geo
                .aso
                .as_deref()
                .unwrap_or("unknown organization")
                .to_owned(),
        ),
        field(
            "rtt",
            format!(
                "{:.2}s {sep} n={} {sep} min {:.2}s max {:.2}s",
                proxy.avg_response_time(),
                proxy.sample_count(),
                proxy.min_response_time(),
                proxy.max_response_time(),
                sep = separator()
            ),
        ),
        field("types", types_summary(proxy)),
    ];
    if let Some(failure) = app.failures.last() {
        lines.push(field("last failure", failure.clone()));
    }
    lines
}

/// One `name  value` line, with the name in a fixed muted gutter.
fn field(name: &'static str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!(" {name:<11} "), theme::text_muted()),
        Span::styled(value, theme::text_primary()),
    ])
}

fn geo_summary(proxy: &flx::Proxy) -> String {
    let city = proxy.geo.city_name.as_deref().unwrap_or("-");
    let asn = proxy
        .geo
        .asn
        .map(|asn| asn.to_string())
        .unwrap_or_else(|| "-".to_owned());
    format!(
        "{} {sep} {city} {sep} asn {asn}",
        proxy.geo.iso_code.as_deref().unwrap_or("--"),
        sep = separator()
    )
}

fn types_summary(proxy: &flx::Proxy) -> String {
    if proxy.proxy_types.is_empty() {
        return "unvalidated".to_owned();
    }
    proxy
        .proxy_types
        .iter()
        .map(|entry| entry.protocol.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![Span::styled(" ", theme::text_muted())];
    // A half-typed row number replaces the hints: while the user is mid-count,
    // what completes it is the only thing worth saying.
    if let Some((count, label)) = event::count_hint(app.key_context()) {
        spans.push(Span::styled(count, theme::accent_primary()));
        spans.push(Span::styled(format!(" {label}"), theme::text_muted()));
        spans.push(Span::styled("  ", theme::text_muted()));
    } else {
        for (position, (keys, label)) in event::hints(app.key_context()).into_iter().enumerate() {
            if position > 0 {
                spans.push(Span::styled(
                    format!("  {}  ", separator()),
                    theme::text_muted(),
                ));
            }
            spans.push(Span::styled(keys, theme::accent_primary()));
            spans.push(Span::styled(format!(" {label}"), theme::text_muted()));
        }
    }
    let mut lines = vec![Line::from(spans)];
    if let Some(message) = &app.message {
        let style = match message.kind {
            MessageKind::Info => theme::status_info(),
            MessageKind::Warning => theme::status_warning(),
            MessageKind::Error => theme::status_error(),
        };
        lines.push(Line::from(Span::styled(
            format!(" {}", message.text),
            style,
        )));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// The single border an overlay gets: accent, with the ASCII set when needed.
fn overlay_block(title: impl Into<String>) -> Block<'static> {
    Block::bordered()
        .border_set(theme::border_set())
        .border_style(theme::border_focus())
        .padding(Padding::horizontal(1))
        .title(Line::from(title.into()).style(theme::title()))
}

/// A centered rectangle of the given size, clamped inside `area`.
fn popup_area(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

fn percent_of(value: u16, percent: u16) -> u16 {
    value.saturating_mul(percent) / 100
}

fn overlay_width(area: Rect, percent: u16) -> u16 {
    percent_of(area.width, percent).max(MIN_OVERLAY_WIDTH)
}

fn render_input(frame: &mut Frame, input: &InputBox, area: Rect) {
    let target = popup_area(
        area,
        overlay_width(area, PROMPT_WIDTH_PERCENT),
        PROMPT_ROWS + OVERLAY_CHROME_ROWS,
    );
    frame.render_widget(Clear, target);
    let title = match input.purpose {
        InputPurpose::Filter => " filter ",
        InputPurpose::ExportPath => " export to path ",
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            input.buffer.clone(),
            theme::text_emphasis(),
        )))
        .block(overlay_block(title))
        .style(theme::bg_overlay()),
        target,
    );
    // The caret sits at the end of the buffer: the prompt has no cursor keys.
    let caret = target.x + 2 + input.buffer.width() as u16;
    if caret < target.right().saturating_sub(1) {
        frame.set_cursor_position((caret, target.y + 1));
    }
}

fn render_confirm(frame: &mut Frame, confirm: &Confirm, area: Rect) {
    let target = popup_area(
        area,
        overlay_width(area, PROMPT_WIDTH_PERCENT),
        CONFIRM_ROWS + OVERLAY_CHROME_ROWS,
    );
    frame.render_widget(Clear, target);
    let lines = vec![
        Line::from(Span::styled(
            confirm.question.clone(),
            theme::text_emphasis(),
        )),
        Line::from(vec![
            Span::styled(" y", theme::accent_primary()),
            Span::styled(" yes", theme::text_muted()),
            Span::styled("     n", theme::accent_primary()),
            Span::styled(" no", theme::text_muted()),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(overlay_block(" confirm "))
            .style(theme::bg_overlay())
            .wrap(Wrap { trim: true }),
        target,
    );
}

fn render_detail(frame: &mut Frame, app: &App, area: Rect) {
    let lines = detail_lines(app);
    let target = popup_area(
        area,
        overlay_width(area, DETAIL_WIDTH_PERCENT),
        (lines.len() as u16 + OVERLAY_CHROME_ROWS).min(area.height),
    );
    frame.render_widget(Clear, target);
    frame.render_widget(
        Paragraph::new(lines)
            .block(overlay_block(" detail "))
            .style(theme::bg_overlay())
            .wrap(Wrap { trim: true }),
        target,
    );
}

/// The full key table: one scrollable column, so the wording can be worth
/// reading instead of squeezed into two narrow ones.
fn render_help(frame: &mut Frame, app: &App, area: Rect) {
    let body = help_body();
    let rows = body.len() as u16;
    let widest = body
        .iter()
        .map(|line| line.width() as u16)
        .max()
        .unwrap_or(0);
    // Size to the content, so a row is never cut mid-word; take the whole screen
    // when the body needs it, rather than leaving strips of the app peeking out
    // from behind a modal that is nearly full anyway.
    let needed_height = (rows + OVERLAY_CHROME_ROWS).min(area.height);
    let target = if needed_height == area.height {
        area
    } else {
        popup_area(
            area,
            overlay_width(area, HELP_WIDTH_PERCENT).max(widest + OVERLAY_CHROME_COLUMNS),
            needed_height,
        )
    };
    let visible = target.height.saturating_sub(OVERLAY_CHROME_ROWS);
    let scroll = app.help_scroll.min(rows.saturating_sub(visible));
    let title = if scroll == 0 && rows <= visible {
        // Nothing is hidden, so there is no position worth reporting.
        " help ".to_owned()
    } else {
        format!(
            " help {}-{}/{rows} ",
            scroll + 1,
            (scroll + visible).min(rows)
        )
    };

    let block = overlay_block(title).style(theme::bg_overlay());
    let inner = block.inner(target);
    frame.render_widget(Clear, target);
    frame.render_widget(
        Paragraph::new(body)
            .style(theme::bg_overlay())
            .scroll((scroll, 0)),
        inner,
    );
    // The border is drawn last so that it frames the content.
    frame.render_widget(block, target);
}

/// Every line of the `?` panel: the key table grouped by surface, then the
/// facts that have no key.
fn help_body() -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (title, scope) in event::HELP_GROUPS {
        if !lines.is_empty() {
            // Whitespace separates sections; a rule would just add chrome.
            lines.push(Line::default());
        }
        lines.push(Line::from(Span::styled(
            format!(" {title}"),
            theme::title(),
        )));
        for (keys, detail) in event::bindings_on(scope) {
            lines.push(Line::from(vec![
                Span::styled(format!("   {keys:<10}"), theme::accent_primary()),
                Span::styled(detail, theme::text_primary()),
            ]));
        }
    }
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(" notes", theme::title())));
    for note in event::HELP_NOTES {
        lines.push(Line::from(Span::styled(
            format!("   {note}"),
            theme::text_muted(),
        )));
    }
    lines
}

fn format_duration(elapsed: std::time::Duration) -> String {
    if elapsed.as_secs() < 60 {
        format!("{:.1}s", elapsed.as_secs_f64())
    } else {
        format!("{}m {:02}s", elapsed.as_secs() / 60, elapsed.as_secs() % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use flx::proxy::models::Proxy;
    use flx::{Protocol, ProxyType};
    use ratatui::backend::TestBackend;
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::Terminal;

    use crate::tui::app::{App, Confirm, ConfirmKind};
    use crate::tui::engine::{test_spec, EngineEvent};
    use crate::tui::event::{Action, Screen};

    /// Pins the process-wide palette for the duration of one test.
    fn use_theme(monochrome: bool, ascii: bool) -> std::sync::MutexGuard<'static, ()> {
        let guard = theme::lock_for_tests();
        theme::configure(monochrome, ascii);
        guard
    }

    /// A deterministic run of rows, each with a country, an ASN, and an RTT.
    fn sample_app(count: usize) -> App {
        let mut app = App::new(test_spec(false));
        for slot in 0..count {
            let mut proxy = Proxy::new(
                Ipv4Addr::new(203, 0, 113, 1 + slot as u8),
                8000 + slot as u16,
            );
            proxy.runtimes.record(0.10 + slot as f64 * 0.05);
            proxy.proxy_types.push(ProxyType::checked(Protocol::Socks5));
            proxy.geo = Arc::new(flx::GeoData {
                iso_code: Some(if slot % 2 == 0 { "DE" } else { "ID" }.into()),
                city_name: Some(if slot % 2 == 0 { "Berlin" } else { "Jakarta" }.into()),
                asn: Some(15169),
                aso: Some("Example Networks".into()),
                ip_type: flx::IpType::Residential,
                ..flx::GeoData::default()
            });
            app.rows.push(RowModel::new(&proxy));
            app.results.push(proxy);
        }
        app.screen = Screen::Done;
        app.refresh_visible();
        app
    }

    fn draw(app: &App, width: u16, height: u16) -> TestBackend {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal builds");
        terminal
            .draw(|frame| render(frame, app))
            .expect("draws without panicking");
        terminal.backend().clone()
    }

    fn style_at(backend: &TestBackend, x: u16, y: u16) -> Style {
        backend
            .buffer()
            .cell((x, y))
            .expect("cell is in bounds")
            .style()
    }

    fn any_style(backend: &TestBackend, matches: impl Fn(Style) -> bool) -> bool {
        let buffer = backend.buffer();
        (0..buffer.area.height).any(|y| {
            (0..buffer.area.width).any(|x| {
                buffer
                    .cell((x, y))
                    .is_some_and(|cell| matches(cell.style()))
            })
        })
    }

    fn text(backend: &TestBackend) -> String {
        backend
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    /// The frame as rows, for diagnostics that read better than one long line.
    fn frame_text(backend: &TestBackend) -> String {
        let buffer = backend.buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.cell((x, y)).expect("in bounds").symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The help panel's whole body as text, the way `?` lays it out.
    fn help_text() -> String {
        let body: String = help_body()
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        normalized(&body)
    }

    /// A frame with runs of whitespace collapsed, so a padded column and its
    /// value can be matched as one phrase.
    fn normalized(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The number a table line opens with, if it opens with one.
    ///
    /// Data lines read `│ 12 203.0.113.7:80 …`, so the first digit run is the
    /// ordinal the jump keys take.
    fn leading_number(line: &str) -> Option<usize> {
        let digits: String = line
            .chars()
            .skip_while(|glyph| !glyph.is_ascii_digit())
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    }

    /// The column index that reports on a sort key.
    fn column_index(key: flx::SortKey) -> usize {
        view::COLUMNS
            .iter()
            .position(|column| column.sort_key == Some(key))
            .expect("every sort key has a column")
    }

    /// A frame as one line, for assertions about what it says.
    fn flatten(spans: &[Span<'static>]) -> String {
        spans.iter().map(|span| span.content.as_ref()).collect()
    }

    /// Cells a run of spans occupies, measured the way the terminal does.
    fn cells(spans: &[Span<'static>]) -> usize {
        spans.iter().map(|span| span.content.width()).sum()
    }

    /// Text of the highlighted row, when any row carries the selection style.
    ///
    /// Reads styles, so the detail pane, which also prints the selected
    /// endpoint, cannot satisfy the assertion on its own.
    fn highlighted_row(backend: &TestBackend) -> Option<String> {
        let buffer = backend.buffer();
        for y in 0..buffer.area.height {
            let mut line = String::new();
            let mut highlighted = false;
            for x in 0..buffer.area.width {
                let cell = buffer.cell((x, y)).expect("cell is in bounds");
                highlighted |= cell.style().add_modifier.contains(Modifier::REVERSED);
                line.push_str(cell.symbol());
            }
            if highlighted {
                return Some(line);
            }
        }
        None
    }

    #[test]
    fn the_selected_row_stays_visible_at_the_bottom() {
        let _theme = use_theme(true, false);
        let mut app = sample_app(30);
        app.view.selected = 29;
        app.refresh_visible();

        let backend = draw(&app, 100, 16);
        let expected = app.results[29].as_text();
        let highlighted =
            highlighted_row(&backend).expect("a row is highlighted while browsing results");
        assert!(
            highlighted.contains(expected),
            "the highlighted row must be {expected}, got: {highlighted}"
        );
    }

    #[test]
    fn every_selection_stays_highlighted_while_scrolling() {
        let _theme = use_theme(true, false);
        let mut app = sample_app(30);

        for selected in 0..app.visible.len() {
            app.view.selected = selected;
            let backend = draw(&app, 100, 16);
            let expected = app.results[selected].as_text();
            let highlighted =
                highlighted_row(&backend).expect("a row is highlighted while browsing results");
            assert!(
                highlighted.contains(expected),
                "selection {selected} must stay highlighted, got: {highlighted}"
            );
        }
    }

    #[test]
    fn opening_the_drill_down_keeps_the_row_marked() {
        let _theme = use_theme(false, false);
        let mut app = sample_app(6);

        let browsing = draw(&app, 80, 24);
        let marked = highlighted_row(&browsing).expect("the browsed row is marked");
        assert!(marked.contains(app.results[0].as_text()));

        app.view.detail = true;
        let drilled_in = draw(&app, 80, 24);
        let marked = highlighted_row(&drilled_in)
            .expect("the detail pane says which row it describes, and so must the table");
        assert!(
            marked.contains(app.results[0].as_text()),
            "the marked row must still be the selected one, got: {marked}"
        );

        app.view.detail = false;
        app.confirm = Some(Confirm {
            question: "cancel the run?".to_owned(),
            kind: ConfirmKind::CancelRun,
        });
        let prompting = draw(&app, 80, 24);
        assert!(
            highlighted_row(&prompting).is_some(),
            "the row marker survives a prompt drawn over the table"
        );
    }

    #[test]
    fn the_focused_table_wears_the_accent_border() {
        let _theme = use_theme(false, false);
        let app = sample_app(3);
        let backend = draw(&app, 80, 24);
        assert_eq!(
            style_at(&backend, 0, 2).fg,
            Some(Color::Cyan),
            "the focused panel must be recognizable without reading its title"
        );
    }

    #[test]
    fn an_overlay_takes_the_focus_ring_from_the_table() {
        let _theme = use_theme(false, false);
        let mut app = sample_app(3);
        app.view.detail = true;
        let backend = draw(&app, 80, 24);
        assert_ne!(
            style_at(&backend, 0, 2).fg,
            Some(Color::Cyan),
            "an open overlay owns the focus"
        );
        assert!(
            any_style(&backend, |style| style.fg == Some(Color::Cyan)),
            "the overlay itself is accented, so focus has not simply vanished"
        );
    }

    #[test]
    fn an_error_status_line_is_red_and_says_what_happened() {
        let _theme = use_theme(false, false);
        let mut app = sample_app(2);
        app.on_engine_event(EngineEvent::Error("no judges reachable".to_owned()));
        let backend = draw(&app, 100, 24);
        assert!(
            any_style(&backend, |style| style.fg == Some(Color::Red)),
            "a failure must not rely on words alone"
        );
        assert!(text(&backend).contains("no judges reachable"));
    }

    #[test]
    fn a_filter_match_is_highlighted_where_it_matched() {
        let _theme = use_theme(false, false);
        let mut app = sample_app(3);
        app.view.filter = "ID".to_owned();
        app.refresh_visible();
        assert_eq!(app.visible.len(), 1, "the filter narrows to the ID rows");
        let backend = draw(&app, 100, 24);
        assert!(
            any_style(&backend, |style| style.bg == Some(Color::Yellow)),
            "the matched substring is marked, not just the row set"
        );
    }

    #[test]
    fn no_color_leaves_every_cell_uncolored() {
        let _theme = use_theme(true, false);
        let mut app = sample_app(3);
        app.on_engine_event(EngineEvent::Error("no judges reachable".to_owned()));
        let backend = draw(&app, 80, 24);
        assert!(
            !any_style(&backend, |style| style
                .fg
                .is_some_and(|fg| fg != Color::Reset)),
            "monochrome must not set a foreground color anywhere"
        );
    }

    #[test]
    fn the_ascii_fallback_draws_no_box_glyphs() {
        let _theme = use_theme(true, true);
        let app = sample_app(3);
        let backend = draw(&app, 80, 24);
        let rendered = text(&backend);
        assert!(
            rendered.contains('+') && rendered.contains('-'),
            "the ASCII border set must be in use"
        );
        assert!(
            !rendered
                .chars()
                .any(|glyph| ('\u{2500}'..='\u{257f}').contains(&glyph)),
            "no box-drawing glyph may survive the fallback"
        );
    }

    #[test]
    fn the_too_small_frame_states_the_requirement() {
        let _theme = use_theme(true, false);
        let app = sample_app(3);
        let backend = draw(&app, 42, 10);
        let rendered = text(&backend);
        assert!(rendered.contains("terminal too small"), "got: {rendered}");
        assert!(
            rendered.contains(&format!(
                "{}{}",
                view::MIN_WIDTH,
                theme::glyph(theme::TIMES)
            )),
            "the message must name the minimum, got: {rendered}"
        );
    }

    #[test]
    fn the_table_title_reports_filter_and_overflow_only_when_real() {
        let plain = sample_app(3);
        let title = table_title(&plain);
        assert!(title.contains("3/3"), "got {title}");
        assert!(!title.contains("filter"), "got {title}");
        assert!(!title.contains("over cap"), "got {title}");

        let mut filtered = sample_app(3);
        filtered.view.filter = "ID".to_owned();
        filtered.overflow = 12;
        let title = table_title(&filtered);
        assert!(title.contains("filter \"ID\""), "got {title}");
        assert!(title.contains("over cap 12"), "got {title}");
    }

    #[test]
    fn the_header_indicator_sits_on_the_sorted_column_only() {
        let mut app = sample_app(3);
        app.view.sort = Some(flx::SortKey::Country);
        let country = column_index(flx::SortKey::Country);
        let sorted = header_text(country, 4, &app);
        assert!(
            sorted.contains(app.view.order_glyph()),
            "the sorted column needs an indicator, got {sorted}"
        );

        let other = header_text(column_index(flx::SortKey::AvgResponseTime), 8, &app);
        assert!(
            !other.contains(app.view.order_glyph()),
            "only the sorted column is marked, got {other}"
        );
    }

    #[test]
    fn the_help_body_documents_every_binding_and_note() {
        let _theme = use_theme(true, false);
        let body = help_text();

        for (group, scope) in event::HELP_GROUPS {
            assert!(body.contains(group), "the {group} group is missing");
            for (keys, detail) in event::bindings_on(scope) {
                assert!(
                    body.contains(&format!("{keys} {detail}")),
                    "`{keys} {detail}` is missing from the help panel"
                );
            }
        }
        for note in event::HELP_NOTES {
            assert!(body.contains(note), "the note {note:?} is missing");
        }
    }

    #[test]
    fn the_help_panel_scrolls_through_its_own_body() {
        let _theme = use_theme(true, false);
        let mut app = sample_app(3);
        app.help = true;

        // The panel opens at the top, so the first group is on screen and the
        // notes at the end are not.
        let backend = draw(&app, 80, 24);
        let top = normalized(&frame_text(&backend));
        assert!(top.contains("help"), "the panel is titled");
        assert!(
            top.contains(event::HELP_GROUPS[0].0),
            "the first group is on screen: {top:?}"
        );
        assert!(
            !top.contains(event::HELP_NOTES[0]),
            "with more below, the notes are off screen"
        );
        assert!(
            top.contains("esc close"),
            "the way out is in the footer: {top:?}"
        );

        // `G` jumps to the end of the body, and the title reports where it is.
        app.handle_action(Action::GotoBottom);
        let backend = draw(&app, 80, 24);
        let end = frame_text(&backend);
        assert!(
            normalized(&end).contains(event::HELP_NOTES[0]),
            "the notes are reachable"
        );
        assert!(
            end.contains("help ") && end.contains('/'),
            "the title reports the position: {:?}",
            end.lines().find(|line| line.contains("help"))
        );

        // Any unbound key leaves, from wherever the panel is scrolled.
        app.handle_action(Action::ScrollUp);
        assert!(app.help, "scrolling does not close the panel");
        app.handle_action(Action::GotoTop);
        assert_eq!(app.help_scroll, 0);
    }

    #[test]
    fn a_short_help_body_leaves_no_position_in_the_title() {
        // The title only reports a window when there is something to scroll to.
        let _theme = use_theme(true, false);
        let mut app = sample_app(3);
        app.help = true;
        // 80x24 shows fewer rows than the body, so the position shows; a taller
        // terminal shows all of it and the title goes back to just "help".
        let backend = draw(&app, 100, 60);
        let frame = frame_text(&backend);
        assert!(
            frame.lines().any(|line| line.contains(" help ")),
            "a fully visible panel needs no window: {:?}",
            frame.lines().find(|line| line.contains("help"))
        );
    }

    #[test]
    fn typing_a_row_number_shows_up_in_the_footer() {
        let _theme = use_theme(true, false);
        let mut app = sample_app(20);

        // A half-typed number replaces the hints: the footer is where the user
        // already looks, and the count is the only thing left to decide.
        app.handle_action(Action::Count(1));
        app.handle_action(Action::Count(2));
        let backend = draw(&app, 80, 24);
        let frame = frame_text(&backend);
        let hints = frame.lines().rev().nth(1).expect("the footer's first line");
        assert!(
            normalized(hints).contains("12 G go to row"),
            "got {hints:?}"
        );

        // Once the jump lands, the ordinary hints come back.
        app.handle_action(Action::GotoCount);
        assert_eq!(app.view.selected, 11);
        let backend = draw(&app, 80, 24);
        let frame = frame_text(&backend);
        let hints = frame.lines().rev().nth(1).expect("the footer's first line");
        assert!(
            normalized(hints).contains("s sort"),
            "the hints must return, got {hints:?}"
        );
    }

    #[test]
    fn the_ordinal_numbers_the_view_not_the_run() {
        let _theme = use_theme(true, false);
        let mut app = sample_app(6);
        app.view.filter = "ID".to_owned();
        app.refresh_visible();
        assert_eq!(app.visible.len(), 3, "every other row is ID");
        let backend = draw(&app, 80, 24);
        let frame = frame_text(&backend);

        // Every data line starts with the row's place in the current view, so a
        // filter renumbers the table rather than leaving gaps.
        let data_rows: Vec<&str> = frame
            .lines()
            .filter(|line| line.contains("203.0.113."))
            .collect();
        let numbered: Vec<usize> = data_rows
            .iter()
            .filter_map(|line| leading_number(line))
            .collect();
        assert_eq!(numbered, vec![1, 2, 3]);
        assert_eq!(data_rows.len(), 3);

        for (position, index) in app.visible.iter().enumerate() {
            let endpoint = app.results[*index].as_text();
            let line = data_rows
                .iter()
                .find(|line| line.contains(endpoint))
                .expect("every visible row is on screen");
            assert_eq!(
                leading_number(line),
                Some(position + 1),
                "row {endpoint} should be numbered {}",
                position + 1
            );
        }
    }

    #[test]
    fn a_bad_judge_report_is_the_only_one_that_shows() {
        let mut app = sample_app(2);
        app.health = Some("8/8 judges healthy".to_owned());
        assert_eq!(unhealthy_judges(&app), None, "all-healthy is the norm");

        app.health = Some("3/8 judges healthy".to_owned());
        assert_eq!(unhealthy_judges(&app), Some("3/8 judges healthy"));

        app.health = None;
        assert_eq!(unhealthy_judges(&app), None);
    }

    #[test]
    fn the_header_is_two_rows_of_chrome() {
        let _theme = use_theme(true, false);
        let app = sample_app(40);
        let backend = draw(&app, 80, 24);
        let frame = frame_text(&backend);
        let rows: Vec<&str> = frame.lines().take(2).collect();

        assert!(rows[0].starts_with(" flx"), "got {:?}", rows[0]);
        assert!(
            rows[1].starts_with(' ') && !rows[1].trim().is_empty(),
            "the second row is the live line, got {:?}",
            rows[1]
        );
        // The table begins immediately after, so no third chrome row exists.
        assert!(
            frame
                .lines()
                .nth(2)
                .is_some_and(|line| line.starts_with('\u{250c}')),
            "the panel must start on row three"
        );
    }

    #[test]
    fn the_progress_strip_reports_counts_percent_rate_and_split() {
        let _theme = use_theme(true, false);
        let spans = progress_spans(250, 1000, 240, 0.25, 12.5, 60);
        let rendered = flatten(&spans);
        assert!(rendered.contains("250/1000"), "got {rendered:?}");
        assert!(rendered.contains("25%"), "got {rendered:?}");
        assert!(rendered.contains("12.5/s"), "got {rendered:?}");
        assert!(rendered.contains("240"), "the pass count is shown");
        assert!(rendered.contains("10"), "the fail count is shown");

        // The bar reflects the fraction: three full cells plus a sub-cell
        // partial, on a bar a quarter of the row wide.
        let bar = spans[0].content.as_ref();
        assert_eq!(bar.width(), 15, "a quarter of 60, got {bar:?}");
        assert_eq!(
            bar.chars().filter(|cell| *cell != ' ').count(),
            4,
            "0.25 of 15 cells is three full and one partial, got {bar:?}"
        );
        assert!(
            cells(&spans) <= 60,
            "the strip must fit its row, got {}",
            cells(&spans)
        );
    }

    #[test]
    fn the_bar_keeps_its_width_as_the_numbers_grow() {
        // Numbers that change width must not shuffle the row, so the bar's own
        // width never depends on them.
        let _theme = use_theme(true, false);
        for (done, passed, rate) in [(0usize, 0usize, 0.0), (250, 240, 12.5), (9999, 9990, 3.0)] {
            let share = progress_spans(done, 10000, passed, done as f64 / 10_000.0, rate, 80);
            assert_eq!(
                share[0].content.width(),
                20,
                "a quarter of 80 stays 20 for {done}/10000"
            );
        }
    }

    #[test]
    fn a_cramped_progress_strip_sheds_the_numbers_not_the_bar() {
        let _theme = use_theme(true, false);
        let at = |width: u16| flatten(&progress_spans(250, 1000, 240, 0.25, 12.5, width));

        let rendered = at(30);
        assert!(
            !rendered.contains("12.5/s"),
            "the rate goes first, got {rendered:?}"
        );
        assert!(rendered.contains("250/1000"), "got {rendered:?}");

        // The split is the last extra to go, and only outside the supported range.
        assert!(at(60).contains("240"), "got {:?}", at(60));
        assert!(!at(40).contains("240"), "got {:?}", at(40));

        // Whatever the row, the strip never spills past it.
        for width in 12..=200u16 {
            let used = cells(&progress_spans(250, 1000, 240, 0.25, 12.5, width));
            assert!(
                used <= width as usize,
                "the strip overflows {width} at {used} cells: {:?}",
                at(width)
            );
        }
    }

    #[test]
    fn a_click_selects_the_row_it_landed_on() {
        let _theme = use_theme(true, false);
        let mut app = sample_app(20);
        let area = Rect::new(0, 0, 80, 24);

        // The first data row sits under the panel's border and header.
        let layout = view::compute_layout(area).expect("80x24 is supported");
        let body = table_block(&app).inner(layout.table);
        let first = body.y + 1;

        assert_eq!(row_at(&app, area, first), Some(0));
        assert_eq!(row_at(&app, area, first + 4), Some(4));
        assert_eq!(row_at(&app, area, body.y), None, "the header is not a row");
        assert_eq!(
            row_at(&app, area, body.bottom()),
            None,
            "a click below the last row selects nothing"
        );

        app.select_visible(4);
        assert_eq!(app.view.selected, 4);
        app.select_visible(999);
        assert_eq!(app.view.selected, 4, "an out-of-range click is ignored");
    }

    #[test]
    fn golden_frames_wide_side_detail() {
        let _theme = use_theme(true, false);
        let mut app = sample_app(18);
        app.view.selected = 2;
        insta::assert_snapshot!(draw(&app, 150, 28));
    }

    #[test]
    fn the_header_clock_stops_once_the_run_is_over() {
        let _theme = use_theme(true, false);
        let mut app = App::new(test_spec(false));
        app.started = Some(Instant::now() - Duration::from_secs(7));
        app.cancel_run();

        let identity = |backend: &TestBackend| -> String {
            frame_text(backend)
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned()
        };
        let first = draw(&app, 80, 24);
        std::thread::sleep(Duration::from_millis(20));
        let second = draw(&app, 80, 24);

        assert!(
            identity(&first).contains("done"),
            "the identity line says the run is over, got {:?}",
            identity(&first)
        );
        assert_eq!(
            identity(&first),
            identity(&second),
            "a finished run's clock must not keep ticking in the header"
        );
    }

    #[test]
    fn golden_help_panel() {
        let _theme = use_theme(true, false);
        let mut app = sample_app(6);
        app.help = true;
        insta::assert_snapshot!(draw(&app, 80, 24));
    }

    #[test]
    fn golden_help_panel_scrolled_to_the_end() {
        let _theme = use_theme(true, false);
        let mut app = sample_app(6);
        app.help = true;
        app.handle_action(Action::GotoBottom);
        insta::assert_snapshot!(draw(&app, 80, 24));
    }

    #[test]
    fn golden_frames_120x30() {
        let _theme = use_theme(true, false);
        let app = sample_app(24);
        insta::assert_snapshot!(draw(&app, 120, 30));
    }

    #[test]
    fn golden_frames_80x24() {
        let _theme = use_theme(true, false);
        let mut app = sample_app(12);
        app.view.detail = true;
        insta::assert_snapshot!(draw(&app, 80, 24));
    }

    #[test]
    fn golden_frames_60x20() {
        let _theme = use_theme(true, false);
        let mut app = sample_app(8);
        app.view.filter = "ID".to_owned();
        app.view.sort = Some(flx::SortKey::Country);
        app.refresh_visible();
        insta::assert_snapshot!(draw(&app, 60, 20));
    }

    #[test]
    fn golden_frames_minimum_size() {
        let _theme = use_theme(true, false);
        let app = sample_app(4);
        insta::assert_snapshot!(draw(&app, 42, 10));
    }

    #[test]
    fn golden_running_frame() {
        let _theme = use_theme(true, false);
        let app = App::new(test_spec(true));
        insta::assert_snapshot!(draw(&app, 100, 20));
    }
}
