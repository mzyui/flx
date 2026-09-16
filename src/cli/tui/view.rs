//! Pure view logic: filtering, ordering, table geometry, and the pieces of the
//! frame that can be decided without a terminal.
//!
//! Everything here is state in, value out, so the responsive ladder and the
//! filter semantics are testable without a `TestBackend`.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::time::Duration;

use flx::proxy::models::{Anonymity, Protocol, Proxy};
use flx::{IpType, SortKey, SortOrder};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use unicode_width::{UnicodeWidthChar as _, UnicodeWidthStr as _};

use super::theme;

/// Cells between two table columns.
pub(crate) const COLUMN_SPACING: u16 = 1;

/// Smallest terminal the layout stays truthful at, as `60×12`.
pub(crate) const MIN_WIDTH: u16 = 60;
pub(crate) const MIN_HEIGHT: u16 = 12;

/// Rows reserved for the compact header and footer.
const HEADER_ROWS: u16 = 1;
const FOOTER_ROWS: u16 = 1;
/// Two rows separate the status line from the main results surface.
const STATUS_ROWS: u16 = 2;
/// The table keeps enough room for its header and at least one result row.
const MIN_TABLE_ROWS: u16 = 2;

/// The borderless table spends one row on its column header.
pub(crate) const TABLE_CHROME_ROWS: u16 = 1;

/// Columns displayed, including the leading ordinal.
pub(crate) const COLUMN_COUNT: usize = 9;
/// Fields a row carries, one per non-ordinal column.
pub(crate) const CELL_COUNT: usize = 8;

/// Bounds on the ordinal column: wide enough for the `#` header and a row
/// number, narrow enough that it never crowds out real data.
const ORDINAL_MIN: u16 = 2;
const ORDINAL_MAX: u16 = 6;

/// Column holding the country code, which the sort key compares.
const COUNTRY_COLUMN: usize = 3;

/// Where a column's content comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    /// A field of [`RowModel::cells`].
    Cell(usize),
    /// The row's position in the current view, numbered from one. It belongs to
    /// the view rather than to the row, so no row stores it.
    Ordinal,
}

/// One column of the results table.
pub(crate) struct Column {
    pub(crate) title: &'static str,
    pub(crate) source: Source,
    /// Floor the column may be squeezed to before the table clips content.
    min: u16,
    /// Width the column gets when the terminal is roomy.
    preferred: u16,
    /// Ceiling the column may grow into when there is spare width.
    max: u16,
    pub(crate) align: Alignment,
    /// Lower value hides first; `None` survives even the narrowest terminal.
    hide_rank: Option<u8>,
    /// Lower value grows first to soak up spare width and shrinks last.
    /// `None` never moves from `preferred`.
    grow_rank: Option<u8>,
    /// Sort key this column reports on, for the `▲/▼` header indicator.
    pub(crate) sort_key: Option<SortKey>,
}

pub(crate) const COLUMNS: [Column; COLUMN_COUNT] = [
    // The ordinal never hides and never grows: it is the address the numeric
    // jump targets, so losing it would make `{n}G` blind.
    Column {
        title: "#",
        source: Source::Ordinal,
        min: ORDINAL_MIN,
        preferred: ORDINAL_MIN,
        max: ORDINAL_MAX,
        align: Alignment::Right,
        hide_rank: None,
        grow_rank: None,
        sort_key: None,
    },
    Column {
        title: "IP:PORT",
        source: Source::Cell(0),
        min: 15,
        preferred: 21,
        max: 45,
        align: Alignment::Left,
        hide_rank: None,
        grow_rank: Some(1),
        sort_key: None,
    },
    Column {
        title: "PROTO",
        source: Source::Cell(1),
        min: 5,
        preferred: 14,
        max: 22,
        align: Alignment::Left,
        hide_rank: None,
        grow_rank: Some(2),
        sort_key: None,
    },
    Column {
        title: "ANON",
        source: Source::Cell(2),
        min: 4,
        preferred: 6,
        max: 8,
        align: Alignment::Left,
        hide_rank: None,
        grow_rank: Some(3),
        sort_key: Some(SortKey::Anonymity),
    },
    Column {
        title: "CC",
        source: Source::Cell(3),
        min: 2,
        preferred: 4,
        max: 4,
        align: Alignment::Left,
        hide_rank: None,
        grow_rank: None,
        sort_key: Some(SortKey::Country),
    },
    Column {
        title: "TYPE",
        source: Source::Cell(4),
        min: 4,
        preferred: 12,
        max: 14,
        align: Alignment::Left,
        hide_rank: Some(3),
        grow_rank: Some(4),
        sort_key: None,
    },
    Column {
        title: "ASN",
        source: Source::Cell(5),
        min: 3,
        preferred: 8,
        max: 10,
        align: Alignment::Left,
        hide_rank: Some(1),
        grow_rank: Some(5),
        sort_key: None,
    },
    Column {
        title: "RTT",
        source: Source::Cell(6),
        min: 5,
        preferred: 8,
        max: 9,
        align: Alignment::Right,
        hide_rank: None,
        grow_rank: None,
        sort_key: Some(SortKey::AvgResponseTime),
    },
    Column {
        title: "N",
        source: Source::Cell(7),
        min: 1,
        preferred: 4,
        max: 6,
        align: Alignment::Right,
        hide_rank: Some(2),
        grow_rank: None,
        sort_key: None,
    },
];

/// A proxy reduced to the strings the table and the filter need.
///
/// Built once when a row arrives, never per frame: the render closure only
/// borrows from here.
#[derive(Clone, Debug)]
pub(crate) struct RowModel {
    pub(crate) cells: [String; CELL_COUNT],
    /// Sort values kept beside their display strings, so ordering never parses
    /// back what the table just formatted.
    rtt: f64,
    anonymity_rank: u8,
    /// Organization name. The filter matches it, but no column shows it, so a
    /// hit here highlights nothing rather than pointing at the wrong column.
    organization: String,
}

impl RowModel {
    pub(crate) fn new(proxy: &Proxy) -> Self {
        Self {
            cells: [
                proxy.as_text().to_owned(),
                protocol_label(proxy),
                anonymity_label(proxy),
                proxy.geo.iso_code.as_deref().unwrap_or("-").to_owned(),
                ip_type_label(proxy.geo.ip_type).to_owned(),
                proxy
                    .geo
                    .asn
                    .map(|asn| asn.to_string())
                    .unwrap_or_else(|| "-".to_owned()),
                format!("{:.2}s", proxy.avg_response_time()),
                proxy.sample_count().to_string(),
            ],
            rtt: proxy.avg_response_time(),
            anonymity_rank: flx::proxy_anonymity_rank(proxy),
            organization: proxy.geo.aso.as_deref().unwrap_or_default().to_owned(),
        }
    }
}

/// Live view state shared by the running and done screens.
#[derive(Clone, Debug)]
pub(crate) struct ViewState {
    pub(crate) filter: String,
    pub(crate) sort: Option<SortKey>,
    pub(crate) order: SortOrder,
    pub(crate) selected: usize,
    pub(crate) detail: bool,
}

impl Default for ViewState {
    fn default() -> Self {
        Self {
            filter: String::new(),
            sort: None,
            order: SortOrder::Asc,
            selected: 0,
            detail: false,
        }
    }
}

impl ViewState {
    /// Cycles `None -> AvgResponseTime -> Country -> Anonymity -> None`.
    pub(crate) fn cycle_sort(&mut self) {
        self.sort = match self.sort {
            None => Some(SortKey::AvgResponseTime),
            Some(SortKey::AvgResponseTime) => Some(SortKey::Country),
            Some(SortKey::Country) => Some(SortKey::Anonymity),
            Some(SortKey::Anonymity) => None,
        };
        self.reset_position();
    }

    pub(crate) fn toggle_order(&mut self) {
        self.order = match self.order {
            SortOrder::Asc => SortOrder::Desc,
            SortOrder::Desc => SortOrder::Asc,
        };
        self.reset_position();
    }

    pub(crate) fn reset_position(&mut self) {
        self.selected = 0;
    }

    /// Human label for the active ordering.
    pub(crate) fn sort_label(&self) -> String {
        match self.sort {
            None => "arrival".to_owned(),
            Some(SortKey::AvgResponseTime) => "response-time".to_owned(),
            Some(SortKey::Country) => "country".to_owned(),
            Some(SortKey::Anonymity) => "anonymity".to_owned(),
        }
    }

    /// `▲`/`▼`, or their ASCII twins.
    pub(crate) fn order_glyph(&self) -> &'static str {
        match self.order {
            SortOrder::Asc => theme::glyph(theme::ARROW_UP),
            SortOrder::Desc => theme::glyph(theme::ARROW_DOWN),
        }
    }
}

fn anonymity_label(proxy: &Proxy) -> String {
    let best = proxy
        .proxy_types
        .iter()
        .filter_map(|proxy_type| match proxy_type.protocol {
            Protocol::Http(anonymity) | Protocol::Https(anonymity) => Some(anonymity),
            _ => None,
        })
        .max_by_key(|anonymity| anonymity.rank());
    match best {
        Some(Anonymity::Elite) => "elite",
        Some(Anonymity::Anonymous) => "anon",
        Some(Anonymity::Transparent) => "transp",
        Some(Anonymity::Unknown) | None => "-",
    }
    .to_owned()
}

fn protocol_label(proxy: &Proxy) -> String {
    if proxy.proxy_types.is_empty() {
        return proxy
            .expected_types
            .iter()
            .map(|protocol| short_protocol(*protocol))
            .collect::<Vec<_>>()
            .join("+");
    }
    proxy
        .proxy_types
        .iter()
        .map(|proxy_type| short_protocol(proxy_type.protocol))
        .collect::<Vec<_>>()
        .join("+")
}

fn short_protocol(protocol: Protocol) -> String {
    match protocol {
        Protocol::Http(_) => "HTTP".to_owned(),
        Protocol::Https(_) => "HTTPS".to_owned(),
        Protocol::Socks4 => "SOCKS4".to_owned(),
        Protocol::Socks5 => "SOCKS5".to_owned(),
        Protocol::Connect(port) => format!("CONNECT:{port}"),
    }
}

fn ip_type_label(ip_type: IpType) -> &'static str {
    match ip_type {
        IpType::Residential => "residential",
        IpType::Datacenter => "datacenter",
        IpType::Mobile => "mobile",
        IpType::Unknown => "-",
    }
}

/// How a filter string is matched against a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Case {
    /// The filter contains an uppercase letter, so it must match exactly.
    Sensitive,
    /// An all-lowercase filter matches regardless of case.
    Insensitive,
}

/// Smart case: one uppercase character makes the whole filter exact.
pub(crate) fn case_of(filter: &str) -> Case {
    if filter.chars().any(char::is_uppercase) {
        Case::Sensitive
    } else {
        Case::Insensitive
    }
}

fn chars_eq(left: char, right: char, case: Case) -> bool {
    if left == right {
        return true;
    }
    if case == Case::Sensitive {
        return false;
    }
    if left.is_ascii() && right.is_ascii() {
        return left.eq_ignore_ascii_case(&right);
    }
    // Only the non-ASCII path allocates; ASCII filters stay allocation-free.
    left.to_lowercase().eq(right.to_lowercase())
}

/// Byte range of the first match of `needle` inside `text`.
fn find_match(text: &str, needle: &str, case: Case) -> Option<(usize, usize)> {
    let needle: Vec<char> = needle.chars().collect();
    if needle.is_empty() {
        return None;
    }
    let text_chars: Vec<(usize, char)> = text.char_indices().collect();
    if text_chars.len() < needle.len() {
        return None;
    }
    for start in 0..=text_chars.len() - needle.len() {
        let matched = needle
            .iter()
            .enumerate()
            .all(|(offset, expected)| chars_eq(text_chars[start + offset].1, *expected, case));
        if matched {
            let begin = text_chars[start].0;
            let end = text_chars
                .get(start + needle.len())
                .map_or(text.len(), |(index, _)| *index);
            return Some((begin, end));
        }
    }
    None
}

/// Where a filter matched a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Hit {
    /// Index into [`COLUMNS`] of the cell that matched.
    pub(crate) column: usize,
    /// Byte range inside that cell.
    pub(crate) range: (usize, usize),
}

/// First column of `row` that satisfies `filter`, so the match can be highlighted.
pub(crate) fn find_hit(row: &RowModel, filter: &str) -> Option<Hit> {
    let case = case_of(filter);
    for (column, cell) in row.cells.iter().enumerate() {
        if let Some(range) = find_match(cell, filter, case) {
            return Some(Hit { column, range });
        }
    }
    None
}

/// Whether a row passes the filter at all, including its organization name.
pub(crate) fn matches_filter(row: &RowModel, filter: &str) -> bool {
    let case = case_of(filter);
    row.cells
        .iter()
        .any(|cell| find_match(cell, filter, case).is_some())
        || find_match(&row.organization, filter, case).is_some()
}

fn compare(left: &RowModel, right: &RowModel, key: SortKey) -> Ordering {
    match key {
        SortKey::AvgResponseTime => left.rtt.partial_cmp(&right.rtt).unwrap_or(Ordering::Equal),
        SortKey::Country => left.cells[COUNTRY_COLUMN].cmp(&right.cells[COUNTRY_COLUMN]),
        SortKey::Anonymity => left.anonymity_rank.cmp(&right.anonymity_rank),
    }
}

/// Indices of the rows that pass the filter, in view order.
pub(crate) fn visible(rows: &[RowModel], view: &ViewState) -> Vec<usize> {
    let mut indices: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| view.filter.is_empty() || matches_filter(row, &view.filter))
        .map(|(index, _)| index)
        .collect();
    if let Some(key) = view.sort {
        // Stable, so rows that compare equal keep their arrival order.
        indices.sort_by(|a, b| {
            let ordering = compare(&rows[*a], &rows[*b], key);
            match view.order {
                SortOrder::Asc => ordering,
                SortOrder::Desc => ordering.reverse(),
            }
        });
    }
    indices
}

/// Keeps the selection inside `len` rows.
pub(crate) fn clamp_selection(view: &mut ViewState, len: usize) {
    if len == 0 {
        view.selected = 0;
    } else if view.selected >= len {
        view.selected = len - 1;
    }
}

/// Visible row window `[start, end)` that keeps `selected` on screen.
pub(crate) fn window(selected: usize, height: usize, len: usize) -> (usize, usize) {
    if len == 0 || height == 0 {
        return (0, 0);
    }
    let selected = selected.min(len - 1);
    let start = if selected >= height {
        selected + 1 - height
    } else {
        0
    };
    (start, (start + height).min(len))
}

/// Columns shown, with the exact width each gets, for `available` cells and
/// `rows` browsable rows.
///
/// The widths sum to `available` whenever the columns allow it, so the table
/// neither clips its last column nor leaves dead cells at the right edge.
pub(crate) fn fit_columns(available: u16, rows: usize) -> Vec<(usize, u16)> {
    let mut widths: Vec<u16> = COLUMNS
        .iter()
        .map(|column| match column.source {
            // The ordinal is as wide as the numbers it has to show.
            Source::Ordinal => ordinal_width(rows),
            Source::Cell(_) => column.preferred,
        })
        .collect();
    let mut shown: Vec<usize> = (0..COLUMN_COUNT).collect();

    let total = |shown: &[usize], widths: &[u16]| -> u16 {
        let cells: u16 = shown.iter().map(|index| widths[*index]).sum();
        let gaps = COLUMN_SPACING * (shown.len().saturating_sub(1) as u16);
        cells.saturating_add(gaps)
    };

    // Low-priority columns go first: ASN, then N, then TYPE.
    while total(&shown, &widths) > available {
        let next = shown
            .iter()
            .filter(|index| COLUMNS[**index].hide_rank.is_some())
            .min_by_key(|index| COLUMNS[**index].hide_rank)
            .copied();
        let Some(next) = next else { break };
        shown.retain(|index| *index != next);
    }

    // Still too wide: squeeze the columns that tolerate it, least important first.
    while total(&shown, &widths) > available {
        let next = shown
            .iter()
            .copied()
            .filter(|index| {
                let column = &COLUMNS[*index];
                column.grow_rank.is_some() && widths[*index] > column.min
            })
            .max_by_key(|index| COLUMNS[*index].grow_rank);
        let Some(next) = next else { break };
        widths[next] -= 1;
    }

    // Spare width goes to the widest-information columns first.
    while total(&shown, &widths) < available {
        let next = shown
            .iter()
            .copied()
            .filter(|index| {
                let column = &COLUMNS[*index];
                column.grow_rank.is_some() && widths[*index] < column.max
            })
            .min_by_key(|index| COLUMNS[*index].grow_rank);
        let Some(next) = next else { break };
        widths[next] += 1;
    }

    shown
        .into_iter()
        .map(|index| (index, widths[index]))
        .collect()
}

/// Cells the ordinal column needs to number `rows` rows.
fn ordinal_width(rows: usize) -> u16 {
    let digits = rows.max(1).to_string().len() as u16;
    digits.clamp(ORDINAL_MIN, ORDINAL_MAX)
}

/// Where each region of the screen goes for one terminal size.
///
/// `None` means the terminal is below the supported minimum; the caller owes
/// the user the plain "too small" message instead of a mangled frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScreenLayout {
    pub(crate) header: Rect,
    pub(crate) status: Rect,
    pub(crate) table: Rect,
    pub(crate) footer: Rect,
}

/// Splits the screen into compact header, status, full-width table, and footer.
pub(crate) fn compute_layout(area: Rect) -> Option<ScreenLayout> {
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        return None;
    }
    let [header, status, table, footer] = Layout::vertical([
        Constraint::Length(HEADER_ROWS),
        Constraint::Length(STATUS_ROWS),
        Constraint::Min(MIN_TABLE_ROWS),
        Constraint::Length(FOOTER_ROWS),
    ])
    .areas(area);

    Some(ScreenLayout {
        header,
        status,
        table,
        footer,
    })
}

/// Rows a bordered table with a header can show.
pub(crate) fn table_rows(area_height: u16) -> usize {
    area_height.saturating_sub(TABLE_CHROME_ROWS) as usize
}

/// Eight-level block ramp, so a partly filled cell still reports progress.
const BAR_LEVELS: [char; 8] = [
    '\u{258f}', '\u{258e}', '\u{258d}', '\u{258c}', '\u{258b}', '\u{258a}', '\u{2589}', '\u{2588}',
];

/// Renders a determinate bar of `width` cells.
pub(crate) fn progress_bar(fraction: f64, width: u16) -> String {
    let width = width as usize;
    if width == 0 {
        return String::new();
    }
    let position = fraction.clamp(0.0, 1.0) * width as f64;
    let full = (position.floor() as usize).min(width);
    if theme::ascii() {
        let filled = (position.round() as usize).min(width);
        return format!("{}{}", "#".repeat(filled), "-".repeat(width - filled));
    }
    let mut bar = String::with_capacity(width * 3);
    for _ in 0..full {
        bar.push(BAR_LEVELS[BAR_LEVELS.len() - 1]);
    }
    let mut drawn = full;
    if drawn < width {
        let level = ((position - position.floor()) * BAR_LEVELS.len() as f64).floor() as usize;
        if level > 0 {
            bar.push(BAR_LEVELS[level.min(BAR_LEVELS.len() - 1)]);
            drawn += 1;
        }
    }
    for _ in drawn..width {
        bar.push(' ');
    }
    bar
}

/// Spinner frames, advanced every `SPINNER_INTERVAL_MS`.
const SPINNER_FRAMES: [&str; 10] = [
    "\u{280b}", "\u{2819}", "\u{2839}", "\u{2838}", "\u{283c}", "\u{2834}", "\u{2826}", "\u{2827}",
    "\u{2807}", "\u{280f}",
];
const SPINNER_INTERVAL_MS: u128 = 80;

/// Indeterminate work only earns a spinner once it has clearly not finished,
/// so fast phases do not flash.
pub(crate) const SPINNER_DELAY: Duration = Duration::from_millis(180);

/// Spinner glyph for a phase that has been running for `elapsed`.
pub(crate) fn spinner_frame(elapsed: Duration) -> &'static str {
    let step = (elapsed.as_millis() / SPINNER_INTERVAL_MS) as usize;
    if theme::ascii() {
        return if step.is_multiple_of(2) { "|" } else { "-" };
    }
    SPINNER_FRAMES[step % SPINNER_FRAMES.len()]
}

/// Truncates `text` to `max` cells, reserving the last cell for an ellipsis.
///
/// Borrows when nothing needs cutting, so the common case allocates nothing.
/// Cells, not bytes: wide characters and combining marks are measured.
pub(crate) fn clamp_cells(text: &str, max: u16) -> Cow<'_, str> {
    let max = max as usize;
    if text.width() <= max {
        return Cow::Borrowed(text);
    }
    if max == 0 {
        return Cow::Borrowed("");
    }
    let ellipsis = if theme::ascii() { "~" } else { "\u{2026}" };
    let budget = max.saturating_sub(ellipsis.width());
    let mut kept = String::with_capacity(text.len().min(max));
    let mut used = 0usize;
    for character in text.chars() {
        let width = character.width().unwrap_or(0);
        if used + width > budget {
            break;
        }
        kept.push(character);
        used += width;
    }
    kept.push_str(ellipsis);
    Cow::Owned(kept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    fn proxy(last: u8, rtt: f64, country: &str) -> Proxy {
        let mut proxy = Proxy::new(Ipv4Addr::new(10, 0, 0, last), 8000 + u16::from(last));
        proxy.runtimes.record(rtt);
        proxy.geo = Arc::new(flx::GeoData {
            iso_code: Some(country.into()),
            ..flx::GeoData::default()
        });
        proxy
    }

    fn rows_of(proxies: &[Proxy]) -> Vec<RowModel> {
        proxies.iter().map(RowModel::new).collect()
    }

    /// Pins the process-wide palette for the duration of one test.
    fn use_theme(monochrome: bool, ascii: bool) -> std::sync::MutexGuard<'static, ()> {
        let guard = theme::lock_for_tests();
        theme::configure(monochrome, ascii);
        guard
    }

    #[test]
    fn filter_matches_endpoint_and_country() {
        let proxies = vec![proxy(1, 0.2, "DE"), proxy(2, 0.4, "ID")];
        let rows = rows_of(&proxies);
        let by_country = ViewState {
            filter: "id".to_owned(),
            ..ViewState::default()
        };
        assert_eq!(visible(&rows, &by_country), vec![1]);
        let by_endpoint = ViewState {
            filter: "10.0.0.1".to_owned(),
            ..ViewState::default()
        };
        assert_eq!(visible(&rows, &by_endpoint), vec![0]);
    }

    #[test]
    fn an_uppercase_filter_becomes_case_sensitive() {
        let proxies = vec![proxy(1, 0.2, "DE"), proxy(2, 0.4, "ID")];
        let rows = rows_of(&proxies);
        assert_eq!(case_of("de"), Case::Insensitive);
        assert_eq!(case_of("De"), Case::Sensitive);

        for filter in ["de", "DE"] {
            let view = ViewState {
                filter: filter.to_owned(),
                ..ViewState::default()
            };
            assert_eq!(visible(&rows, &view), vec![0], "filter {filter:?}");
        }

        let wrong_case = ViewState {
            filter: "De".to_owned(),
            ..ViewState::default()
        };
        assert!(
            visible(&rows, &wrong_case).is_empty(),
            "an uppercase filter must not match a differently cased cell"
        );
    }

    #[test]
    fn a_hit_points_at_the_matching_column_and_range() {
        let proxies = vec![proxy(1, 0.2, "DE")];
        let rows = rows_of(&proxies);

        let country = find_hit(&rows[0], "DE").expect("the country matches");
        assert_eq!(country.column, COUNTRY_COLUMN);
        assert_eq!(
            &rows[0].cells[country.column][country.range.0..country.range.1],
            "DE"
        );

        let endpoint = find_hit(&rows[0], "10.0.0.").expect("the endpoint matches");
        assert_eq!(endpoint.column, 0);
        assert_eq!(
            &rows[0].cells[endpoint.column][endpoint.range.0..endpoint.range.1],
            "10.0.0."
        );
    }

    #[test]
    fn ordering_follows_the_sort_key_and_direction() {
        let proxies = vec![proxy(1, 0.5, "DE"), proxy(2, 0.1, "ID")];
        let rows = rows_of(&proxies);
        let fastest_first = ViewState {
            sort: Some(SortKey::AvgResponseTime),
            ..ViewState::default()
        };
        assert_eq!(visible(&rows, &fastest_first), vec![1, 0]);

        let slowest_first = ViewState {
            order: SortOrder::Desc,
            ..fastest_first
        };
        assert_eq!(visible(&rows, &slowest_first), vec![0, 1]);

        let by_country = ViewState {
            sort: Some(SortKey::Country),
            ..ViewState::default()
        };
        assert_eq!(visible(&rows, &by_country), vec![0, 1]);
    }

    #[test]
    fn sort_cycles_through_every_key_and_back() {
        let mut view = ViewState::default();
        view.cycle_sort();
        assert_eq!(view.sort, Some(SortKey::AvgResponseTime));
        assert_eq!(view.sort_label(), "response-time");
        view.cycle_sort();
        assert_eq!(view.sort, Some(SortKey::Country));
        view.cycle_sort();
        assert_eq!(view.sort, Some(SortKey::Anonymity));
        view.cycle_sort();
        assert_eq!(view.sort, None);
        assert_eq!(view.sort_label(), "arrival");
    }

    #[test]
    fn selection_clamps_to_available_rows() {
        let mut view = ViewState {
            selected: 9,
            ..ViewState::default()
        };
        clamp_selection(&mut view, 3);
        assert_eq!(view.selected, 2);
        clamp_selection(&mut view, 0);
        assert_eq!(view.selected, 0);
    }

    #[test]
    fn window_keeps_the_selection_visible() {
        assert_eq!(window(0, 5, 20), (0, 5));
        assert_eq!(window(12, 5, 20), (8, 13));
        assert_eq!(window(19, 5, 20), (15, 20));
        assert_eq!(window(3, 5, 0), (0, 0));
        assert_eq!(window(3, 0, 10), (0, 0));
    }

    #[test]
    fn table_reserves_only_its_column_header() {
        assert_eq!(table_rows(14), 13);
        assert_eq!(table_rows(3), 2);
        assert_eq!(table_rows(0), 0);
    }

    #[test]
    fn minimalist_layout_keeps_the_table_full_width() {
        let layout = compute_layout(Rect::new(0, 0, 80, 24)).expect("80x24 is supported");
        assert_eq!(layout.header.height, HEADER_ROWS);
        assert_eq!(layout.status.height, STATUS_ROWS);
        assert_eq!(layout.footer.height, FOOTER_ROWS);
        assert_eq!(layout.table.width, 80);
        assert_eq!(layout.table.y, layout.status.bottom());
        assert_eq!(
            layout.table.height,
            24 - HEADER_ROWS - STATUS_ROWS - FOOTER_ROWS
        );
    }

    #[test]
    fn wide_terminals_keep_the_same_single_pane_layout() {
        let layout = compute_layout(Rect::new(0, 0, 200, 50)).expect("200x50 is supported");
        assert_eq!(layout.table.width, 200);
        assert_eq!(layout.table.x, 0);
    }

    #[test]
    fn the_layout_refuses_terminals_below_the_minimum() {
        assert!(compute_layout(Rect::new(0, 0, 59, 24)).is_none());
        assert!(compute_layout(Rect::new(0, 0, 60, 11)).is_none());
        let minimum = compute_layout(Rect::new(0, 0, 60, 12)).expect("60x12 is supported");
        assert_eq!(minimum.table.width, 60);
        assert_eq!(minimum.table.height, 8);
    }

    #[test]
    fn narrow_terminals_drop_asn_then_count_then_type() {
        let titles = |available: u16| -> Vec<&'static str> {
            fit_columns(available, 40)
                .into_iter()
                .map(|(index, _)| COLUMNS[index].title)
                .collect()
        };

        assert_eq!(
            titles(120),
            vec!["#", "IP:PORT", "PROTO", "ANON", "CC", "TYPE", "ASN", "RTT", "N"]
        );
        // 56 cells is what a 60-column terminal leaves the table.
        assert_eq!(
            titles(56),
            vec!["#", "IP:PORT", "PROTO", "ANON", "CC", "RTT"],
            "ASN, N, and TYPE are the first to go, never the ordinal"
        );
    }

    #[test]
    fn the_ordinal_column_is_as_wide_as_the_numbers_it_shows() {
        let width = |rows: usize| -> u16 {
            fit_columns(120, rows)
                .into_iter()
                .find(|(index, _)| COLUMNS[*index].source == Source::Ordinal)
                .map(|(_, width)| width)
                .expect("the ordinal is always shown")
        };

        // Two cells covers the `#` header for short lists.
        assert_eq!(width(1), ORDINAL_MIN);
        assert_eq!(width(99), ORDINAL_MIN);
        assert_eq!(width(100), 3);
        assert_eq!(width(1_234), 4);
        assert_eq!(width(1_000_000), ORDINAL_MAX);
        assert_eq!(width(usize::MAX), ORDINAL_MAX, "and it stops growing");
    }

    #[test]
    fn the_ordinal_survives_every_narrow_terminal() {
        // The number is the address `{n}G` takes, so it must never be the
        // column that hides.
        for available in [12u16, 20, 30, 40, 56] {
            let shown = fit_columns(available, 500);
            assert!(
                shown
                    .iter()
                    .any(|(index, _)| COLUMNS[*index].source == Source::Ordinal),
                "the ordinal vanished at {available} cells"
            );
        }
    }

    #[test]
    fn fitted_columns_use_the_whole_width() {
        // The ceilings cap how wide the table stretches; below that it must
        // leave no dead cells at the right edge. Columns that never grow stop
        // at their preferred width.
        let ceilings: u16 = COLUMNS
            .iter()
            .map(|column| match column.source {
                // The ordinal is already at the widest it needs to be.
                Source::Ordinal => ordinal_width(500),
                Source::Cell(_) => match column.grow_rank {
                    Some(_) => column.max,
                    None => column.preferred,
                },
            })
            .sum();
        let gaps = COLUMN_SPACING * (COLUMN_COUNT as u16 - 1);
        let widest = ceilings + gaps;

        for available in [56u16, 70, 90, 120, 160] {
            let columns = fit_columns(available, 500);
            let cells: u16 = columns.iter().map(|(_, width)| width).sum();
            let gaps = COLUMN_SPACING * (columns.len() as u16 - 1);
            let used = cells + gaps;
            assert!(
                used <= available,
                "{available} cells is an overflow at {used}, got {columns:?}"
            );
            assert_eq!(
                used,
                available.min(widest),
                "{available} cells should be used exactly, got {columns:?}"
            );
        }
    }

    #[test]
    fn columns_never_shrink_below_their_floor() {
        for available in [20u16, 30, 40, 50, 56] {
            for (index, width) in fit_columns(available, 500) {
                assert!(
                    width >= COLUMNS[index].min,
                    "{} shrank to {width}, below its floor",
                    COLUMNS[index].title
                );
            }
        }
    }

    #[test]
    fn narrow_cells_truncate_with_a_reserved_ellipsis() {
        let _theme = use_theme(true, false);
        let clamped = clamp_cells("203.0.113.207:8080", 10);
        assert_eq!(clamped.width(), 10);
        assert!(clamped.ends_with('\u{2026}'));

        let short = clamp_cells("203.0.113.7:80", 21);
        assert_eq!(short, "203.0.113.7:80", "short cells are not rewritten");
        assert!(
            matches!(short, Cow::Borrowed(_)),
            "the common case must not allocate"
        );
    }

    #[test]
    fn clamping_counts_cells_not_bytes() {
        let _theme = use_theme(true, false);
        // Three CJK glyphs are six cells wide; the ellipsis needs the seventh.
        let clamped = clamp_cells("\u{4e2d}\u{6587}\u{5b57}\u{4e2d}", 7);
        assert_eq!(clamped.width(), 7);
        assert!(clamped.starts_with("\u{4e2d}\u{6587}\u{5b57}"));
        assert!(clamped.ends_with('\u{2026}'));
    }

    #[test]
    fn emoji_and_combining_marks_do_not_overflow_their_cell() {
        let emoji = clamp_cells("\u{1f310}\u{1f310}\u{1f310}", 3);
        assert!(emoji.width() <= 3, "got {emoji:?}");

        let combining = clamp_cells("e\u{301}e\u{301}e\u{301}", 2);
        assert!(combining.width() <= 2, "got {combining:?}");
    }

    #[test]
    fn progress_bar_fills_cell_by_cell() {
        let _theme = use_theme(true, false);
        assert_eq!(progress_bar(0.0, 4), "    ");
        assert_eq!(progress_bar(1.0, 4), "\u{2588}\u{2588}\u{2588}\u{2588}");
        assert_eq!(progress_bar(0.5, 4), "\u{2588}\u{2588}  ");
        // Half a cell is a half-filled leading cell, not a rounded-up one.
        let partial = progress_bar(0.125, 4);
        assert_eq!(partial, "\u{258b}   ", "got {partial:?}");
        assert_eq!(partial.chars().count(), 4);
        assert_eq!(progress_bar(0.5, 0), "");
    }

    #[test]
    fn the_ascii_fallback_draws_an_ascii_bar() {
        let _theme = use_theme(true, true);
        assert_eq!(progress_bar(0.5, 4), "##--");
    }

    #[test]
    fn the_spinner_advances_with_time() {
        let _theme = use_theme(true, false);
        let first = spinner_frame(Duration::ZERO);
        assert_ne!(first, spinner_frame(Duration::from_millis(80)));
        assert_eq!(first, spinner_frame(Duration::from_millis(800)));
        assert!((150..=200).contains(&SPINNER_DELAY.as_millis()));
    }
}
