//! Body parsers for the different shapes proxy sources come in.
//!
//! Each parser turns a raw response body into `(Ipv4Addr, u16, Option<Protocol>)`
//! triples. A `Some(protocol)` means the source told us the protocol for that
//! specific row and it overrides the source's `default_types`.
//!
//! Ported from the Node implementation in `mzyui/proxy-list` (engine/src/providers).

use std::{borrow::Cow, cell::Cell, collections::HashMap, net::Ipv4Addr, sync::LazyLock};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use regex::Regex;
use scraper::{Html, Selector};
use serde::{
    de::{
        DeserializeOwned, DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor,
    },
    Deserialize, Deserializer,
};

use crate::proxy::models::{Anonymity, Protocol};

/// A single parsed row. `protocol` is `None` when the source does not say.
pub type ParsedProxy = (Ipv4Addr, u16, Option<Protocol>);
const VISITOR_STOPPED: &str = "fluxy parser visitor stopped";

struct JsonDataSeed<'a, T, F> {
    visit: &'a mut F,
    stopped: &'a Cell<bool>,
    marker: std::marker::PhantomData<T>,
}

impl<'de, T, F> DeserializeSeed<'de> for JsonDataSeed<'_, T, F>
where
    T: DeserializeOwned,
    F: FnMut(T) -> bool,
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(JsonRootVisitor {
            visit: self.visit,
            stopped: self.stopped,
            marker: std::marker::PhantomData,
        })
    }
}

struct JsonRootVisitor<'a, T, F> {
    visit: &'a mut F,
    stopped: &'a Cell<bool>,
    marker: std::marker::PhantomData<T>,
}

impl<'de, T, F> Visitor<'de> for JsonRootVisitor<'_, T, F>
where
    T: DeserializeOwned,
    F: FnMut(T) -> bool,
{
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON object containing a data array")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            if key == "data" {
                map.next_value_seed(JsonRowsSeed {
                    visit: self.visit,
                    stopped: self.stopped,
                    marker: std::marker::PhantomData,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct JsonRowsSeed<'a, T, F> {
    visit: &'a mut F,
    stopped: &'a Cell<bool>,
    marker: std::marker::PhantomData<T>,
}

impl<'de, T, F> DeserializeSeed<'de> for JsonRowsSeed<'_, T, F>
where
    T: DeserializeOwned,
    F: FnMut(T) -> bool,
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(JsonRowsVisitor {
            visit: self.visit,
            stopped: self.stopped,
            marker: std::marker::PhantomData,
        })
    }
}

struct JsonRowsVisitor<'a, T, F> {
    visit: &'a mut F,
    stopped: &'a Cell<bool>,
    marker: std::marker::PhantomData<T>,
}

impl<'de, T, F> Visitor<'de> for JsonRowsVisitor<'_, T, F>
where
    T: DeserializeOwned,
    F: FnMut(T) -> bool,
{
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a sequence of proxy rows")
    }

    fn visit_seq<A>(self, mut rows: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(row) = rows.next_element::<T>()? {
            if !(self.visit)(row) {
                self.stopped.set(true);
                return Err(A::Error::custom(VISITOR_STOPPED));
            }
        }
        Ok(())
    }
}

/// Walks a JSON response whose top-level object holds a `data` array, feeding
/// each row to `visit`. A `false` return aborts the walk early without the
/// deserializer having to parse the rest of the document.
fn visit_json_data<T>(body: &str, mut visit: impl FnMut(T) -> bool) -> anyhow::Result<()>
where
    T: DeserializeOwned,
{
    let stopped = Cell::new(false);
    let mut deserializer = serde_json::Deserializer::from_str(body);
    let result = JsonDataSeed::<T, _> {
        visit: &mut visit,
        stopped: &stopped,
        marker: std::marker::PhantomData,
    }
    .deserialize(&mut deserializer);
    match result {
        Ok(()) => Ok(()),
        // The visitor aborted the walk on purpose (early stop); every other
        // error is a genuine parse problem. Detecting the stop via the flag
        // avoids formatting the error message just to compare strings.
        Err(_error) if stopped.get() => Ok(()),
        Err(error) => Err(error.into()),
    }
}

// ── Compile-once regexes ──────────────────────────────────────────────

/// Extracts the `code-N` offset from a ProxyNova `String.fromCharCode` clause.
static RE_PROXYNOVA_OFFSET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"code\s*-\s*(\d+)").unwrap());

/// Matches the `atob("...")` base64 tail in a ProxyNova obfuscated IP.
static RE_PROXYNOVA_ATOB: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"atob\(\s*["']([A-Za-z0-9+/=]+)["']\s*\)"#).unwrap());

/// Finds every `ip:port` pair in free-form HTML (my-proxy.com).
static RE_IP_PORT_PAIR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b").unwrap());

/// Decodes `Proxy('base64')` calls inside proxy-list.org rows.
static RE_PROXY_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Proxy\('([A-Za-z0-9+/=]+)'\)").unwrap());

static TABLE_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("table").expect("static table selector is valid"));
static ROW_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("tr").expect("static row selector is valid"));
static HEADER_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("th").expect("static header selector is valid"));
static CELL_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("td").expect("static cell selector is valid"));

/// Maps a protocol label from a source into a [`Protocol`].
///
/// Unknown labels yield `None` so the caller falls back to the source defaults.
pub fn protocol_from_str(raw: &str) -> Option<Protocol> {
    let raw = raw.trim().to_ascii_lowercase();
    match raw.as_str() {
        "http" => Some(Protocol::Http(Anonymity::Unknown)),
        "https" | "ssl" => Some(Protocol::Https(Anonymity::Unknown)),
        "socks4" => Some(Protocol::Socks4),
        "socks5" => Some(Protocol::Socks5),
        _ => None,
    }
}

/// Maps an anonymity label from a source into an [`Anonymity`].
fn anonymity_from_str(raw: &str) -> Anonymity {
    let raw = raw.trim().to_ascii_lowercase();
    if raw.contains("elite") || raw.contains("high") {
        Anonymity::Elite
    } else if raw.contains("anonymous") {
        Anonymity::Anonymous
    } else if raw.contains("transparent") {
        Anonymity::Transparent
    } else {
        Anonymity::Unknown
    }
}

/// Parses `ip:port` from the start of a line, ignoring any trailing fields.
///
/// Handles the `1.2.3.4:8080`, `1.2.3.4:8080 US`, and `1.2.3.4:8080#US`
/// variants, as well as colon-delimited trailers such as
/// `1.2.3.4:8080:Argentina` used by hideip.me.
fn parse_pair(text: &str) -> Option<(Ipv4Addr, u16)> {
    let text = text.trim();
    let head = text
        .split([' ', '\t', '#', ',', '|'])
        .next()
        .unwrap_or(text)
        .trim();
    // Strip a scheme prefix such as `http://1.2.3.4:8080`.
    let head = head.rsplit("//").next().unwrap_or(head);

    // Take the first two colon-separated fields so that any further trailer
    // (country name, latency, ...) is discarded rather than read as the port.
    let mut fields = head.split(':');
    let ip = fields.next()?.trim().parse().ok()?;
    let port = fields.next()?.trim().parse().ok()?;
    Some((ip, port))
}

/// Visits newline-delimited `ip:port` rows without accumulating an output list.
pub fn visit_plaintext(body: &str, mut visit: impl FnMut(ParsedProxy) -> bool) {
    for row in body
        .lines()
        .filter_map(|line| parse_pair(line).map(|(ip, port)| (ip, port, None)))
    {
        if !visit(row) {
            break;
        }
    }
}

#[derive(Deserialize)]
struct GeonodeRow {
    ip: String,
    port: String,
    #[serde(default)]
    protocols: Vec<String>,
}

/// Parses the GeoNode JSON API.
///
/// A single entry may advertise several protocols; each becomes its own row.
pub fn visit_geonode(body: &str, mut visit: impl FnMut(ParsedProxy) -> bool) -> anyhow::Result<()> {
    visit_json_data::<GeonodeRow>(body, |row| {
        let (Ok(ip), Ok(port)) = (row.ip.parse::<Ipv4Addr>(), row.port.parse::<u16>()) else {
            return true;
        };
        if row.protocols.is_empty() {
            return visit((ip, port, None));
        }
        for protocol in &row.protocols {
            if !visit((ip, port, protocol_from_str(protocol))) {
                return false;
            }
        }
        true
    })
}

#[derive(Deserialize)]
struct ProxyNovaRow {
    ip: String,
    port: serde_json::Value,
}

/// Decodes ProxyNova's obfuscated `ip` field without evaluating JavaScript.
///
/// The API returns an expression that concatenates two encoded halves, e.g.
/// `[51,49,...].map((code) => String.fromCharCode(code-1)).join("").concat(atob("MTQ4"))`.
/// Both encodings are decoded structurally:
///
/// * a `[..]` char-code array, each entry offset by the `code-N` term;
/// * an `atob("..")` base64 literal.
///
/// Plain addresses are passed through unchanged.
fn deobfuscate_proxynova_ip(raw: &str) -> Option<Ipv4Addr> {
    let raw = raw.trim();
    if let Ok(ip) = raw.parse::<Ipv4Addr>() {
        return Some(ip);
    }

    let mut decoded = String::new();

    // Leading char-code array, e.g. `[51,49,51].map(code => fromCharCode(code-1))`.
    if let Some(start) = raw.find('[') {
        if let Some(end) = raw[start..].find(']').map(|i| start + i) {
            // The `code-N` offset applied to every entry (defaults to 0).
            let offset: i64 = RE_PROXYNOVA_OFFSET
                .captures(raw)
                .and_then(|caps| caps.get(1)?.as_str().parse().ok())
                .unwrap_or(0);

            for token in raw[start + 1..end].split(',') {
                let Ok(code) = token.trim().parse::<i64>() else {
                    continue;
                };
                let Some(ch) = u32::try_from(code - offset).ok().and_then(char::from_u32) else {
                    continue;
                };
                decoded.push(ch);
            }
        }
    }

    // Trailing `atob("...")` base64 literal.
    if let Some(caps) = RE_PROXYNOVA_ATOB.captures(raw) {
        if let Some(text) = caps
            .get(1)
            .and_then(|m| BASE64.decode(m.as_str()).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok())
        {
            decoded.push_str(&text);
        }
    }

    decoded.trim().parse().ok()
}

/// Parses the ProxyNova JSON API.
pub fn visit_proxynova(
    body: &str,
    mut visit: impl FnMut(ParsedProxy) -> bool,
) -> anyhow::Result<()> {
    visit_json_data::<ProxyNovaRow>(body, |row| {
        let Some(ip) = deobfuscate_proxynova_ip(&row.ip) else {
            return true;
        };
        let port = match &row.port {
            serde_json::Value::String(s) => s.trim().parse::<u16>().ok(),
            serde_json::Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
            _ => None,
        };
        let Some(port) = port else { return true };
        visit((ip, port, Some(Protocol::Http(Anonymity::Unknown))))
    })
}

/// Header cell texts that identify each proxy column, most specific first so
/// an exact match is preferred when several names could apply.
const IP_HEADER_NAMES: &[&str] = &["ip address", "ip"];
const PORT_HEADER_NAMES: &[&str] = &["port"];
const PROTOCOL_HEADER_NAMES: &[&str] = &["version", "type", "protocol"];
const HTTPS_HEADER_NAMES: &[&str] = &["https"];
const ANONYMITY_HEADER_NAMES: &[&str] = &["anonymity"];

/// Column indices of a proxy `<table>` header row.
struct HeaderColumns {
    ip: usize,
    port: usize,
    protocol: Option<usize>,
    https: Option<usize>,
    anonymity: Option<usize>,
}

/// Resolves the proxy columns from a table header.
///
/// Lowercases and trims every header cell exactly once, then indexes the cells
/// by their normalized text in a `HashMap` so all five columns resolve against
/// a single map.
fn header_columns(header: &[String]) -> HeaderColumns {
    let lower: Vec<String> = header
        .iter()
        .map(|cell| cell.trim().to_ascii_lowercase())
        .collect();
    let mut by_text: HashMap<&str, usize> = HashMap::with_capacity(lower.len());
    for (index, cell) in lower.iter().enumerate() {
        by_text.entry(cell.as_str()).or_insert(index);
    }

    HeaderColumns {
        ip: find_column(&by_text, &lower, IP_HEADER_NAMES).unwrap_or(0),
        port: find_column(&by_text, &lower, PORT_HEADER_NAMES).unwrap_or(1),
        protocol: find_column(&by_text, &lower, PROTOCOL_HEADER_NAMES),
        https: find_column(&by_text, &lower, HTTPS_HEADER_NAMES),
        anonymity: find_column(&by_text, &lower, ANONYMITY_HEADER_NAMES),
    }
}

/// Returns the index of the first header cell matching any of `names`.
///
/// Cells whose normalized text equals one of `names` (the common case, e.g.
/// "IP Address") are resolved with an O(1) map lookup; headers that only
/// contain a name as a substring (e.g. "Proxy Type") fall back to a linear
/// scan of the already-lowercased cells, so nothing is re-lowercased per
/// column.
fn find_column(by_text: &HashMap<&str, usize>, lower: &[String], names: &[&str]) -> Option<usize> {
    if let Some(&index) = names.iter().find_map(|name| by_text.get(name)) {
        return Some(index);
    }
    lower
        .iter()
        .position(|cell| names.iter().any(|name| cell.contains(name)))
}

/// True when `text` contains no whitespace other than single ASCII spaces, so
/// it is already in normalized shape (nothing to collapse, no tabs/newlines).
fn is_simple_text(text: &str) -> bool {
    let mut previous_space = false;
    for ch in text.chars() {
        if ch == ' ' {
            if previous_space {
                return false;
            }
            previous_space = true;
        } else if ch.is_whitespace() {
            return false;
        } else {
            previous_space = false;
        }
    }
    true
}

/// Normalizes an HTML fragment's text: whitespace runs collapse to single
/// spaces and empty text nodes are dropped.
///
/// Borrows the source text when a single text node is already normalized (the
/// common case for IP/port/protocol cells), avoiding a `String` allocation per
/// cell. Multi-node cells and cells with whitespace runs fall back to the
/// allocating fold.
fn normalized_text(element: scraper::ElementRef<'_>) -> Cow<'_, str> {
    let mut fragments = element.text();
    let first = match fragments.next() {
        Some(first) => first,
        None => return Cow::Borrowed(""),
    };
    let trimmed = first.trim();

    let second = fragments.next();
    if second.is_none() && is_simple_text(trimmed) {
        return Cow::Borrowed(trimmed);
    }

    let mut normalized = String::new();
    for fragment in std::iter::once(first).chain(second).chain(fragments) {
        for word in fragment.split_whitespace() {
            if !normalized.is_empty() {
                normalized.push(' ');
            }
            normalized.push_str(word);
        }
    }
    Cow::Owned(normalized)
}

/// Parses the HTML `<table>` markup shared by free-proxy-list.net,
/// sslproxies.org, us-proxy.org, socks-proxy.net and freeproxy.world.
///
/// Column positions differ between those sites, so columns are located by
/// header text rather than by fixed index.
pub fn visit_html_table(body: &str, mut visit: impl FnMut(ParsedProxy) -> bool) {
    let document = Html::parse_document(body);

    for table in document.select(&TABLE_SELECTOR) {
        let header: Vec<String> = table
            .select(&ROW_SELECTOR)
            .next()
            .map(|row| {
                let cells: Vec<String> = row
                    .select(&HEADER_SELECTOR)
                    .map(normalized_text)
                    .map(Cow::into_owned)
                    .collect();
                if cells.is_empty() {
                    row.select(&CELL_SELECTOR)
                        .map(normalized_text)
                        .map(Cow::into_owned)
                        .collect()
                } else {
                    cells
                }
            })
            .unwrap_or_default();

        let columns = header_columns(&header);

        for row in table.select(&ROW_SELECTOR) {
            let mut ip_cell: Option<Cow<'_, str>> = None;
            let mut port_cell: Option<Cow<'_, str>> = None;
            let mut type_cell: Option<Cow<'_, str>> = None;
            let mut https_cell: Option<Cow<'_, str>> = None;
            let mut anon_cell: Option<Cow<'_, str>> = None;

            // Normalize only the columns we actually need, instead of
            // materializing a Vec<String> for every cell of every row.
            for (index, cell) in row.select(&CELL_SELECTOR).enumerate() {
                if index == columns.ip {
                    ip_cell = Some(normalized_text(cell));
                } else if index == columns.port {
                    port_cell = Some(normalized_text(cell));
                } else if Some(index) == columns.protocol {
                    type_cell = Some(normalized_text(cell));
                } else if Some(index) == columns.https {
                    https_cell = Some(normalized_text(cell));
                } else if Some(index) == columns.anonymity {
                    anon_cell = Some(normalized_text(cell));
                }
            }

            let (Some(ip_cell), Some(port_cell)) = (ip_cell.as_deref(), port_cell.as_deref())
            else {
                continue;
            };
            let (Ok(ip), Ok(port)) = (
                ip_cell.trim().parse::<Ipv4Addr>(),
                port_cell.trim().parse::<u16>(),
            ) else {
                continue;
            };

            // Prefer an explicit protocol column, then the yes/no "Https" column.
            let mut protocol = type_cell.as_deref().and_then(protocol_from_str);
            if protocol.is_none() {
                if let Some(cell) = https_cell.as_deref() {
                    if cell.trim().eq_ignore_ascii_case("yes") {
                        protocol = Some(Protocol::Https(Anonymity::Unknown));
                    }
                }
            }
            // Carry the anonymity level through for HTTP rows.
            if let (Some(Protocol::Http(_)), Some(cell)) = (protocol.as_ref(), anon_cell.as_deref())
            {
                protocol = Some(Protocol::Http(anonymity_from_str(cell)));
            }

            if !visit((ip, port, protocol)) {
                return;
            }
        }
    }
}

/// Extracts every `ip:port` pair from free-form HTML (my-proxy.com).
pub fn visit_regex_pairs(body: &str, mut visit: impl FnMut(ParsedProxy) -> bool) {
    for row in RE_IP_PORT_PAIR.captures_iter(body).filter_map(|caps| {
        let ip = caps.get(1)?.as_str().parse::<Ipv4Addr>().ok()?;
        let port = caps.get(2)?.as_str().parse::<u16>().ok()?;
        Some((ip, port, None))
    }) {
        if !visit(row) {
            break;
        }
    }
}

/// Parses proxy-list.org rows, whose `ip:port` is base64 encoded inside a
/// `Proxy('...')` call.
pub fn visit_base64_rows(body: &str, mut visit: impl FnMut(ParsedProxy) -> bool) {
    for row in RE_PROXY_CALL.captures_iter(body).filter_map(|caps| {
        let decoded = BASE64.decode(caps.get(1)?.as_str()).ok()?;
        let text = String::from_utf8(decoded).ok()?;
        let (ip, port) = parse_pair(&text)?;
        Some((ip, port, None))
    }) {
        if !visit(row) {
            break;
        }
    }
}

#[cfg(test)]
fn collect_rows(run: impl FnOnce(&mut dyn FnMut(ParsedProxy) -> bool)) -> Vec<ParsedProxy> {
    let mut rows = Vec::new();
    run(&mut |row| {
        rows.push(row);
        true
    });
    rows
}

#[cfg(test)]
fn parse_plaintext(body: &str) -> Vec<ParsedProxy> {
    collect_rows(|visit| visit_plaintext(body, visit))
}

#[cfg(test)]
fn parse_geonode(body: &str) -> anyhow::Result<Vec<ParsedProxy>> {
    let mut rows = Vec::new();
    visit_geonode(body, |row| {
        rows.push(row);
        true
    })?;
    Ok(rows)
}

#[cfg(test)]
fn parse_proxynova(body: &str) -> anyhow::Result<Vec<ParsedProxy>> {
    let mut rows = Vec::new();
    visit_proxynova(body, |row| {
        rows.push(row);
        true
    })?;
    Ok(rows)
}

#[cfg(test)]
fn parse_html_table(body: &str) -> Vec<ParsedProxy> {
    collect_rows(|visit| visit_html_table(body, visit))
}

#[cfg(test)]
fn parse_regex_pairs(body: &str) -> Vec<ParsedProxy> {
    collect_rows(|visit| visit_regex_pairs(body, visit))
}

#[cfg(test)]
fn parse_base64_rows(body: &str) -> Vec<ParsedProxy> {
    collect_rows(|visit| visit_base64_rows(body, visit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geonode_stops_deserializing_after_visitor_closes() {
        let body = r#"{"data":[{"ip":"192.0.2.1","port":"8080","protocols":["http"]},INVALID]}"#;
        let mut visited = 0;

        visit_geonode(body, |_| {
            visited += 1;
            false
        })
        .unwrap();

        assert_eq!(visited, 1);
    }

    #[test]
    fn plaintext_handles_bare_and_annotated_lines() {
        let body = "1.2.3.4:8080\n5.6.7.8:1080 US\n9.10.11.12:3128#DE\nhttp://13.14.15.16:80\ngarbage\n1.2.3.4:99999\n";
        let parsed = parse_plaintext(body);
        assert_eq!(
            parsed
                .iter()
                .map(|(ip, port, _)| (ip.to_string(), *port))
                .collect::<Vec<_>>(),
            vec![
                ("1.2.3.4".into(), 8080),
                ("5.6.7.8".into(), 1080),
                ("9.10.11.12".into(), 3128),
                ("13.14.15.16".into(), 80),
            ]
        );
    }

    #[test]
    fn plaintext_ignores_colon_delimited_trailer() {
        // hideip.me ships `ip:port:Country`; the country must not be read
        // as the port.
        let body = "186.182.6.191:3129:Argentina\n119.93.83.106:8082:Philippines\n";
        let parsed = parse_plaintext(body);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0.to_string(), "186.182.6.191");
        assert_eq!(parsed[0].1, 3129);
        assert_eq!(parsed[1].1, 8082);
    }

    #[test]
    fn geonode_expands_multi_protocol_rows() {
        let body = r#"{"data":[{"ip":"1.2.3.4","port":"8080","protocols":["http","socks5"]}]}"#;
        let parsed = parse_geonode(body).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].2, Some(Protocol::Socks5));
    }

    #[test]
    fn proxynova_decodes_charcode_and_atob_halves() {
        // Real payload shape: `[..]` char codes offset by 1, concatenated with
        // an atob() base64 tail. Decodes to 202.137.8.148.
        let body = r#"{"data":[{"ip":"[51,49,51,47,50,52,56,47,57,47].map((code) => String.fromCharCode(code-1)).join(\"\").concat(atob(\"MTQ4\"))","port":8080}]}"#;
        let parsed = parse_proxynova(body).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0.to_string(), "202.137.8.148");
        assert_eq!(parsed[0].1, 8080);
    }

    #[test]
    fn proxynova_passes_through_plain_ip() {
        let body = r#"{"data":[{"ip":"1.2.3.4","port":"3128"}]}"#;
        let parsed = parse_proxynova(body).unwrap();
        assert_eq!(parsed[0].0.to_string(), "1.2.3.4");
        assert_eq!(parsed[0].1, 3128);
    }

    #[test]
    fn html_table_locates_columns_by_header() {
        let body = r#"<table><tr><th>IP Address</th><th>Port</th><th>Anonymity</th><th>Https</th></tr>
            <tr><td>1.2.3.4</td><td>8080</td><td>elite proxy</td><td>yes</td></tr>
            <tr><td>bad</td><td>x</td><td></td><td>no</td></tr></table>"#;
        let parsed = parse_html_table(body);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].1, 8080);
        assert_eq!(parsed[0].2, Some(Protocol::Https(Anonymity::Unknown)));
    }

    #[test]
    fn html_table_columns_resolve_by_exact_name_and_substring_fallback() {
        // "IP ADDRESS" hits the exact-match map; "Proxy Type" only matches by
        // substring, exercising the linear-scan fallback over the
        // pre-lowercased header cells.
        let body = r#"<table><tr><th>Proxy Type</th><th>IP ADDRESS</th><th>Port</th><th>Anonymity</th></tr>
            <tr><td>http</td><td>1.2.3.4</td><td>8080</td><td>elite proxy</td></tr>
            <tr><td>bad</td><td>x</td><td></td><td></td></tr></table>"#;
        let parsed = parse_html_table(body);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0.to_string(), "1.2.3.4");
        assert_eq!(parsed[0].1, 8080);
        assert_eq!(parsed[0].2, Some(Protocol::Http(Anonymity::Elite)));
    }

    #[test]
    fn html_table_defaults_to_first_two_columns_when_header_unknown() {
        // A header row that matches no known name falls back to ip=0/port=1,
        // matching the pre-fix `header_index(..).unwrap_or(..)` behavior.
        let body = r#"<table><tr><th>Foo</th><th>Bar</th></tr>
            <tr><td>1.2.3.4</td><td>8080</td></tr></table>"#;
        let parsed = parse_html_table(body);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0.to_string(), "1.2.3.4");
        assert_eq!(parsed[0].1, 8080);
    }

    #[test]
    fn html_cell_text_normalizes_whitespace_without_empty_fragments() {
        let document =
            Html::parse_fragment("<table><tr><td>  elite\n <b>proxy</b>\t </td></tr></table>");
        let cell = document.select(&CELL_SELECTOR).next().unwrap();

        assert_eq!(normalized_text(cell), "elite proxy");
    }

    #[test]
    fn base64_rows_decode_proxy_calls() {
        let encoded = BASE64.encode("1.2.3.4:8080");
        let body = format!("<li><script>Proxy('{}')</script></li>", encoded);
        let parsed = parse_base64_rows(&body);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].1, 8080);
    }

    #[test]
    fn regex_pairs_extract_from_free_form_html() {
        let body = "<div>1.2.3.4:8080#US</div><div>5.6.7.8:3128#DE</div>";
        assert_eq!(parse_regex_pairs(body).len(), 2);
    }
}
