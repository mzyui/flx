use std::{borrow::Cow, cell::Cell, collections::HashMap, net::Ipv4Addr, sync::LazyLock};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use regex::Regex;
use scraper::{Html, Selector};
use serde::{
    de::{DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor},
    Deserializer,
};

use crate::{
    providers::models::{JsonIpTransform, JsonRowsConfig},
    proxy::models::{Anonymity, Protocol},
};

/// One parsed proxy row: address, port, and optional advertised protocol.
pub type ParsedProxy = (Ipv4Addr, u16, Option<Protocol>);
const VISITOR_STOPPED: &str = "flx parser visitor stopped";
const OBFUSCATED_IP_BUFFER_LEN: usize = 64;
const BASE64_ROW_BUFFER_LEN: usize = 256;

static RE_JS_CHARCODE_OFFSET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"code\s*-\s*(\d+)").unwrap());

static RE_JS_ATOB_HALF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"atob\(\s*["']([A-Za-z0-9+/=]+)["']\s*\)"#).unwrap());

static RE_IP_PORT_PAIR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b").unwrap());

static RE_PROXY_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Proxy\('([A-Za-z0-9+/=]+)'\)").unwrap());

fn decode_js_ip(raw: &str) -> Option<Ipv4Addr> {
    let raw = raw.trim();
    if let Ok(ip) = raw.parse::<Ipv4Addr>() {
        return Some(ip);
    }

    let mut buffer = [0u8; OBFUSCATED_IP_BUFFER_LEN];
    let mut len = 0usize;

    if let Some(start) = raw.find('[') {
        if let Some(end) = raw[start..].find(']').map(|i| start + i) {
            let offset: i64 = RE_JS_CHARCODE_OFFSET
                .captures(raw)
                .and_then(|caps| caps.get(1)?.as_str().parse().ok())
                .unwrap_or(0);

            for token in raw[start + 1..end].split(',') {
                let Ok(code) = token.trim().parse::<i64>() else {
                    continue;
                };
                let Some(value) = code.checked_sub(offset).and_then(|v| u32::try_from(v).ok())
                else {
                    continue;
                };
                let Some(ch) = char::from_u32(value) else {
                    continue;
                };
                if buffer.len() - len < 4 {
                    return None;
                }
                len += ch.encode_utf8(&mut buffer[len..]).len();
            }
        }
    }

    if let Some(caps) = RE_JS_ATOB_HALF.captures(raw) {
        if let Some(text) = caps.get(1) {
            if let Ok(written) = BASE64.decode_slice(text.as_str(), &mut buffer[len..]) {
                len += written;
            }
        }
    }

    std::str::from_utf8(&buffer[..len])
        .ok()?
        .trim()
        .parse()
        .ok()
}

static TABLE_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("table").expect("static table selector is valid"));
static ROW_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("tr").expect("static row selector is valid"));
static HEADER_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("th").expect("static header selector is valid"));
static CELL_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("td").expect("static cell selector is valid"));

/// Maps a raw protocol label to a [`Protocol`], or `None` when unknown.
///
/// Accepts `http`, `https`/`ssl`, `socks4`, and `socks5` case-insensitively.
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

fn valid_port(port: u16) -> Option<u16> {
    (port != 0).then_some(port)
}

pub(crate) fn parse_pair(text: &str) -> Option<(Ipv4Addr, u16)> {
    let text = text.trim();
    let head = text
        .split([' ', '\t', '#', ',', '|'])
        .next()
        .unwrap_or(text)
        .trim();
    let head = match head.split_once("//") {
        Some((scheme, rest)) if scheme.ends_with(':') => {
            rest.split(['/', '?']).next().unwrap_or(rest)
        }
        Some((before, _)) => before,
        None => head,
    }
    .trim();

    let mut fields = head.split(':');
    let ip = fields.next()?.trim().parse().ok()?;
    let port = valid_port(fields.next()?.trim().parse().ok()?)?;
    Some((ip, port))
}

/// Visits untyped `ip:port` rows, one per line; skips invalid lines.
///
/// Returning `false` from `visit` stops the scan early.
pub fn visit_plaintext(body: &str, mut visit: impl FnMut(ParsedProxy) -> bool) {
    let body = body.strip_prefix('\u{feff}').unwrap_or(body);
    for row in body
        .lines()
        .filter_map(|line| parse_pair(line).map(|(ip, port)| (ip, port, None)))
    {
        if !visit(row) {
            break;
        }
    }
}

const IP_HEADER_NAMES: &[&str] = &["ip address", "ip"];
const PORT_HEADER_NAMES: &[&str] = &["port"];
const PROTOCOL_HEADER_NAMES: &[&str] = &["version", "type", "protocol"];
const HTTPS_HEADER_NAMES: &[&str] = &["https"];
const ANONYMITY_HEADER_NAMES: &[&str] = &["anonymity"];

struct HeaderColumns {
    ip: usize,
    port: usize,
    protocol: Option<usize>,
    https: Option<usize>,
    anonymity: Option<usize>,
}

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

fn find_column(by_text: &HashMap<&str, usize>, lower: &[String], names: &[&str]) -> Option<usize> {
    if let Some(&index) = names.iter().find_map(|name| by_text.get(name)) {
        return Some(index);
    }
    lower
        .iter()
        .position(|cell| names.iter().any(|name| cell.contains(name)))
}

/// Parse port cell using last token to skip proxydb hidden prefix.
fn parse_port(text: &str) -> Option<u16> {
    let trimmed = text.trim();
    let port = match trimmed.parse::<u16>().ok() {
        Some(port) => port,
        None => trimmed
            .split_whitespace()
            .last()?
            .trim()
            .parse::<u16>()
            .ok()?,
    };
    valid_port(port)
}

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

/// Visits HTML table rows, locating IP/port columns from headers.
///
/// Falls back to the first two columns when headers are unknown and skips
/// rows with unparseable addresses. Returning `false` from `visit` stops
/// the scan early.
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
            let (Ok(ip), Some(port)) = (ip_cell.trim().parse::<Ipv4Addr>(), parse_port(port_cell))
            else {
                continue;
            };

            let mut protocol = type_cell.as_deref().and_then(protocol_from_str);
            if protocol.is_none() {
                if let Some(cell) = https_cell.as_deref() {
                    if cell.trim().eq_ignore_ascii_case("yes") {
                        protocol = Some(Protocol::Https(Anonymity::Unknown));
                    }
                }
            }
            if let (Some(current), Some(cell)) = (protocol, anon_cell.as_deref()) {
                let level = anonymity_from_str(cell);
                protocol = match current {
                    Protocol::Http(_) => Some(Protocol::Http(level)),
                    Protocol::Https(_) => Some(Protocol::Https(level)),
                    other => Some(other),
                };
            }

            if !visit((ip, port, protocol)) {
                return;
            }
        }
    }
}

/// Visits untyped `ip:port` pairs found anywhere in free-form text.
///
/// Returning `false` from `visit` stops the scan early.
pub fn visit_regex_pairs(body: &str, mut visit: impl FnMut(ParsedProxy) -> bool) {
    for row in RE_IP_PORT_PAIR.captures_iter(body).filter_map(|caps| {
        let ip = caps.get(1)?.as_str().parse::<Ipv4Addr>().ok()?;
        let port = valid_port(caps.get(2)?.as_str().parse::<u16>().ok()?)?;
        Some((ip, port, None))
    }) {
        if !visit(row) {
            break;
        }
    }
}

/// Visits base64-encoded `Proxy('...')` rows decoded as `ip:port`.
///
/// Rows that fail to decode or parse are skipped. Returning `false` from
/// `visit` stops the scan early.
pub fn visit_base64_rows(body: &str, mut visit: impl FnMut(ParsedProxy) -> bool) {
    for row in RE_PROXY_CALL.captures_iter(body).filter_map(|caps| {
        let encoded = caps.get(1)?.as_str();
        let mut buffer = [0u8; BASE64_ROW_BUFFER_LEN];
        let decoded: &[u8] = if encoded.len() <= buffer.len() {
            let written = BASE64.decode_slice(encoded, &mut buffer).ok()?;
            &buffer[..written]
        } else {
            &BASE64.decode(encoded).ok()?
        };
        let text = std::str::from_utf8(decoded).ok()?;
        let (ip, port) = parse_pair(text)?;
        Some((ip, port, None))
    }) {
        if !visit(row) {
            break;
        }
    }
}

struct CompiledJsonRows {
    rows_path: Vec<String>,
    ip_path: Vec<String>,
    port_path: Vec<String>,
    protocol_path: Option<Vec<String>>,
    protocols_path: Option<Vec<String>>,
    ip_transform: JsonIpTransform,
    fixed_protocol: Option<Protocol>,
}

fn compile_json_rows(config: &JsonRowsConfig) -> anyhow::Result<CompiledJsonRows> {
    let split = |path: &crate::providers::models::JsonPath| {
        path.as_str()
            .split('.')
            .filter(|segment| !segment.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let rows_path = split(&config.rows_path);
    let ip_path = split(&config.ip_path);
    let port_path = split(&config.port_path);
    if ip_path.is_empty() || port_path.is_empty() {
        anyhow::bail!("JSON row field paths cannot be empty");
    }
    Ok(CompiledJsonRows {
        rows_path,
        ip_path,
        port_path,
        protocol_path: config.protocol_path.as_ref().map(split),
        protocols_path: config.protocols_path.as_ref().map(split),
        ip_transform: config.ip_transform,
        fixed_protocol: config.fixed_protocol.map(|protocol| protocol.as_protocol()),
    })
}

fn json_path<'a>(value: &'a serde_json::Value, path: &[String]) -> Option<&'a serde_json::Value> {
    path.iter()
        .try_fold(value, |current, segment| current.get(segment))
}

fn json_port(value: &serde_json::Value) -> Option<u16> {
    match value {
        serde_json::Value::Number(value) => value
            .as_u64()
            .and_then(|port| u16::try_from(port).ok().and_then(valid_port)),
        serde_json::Value::String(value) => value.trim().parse().ok().and_then(valid_port),
        _ => None,
    }
}

fn visit_json_row(
    row: &serde_json::Value,
    schema: &CompiledJsonRows,
    visit: &mut dyn FnMut(ParsedProxy) -> bool,
) -> bool {
    let transform = schema.ip_transform;
    let Some(ip) = json_path(row, &schema.ip_path)
        .and_then(serde_json::Value::as_str)
        .and_then(|ip| match transform {
            JsonIpTransform::Plain => ip.trim().parse::<Ipv4Addr>().ok(),
            JsonIpTransform::JsObfuscated => decode_js_ip(ip),
        })
    else {
        return true;
    };
    let Some(port) = json_path(row, &schema.port_path).and_then(json_port) else {
        return true;
    };

    if let Some(protocol_path) = &schema.protocol_path {
        let Some(protocol) = json_path(row, protocol_path)
            .and_then(serde_json::Value::as_str)
            .and_then(protocol_from_str)
        else {
            return true;
        };
        return visit((ip, port, Some(protocol)));
    }
    if let Some(protocols_path) = &schema.protocols_path {
        let Some(protocols) = json_path(row, protocols_path).and_then(serde_json::Value::as_array)
        else {
            return true;
        };
        let protocols = protocols
            .iter()
            .filter_map(|protocol| protocol.as_str().and_then(protocol_from_str));
        let mut emitted = false;
        for protocol in protocols {
            emitted = true;
            if !visit((ip, port, Some(protocol))) {
                return false;
            }
        }
        if !emitted {
            return visit((ip, port, schema.fixed_protocol));
        }
        return true;
    }
    visit((ip, port, schema.fixed_protocol))
}

struct JsonRowsPathSeed<'a> {
    path: &'a [String],
    schema: &'a CompiledJsonRows,
    visit: &'a mut dyn FnMut(ParsedProxy) -> bool,
    stopped: &'a Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for JsonRowsPathSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        visit_json_rows_path(
            deserializer,
            self.path,
            self.schema,
            self.visit,
            self.stopped,
        )
    }
}

struct JsonRowsRootVisitor<'a> {
    key: &'a str,
    path: &'a [String],
    schema: &'a CompiledJsonRows,
    visit: &'a mut dyn FnMut(ParsedProxy) -> bool,
    stopped: &'a Cell<bool>,
}

impl<'de> Visitor<'de> for JsonRowsRootVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON object containing the configured rows array")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
            if key == self.key {
                map.next_value_seed(JsonRowsPathSeed {
                    path: self.path,
                    schema: self.schema,
                    visit: self.visit,
                    stopped: self.stopped,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct SchemaJsonRowsVisitor<'a> {
    schema: &'a CompiledJsonRows,
    visit: &'a mut dyn FnMut(ParsedProxy) -> bool,
    stopped: &'a Cell<bool>,
}

impl<'de> Visitor<'de> for SchemaJsonRowsVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON array of proxy rows")
    }

    fn visit_seq<A>(self, mut rows: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(row) = rows.next_element::<serde_json::Value>()? {
            if !visit_json_row(&row, self.schema, self.visit) {
                self.stopped.set(true);
                return Err(A::Error::custom(VISITOR_STOPPED));
            }
        }
        Ok(())
    }
}

fn visit_json_rows_path<'de, D>(
    deserializer: D,
    path: &[String],
    schema: &CompiledJsonRows,
    visit: &mut dyn FnMut(ParsedProxy) -> bool,
    stopped: &Cell<bool>,
) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    if path.is_empty() {
        return deserializer.deserialize_seq(SchemaJsonRowsVisitor {
            schema,
            visit,
            stopped,
        });
    }
    deserializer.deserialize_map(JsonRowsRootVisitor {
        key: &path[0],
        path: &path[1..],
        schema,
        visit,
        stopped,
    })
}

/// Visits schema-driven JSON rows with nested object paths.
pub fn visit_json_rows(
    body: &str,
    config: &JsonRowsConfig,
    mut visit: impl FnMut(ParsedProxy) -> bool,
) -> anyhow::Result<()> {
    let schema = compile_json_rows(config)?;
    let stopped = Cell::new(false);
    let mut deserializer = serde_json::Deserializer::from_str(body);
    let result = visit_json_rows_path(
        &mut deserializer,
        &schema.rows_path,
        &schema,
        &mut visit,
        &stopped,
    );
    match result {
        Ok(()) => Ok(()),
        Err(_error) if stopped.get() => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Visits untyped proxies from a JSON array of `ip:port` strings.
///
/// Unparseable strings are skipped; returning `false` from `visit` stops
/// deserialization early.
///
/// # Errors
///
/// Returns an error when `body` is not a JSON array of strings.
pub fn visit_json_strings(
    body: &str,
    mut visit: impl FnMut(ParsedProxy) -> bool,
) -> anyhow::Result<()> {
    let stopped = Cell::new(false);

    struct RowsVisitor<'a> {
        visit: &'a mut dyn FnMut(ParsedProxy) -> bool,
        stopped: &'a Cell<bool>,
    }

    impl<'de> Visitor<'de> for RowsVisitor<'_> {
        type Value = ();

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a JSON array of proxy strings")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            while let Some(row) = seq.next_element::<Cow<'de, str>>()? {
                let Some((ip, port)) = parse_pair(&row) else {
                    continue;
                };
                if !(self.visit)((ip, port, None)) {
                    self.stopped.set(true);
                    return Err(A::Error::custom(VISITOR_STOPPED));
                }
            }
            Ok(())
        }
    }

    let mut deserializer = serde_json::Deserializer::from_str(body);
    let result = deserializer.deserialize_seq(RowsVisitor {
        visit: &mut visit,
        stopped: &stopped,
    });
    match result {
        Ok(()) => Ok(()),
        Err(_error) if stopped.get() => Ok(()),
        Err(error) => Err(error.into()),
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
fn parse_json_strings(body: &str) -> anyhow::Result<Vec<ParsedProxy>> {
    let mut rows = Vec::new();
    visit_json_strings(body, |row| {
        rows.push(row);
        true
    })?;
    Ok(rows)
}

#[cfg(test)]
fn parse_json_rows(body: &str, config: &JsonRowsConfig) -> anyhow::Result<Vec<ParsedProxy>> {
    let mut rows = Vec::new();
    visit_json_rows(body, config, |row| {
        rows.push(row);
        true
    })?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_rows_stops_after_callback_returns_false_nested() {
        let body = r#"{"data":[{"ip":"192.0.2.1","port":"8080","protocols":["http"]},INVALID]}"#;
        let config = JsonRowsConfig::new("data", "ip", "port")
            .unwrap()
            .with_protocols_path("protocols")
            .unwrap();
        let mut visited = 0;

        visit_json_rows(body, &config, |_| {
            visited += 1;
            false
        })
        .unwrap();

        assert_eq!(visited, 1);
    }

    #[test]
    fn plaintext_rejects_zero_ports() {
        assert_eq!(parse_pair("1.2.3.4:0"), None);
        let parsed = parse_plaintext("1.2.3.4:0\n5.6.7.8:1080\n");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].1, 1080);
    }

    #[test]
    fn json_rows_maps_protocols_and_accepts_numeric_or_string_ports() {
        let body = r#"[
            {"protocol":"http","host":"192.0.2.1","port":8080},
            {"protocol":"https","host":"192.0.2.2","port":"8443"},
            {"protocol":"socks4","host":"192.0.2.3","port":1080},
            {"protocol":"socks5","host":"192.0.2.4","port":1081}
        ]"#;
        let config = JsonRowsConfig::new("", "host", "port")
            .unwrap()
            .with_protocol_path("protocol")
            .unwrap();
        let parsed = parse_json_rows(body, &config).unwrap();

        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0].2, Some(Protocol::Http(Anonymity::Unknown)));
        assert_eq!(parsed[1].2, Some(Protocol::Https(Anonymity::Unknown)));
        assert_eq!(parsed[2].2, Some(Protocol::Socks4));
        assert_eq!(parsed[3].2, Some(Protocol::Socks5));
        assert_eq!(parsed[1].1, 8443);
    }

    #[test]
    fn json_rows_support_nested_rows_and_fields() {
        let body = r#"{"payload":{"proxies":[{"endpoint":{"host":"192.0.2.1","port":8080},"kind":"socks5"}]}}"#;
        let config = JsonRowsConfig::new("payload.proxies", "endpoint.host", "endpoint.port")
            .unwrap()
            .with_protocol_path("kind")
            .unwrap();
        let parsed = parse_json_rows(body, &config).unwrap();

        assert_eq!(
            parsed,
            vec![(Ipv4Addr::new(192, 0, 2, 1), 8080, Some(Protocol::Socks5))]
        );
    }

    #[test]
    fn json_rows_skips_invalid_rows_and_unknown_protocols() {
        let body = r#"[
            {"protocol":"http","host":"192.0.2.1","port":8080},
            {"protocol":"http","host":"not-an-ip","port":8080},
            {"protocol":"http","host":"192.0.2.2","port":0},
            {"protocol":"other","host":"192.0.2.3","port":8080},
            {"protocol":"socks5","host":"192.0.2.4","port":65536}
        ]"#;
        let config = JsonRowsConfig::new("", "host", "port")
            .unwrap()
            .with_protocol_path("protocol")
            .unwrap();

        assert_eq!(parse_json_rows(body, &config).unwrap().len(), 1);
    }

    #[test]
    fn json_rows_rejects_non_array_json() {
        let config = JsonRowsConfig::new("", "host", "port").unwrap();
        assert!(parse_json_rows(r#"{"data":[]}"#, &config).is_err());
        assert!(parse_json_rows("not json", &config).is_err());
    }

    #[test]
    fn json_rows_stops_after_callback_returns_false() {
        let body = r#"[
            {"host":"192.0.2.1","port":8080},
            INVALID
        ]"#;
        let config = JsonRowsConfig::new("", "host", "port").unwrap();
        let mut visited = 0;

        visit_json_rows(body, &config, |_| {
            visited += 1;
            false
        })
        .unwrap();

        assert_eq!(visited, 1);
    }

    #[test]
    fn all_parsers_reject_zero_ports() {
        let config = JsonRowsConfig::new("data", "ip", "port").unwrap();
        assert!(
            parse_json_rows(r#"{"data":[{"ip":"1.2.3.4","port":"0"}]}"#, &config)
                .unwrap()
                .is_empty()
        );
        let obfuscated = JsonRowsConfig::new("data", "ip", "port")
            .map(|config| config.with_ip_transform(JsonIpTransform::JsObfuscated))
            .unwrap();
        assert!(
            parse_json_rows(r#"{"data":[{"ip":"1.2.3.4","port":0}]}"#, &obfuscated)
                .unwrap()
                .is_empty()
        );
        assert!(parse_regex_pairs("1.2.3.4:0").is_empty());
        assert!(parse_json_strings(r#"["1.2.3.4:0"]"#).unwrap().is_empty());
        let body = r#"<table><tr><th>IP</th><th>Port</th></tr>
            <tr><td>1.2.3.4</td><td>0</td></tr></table>"#;
        assert!(parse_html_table(body).is_empty());
    }

    #[test]
    fn plaintext_strips_utf8_bom() {
        let body = "\u{feff}1.2.3.4:8080\n5.6.7.8:1080\n";
        let parsed = parse_plaintext(body);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, Ipv4Addr::new(1, 2, 3, 4));
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
    fn js_obfuscated_ip_ignores_char_codes_that_overflow_the_offset() {
        assert!(decode_js_ip("[-9223372036854775808].map(code => fromCharCode(code-1))").is_none());
    }

    #[test]
    fn parse_pair_handles_scheme_prefixes_and_slash_comments() {
        assert_eq!(
            parse_pair("socks5://1.2.3.4:1080"),
            Some((Ipv4Addr::new(1, 2, 3, 4), 1080))
        );
        assert_eq!(
            parse_pair("http://1.2.3.4:8080/path"),
            Some((Ipv4Addr::new(1, 2, 3, 4), 8080))
        );
        assert_eq!(
            parse_pair("1.2.3.4:8080//US"),
            Some((Ipv4Addr::new(1, 2, 3, 4), 8080))
        );
    }

    #[test]
    fn plaintext_keeps_a_pair_followed_by_a_slash_comment() {
        let parsed = parse_plaintext("5.6.7.8:1080//DE\n");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].1, 1080);
    }

    #[test]
    fn plaintext_ignores_colon_delimited_trailer() {
        let body = "186.182.6.191:3129:Argentina\n119.93.83.106:8082:Philippines\n";
        let parsed = parse_plaintext(body);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0.to_string(), "186.182.6.191");
        assert_eq!(parsed[0].1, 3129);
        assert_eq!(parsed[1].1, 8082);
    }

    #[test]
    fn json_rows_expands_multi_protocol_rows() {
        let body = r#"{"data":[{"ip":"1.2.3.4","port":"8080","protocols":["http","socks5"]}]}"#;
        let config = JsonRowsConfig::new("data", "ip", "port")
            .unwrap()
            .with_protocols_path("protocols")
            .unwrap();
        let parsed = parse_json_rows(body, &config).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].2, Some(Protocol::Socks5));
    }

    #[test]
    fn json_rows_decodes_js_obfuscated_ip_halves() {
        let body = r#"{"data":[{"ip":"[51,49,51,47,50,52,56,47,57,47].map((code) => String.fromCharCode(code-1)).join(\"\").concat(atob(\"MTQ4\"))","port":8080}]}"#;
        let config = JsonRowsConfig::new("data", "ip", "port")
            .map(|config| config.with_ip_transform(JsonIpTransform::JsObfuscated))
            .unwrap();
        let parsed = parse_json_rows(body, &config).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0.to_string(), "202.137.8.148");
        assert_eq!(parsed[0].1, 8080);
        assert_eq!(parsed[0].2, None);
    }

    #[test]
    fn json_rows_attaches_fixed_protocol_to_untyped_rows() {
        let body = r#"{"data":[{"ip":"1.2.3.4","port":3128}]}"#;
        let config = JsonRowsConfig::new("data", "ip", "port")
            .map(|config| {
                config
                    .with_ip_transform(JsonIpTransform::JsObfuscated)
                    .with_fixed_protocol(crate::providers::models::JsonFixedProtocol::Http)
            })
            .unwrap();
        let parsed = parse_json_rows(body, &config).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].2, Some(Protocol::Http(Anonymity::Unknown)));
    }

    #[test]
    fn js_obfuscated_ip_passes_through_plain_ip() {
        let body = r#"{"data":[{"ip":"1.2.3.4","port":"3128"}]}"#;
        let config = JsonRowsConfig::new("data", "ip", "port")
            .map(|config| config.with_ip_transform(JsonIpTransform::JsObfuscated))
            .unwrap();
        let parsed = parse_json_rows(body, &config).unwrap();
        assert_eq!(parsed[0].0.to_string(), "1.2.3.4");
        assert_eq!(parsed[0].1, 3128);
    }

    #[test]
    fn js_obfuscated_ip_skips_rows_with_null_or_missing_ports() {
        let body = r#"{"data":[
            {"ip":"1.2.3.4","port":null},
            {"ip":"5.6.7.8"},
            {"ip":"9.10.11.12","port":true},
            {"ip":"13.14.15.16","port":8080}
        ]}"#;
        let config = JsonRowsConfig::new("data", "ip", "port")
            .map(|config| config.with_ip_transform(JsonIpTransform::JsObfuscated))
            .unwrap();
        let parsed = parse_json_rows(body, &config).unwrap();
        assert_eq!(
            parsed
                .iter()
                .map(|(ip, port, _)| (ip.to_string(), *port))
                .collect::<Vec<_>>(),
            vec![("13.14.15.16".to_string(), 8080)]
        );
    }

    #[test]
    fn js_obfuscated_ip_skips_rows_with_missing_ip() {
        let body = r#"{"data":[{"port":8080},{"ip":"1.2.3.4","port":3128}]}"#;
        let config = JsonRowsConfig::new("data", "ip", "port")
            .map(|config| config.with_ip_transform(JsonIpTransform::JsObfuscated))
            .unwrap();
        let parsed = parse_json_rows(body, &config).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0.to_string(), "1.2.3.4");
    }

    #[test]
    fn html_table_locates_columns_by_header() {
        let body = r#"<table><tr><th>IP Address</th><th>Port</th><th>Anonymity</th><th>Https</th></tr>
            <tr><td>1.2.3.4</td><td>8080</td><td>elite proxy</td><td>yes</td></tr>
            <tr><td>bad</td><td>x</td><td></td><td>no</td></tr></table>"#;
        let parsed = parse_html_table(body);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].1, 8080);
        assert_eq!(parsed[0].2, Some(Protocol::Https(Anonymity::Elite)));
    }

    #[test]
    fn html_table_https_yes_without_anonymity_column_stays_unknown() {
        let body = r#"<table><tr><th>IP Address</th><th>Port</th><th>Https</th></tr>
            <tr><td>1.2.3.4</td><td>8080</td><td>yes</td></tr></table>"#;
        let parsed = parse_html_table(body);
        assert_eq!(parsed[0].2, Some(Protocol::Https(Anonymity::Unknown)));
    }

    #[test]
    fn html_table_socks_rows_ignore_the_anonymity_column() {
        let body = r#"<table><tr><th>Proxy Type</th><th>IP ADDRESS</th><th>Port</th><th>Anonymity</th></tr>
            <tr><td>socks4</td><td>1.2.3.4</td><td>1080</td><td>elite proxy</td></tr></table>"#;
        let parsed = parse_html_table(body);
        assert_eq!(parsed[0].2, Some(Protocol::Socks4));
    }

    #[test]
    fn html_table_columns_resolve_by_exact_name_and_substring_fallback() {
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

    #[test]
    fn json_string_array_parses_bare_and_prefixed_rows() {
        let body = r#"["1.2.3.4:8080","http://5.6.7.8:3128","garbage","9.10.11.12:1080"]"#;
        let parsed = parse_json_strings(body).unwrap();
        assert_eq!(
            parsed
                .iter()
                .map(|(ip, port, _)| (ip.to_string(), *port))
                .collect::<Vec<_>>(),
            vec![
                ("1.2.3.4".into(), 8080),
                ("5.6.7.8".into(), 3128),
                ("9.10.11.12".into(), 1080),
            ]
        );
    }

    #[test]
    fn json_string_array_stops_deserializing_after_visitor_closes() {
        let body = r#"["1.2.3.4:8080",INVALID]"#;
        let mut visited = 0;

        visit_json_strings(body, |_| {
            visited += 1;
            false
        })
        .unwrap();

        assert_eq!(visited, 1);
    }

    #[test]
    fn json_string_array_non_string_element_fails_the_whole_parse() {
        let body = r#"["1.2.3.4:8080",42]"#;
        assert!(parse_json_strings(body).is_err());
    }

    #[test]
    fn json_rows_without_protocols_field_default_to_untyped() {
        let body = r#"{"data":[{"ip":"1.2.3.4","port":"8080"}]}"#;
        let config = JsonRowsConfig::new("data", "ip", "port").unwrap();
        let parsed = parse_json_rows(body, &config).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0.to_string(), "1.2.3.4");
        assert_eq!(parsed[0].1, 8080);
        assert_eq!(parsed[0].2, None);
    }

    #[test]
    fn regex_pairs_extracts_ip_port_pairs_from_script_text() {
        let body = r#"<script>var x="1.2.3.4:8080"; var y="5.6.7.8:3128";</script>"#;
        let parsed = parse_regex_pairs(body);
        assert_eq!(
            parsed
                .iter()
                .map(|(ip, port, _)| (ip.to_string(), *port))
                .collect::<Vec<_>>(),
            vec![("1.2.3.4".into(), 8080), ("5.6.7.8".into(), 3128)]
        );
    }

    #[test]
    fn html_table_port_cell_falls_back_to_last_token() {
        let body = r#"<table><tr><th>IP</th><th>Port</th></tr>
            <tr><td>1.2.3.4</td><td><div style="display:none">12</div>80</td></tr></table>"#;
        let parsed = parse_html_table(body);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0.to_string(), "1.2.3.4");
        assert_eq!(parsed[0].1, 80);
    }
}
