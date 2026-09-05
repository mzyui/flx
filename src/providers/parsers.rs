use std::{borrow::Cow, cell::Cell, collections::HashMap, net::Ipv4Addr, sync::LazyLock};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use regex::Regex;
use scraper::{Html, Selector};
use serde::{
    de::{DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};

use crate::proxy::models::{Anonymity, Protocol};

pub type ParsedProxy = (Ipv4Addr, u16, Option<Protocol>);
const VISITOR_STOPPED: &str = "flx parser visitor stopped";
// Reserve headroom for split UTF-8 sequences before rejecting overflow.
const PROXYNOVA_IP_BUFFER_LEN: usize = 64;
const BASE64_ROW_BUFFER_LEN: usize = 256;

struct JsonDataSeed<'a, 'de, T, F>
where
    T: Deserialize<'de>,
    F: FnMut(T) -> bool,
{
    visit: &'a mut F,
    stopped: &'a Cell<bool>,
    marker: std::marker::PhantomData<&'de T>,
}

impl<'de, T, F> DeserializeSeed<'de> for JsonDataSeed<'_, 'de, T, F>
where
    T: Deserialize<'de>,
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

struct JsonRootVisitor<'a, 'de, T, F>
where
    T: Deserialize<'de>,
    F: FnMut(T) -> bool,
{
    visit: &'a mut F,
    stopped: &'a Cell<bool>,
    marker: std::marker::PhantomData<&'de T>,
}

impl<'de, T, F> Visitor<'de> for JsonRootVisitor<'_, 'de, T, F>
where
    T: Deserialize<'de>,
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
        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
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

struct JsonRowsSeed<'a, 'de, T, F>
where
    T: Deserialize<'de>,
    F: FnMut(T) -> bool,
{
    visit: &'a mut F,
    stopped: &'a Cell<bool>,
    marker: std::marker::PhantomData<&'de T>,
}

impl<'de, T, F> DeserializeSeed<'de> for JsonRowsSeed<'_, 'de, T, F>
where
    T: Deserialize<'de>,
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

struct JsonRowsVisitor<'a, 'de, T, F>
where
    T: Deserialize<'de>,
    F: FnMut(T) -> bool,
{
    visit: &'a mut F,
    stopped: &'a Cell<bool>,
    marker: std::marker::PhantomData<&'de T>,
}

impl<'de, T, F> Visitor<'de> for JsonRowsVisitor<'_, 'de, T, F>
where
    T: Deserialize<'de>,
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

fn visit_json_data<'de, T, F>(body: &'de str, mut visit: F) -> anyhow::Result<()>
where
    T: Deserialize<'de> + 'de,
    F: FnMut(T) -> bool,
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
        // Treat visitor-initiated stop as success; other errors are parse failures.
        Err(_error) if stopped.get() => Ok(()),
        Err(error) => Err(error.into()),
    }
}

static RE_PROXYNOVA_OFFSET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"code\s*-\s*(\d+)").unwrap());

static RE_PROXYNOVA_ATOB: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"atob\(\s*["']([A-Za-z0-9+/=]+)["']\s*\)"#).unwrap());

static RE_IP_PORT_PAIR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b").unwrap());

static RE_PROXY_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Proxy\('([A-Za-z0-9+/=]+)'\)").unwrap());

static RE_GATHERPROXY_ROW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""ip"\s*:\s*"((?:\d{1,3}\.){3}\d{1,3})"\s*,\s*"port"\s*:\s*"(\d{1,5})""#).unwrap()
});

static TABLE_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("table").expect("static table selector is valid"));
static ROW_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("tr").expect("static row selector is valid"));
static HEADER_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("th").expect("static header selector is valid"));
static CELL_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("td").expect("static cell selector is valid"));

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

pub(crate) fn parse_pair(text: &str) -> Option<(Ipv4Addr, u16)> {
    let text = text.trim();
    let head = text
        .split([' ', '\t', '#', ',', '|'])
        .next()
        .unwrap_or(text)
        .trim();
    let head = head.rsplit("//").next().unwrap_or(head);

    // Discard trailing fields like country or latency after ip:port.
    let mut fields = head.split(':');
    let ip = fields.next()?.trim().parse().ok()?;
    let port = fields.next()?.trim().parse().ok()?;
    Some((ip, port))
}

pub fn visit_plaintext(body: &str, mut visit: impl FnMut(ParsedProxy) -> bool) {
    // Strip leading BOM corrupting the first ip:port pair.
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

#[derive(Deserialize)]
struct GeonodeRow<'a> {
    ip: Cow<'a, str>,
    port: Cow<'a, str>,
    #[serde(default)]
    protocols: Vec<Cow<'a, str>>,
}

pub fn visit_geonode(body: &str, mut visit: impl FnMut(ParsedProxy) -> bool) -> anyhow::Result<()> {
    visit_json_data::<GeonodeRow, _>(body, |row| {
        let (Ok(ip), Ok(port)) = (row.ip.parse::<Ipv4Addr>(), row.port.parse::<u16>()) else {
            return true;
        };
        if row.protocols.is_empty() {
            return visit((ip, port, None));
        }
        for protocol in &row.protocols {
            if !visit((ip, port, protocol_from_str(protocol.as_ref()))) {
                return false;
            }
        }
        true
    })
}

#[derive(Deserialize)]
struct ProxyNovaRow<'a> {
    ip: Cow<'a, str>,
    #[serde(deserialize_with = "deserialize_port")]
    port: Option<u16>,
}

/// Accept string or numeric ProxyNova ports without buffering JSON values.
fn deserialize_port<'de, D>(deserializer: D) -> Result<Option<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    struct PortVisitor;

    impl<'de> Visitor<'de> for PortVisitor {
        type Value = Option<u16>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a string or numeric port")
        }

        fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(value.trim().parse::<u16>().ok())
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(value.trim().parse::<u16>().ok())
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(u16::try_from(value).ok())
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(u16::try_from(value).ok())
        }

        fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(PortVisitor)
}

fn deobfuscate_proxynova_ip(raw: &str) -> Option<Ipv4Addr> {
    let raw = raw.trim();
    if let Ok(ip) = raw.parse::<Ipv4Addr>() {
        return Some(ip);
    }

    let mut buffer = [0u8; PROXYNOVA_IP_BUFFER_LEN];
    let mut len = 0usize;

    // Decode leading char-code array like `[51,49].map(code => fromCharCode(code-1))`.
    if let Some(start) = raw.find('[') {
        if let Some(end) = raw[start..].find(']').map(|i| start + i) {
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
                if buffer.len() - len < 4 {
                    return None;
                }
                len += ch.encode_utf8(&mut buffer[len..]).len();
            }
        }
    }

    if let Some(caps) = RE_PROXYNOVA_ATOB.captures(raw) {
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

pub fn visit_proxynova(
    body: &str,
    mut visit: impl FnMut(ParsedProxy) -> bool,
) -> anyhow::Result<()> {
    visit_json_data::<ProxyNovaRow, _>(body, |row| {
        let Some(ip) = deobfuscate_proxynova_ip(row.ip.as_ref()) else {
            return true;
        };
        let Some(port) = row.port else { return true };
        visit((ip, port, Some(Protocol::Http(Anonymity::Unknown))))
    })
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
fn parse_port(text: &str) -> Result<u16, std::num::ParseIntError> {
    let trimmed = text.trim();
    match trimmed.parse::<u16>() {
        Ok(port) => Ok(port),
        Err(error) => trimmed
            .split_whitespace()
            .last()
            .and_then(|token| token.trim().parse::<u16>().ok())
            .ok_or(error),
    }
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

            // Normalize only needed columns to avoid allocating every cell.
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
            let (Ok(ip), Ok(port)) = (ip_cell.trim().parse::<Ipv4Addr>(), parse_port(port_cell))
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
            // Apply anonymity column to HTTP/HTTPS rows; other protocols ignore it.
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

pub fn visit_gatherproxy(body: &str, mut visit: impl FnMut(ParsedProxy) -> bool) {
    for row in RE_GATHERPROXY_ROW.captures_iter(body).filter_map(|caps| {
        let ip = caps.get(1)?.as_str().parse::<Ipv4Addr>().ok()?;
        let port = caps.get(2)?.as_str().parse::<u16>().ok()?;
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
fn parse_json_strings(body: &str) -> anyhow::Result<Vec<ParsedProxy>> {
    let mut rows = Vec::new();
    visit_json_strings(body, |row| {
        rows.push(row);
        true
    })?;
    Ok(rows)
}

#[cfg(test)]
fn parse_gatherproxy(body: &str) -> Vec<ParsedProxy> {
    collect_rows(|visit| visit_gatherproxy(body, visit))
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
    fn plaintext_ignores_colon_delimited_trailer() {
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
        // Fall back to ip=0/port=1 matching legacy header_index behavior.
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
        // Fail whole parse on non-string elements to match owned String path.
        let body = r#"["1.2.3.4:8080",42]"#;
        assert!(parse_json_strings(body).is_err());
    }

    #[test]
    fn geonode_rows_without_protocols_field_default_to_untyped() {
        let body = r#"{"data":[{"ip":"1.2.3.4","port":"8080"}]}"#;
        let parsed = parse_geonode(body).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0.to_string(), "1.2.3.4");
        assert_eq!(parsed[0].1, 8080);
        assert_eq!(parsed[0].2, None);
    }

    #[test]
    fn gatherproxy_js_extracts_ip_port_pairs() {
        let body = r#"<script>gp.insertPrx({"t": "HTTP", "ip": "1.2.3.4", "port": "8080", "country": "US"});</script>
            <script>gp.insertPrx({"ip": "5.6.7.8","port":"3128","type":"HTTPS"});</script>
            <script>gp.insertPrx({"ip": "not-an-ip","port":"99999"});</script>"#;
        let parsed = parse_gatherproxy(body);
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
