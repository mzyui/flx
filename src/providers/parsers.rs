//! Body parsers for the different shapes proxy sources come in.
//!
//! Each parser turns a raw response body into `(Ipv4Addr, u16, Option<Protocol>)`
//! triples. A `Some(protocol)` means the source told us the protocol for that
//! specific row and it overrides the source's `default_types`.
//!
//! Ported from the Node implementation in `mzyui/proxy-list` (engine/src/providers).

use std::net::Ipv4Addr;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use regex::Regex;
use scraper::{Html, Selector};
use serde::Deserialize;

use crate::proxy::models::{Anonymity, Protocol};

/// A single parsed row. `protocol` is `None` when the source does not say.
pub type ParsedProxy = (Ipv4Addr, u16, Option<Protocol>);

/// Maps a protocol label from a source into a [`Protocol`].
///
/// Unknown labels yield `None` so the caller falls back to the source defaults.
pub fn protocol_from_str(raw: &str) -> Option<Protocol> {
    let raw = raw.trim().to_ascii_lowercase();
    match raw.as_str() {
        "http" => Some(Protocol::Http(Anonymity::Unknown)),
        "https" | "ssl" => Some(Protocol::Https),
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

/// Parses newline-delimited `ip:port` lists.
pub fn parse_plaintext(body: &str) -> Vec<ParsedProxy> {
    body.lines()
        .filter_map(|line| parse_pair(line).map(|(ip, port)| (ip, port, None)))
        .collect()
}

#[derive(Deserialize)]
struct GeonodeResponse {
    #[serde(default)]
    data: Vec<GeonodeRow>,
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
pub fn parse_geonode(body: &str) -> anyhow::Result<Vec<ParsedProxy>> {
    let payload: GeonodeResponse = serde_json::from_str(body)?;
    let mut out = Vec::new();
    for row in payload.data {
        let (Ok(ip), Ok(port)) = (row.ip.parse::<Ipv4Addr>(), row.port.parse::<u16>()) else {
            continue;
        };
        if row.protocols.is_empty() {
            out.push((ip, port, None));
        }
        for protocol in &row.protocols {
            out.push((ip, port, protocol_from_str(protocol)));
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
struct ProxyNovaResponse {
    #[serde(default)]
    data: Vec<ProxyNovaRow>,
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
            let offset: i64 = Regex::new(r"code\s*-\s*(\d+)")
                .ok()
                .and_then(|re| re.captures(raw))
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
    if let Some(caps) = Regex::new(r#"atob\(\s*["']([A-Za-z0-9+/=]+)["']\s*\)"#)
        .ok()
        .and_then(|re| re.captures(raw))
    {
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
pub fn parse_proxynova(body: &str) -> anyhow::Result<Vec<ParsedProxy>> {
    let payload: ProxyNovaResponse = serde_json::from_str(body)?;
    let mut out = Vec::new();
    for row in payload.data {
        let Some(ip) = deobfuscate_proxynova_ip(&row.ip) else {
            continue;
        };
        let port = match &row.port {
            serde_json::Value::String(s) => s.trim().parse::<u16>().ok(),
            serde_json::Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
            _ => None,
        };
        let Some(port) = port else { continue };
        out.push((ip, port, Some(Protocol::Http(Anonymity::Unknown))));
    }
    Ok(out)
}

/// Returns the index of the first header cell matching any of `names`.
fn header_index(header: &[String], names: &[&str]) -> Option<usize> {
    header.iter().position(|cell| {
        let cell = cell.trim().to_ascii_lowercase();
        names.iter().any(|name| cell.contains(name))
    })
}

/// Parses the HTML `<table>` markup shared by free-proxy-list.net,
/// sslproxies.org, us-proxy.org, socks-proxy.net and freeproxy.world.
///
/// Column positions differ between those sites, so columns are located by
/// header text rather than by fixed index.
pub fn parse_html_table(body: &str) -> Vec<ParsedProxy> {
    let document = Html::parse_document(body);
    let (Ok(table_sel), Ok(tr_sel), Ok(th_sel), Ok(td_sel)) = (
        Selector::parse("table"),
        Selector::parse("tr"),
        Selector::parse("th"),
        Selector::parse("td"),
    ) else {
        return Vec::new();
    };

    let cell_text = |element: scraper::ElementRef| {
        element
            .text()
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };

    let mut out = Vec::new();
    for table in document.select(&table_sel) {
        let header: Vec<String> = table
            .select(&tr_sel)
            .next()
            .map(|row| {
                let cells: Vec<String> = row.select(&th_sel).map(cell_text).collect();
                if cells.is_empty() {
                    row.select(&td_sel).map(cell_text).collect()
                } else {
                    cells
                }
            })
            .unwrap_or_default();

        let i_ip = header_index(&header, &["ip address", "ip"]).unwrap_or(0);
        let i_port = header_index(&header, &["port"]).unwrap_or(1);
        let i_type = header_index(&header, &["version", "type", "protocol"]);
        let i_https = header_index(&header, &["https"]);
        let i_anon = header_index(&header, &["anonymity"]);

        for row in table.select(&tr_sel) {
            let cells: Vec<String> = row.select(&td_sel).map(cell_text).collect();
            if cells.len() < 2 {
                continue;
            }
            let (Some(ip_cell), Some(port_cell)) = (cells.get(i_ip), cells.get(i_port)) else {
                continue;
            };
            let (Ok(ip), Ok(port)) = (
                ip_cell.trim().parse::<Ipv4Addr>(),
                port_cell.trim().parse::<u16>(),
            ) else {
                continue;
            };

            // Prefer an explicit protocol column, then the yes/no "Https" column.
            let mut protocol = i_type
                .and_then(|i| cells.get(i))
                .and_then(|cell| protocol_from_str(cell));
            if protocol.is_none() {
                if let Some(cell) = i_https.and_then(|i| cells.get(i)) {
                    if cell.trim().eq_ignore_ascii_case("yes") {
                        protocol = Some(Protocol::Https);
                    }
                }
            }
            // Carry the anonymity level through for HTTP rows.
            if let (Some(Protocol::Http(_)), Some(cell)) =
                (protocol.as_ref(), i_anon.and_then(|i| cells.get(i)))
            {
                protocol = Some(Protocol::Http(anonymity_from_str(cell)));
            }

            out.push((ip, port, protocol));
        }
    }
    out
}

/// Extracts every `ip:port` pair from free-form HTML (my-proxy.com).
pub fn parse_regex_pairs(body: &str) -> Vec<ParsedProxy> {
    let Ok(re) = Regex::new(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b") else {
        return Vec::new();
    };
    re.captures_iter(body)
        .filter_map(|caps| {
            let ip = caps.get(1)?.as_str().parse::<Ipv4Addr>().ok()?;
            let port = caps.get(2)?.as_str().parse::<u16>().ok()?;
            Some((ip, port, None))
        })
        .collect()
}

/// Parses proxy-list.org rows, whose `ip:port` is base64 encoded inside a
/// `Proxy('...')` call.
pub fn parse_base64_rows(body: &str) -> Vec<ParsedProxy> {
    let Ok(re) = Regex::new(r"Proxy\('([A-Za-z0-9+/=]+)'\)") else {
        return Vec::new();
    };
    re.captures_iter(body)
        .filter_map(|caps| {
            let decoded = BASE64.decode(caps.get(1)?.as_str()).ok()?;
            let text = String::from_utf8(decoded).ok()?;
            let (ip, port) = parse_pair(&text)?;
            Some((ip, port, None))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(parsed[0].2, Some(Protocol::Https));
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
