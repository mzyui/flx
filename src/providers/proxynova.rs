use std::{net::Ipv4Addr, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use super::models::{valid_sources, JsonFixedProtocol, JsonRowsConfig, ScrapeMode, Source};
use super::ProxyProvider;

/// Scrapes the ProxyNova API proxy list.
pub struct ProxyNovaProvider;

/// Cap for intermediate strings while evaluating an obfuscated expression.
const MAX_EVAL_LEN: usize = 512;

/// Cap for decoded charcode bodies.
const MAX_CHARCODE_LEN: usize = 64;

/// Decodes ProxyNova's JavaScript-expression IP obfuscation.
///
/// Evaluates the small expression language the feed uses on top of string
/// literals, charcode arrays, and `atob`: `substring`, `repeat`, `split`,
/// `reverse`, `join`, `concat`, and `map` with a `fromCharCode(code-N)`
/// callback. Plain dotted-quads pass through; anything unrecognizable
/// returns `None` so the row is skipped.
pub fn decode_proxynova_ip(raw: &str) -> Option<Ipv4Addr> {
    let raw = raw.trim();
    if let Ok(ip) = raw.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    eval_proxynova_expr(raw).ok()?.trim().parse().ok()
}

fn eval_proxynova_expr(raw: &str) -> Result<String, ()> {
    let mut parser = ExprParser {
        input: raw.as_bytes(),
        pos: 0,
    };
    let value = parser.parse_expr()?;
    parser.skip_ws();
    if parser.pos != parser.input.len() {
        return Err(());
    }
    match value {
        Val::Str(text) => Ok(text),
        Val::Arr(_) => Err(()),
    }
}

enum Val {
    Str(String),
    Arr(Vec<Elem>),
}

enum Elem {
    Num(i64),
    Txt(String),
}

struct ExprParser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> ExprParser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.input.len() && self.input[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn expect(&mut self, byte: u8) -> bool {
        self.skip_ws();
        if self.peek() == Some(byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_ident(&mut self) -> Result<&'a str, ()> {
        self.skip_ws();
        let input = self.input;
        let start = self.pos;
        let first = self.peek().ok_or(())?;
        if !first.is_ascii_alphabetic() && first != b'_' && first != b'$' {
            return Err(());
        }
        self.pos += 1;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' {
                self.pos += 1;
            } else {
                break;
            }
        }
        std::str::from_utf8(&input[start..self.pos]).map_err(|_| ())
    }

    fn parse_string(&mut self) -> Result<String, ()> {
        if !self.expect(b'"') {
            return Err(());
        }
        let mut bytes = Vec::new();
        loop {
            let byte = self.peek().ok_or(())?;
            if byte == b'"' {
                self.pos += 1;
                break;
            }
            if byte == b'\\' {
                self.pos += 1;
                let escaped = self.peek().ok_or(())?;
                self.pos += 1;
                match escaped {
                    b'"' => bytes.push(b'"'),
                    b'\\' => bytes.push(b'\\'),
                    b'n' => bytes.push(b'\n'),
                    b't' => bytes.push(b'\t'),
                    b'r' => bytes.push(b'\r'),
                    _ => return Err(()),
                }
            } else {
                bytes.push(byte);
                self.pos += 1;
            }
        }
        String::from_utf8(bytes).map_err(|_| ())
    }

    fn parse_number(&mut self) -> Result<i64, ()> {
        self.skip_ws();
        let input = self.input;
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits = self.pos;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == digits {
            return Err(());
        }
        std::str::from_utf8(&input[start..self.pos])
            .map_err(|_| ())?
            .parse()
            .map_err(|_| ())
    }

    fn parse_arith(&mut self) -> Result<i64, ()> {
        let mut value = self.parse_number()?;
        loop {
            self.skip_ws();
            match self.peek() {
                Some(b'+') => {
                    self.pos += 1;
                    let rhs = self.parse_number()?;
                    value = value.checked_add(rhs).ok_or(())?;
                }
                Some(b'-') => {
                    self.pos += 1;
                    let rhs = self.parse_number()?;
                    value = value.checked_sub(rhs).ok_or(())?;
                }
                _ => return Ok(value),
            }
        }
    }

    fn parse_array(&mut self) -> Result<Vec<Elem>, ()> {
        if !self.expect(b'[') {
            return Err(());
        }
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(items);
        }
        loop {
            items.push(Elem::Num(self.parse_number()?));
            self.skip_ws();
            match self.peek().ok_or(())? {
                b',' => self.pos += 1,
                b']' => {
                    self.pos += 1;
                    return Ok(items);
                }
                _ => return Err(()),
            }
        }
    }

    fn parse_primary(&mut self) -> Result<Val, ()> {
        self.skip_ws();
        match self.peek().ok_or(())? {
            b'"' => Ok(Val::Str(self.parse_string()?)),
            b'[' => Ok(Val::Arr(self.parse_array()?)),
            _ => {
                if self.parse_ident()? != "atob" {
                    return Err(());
                }
                if !self.expect(b'(') {
                    return Err(());
                }
                let payload = self.parse_string()?;
                if !self.expect(b')') {
                    return Err(());
                }
                let decoded = BASE64.decode(payload.trim()).map_err(|_| ())?;
                let text = String::from_utf8(decoded).map_err(|_| ())?;
                Ok(Val::Str(text))
            }
        }
    }

    fn parse_expr(&mut self) -> Result<Val, ()> {
        let mut value = self.parse_primary()?;
        loop {
            self.skip_ws();
            if self.peek() != Some(b'.') {
                return Ok(value);
            }
            self.pos += 1;
            let method = self.parse_ident()?;
            value = match method {
                "substring" => self.apply_substring(value)?,
                "repeat" => self.apply_repeat(value)?,
                "split" => self.apply_split(value)?,
                "reverse" => self.apply_reverse(value)?,
                "join" => self.apply_join(value)?,
                "concat" => self.apply_concat(value)?,
                "map" => self.apply_map(value)?,
                _ => return Err(()),
            };
        }
    }

    fn apply_substring(&mut self, value: Val) -> Result<Val, ()> {
        if !self.expect(b'(') {
            return Err(());
        }
        let start = self.parse_arith()?;
        self.skip_ws();
        let end = if self.peek() == Some(b',') {
            self.pos += 1;
            self.parse_arith()?
        } else {
            i64::MAX
        };
        if !self.expect(b')') {
            return Err(());
        }
        let Val::Str(text) = value else {
            return Err(());
        };
        let chars: Vec<char> = text.chars().collect();
        let len = chars.len() as i64;
        let mut from = start.clamp(0, len);
        let mut to = end.clamp(0, len);
        if from > to {
            std::mem::swap(&mut from, &mut to);
        }
        Ok(Val::Str(chars[from as usize..to as usize].iter().collect()))
    }

    fn apply_repeat(&mut self, value: Val) -> Result<Val, ()> {
        if !self.expect(b'(') {
            return Err(());
        }
        let count = self.parse_arith()?;
        if !self.expect(b')') {
            return Err(());
        }
        let Val::Str(text) = value else {
            return Err(());
        };
        if count < 0 {
            return Err(());
        }
        let total = text.len().checked_mul(count as usize).ok_or(())?;
        if total > MAX_EVAL_LEN {
            return Err(());
        }
        Ok(Val::Str(text.repeat(count as usize)))
    }

    fn apply_split(&mut self, value: Val) -> Result<Val, ()> {
        if !self.expect(b'(') {
            return Err(());
        }
        let sep = self.parse_string()?;
        if !self.expect(b')') {
            return Err(());
        }
        let Val::Str(text) = value else {
            return Err(());
        };
        let parts = if sep.is_empty() {
            text.chars().map(|ch| Elem::Txt(ch.to_string())).collect()
        } else {
            text.split(sep.as_str())
                .map(|part| Elem::Txt(part.to_owned()))
                .collect()
        };
        Ok(Val::Arr(parts))
    }

    fn apply_join(&mut self, value: Val) -> Result<Val, ()> {
        if !self.expect(b'(') {
            return Err(());
        }
        self.skip_ws();
        let sep = self.parse_string()?;
        if !self.expect(b')') {
            return Err(());
        }
        match value {
            Val::Str(text) => return Ok(Val::Str(text)),
            Val::Arr(_) => {}
        };
        let Val::Arr(items) = value else {
            return Err(());
        };
        let mut out = String::new();
        for (index, item) in items.iter().enumerate() {
            if index > 0 {
                out.push_str(&sep);
            }
            match item {
                Elem::Num(num) => out.push_str(&num.to_string()),
                Elem::Txt(text) => out.push_str(text),
            }
            if out.len() > MAX_EVAL_LEN {
                return Err(());
            }
        }
        Ok(Val::Str(out))
    }

    fn apply_reverse(&mut self, value: Val) -> Result<Val, ()> {
        if !self.expect(b'(') {
            return Err(());
        }
        if !self.expect(b')') {
            return Err(());
        }
        let Val::Arr(mut items) = value else {
            return Err(());
        };
        items.reverse();
        Ok(Val::Arr(items))
    }

    fn apply_concat(&mut self, value: Val) -> Result<Val, ()> {
        if !self.expect(b'(') {
            return Err(());
        }
        let Val::Str(mut text) = value else {
            return Err(());
        };
        self.skip_ws();
        if self.peek() == Some(b')') {
            self.pos += 1;
            return Ok(Val::Str(text));
        }
        loop {
            let arg = self.parse_expr()?;
            let Val::Str(part) = arg else {
                return Err(());
            };
            text.push_str(&part);
            if text.len() > MAX_EVAL_LEN {
                return Err(());
            }
            self.skip_ws();
            match self.peek().ok_or(())? {
                b',' => self.pos += 1,
                b')' => {
                    self.pos += 1;
                    return Ok(Val::Str(text));
                }
                _ => return Err(()),
            }
        }
    }

    fn apply_map(&mut self, value: Val) -> Result<Val, ()> {
        if !self.expect(b'(') {
            return Err(());
        }
        self.skip_ws();
        if self.peek() == Some(b'(') {
            self.pos += 1;
            self.skip_ws();
            let param = self.parse_ident()?;
            self.skip_ws();
            if !self.expect(b')') {
                return Err(());
            }
            self.skip_ws();
            if !self.expect(b'=') || !self.expect(b'>') {
                return Err(());
            }
            self.skip_ws();
            return self.parse_map_body(value, param);
        }
        let param = self.parse_ident()?;
        self.skip_ws();
        if !self.expect(b'=') || !self.expect(b'>') {
            return Err(());
        }
        self.skip_ws();
        self.parse_map_body(value, param)
    }

    fn parse_map_body(&mut self, value: Val, param: &str) -> Result<Val, ()> {
        self.skip_ws();
        if self.peek() == Some(b'S') {
            if self.parse_ident()? != "String" {
                return Err(());
            }
            if !self.expect(b'.') {
                return Err(());
            }
        }
        if self.parse_ident()? != "fromCharCode" {
            return Err(());
        }
        if !self.expect(b'(') {
            return Err(());
        }
        if self.parse_ident()? != param {
            return Err(());
        }
        self.skip_ws();
        let offset = if self.peek() == Some(b'-') {
            self.pos += 1;
            self.parse_number()?
        } else {
            0
        };
        if !self.expect(b')') {
            return Err(());
        }
        if !self.expect(b')') {
            return Err(());
        }
        let Val::Arr(items) = value else {
            return Err(());
        };
        let mut out = String::new();
        for item in &items {
            let Elem::Num(code) = item else {
                return Err(());
            };
            let Some(shifted) = code.checked_sub(offset) else {
                continue;
            };
            let Ok(scalar) = u32::try_from(shifted) else {
                continue;
            };
            let Some(ch) = char::from_u32(scalar) else {
                continue;
            };
            if out.len() + ch.len_utf8() > MAX_CHARCODE_LEN {
                return Err(());
            }
            out.push(ch);
        }
        Ok(Val::Str(out))
    }
}

#[async_trait]
impl ProxyProvider for ProxyNovaProvider {
    fn name(&self) -> &'static str {
        "proxynova"
    }

    fn ip_decoder(&self) -> fn(&str) -> Option<Ipv4Addr> {
        decode_proxynova_ip
    }

    fn sources(&self) -> Vec<Source> {
        valid_sources(vec![Source::all("https://api.proxynova.com/proxylist")
            .map(|source| {
                source
                    .with_mode(ScrapeMode::JsonRows(
                        JsonRowsConfig::new("data", "ip", "port")
                            .map(|config| config.with_fixed_protocol(JsonFixedProtocol::Http))
                            .expect("static ProxyNova JSON schema is valid"),
                    ))
                    .with_timeout(Duration::from_secs(15))
            })])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::parsers::visit_json_rows_with;

    fn parse_rows(
        body: &str,
        config: &JsonRowsConfig,
    ) -> anyhow::Result<Vec<(Ipv4Addr, u16, Option<crate::proxy::models::Protocol>)>> {
        let mut rows = Vec::new();
        visit_json_rows_with(body, config, decode_proxynova_ip, |row| {
            rows.push(row);
            true
        })?;
        Ok(rows)
    }

    #[test]
    fn proxynova_decodes_js_obfuscated_ip_halves() {
        let body = r#"{"data":[{"ip":"[51,49,51,47,50,52,56,47,57,47].map((code) => String.fromCharCode(code-1)).join(\"\").concat(atob(\"MTQ4\"))","port":8080}]}"#;
        let config = JsonRowsConfig::new("data", "ip", "port").unwrap();
        let parsed = parse_rows(body, &config).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0.to_string(), "202.137.8.148");
        assert_eq!(parsed[0].1, 8080);
        assert_eq!(parsed[0].2, None);
    }

    #[test]
    fn proxynova_decodes_substring_concat_chains() {
        assert_eq!(
            decode_proxynova_ip(
                r#""1.1195.178.1.18.759".substring(5-2, 14-3).concat("38333.86383".substring(2+1, 15-7))"#
            ),
            Some(Ipv4Addr::new(195, 178, 33, 86))
        );
    }

    #[test]
    fn proxynova_decodes_split_reverse_chains() {
        assert_eq!(
            decode_proxynova_ip(
                r#""1.452.15".split("").reverse().join("").concat("32.238".repeat(1).substring(0))"#
            ),
            Some(Ipv4Addr::new(51, 254, 132, 238))
        );
    }

    #[test]
    fn proxynova_decodes_repeat_substring_chains() {
        assert_eq!(
            decode_proxynova_ip(
                r#""36.66.1".repeat(2).substring(7).concat("03".split("").reverse().join("")).concat(".147".repeat(2).substring(4))"#
            ),
            Some(Ipv4Addr::new(36, 66, 130, 147))
        );
    }

    #[test]
    fn proxynova_decodes_bare_repeat_substring_pair() {
        assert_eq!(
            decode_proxynova_ip(
                r#""120.26.".repeat(3).substring(14).concat("0.11".repeat(2).substring(4))"#
            ),
            Some(Ipv4Addr::new(120, 26, 0, 11))
        );
    }

    #[test]
    fn proxynova_decodes_multi_arg_concat_chains() {
        assert_eq!(
            decode_proxynova_ip(
                r#""118".substring(0+1, 3+0).concat("455.44".substring(4-2, 8-3)).concat("4.232.30".repeat(3).substring(16))"#
            ),
            Some(Ipv4Addr::new(185, 44, 232, 30))
        );
    }

    #[test]
    fn proxynova_decodes_bare_atob() {
        assert_eq!(
            decode_proxynova_ip(r#"atob("MTgxLjExNC42MS4xNw==")"#),
            Some(Ipv4Addr::new(181, 114, 61, 17))
        );
    }

    #[test]
    fn proxynova_decodes_charcode_concat_split_reverse() {
        assert_eq!(
            decode_proxynova_ip(
                r#"[51,53,58,48,51,51,57,48].map((code) => String.fromCharCode(code-2)).join("").concat("712.58".split("").reverse().join(""))"#
            ),
            Some(Ipv4Addr::new(138, 117, 85, 217))
        );
    }

    #[test]
    fn proxynova_rejects_unknown_methods_and_trailing_garbage() {
        assert_eq!(decode_proxynova_ip(r#""1.2.3.4".rot13()"#), None);
        assert_eq!(decode_proxynova_ip("1.2.3.4;"), None);
        assert_eq!(decode_proxynova_ip(""), None);
    }

    #[test]
    fn proxynova_decoder_passes_through_plain_ip() {
        assert_eq!(
            decode_proxynova_ip("1.2.3.4"),
            Some(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn proxynova_decoder_rejects_overflowing_charcode_offset() {
        assert!(
            decode_proxynova_ip("[-9223372036854775808].map(code => fromCharCode(code-1))")
                .is_none()
        );
    }

    #[test]
    fn proxynova_decoder_skips_rows_with_null_or_missing_ports() {
        let body = r#"{"data":[
            {"ip":"1.2.3.4","port":null},
            {"ip":"5.6.7.8"},
            {"ip":"9.10.11.12","port":true},
            {"ip":"13.14.15.16","port":8080}
        ]}"#;
        let config = JsonRowsConfig::new("data", "ip", "port").unwrap();
        let parsed = parse_rows(body, &config).unwrap();
        assert_eq!(
            parsed
                .iter()
                .map(|(ip, port, _)| (ip.to_string(), *port))
                .collect::<Vec<_>>(),
            vec![("13.14.15.16".to_string(), 8080)]
        );
    }

    #[test]
    fn proxynova_decoder_skips_rows_with_missing_ip() {
        let body = r#"{"data":[{"port":8080},{"ip":"1.2.3.4","port":3128}]}"#;
        let config = JsonRowsConfig::new("data", "ip", "port").unwrap();
        let parsed = parse_rows(body, &config).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0.to_string(), "1.2.3.4");
    }

    #[test]
    fn proxynova_decoder_rejects_zero_ports() {
        let config = JsonRowsConfig::new("data", "ip", "port").unwrap();
        assert!(
            parse_rows(r#"{"data":[{"ip":"1.2.3.4","port":0}]}"#, &config)
                .unwrap()
                .is_empty()
        );
    }
}
