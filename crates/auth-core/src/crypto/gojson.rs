//! Go `encoding/json` compatibility for byte-exact signed payloads.
//!
//! Signed bytes (provider-state envelopes, JWT headers and claims) must match
//! what Go produced, so this module reproduces `encoding/json`:
//!
//! - [`write_string`] / [`to_string`]: `json.Marshal` output, including HTML
//!   escaping of `<`, `>`, `&` and `\u2028`/`\u2029`, `\b`/`\f` short escapes,
//!   map keys sorted byte-wise and Go float formatting.
//! - [`check_valid`]: Go's scanner, so syntax errors carry Go's exact text
//!   (`invalid character 'o' in literal null (expecting 'u')`).
//! - [`parse_flat_object`]: the value-level view a flat Go struct decoder
//!   needs (string unquoting with U+FFFD replacement like Go).

use std::fmt::Write as _;

use serde_json::{Number, Value};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Appends `s` as a Go `encoding/json` string literal (with HTML escaping).
pub fn write_string(out: &mut String, s: &str) {
    out.push('"');
    let mut start = 0;
    for (i, c) in s.char_indices() {
        let escape: Option<&str> = match c {
            '\\' => Some("\\\\"),
            '"' => Some("\\\""),
            '\u{08}' => Some("\\b"),
            '\u{0c}' => Some("\\f"),
            '\n' => Some("\\n"),
            '\r' => Some("\\r"),
            '\t' => Some("\\t"),
            '<' | '>' | '&' | '\u{00}'..='\u{1f}' | '\u{2028}' | '\u{2029}' => Some(""),
            _ => None,
        };
        let Some(escape) = escape else { continue };
        out.push_str(&s[start..i]);
        if escape.is_empty() {
            let code = u32::from(c);
            out.push_str("\\u");
            for shift in [12, 8, 4, 0] {
                out.push(char::from(HEX[((code >> shift) & 0xf) as usize]));
            }
        } else {
            out.push_str(escape);
        }
        start = i + c.len_utf8();
    }
    out.push_str(&s[start..]);
    out.push('"');
}

/// `json.Marshal` of a decoded `any` value (objects as Go maps: sorted keys).
#[must_use]
pub fn to_string(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

/// Appends `json.Marshal(value)`; see [`to_string`].
pub fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => write_number(out, number),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => write_object(out, map.iter()),
    }
}

/// Appends a Go map: entries sorted by key bytes, whatever the input order.
pub fn write_object<'a>(
    out: &mut String,
    entries: impl IntoIterator<Item = (&'a String, &'a Value)>,
) {
    let mut entries: Vec<_> = entries.into_iter().collect();
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    out.push('{');
    for (i, (key, value)) in entries.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_string(out, key);
        out.push(':');
        write_value(out, value);
    }
    out.push('}');
}

fn write_number(out: &mut String, number: &Number) {
    if let Some(n) = number.as_i64() {
        let _ = write!(out, "{n}");
    } else if let Some(n) = number.as_u64() {
        let _ = write!(out, "{n}");
    } else if let Some(f) = number.as_f64() {
        write_float(out, f);
    }
}

/// Go `floatEncoder` for float64: `'f'` format for 1e-6 <= |f| < 1e21,
/// otherwise `'e'` with Go's exponent spelling (`1e+21`, `1e-7`).
fn write_float(out: &mut String, f: f64) {
    let abs = f.abs();
    if abs == 0.0 || (1e-6..1e21).contains(&abs) {
        let _ = write!(out, "{f}");
        return;
    }
    let formatted = format!("{f:e}");
    match formatted.split_once('e') {
        Some((mantissa, exponent)) => {
            out.push_str(mantissa);
            out.push('e');
            if let Some(negative) = exponent.strip_prefix('-') {
                out.push('-');
                out.push_str(negative);
            } else {
                out.push('+');
                if exponent.len() < 2 {
                    out.push('0');
                }
                out.push_str(exponent);
            }
        }
        None => out.push_str(&formatted),
    }
}

/// Go `json.SyntaxError`. Display is Go's `Error()` text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct SyntaxError {
    message: String,
    /// Go's `Offset`: bytes read before the error.
    pub offset: usize,
}

impl SyntaxError {
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

const MAX_NESTING_DEPTH: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    BeginValueOrEmpty,
    BeginValue,
    BeginStringOrEmpty,
    BeginString,
    EndValue,
    EndTop,
    InString,
    InStringEsc,
    InStringEscU,
    InStringEscU1,
    InStringEscU12,
    InStringEscU123,
    Neg,
    One,
    Zero,
    Dot,
    Dot0,
    E,
    ESign,
    E0,
    T,
    Tr,
    Tru,
    F,
    Fa,
    Fal,
    Fals,
    N,
    Nu,
    Nul,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Parse {
    ObjectKey,
    ObjectValue,
    ArrayValue,
}

/// Port of Go's `encoding/json` scanner (used by `checkValid`).
struct Scanner {
    state: State,
    stack: Vec<Parse>,
    end_top: bool,
    error: Option<String>,
}

const fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

/// Go `quoteChar`.
fn quote_char(c: u8) -> String {
    match c {
        b'\'' => "'\\''".to_owned(),
        b'"' => "'\"'".to_owned(),
        _ => {
            let mut out = String::from("'");
            match c {
                b'\\' => out.push_str("\\\\"),
                0x07 => out.push_str("\\a"),
                0x08 => out.push_str("\\b"),
                0x0c => out.push_str("\\f"),
                b'\n' => out.push_str("\\n"),
                b'\r' => out.push_str("\\r"),
                b'\t' => out.push_str("\\t"),
                0x0b => out.push_str("\\v"),
                0x20..=0x7e => out.push(char::from(c)),
                0x00..=0x1f | 0x7f => {
                    let _ = write!(out, "\\x{c:02x}");
                }
                // strconv.IsPrint for Latin-1: U+00A1..U+00FF except U+00AD.
                0xa1..=0xff if c != 0xad => out.push(char::from(c)),
                _ => {
                    let _ = write!(out, "\\u{:04x}", u32::from(c));
                }
            }
            out.push('\'');
            out
        }
    }
}

impl Scanner {
    const fn new() -> Self {
        Self {
            state: State::BeginValue,
            stack: Vec::new(),
            end_top: false,
            error: None,
        }
    }

    fn fail(&mut self, c: u8, context: &str) {
        self.state = State::Error;
        self.error = Some(format!("invalid character {} {context}", quote_char(c)));
    }

    fn push(&mut self, c: u8, parse: Parse) {
        self.stack.push(parse);
        if self.stack.len() > MAX_NESTING_DEPTH {
            self.fail(c, "exceeded max depth");
        }
    }

    fn pop(&mut self) {
        self.stack.pop();
        if self.stack.is_empty() {
            self.state = State::EndTop;
            self.end_top = true;
        } else {
            self.state = State::EndValue;
        }
    }

    fn literal(&mut self, c: u8, want: u8, next: State, context: &str) {
        if c == want {
            self.state = next;
        } else {
            self.fail(c, context);
        }
    }

    fn hex(&mut self, c: u8, next: State) {
        if c.is_ascii_hexdigit() {
            self.state = next;
        } else {
            self.fail(c, "in \\u hexadecimal character escape");
        }
    }

    #[allow(clippy::too_many_lines)]
    fn step(&mut self, c: u8) {
        match self.state {
            State::Error => {}
            State::BeginValueOrEmpty => {
                if is_space(c) {
                } else if c == b']' {
                    self.end_value(c);
                } else {
                    self.begin_value(c);
                }
            }
            State::BeginValue => self.begin_value(c),
            State::BeginStringOrEmpty => {
                if is_space(c) {
                } else if c == b'}' {
                    if let Some(top) = self.stack.last_mut() {
                        *top = Parse::ObjectValue;
                    }
                    self.end_value(c);
                } else {
                    self.begin_string(c);
                }
            }
            State::BeginString => self.begin_string(c),
            State::EndValue => self.end_value(c),
            State::EndTop => {
                if !is_space(c) {
                    self.fail(c, "after top-level value");
                }
            }
            State::InString => match c {
                b'"' => self.state = State::EndValue,
                b'\\' => self.state = State::InStringEsc,
                0x00..=0x1f => self.fail(c, "in string literal"),
                _ => {}
            },
            State::InStringEsc => match c {
                b'b' | b'f' | b'n' | b'r' | b't' | b'\\' | b'/' | b'"' => {
                    self.state = State::InString;
                }
                b'u' => self.state = State::InStringEscU,
                _ => self.fail(c, "in string escape code"),
            },
            State::InStringEscU => self.hex(c, State::InStringEscU1),
            State::InStringEscU1 => self.hex(c, State::InStringEscU12),
            State::InStringEscU12 => self.hex(c, State::InStringEscU123),
            State::InStringEscU123 => self.hex(c, State::InString),
            State::Neg => match c {
                b'0' => self.state = State::Zero,
                b'1'..=b'9' => self.state = State::One,
                _ => self.fail(c, "in numeric literal"),
            },
            State::One => {
                if c.is_ascii_digit() {
                } else {
                    self.zero(c);
                }
            }
            State::Zero => self.zero(c),
            State::Dot => {
                if c.is_ascii_digit() {
                    self.state = State::Dot0;
                } else {
                    self.fail(c, "after decimal point in numeric literal");
                }
            }
            State::Dot0 => {
                if c.is_ascii_digit() {
                } else if c == b'e' || c == b'E' {
                    self.state = State::E;
                } else {
                    self.end_value(c);
                }
            }
            State::E => {
                if c == b'+' || c == b'-' {
                    self.state = State::ESign;
                } else {
                    self.e_sign(c);
                }
            }
            State::ESign => self.e_sign(c),
            State::E0 => {
                if !c.is_ascii_digit() {
                    self.end_value(c);
                }
            }
            State::T => self.literal(c, b'r', State::Tr, "in literal true (expecting 'r')"),
            State::Tr => self.literal(c, b'u', State::Tru, "in literal true (expecting 'u')"),
            State::Tru => self.literal(c, b'e', State::EndValue, "in literal true (expecting 'e')"),
            State::F => self.literal(c, b'a', State::Fa, "in literal false (expecting 'a')"),
            State::Fa => self.literal(c, b'l', State::Fal, "in literal false (expecting 'l')"),
            State::Fal => self.literal(c, b's', State::Fals, "in literal false (expecting 's')"),
            State::Fals => {
                self.literal(c, b'e', State::EndValue, "in literal false (expecting 'e')");
            }
            State::N => self.literal(c, b'u', State::Nu, "in literal null (expecting 'u')"),
            State::Nu => self.literal(c, b'l', State::Nul, "in literal null (expecting 'l')"),
            State::Nul => self.literal(c, b'l', State::EndValue, "in literal null (expecting 'l')"),
        }
    }

    fn begin_value(&mut self, c: u8) {
        if is_space(c) {
            return;
        }
        match c {
            b'{' => {
                self.state = State::BeginStringOrEmpty;
                self.push(c, Parse::ObjectKey);
            }
            b'[' => {
                self.state = State::BeginValueOrEmpty;
                self.push(c, Parse::ArrayValue);
            }
            b'"' => self.state = State::InString,
            b'-' => self.state = State::Neg,
            b'0' => self.state = State::Zero,
            b't' => self.state = State::T,
            b'f' => self.state = State::F,
            b'n' => self.state = State::N,
            b'1'..=b'9' => self.state = State::One,
            _ => self.fail(c, "looking for beginning of value"),
        }
    }

    fn begin_string(&mut self, c: u8) {
        if is_space(c) {
        } else if c == b'"' {
            self.state = State::InString;
        } else {
            self.fail(c, "looking for beginning of object key string");
        }
    }

    fn zero(&mut self, c: u8) {
        if c == b'.' {
            self.state = State::Dot;
        } else if c == b'e' || c == b'E' {
            self.state = State::E;
        } else {
            self.end_value(c);
        }
    }

    fn e_sign(&mut self, c: u8) {
        if c.is_ascii_digit() {
            self.state = State::E0;
        } else {
            self.fail(c, "in exponent of numeric literal");
        }
    }

    fn end_value(&mut self, c: u8) {
        let Some(&top) = self.stack.last() else {
            self.state = State::EndTop;
            self.end_top = true;
            self.step(c);
            return;
        };
        if is_space(c) {
            self.state = State::EndValue;
            return;
        }
        match top {
            Parse::ObjectKey => {
                if c == b':' {
                    if let Some(top) = self.stack.last_mut() {
                        *top = Parse::ObjectValue;
                    }
                    self.state = State::BeginValue;
                } else {
                    self.fail(c, "after object key");
                }
            }
            Parse::ObjectValue => {
                if c == b',' {
                    if let Some(top) = self.stack.last_mut() {
                        *top = Parse::ObjectKey;
                    }
                    self.state = State::BeginString;
                } else if c == b'}' {
                    self.pop();
                } else {
                    self.fail(c, "after object key:value pair");
                }
            }
            Parse::ArrayValue => {
                if c == b',' {
                    self.state = State::BeginValue;
                } else if c == b']' {
                    self.pop();
                } else {
                    self.fail(c, "after array element");
                }
            }
        }
    }
}

/// Go `checkValid`: validates `data` as exactly one JSON value.
///
/// # Errors
/// Returns Go's syntax error text for the first offending byte, or
/// `unexpected end of JSON input`.
pub fn check_valid(data: &[u8]) -> Result<(), SyntaxError> {
    let mut scanner = Scanner::new();
    for (index, &c) in data.iter().enumerate() {
        scanner.step(c);
        if let Some(message) = scanner.error.take() {
            return Err(SyntaxError {
                message,
                offset: index + 1,
            });
        }
    }
    if scanner.end_top {
        return Ok(());
    }
    scanner.step(b' ');
    if scanner.end_top {
        return Ok(());
    }
    Err(SyntaxError {
        message: scanner
            .error
            .unwrap_or_else(|| "unexpected end of JSON input".to_owned()),
        offset: data.len(),
    })
}

/// A member value of a flat object, as a Go struct decoder sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlatValue<'a> {
    Null,
    Bool(bool),
    /// The literal number text.
    Number(&'a str),
    /// Unquoted like Go (`\u` surrogate pairs joined, invalid UTF-8 and lone
    /// surrogates replaced by U+FFFD).
    String(String),
    /// A nested object (content skipped).
    Object,
    /// A nested array (content skipped).
    Array,
}

impl FlatValue<'_> {
    /// The value name Go puts in `UnmarshalTypeError` (`"number"` etc.).
    #[must_use]
    pub const fn go_kind(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "bool",
            Self::Number(_) => "number",
            Self::String(_) => "string",
            Self::Object => "object",
            Self::Array => "array",
        }
    }
}

/// A top-level JSON value, with object members kept in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlatDocument<'a> {
    Object(Vec<(String, FlatValue<'a>)>),
    Other(FlatValue<'a>),
}

/// Validates `data` like Go's `checkValid`, then returns the top-level value
/// with one level of object members.
///
/// # Errors
/// Returns Go's syntax error for invalid JSON.
pub fn parse_flat_object(data: &[u8]) -> Result<FlatDocument<'_>, SyntaxError> {
    check_valid(data)?;
    let mut cursor = Cursor { data, pos: 0 };
    cursor.skip_space();
    if cursor.peek() != Some(b'{') {
        return Ok(FlatDocument::Other(cursor.value()));
    }
    cursor.pos += 1;
    let mut members = Vec::new();
    loop {
        cursor.skip_space();
        match cursor.peek() {
            Some(b'"') => {}
            _ => break,
        }
        let key = cursor.string();
        cursor.skip_space();
        cursor.pos += 1; // ':'
        cursor.skip_space();
        let value = cursor.value();
        members.push((key, value));
        cursor.skip_space();
        if cursor.peek() == Some(b',') {
            cursor.pos += 1;
        }
    }
    Ok(FlatDocument::Object(members))
}

/// Reader over input already accepted by [`check_valid`].
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn skip_space(&mut self) {
        while self.peek().is_some_and(is_space) {
            self.pos += 1;
        }
    }

    fn value(&mut self) -> FlatValue<'a> {
        match self.peek() {
            Some(b'"') => FlatValue::String(self.string()),
            Some(b'{') => {
                self.skip_container();
                FlatValue::Object
            }
            Some(b'[') => {
                self.skip_container();
                FlatValue::Array
            }
            Some(b't') => {
                self.pos += 4;
                FlatValue::Bool(true)
            }
            Some(b'f') => {
                self.pos += 5;
                FlatValue::Bool(false)
            }
            Some(b'n') => {
                self.pos += 4;
                FlatValue::Null
            }
            _ => {
                let start = self.pos;
                while self.peek().is_some_and(|c| {
                    c.is_ascii_digit() || matches!(c, b'-' | b'+' | b'.' | b'e' | b'E')
                }) {
                    self.pos += 1;
                }
                // Number literals are ASCII.
                FlatValue::Number(std::str::from_utf8(&self.data[start..self.pos]).unwrap_or(""))
            }
        }
    }

    /// Skips a nested object or array without recursion.
    fn skip_container(&mut self) {
        let mut depth = 0_usize;
        while let Some(c) = self.peek() {
            match c {
                b'"' => {
                    self.string_end();
                    if depth == 0 {
                        return;
                    }
                    continue;
                }
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    depth -= 1;
                    if depth == 0 {
                        self.pos += 1;
                        return;
                    }
                }
                _ => {}
            }
            self.pos += 1;
        }
    }

    /// Advances past a string literal and returns its raw content.
    fn string_end(&mut self) -> &'a [u8] {
        let start = self.pos + 1;
        let mut i = start;
        while i < self.data.len() {
            match self.data[i] {
                b'\\' => i += 2,
                b'"' => break,
                _ => i += 1,
            }
        }
        self.pos = i + 1;
        &self.data[start..i]
    }

    fn string(&mut self) -> String {
        unquote(self.string_end())
    }
}

fn hex4(raw: &[u8]) -> Option<u32> {
    let digits = raw.get(..4)?;
    let text = std::str::from_utf8(digits).ok()?;
    u32::from_str_radix(text, 16).ok()
}

/// Go `unquoteBytes` on the content of a valid string literal.
fn unquote(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if c == b'\\' {
            let escape = raw.get(i + 1).copied().unwrap_or(b'\\');
            i += 2;
            match escape {
                b'b' => out.push('\u{08}'),
                b'f' => out.push('\u{0c}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' => {
                    let first = hex4(&raw[i..]).unwrap_or(0xfffd);
                    i += 4;
                    if (0xd800..0xe000).contains(&first) {
                        let second = if raw.get(i) == Some(&b'\\') && raw.get(i + 1) == Some(&b'u')
                        {
                            hex4(&raw[i + 2..])
                        } else {
                            None
                        };
                        match second {
                            Some(low)
                                if (0xd800..0xdc00).contains(&first)
                                    && (0xdc00..0xe000).contains(&low) =>
                            {
                                let code = 0x10000 + ((first - 0xd800) << 10) + (low - 0xdc00);
                                out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                                i += 6;
                            }
                            _ => out.push('\u{fffd}'),
                        }
                    } else {
                        out.push(char::from_u32(first).unwrap_or('\u{fffd}'));
                    }
                }
                other => out.push(char::from(other)),
            }
            continue;
        }
        // Copy the run up to the next escape, replacing each invalid byte.
        let end = raw[i..]
            .iter()
            .position(|&b| b == b'\\')
            .map_or(raw.len(), |p| i + p);
        let mut chunk = &raw[i..end];
        while !chunk.is_empty() {
            match std::str::from_utf8(chunk) {
                Ok(text) => {
                    out.push_str(text);
                    break;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    out.push_str(std::str::from_utf8(&chunk[..valid]).unwrap_or_default());
                    out.push('\u{fffd}');
                    chunk = &chunk[valid + 1..];
                }
            }
        }
        i = end;
    }
    out
}

/// Go `foldName`: the key used for case-insensitive struct field matching.
#[must_use]
pub fn fold_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii() {
                return c.to_ascii_uppercase();
            }
            let mut lower = c.to_lowercase();
            let lowered = match (lower.next(), lower.next()) {
                (Some(l), None) => l,
                _ => c,
            };
            let mut upper = lowered.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(u), None) => u,
                _ => lowered,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn quoted(s: &str) -> String {
        let mut out = String::new();
        write_string(&mut out, s);
        out
    }

    #[test]
    fn strings_escape_like_go() {
        assert_eq!(quoted("a<b>&c"), r#""a\u003cb\u003e\u0026c""#);
        assert_eq!(quoted("\u{2028}\u{2029}"), r#""\u2028\u2029""#);
        assert_eq!(
            quoted("\u{08}\u{0c}\n\r\t\u{01}\u{1f}"),
            r#""\b\f\n\r\t\u0001\u001f""#
        );
        assert_eq!(quoted("q\"b\\/'\u{7f}"), "\"q\\\"b\\\\/'\u{7f}\"");
        assert_eq!(quoted("สวัสดี"), "\"สวัสดี\"");
    }

    #[test]
    fn values_marshal_like_go_maps() {
        let value = json!({"b": 1, "a": [true, null, "x"], "c": {"z": 1.5, "y": -3}});
        assert_eq!(
            to_string(&value),
            r#"{"a":[true,null,"x"],"b":1,"c":{"y":-3,"z":1.5}}"#
        );
        let floats = [
            (1e21, "1e+21"),
            (1.5e300, "1.5e+300"),
            (1e-7, "1e-7"),
            (1.25e-10, "1.25e-10"),
            (0.000_001, "0.000001"),
            (1e20, "100000000000000000000"),
            (0.5, "0.5"),
            (1_775_045_400.0, "1775045400"),
        ];
        for (f, want) in floats {
            assert_eq!(to_string(&json!(f)), want, "{f}");
        }
    }

    #[test]
    fn syntax_errors_match_go() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"not json",
                "invalid character 'o' in literal null (expecting 'u')",
            ),
            (b"", "unexpected end of JSON input"),
            (b"   ", "unexpected end of JSON input"),
            (b"{", "unexpected end of JSON input"),
            (
                b"tru",
                "invalid character ' ' in literal true (expecting 'e')",
            ),
            (b"{}x", "invalid character 'x' after top-level value"),
            (b"{\"a\" 1}", "invalid character '1' after object key"),
            (
                b"{\"a\":1 2}",
                "invalid character '2' after object key:value pair",
            ),
            (b"[1 2]", "invalid character '2' after array element"),
            (
                b"{1:2}",
                "invalid character '1' looking for beginning of object key string",
            ),
            (b"\"a\x01\"", "invalid character '\\x01' in string literal"),
            (b"\"\\x\"", "invalid character 'x' in string escape code"),
            (
                b"\"\\u12g4\"",
                "invalid character 'g' in \\u hexadecimal character escape",
            ),
            (b"-a", "invalid character 'a' in numeric literal"),
            (
                b"1.e",
                "invalid character 'e' after decimal point in numeric literal",
            ),
            (
                b"1e+x",
                "invalid character 'x' in exponent of numeric literal",
            ),
            (
                b"'",
                "invalid character '\\'' looking for beginning of value",
            ),
            (
                b"\xe0",
                "invalid character '\u{e0}' looking for beginning of value",
            ),
            (
                b"\xa0",
                "invalid character '\\u00a0' looking for beginning of value",
            ),
            (
                b"\t\n}",
                "invalid character '}' looking for beginning of value",
            ),
            (b"01", "invalid character '1' after top-level value"),
            (
                b"[1,]",
                "invalid character ']' looking for beginning of value",
            ),
        ];
        for (input, want) in cases {
            let error = check_valid(input).expect_err("invalid");
            assert_eq!(
                error.to_string(),
                *want,
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
        for valid in [
            &b"{}"[..],
            b" [ ] ",
            b"{\"a\":[1,{\"b\":null}],\"c\":-0.5e+3}",
            b"\"\\ud83d\\ude00\"",
            b"0",
        ] {
            assert_eq!(
                check_valid(valid),
                Ok(()),
                "{:?}",
                String::from_utf8_lossy(valid)
            );
        }
        let deep = "[".repeat(10_001);
        assert_eq!(
            check_valid(deep.as_bytes()).expect_err("deep").to_string(),
            "invalid character '[' exceeded max depth"
        );
    }

    #[test]
    fn flat_object_members() {
        let doc = parse_flat_object(
            b" {\"a\":\"x\\u0026\\ud83d\\ude00\\ud800y\", \"b\" : -12.5e1, \"c\":{\"d\":[\"}\"]},\"e\":[1,[2]],\"f\":true,\"g\":null,\"h\":false} ",
        )
        .expect("valid");
        assert_eq!(
            doc,
            FlatDocument::Object(vec![
                ("a".into(), FlatValue::String("x&\u{1f600}\u{fffd}y".into())),
                ("b".into(), FlatValue::Number("-12.5e1")),
                ("c".into(), FlatValue::Object),
                ("e".into(), FlatValue::Array),
                ("f".into(), FlatValue::Bool(true)),
                ("g".into(), FlatValue::Null),
                ("h".into(), FlatValue::Bool(false)),
            ])
        );
        assert_eq!(
            parse_flat_object(b"[1]").expect("valid"),
            FlatDocument::Other(FlatValue::Array)
        );
        assert_eq!(
            parse_flat_object(b"\"a\xffb\xe0\xa0\"").expect("valid"),
            FlatDocument::Other(FlatValue::String("a\u{fffd}b\u{fffd}\u{fffd}".into()))
        );
    }

    #[test]
    fn fold_name_matches_go() {
        assert_eq!(fold_name("Client_ID"), "CLIENT_ID");
        assert_eq!(fold_name("\u{17f}tate"), "STATE");
        assert_eq!(fold_name("\u{212a}"), "K");
    }
}
