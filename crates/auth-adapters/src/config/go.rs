//! Go standard-library parsing semantics the config loader depends on:
//! `time.ParseDuration`, `strconv.ParseBool`, `strconv.Atoi` and the error
//! text each produces.

use std::fmt;
use std::num::IntErrorKind;

use time::Duration;

/// `time.ParseDuration` failure. Display matches Go's message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DurationError {
    #[error("time: invalid duration {}", quote(.0))]
    Invalid(String),
    #[error("time: missing unit in duration {}", quote(.0))]
    MissingUnit(String),
    #[error("time: unknown unit {} in duration {}", quote(.unit), quote(.input))]
    UnknownUnit { unit: String, input: String },
}

const NANOS_PER_UNIT: &[(&[u8], u64)] = &[
    (b"ns", 1),
    (b"us", 1_000),
    ("\u{b5}s".as_bytes(), 1_000),
    ("\u{3bc}s".as_bytes(), 1_000),
    (b"ms", 1_000_000),
    (b"s", 1_000_000_000),
    (b"m", 60_000_000_000),
    (b"h", 3_600_000_000_000),
];

const LIMIT: u64 = 1 << 63;

/// Parses a Go duration string (`300ms`, `-1.5h`, `2h45m`, `10m`).
///
/// Units are `ns`, `us`/`µs`/`μs`, `ms`, `s`, `m`, `h`; there is no `d`.
/// Negative values are accepted, and the result must fit Go's `int64`
/// nanoseconds, exactly as `time.ParseDuration` does.
pub fn parse_duration(input: &str) -> Result<Duration, DurationError> {
    let invalid = || DurationError::Invalid(input.to_owned());
    let mut s = input.as_bytes();
    let mut negative = false;
    if let Some((&sign @ (b'-' | b'+'), rest)) = s.split_first() {
        negative = sign == b'-';
        s = rest;
    }
    if s == b"0" {
        return Ok(Duration::ZERO);
    }
    if s.is_empty() {
        return Err(invalid());
    }

    let mut total: u64 = 0;
    while !s.is_empty() {
        if !(s[0] == b'.' || s[0].is_ascii_digit()) {
            return Err(invalid());
        }

        let before = s.len();
        let (whole, rest) = leading_int(s).ok_or_else(invalid)?;
        s = rest;
        let has_whole = before != s.len();

        let mut fraction = 0;
        let mut scale = 1.0;
        let mut has_fraction = false;
        if let Some((b'.', rest)) = s.split_first() {
            let before = rest.len();
            (fraction, scale, s) = leading_fraction(rest);
            has_fraction = before != s.len();
        }
        if !has_whole && !has_fraction {
            return Err(invalid());
        }

        let unit_len = s
            .iter()
            .position(|&c| c == b'.' || c.is_ascii_digit())
            .unwrap_or(s.len());
        if unit_len == 0 {
            return Err(DurationError::MissingUnit(input.to_owned()));
        }
        let (unit, rest) = s.split_at(unit_len);
        s = rest;
        let Some(&(_, per_unit)) = NANOS_PER_UNIT.iter().find(|(name, _)| *name == unit) else {
            return Err(DurationError::UnknownUnit {
                unit: String::from_utf8_lossy(unit).into_owned(),
                input: input.to_owned(),
            });
        };

        if whole > LIMIT / per_unit {
            return Err(invalid());
        }
        let mut value = whole * per_unit;
        if fraction > 0 {
            // Same float arithmetic as Go so rounding matches.
            let extra = (fraction as f64 * (per_unit as f64 / scale)) as u64;
            value += extra;
            if value > LIMIT {
                return Err(invalid());
            }
        }
        total += value;
        if total > LIMIT {
            return Err(invalid());
        }
    }

    let nanos = if negative {
        -i128::from(total)
    } else if total > LIMIT - 1 {
        return Err(invalid());
    } else {
        i128::from(total)
    };
    Ok(Duration::nanoseconds_i128(nanos))
}

/// Go `leadingInt`: `None` on overflow past 2^63.
fn leading_int(s: &[u8]) -> Option<(u64, &[u8])> {
    let digits = s.iter().take_while(|c| c.is_ascii_digit()).count();
    let mut value: u64 = 0;
    for &c in &s[..digits] {
        if value > LIMIT / 10 {
            return None;
        }
        value = value * 10 + u64::from(c - b'0');
        if value > LIMIT {
            return None;
        }
    }
    Some((value, &s[digits..]))
}

/// Go `leadingFraction`: digits past the representable precision are skipped.
fn leading_fraction(s: &[u8]) -> (u64, f64, &[u8]) {
    let digits = s.iter().take_while(|c| c.is_ascii_digit()).count();
    let mut value: u64 = 0;
    let mut scale = 1.0;
    let mut overflow = false;
    for &c in &s[..digits] {
        if overflow {
            continue;
        }
        if value > (LIMIT - 1) / 10 {
            overflow = true;
            continue;
        }
        let next = value * 10 + u64::from(c - b'0');
        if next > LIMIT {
            overflow = true;
            continue;
        }
        value = next;
        scale *= 10.0;
    }
    (value, scale, &s[digits..])
}

/// `strconv.Atoi` failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("strconv.Atoi: parsing {}: {}", quote(.input), .kind)]
pub struct AtoiError {
    input: String,
    kind: NumErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumErrorKind {
    Syntax,
    Range,
}

impl fmt::Display for NumErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Syntax => "invalid syntax",
            Self::Range => "value out of range",
        })
    }
}

/// Go `strconv.Atoi` on a 64-bit platform: optional sign, ASCII digits only.
pub fn atoi(input: &str) -> Result<i64, AtoiError> {
    input.parse::<i64>().map_err(|error| AtoiError {
        input: input.to_owned(),
        kind: match error.kind() {
            IntErrorKind::PosOverflow | IntErrorKind::NegOverflow => NumErrorKind::Range,
            _ => NumErrorKind::Syntax,
        },
    })
}

/// `strconv.ParseBool` failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("strconv.ParseBool: parsing {}: invalid syntax", quote(.0))]
pub struct ParseBoolError(String);

/// Go `strconv.ParseBool`.
pub fn parse_bool(input: &str) -> Result<bool, ParseBoolError> {
    match input {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(ParseBoolError(input.to_owned())),
    }
}

/// Approximates Go `strconv.Quote` for error messages.
pub(crate) fn quote(value: &str) -> String {
    use fmt::Write as _;

    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if c < ' ' || c == '\u{7f}' => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c if c.is_control() || (c.is_whitespace() && c != ' ') => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: i128 = 1;
    const US: i128 = 1_000;
    const MS: i128 = 1_000_000;
    const SEC: i128 = 1_000_000_000;
    const MIN: i128 = 60 * SEC;
    const HOUR: i128 = 60 * MIN;

    #[test]
    fn parses_like_go() {
        // Cases from Go's time package `parseDurationTests`.
        let cases: &[(&str, i128)] = &[
            ("0", 0),
            ("5s", 5 * SEC),
            ("30s", 30 * SEC),
            ("1478s", 1478 * SEC),
            ("-5s", -5 * SEC),
            ("+5s", 5 * SEC),
            ("-0", 0),
            ("+0", 0),
            ("5.0s", 5 * SEC),
            ("5.6s", 5 * SEC + 600 * MS),
            ("5.s", 5 * SEC),
            (".5s", 500 * MS),
            ("1.0s", SEC),
            ("1.00s", SEC),
            ("1.004s", SEC + 4 * MS),
            ("1.0040s", SEC + 4 * MS),
            ("100.00100s", 100 * SEC + MS),
            ("10ns", 10 * NS),
            ("11us", 11 * US),
            ("12µs", 12 * US),
            ("12μs", 12 * US),
            ("13ms", 13 * MS),
            ("14s", 14 * SEC),
            ("15m", 15 * MIN),
            ("16h", 16 * HOUR),
            ("3h30m", 3 * HOUR + 30 * MIN),
            ("10.5s4m", 4 * MIN + 10 * SEC + 500 * MS),
            ("-2m3.4s", -(2 * MIN + 3 * SEC + 400 * MS)),
            (
                "1h2m3s4ms5us6ns",
                HOUR + 2 * MIN + 3 * SEC + 4 * MS + 5 * US + 6 * NS,
            ),
            ("39h9m14.425s", 39 * HOUR + 9 * MIN + 14 * SEC + 425 * MS),
            ("52763797000ns", 52_763_797_000 * NS),
            ("0.3333333333333333333h", 20 * MIN),
            ("9007199254740993ns", (1 << 53) + 1),
            ("9223372036854775807ns", i128::from(i64::MAX)),
            ("9223372036.854775807s", i128::from(i64::MAX)),
            ("-9223372036854775808ns", i128::from(i64::MIN)),
            ("-9223372036.854775808s", i128::from(i64::MIN)),
            ("0.100000000000000000000h", 6 * MIN),
            (
                "0.830103483285477580700h",
                49 * MIN + 48 * SEC + 372_539_827 * NS,
            ),
            // Values this service uses.
            ("10m", 10 * MIN),
            ("720h", 720 * HOUR),
            ("60s", 60 * SEC),
            ("1h30m", HOUR + 30 * MIN),
            ("500ms", 500 * MS),
        ];
        for (input, want) in cases {
            let got = parse_duration(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(got.whole_nanoseconds(), *want, "{input}");
        }
    }

    #[test]
    fn rejects_like_go() {
        let cases: &[(&str, &str)] = &[
            ("", r#"time: invalid duration """#),
            ("3", r#"time: missing unit in duration "3""#),
            ("-", r#"time: invalid duration "-""#),
            ("s", r#"time: invalid duration "s""#),
            (".", r#"time: invalid duration ".""#),
            ("-.", r#"time: invalid duration "-.""#),
            (".s", r#"time: invalid duration ".s""#),
            ("+.s", r#"time: invalid duration "+.s""#),
            ("1d", r#"time: unknown unit "d" in duration "1d""#),
            ("7d", r#"time: unknown unit "d" in duration "7d""#),
            ("1.1.1s", r#"time: missing unit in duration "1.1.1s""#),
            ("10M", r#"time: unknown unit "M" in duration "10M""#),
            (" 10m", r#"time: invalid duration " 10m""#),
            ("10m ", r#"time: unknown unit "m " in duration "10m ""#),
            (
                "9223372036854775808ns",
                r#"time: invalid duration "9223372036854775808ns""#,
            ),
            (
                "9223372036854775.808us",
                r#"time: invalid duration "9223372036854775.808us""#,
            ),
            (
                "9223372036854ms775us808ns",
                r#"time: invalid duration "9223372036854ms775us808ns""#,
            ),
            (
                "-9223372036854775809ns",
                r#"time: invalid duration "-9223372036854775809ns""#,
            ),
            ("3000000h", r#"time: invalid duration "3000000h""#),
        ];
        for (input, want) in cases {
            let error = parse_duration(input).expect_err(input);
            assert_eq!(error.to_string(), *want, "{input}");
        }
    }

    #[test]
    fn atoi_matches_go() {
        assert_eq!(atoi("6"), Ok(6));
        assert_eq!(atoi("+6"), Ok(6));
        assert_eq!(atoi("-1"), Ok(-1));
        assert_eq!(atoi("007"), Ok(7));
        assert_eq!(
            atoi("six").unwrap_err().to_string(),
            r#"strconv.Atoi: parsing "six": invalid syntax"#
        );
        assert_eq!(
            atoi("1_000").unwrap_err().to_string(),
            r#"strconv.Atoi: parsing "1_000": invalid syntax"#
        );
        assert_eq!(
            atoi("9223372036854775808").unwrap_err().to_string(),
            r#"strconv.Atoi: parsing "9223372036854775808": value out of range"#
        );
        assert!(atoi("").is_err());
        assert!(atoi("-").is_err());
    }

    #[test]
    fn parse_bool_matches_go() {
        for input in ["1", "t", "T", "TRUE", "true", "True"] {
            assert_eq!(parse_bool(input), Ok(true), "{input}");
        }
        for input in ["0", "f", "F", "FALSE", "false", "False"] {
            assert_eq!(parse_bool(input), Ok(false), "{input}");
        }
        for input in ["yes", "on", "tRUE", "", "2"] {
            assert!(parse_bool(input).is_err(), "{input}");
        }
        assert_eq!(
            parse_bool("yes").unwrap_err().to_string(),
            r#"strconv.ParseBool: parsing "yes": invalid syntax"#
        );
    }

    #[test]
    fn quote_escapes_like_go() {
        assert_eq!(quote("a\"b\\c\n\t"), r#""a\"b\\c\n\t""#);
        assert_eq!(quote("\u{1}"), r#""\x01""#);
        assert_eq!(quote("µs"), "\"µs\"");
    }
}
