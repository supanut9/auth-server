//! Shared helpers for golden-vector tests (`testdata/golden`, AUTH-027).
//! The vector files and the TEST-ONLY key are read-only inputs.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use auth_core::ports::Clock;
use serde_json::Value;
use time::OffsetDateTime;

pub fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/golden")
}

/// Parses `testdata/golden/<name>`.
pub fn load(name: &str) -> Value {
    let raw = read_text(name);
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// Reads a file under `testdata/golden` (e.g. `keys/...pem`).
pub fn read_text(relative: &str) -> String {
    let path = golden_dir().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

pub fn sections(doc: &Value) -> BTreeSet<String> {
    doc.as_object().expect("object").keys().cloned().collect()
}

pub fn cases<'a>(doc: &'a Value, section: &str) -> &'a [Value] {
    doc[section]["cases"]
        .as_array()
        .unwrap_or_else(|| panic!("{section}.cases"))
}

pub fn s<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("string field {key} in {value}"))
}

pub fn i(value: &Value, key: &str) -> i64 {
    value[key]
        .as_i64()
        .unwrap_or_else(|| panic!("integer field {key} in {value}"))
}

pub struct FixedClock(pub OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

pub fn unix(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(seconds).expect("unix time")
}
