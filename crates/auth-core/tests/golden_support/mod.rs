//! Shared helpers for golden-vector tests (`testdata/golden`, AUTH-027).
//! The vector files are read-only inputs produced by the Go service.
#![allow(dead_code)]

use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use auth_core::ports::{Clock, JtiStore, JtiStoreError, RandomError, RandomSource};
use serde_json::Value;
use time::OffsetDateTime;

pub fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/golden")
}

/// Parses `testdata/golden/<name>`.
pub fn load(name: &str) -> Value {
    let path = golden_dir().join(name);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

/// Section names of a vector file.
pub fn sections(doc: &Value) -> BTreeSet<String> {
    doc.as_object().expect("object").keys().cloned().collect()
}

/// `doc[section].cases`.
pub fn cases<'a>(doc: &'a Value, section: &str) -> &'a [Value] {
    doc[section]["cases"]
        .as_array()
        .unwrap_or_else(|| panic!("{section}.cases"))
}

/// A required string field.
pub fn s<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("string field {key} in {value}"))
}

/// An optional string field (`""` when absent).
pub fn opt<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("")
}

pub fn i(value: &Value, key: &str) -> i64 {
    value[key]
        .as_i64()
        .unwrap_or_else(|| panic!("integer field {key} in {value}"))
}

pub fn unix(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(seconds).expect("unix time")
}

/// Hands out pre-recorded random bytes in order.
#[derive(Default)]
pub struct ScriptedRandom(Mutex<VecDeque<u8>>);

impl ScriptedRandom {
    pub fn new(bytes: impl IntoIterator<Item = u8>) -> Self {
        Self(Mutex::new(bytes.into_iter().collect()))
    }

    pub fn from_hex(raw_hex: &str) -> Self {
        Self::new(hex::decode(raw_hex).expect("raw_hex"))
    }
}

impl RandomSource for ScriptedRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        let mut bytes = self.0.lock().expect("lock");
        if bytes.len() < dest.len() {
            return Err(RandomError::new("scripted random exhausted"));
        }
        for byte in dest.iter_mut() {
            *byte = bytes.pop_front().expect("byte");
        }
        Ok(())
    }
}

pub struct FixedClock(pub OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// Go `MemoryJTIStore`.
#[derive(Default)]
pub struct MemoryJtiStore(Mutex<BTreeSet<String>>);

#[async_trait]
impl JtiStore for MemoryJtiStore {
    async fn insert(&self, jti: &str, _expires_at: OffsetDateTime) -> Result<(), JtiStoreError> {
        if self.0.lock().expect("lock").insert(jti.to_owned()) {
            Ok(())
        } else {
            Err(JtiStoreError::Replay)
        }
    }
}
