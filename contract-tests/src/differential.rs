//! Record normalized observations of one scripted run per server and diff
//! them. Each difference must match an allowlist entry or the run fails.

use std::{collections::BTreeMap, fmt::Write as _};

use reqwest::RequestBuilder;
use serde_json::{Map, Value, json};

use crate::{dual::Reply, normalize::Normalizer};

/// Headers whose values are transport detail rather than contract.
const IGNORED_HEADERS: &[&str] = &[
    "date",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
];

/// The 30-day SSO cookie lifetime is computed from `expires_at - now`, so it
/// can be a few seconds short of 2 592 000 depending on request timing.
const SSO_MAX_AGE: std::ops::RangeInclusive<i64> = 2_591_990..=2_592_000;

pub struct Recorder {
    pub target: &'static str,
    pub normalizer: Normalizer,
    pub steps: Vec<(String, Value)>,
}

impl Recorder {
    pub fn new(target: &'static str) -> Self {
        Self {
            target,
            normalizer: Normalizer::default(),
            steps: Vec::new(),
        }
    }

    /// Send, record the normalized reply under `label`, return the raw reply.
    pub async fn step(&mut self, label: &str, request: RequestBuilder) -> Reply {
        self.step_with_request_id(label, request, None).await
    }

    pub async fn step_with_request_id(
        &mut self,
        label: &str,
        mut request: RequestBuilder,
        request_id: Option<&str>,
    ) -> Reply {
        if let Some(id) = request_id {
            request = request.header("X-Request-Id", id);
        }
        self.normalizer.sent_request_id = request_id.map(str::to_owned);
        let reply = Reply::send(request).await;
        let observation = self.observe(&reply);
        self.normalizer.sent_request_id = None;
        self.record(label, observation);
        reply
    }

    /// Record a derived observation (e.g. raw bytes equality, a checked fact).
    pub fn note(&mut self, label: &str, value: Value) {
        self.record(label, value);
    }

    fn record(&mut self, label: &str, value: Value) {
        assert!(
            self.steps.iter().all(|(existing, _)| existing != label),
            "duplicate step label {label}"
        );
        self.steps.push((label.into(), value));
    }

    pub fn observe(&mut self, reply: &Reply) -> Value {
        let mut headers = BTreeMap::<String, Value>::new();
        for name in reply.headers.keys() {
            let name = name.as_str();
            if IGNORED_HEADERS.contains(&name) || headers.contains_key(name) {
                continue;
            }
            let values: Vec<&str> = reply
                .headers
                .get_all(name)
                .iter()
                .map(|value| value.to_str().unwrap_or("<non-ascii>"))
                .collect();
            let value = match name {
                "set-cookie" => Value::Array(values.iter().map(|raw| self.cookie(raw)).collect()),
                "location" => Value::String(self.normalizer.url(values[0])),
                "x-request-id" => Value::String(self.normalizer.request_id(values[0])),
                "retry-after" => match values[0].parse::<u64>() {
                    Ok(1..=60) => Value::String("<1..=60 seconds>".into()),
                    _ => Value::String(values[0].into()),
                },
                _ => Value::String(values.join(", ")),
            };
            headers.insert(name.into(), value);
        }
        let content_type = reply.header("content-type").unwrap_or_default();
        let body = if reply.body.is_empty() {
            Value::String(String::new())
        } else if content_type.starts_with("application/json") {
            serde_json::from_slice::<Value>(&reply.body).map_or_else(
                |_| Value::String(reply.text()),
                |parsed| self.normalizer.json(&parsed),
            )
        } else {
            Value::String(self.redirect_body(&reply.text()))
        };
        json!({"status": reply.status, "headers": headers, "body": body})
    }

    /// net/http's redirect body (`<a href="URL">Found</a>.`) embeds the
    /// HTML-escaped Location; normalize that URL like the header.
    fn redirect_body(&mut self, text: &str) -> String {
        let Some(rest) = text.strip_prefix("<a href=\"") else {
            return text.into();
        };
        let Some((href, tail)) = rest.split_once('"') else {
            return text.into();
        };
        let url = self.normalizer.url(&href.replace("&amp;", "&"));
        format!("<a href=\"{}\"{tail}", url.replace('&', "&amp;"))
    }

    fn cookie(&mut self, raw: &str) -> Value {
        let (name, value, attrs) = crate::dual::parse_set_cookie(raw);
        let attrs: Map<String, Value> = attrs
            .into_iter()
            .map(|(key, value)| {
                let value = match (key.as_str(), value.parse::<i64>()) {
                    ("max-age", Ok(age)) if SSO_MAX_AGE.contains(&age) => "<~30 days>".into(),
                    _ => value,
                };
                (key, Value::String(value))
            })
            .collect();
        let value = self.normalizer.string(&name, &value, false);
        json!({"name": name, "value": value, "attributes": attrs})
    }
}

#[derive(Debug)]
pub struct Difference {
    pub step: String,
    pub path: String,
    pub go: Option<Value>,
    pub rust: Option<Value>,
}

impl Difference {
    pub fn go_str(&self) -> &str {
        self.go.as_ref().and_then(Value::as_str).unwrap_or_default()
    }

    pub fn rust_str(&self) -> &str {
        self.rust
            .as_ref()
            .and_then(Value::as_str)
            .unwrap_or_default()
    }
}

/// One accepted deviation. `plan` names the port plan's accepted-deviation
/// bullet (§3) the entry maps to; `matches` sees the difference plus both
/// full step observations.
pub struct Allowed {
    pub id: &'static str,
    pub plan: &'static str,
    pub why: &'static str,
    pub matches: fn(&Difference, &Value, &Value) -> bool,
}

pub fn diff_runs(go: &Recorder, rust: &Recorder) -> Vec<(Difference, Value, Value)> {
    let mut out = Vec::new();
    let rust_steps: BTreeMap<_, _> = rust.steps.iter().cloned().collect();
    let go_labels: Vec<_> = go.steps.iter().map(|(label, _)| label).collect();
    for (label, go_value) in &go.steps {
        match rust_steps.get(label) {
            Some(rust_value) => {
                let mut found = Vec::new();
                diff_values("", go_value, rust_value, &mut found);
                out.extend(found.into_iter().map(|(path, go, rust)| {
                    (
                        Difference {
                            step: label.clone(),
                            path,
                            go,
                            rust,
                        },
                        go_value.clone(),
                        rust_value.clone(),
                    )
                }));
            }
            None => out.push((
                Difference {
                    step: label.clone(),
                    path: "<step>".into(),
                    go: Some(go_value.clone()),
                    rust: None,
                },
                go_value.clone(),
                Value::Null,
            )),
        }
    }
    for (label, rust_value) in &rust.steps {
        if !go_labels.contains(&label) {
            out.push((
                Difference {
                    step: label.clone(),
                    path: "<step>".into(),
                    go: None,
                    rust: Some(rust_value.clone()),
                },
                Value::Null,
                rust_value.clone(),
            ));
        }
    }
    out
}

type Found = Vec<(String, Option<Value>, Option<Value>)>;

fn diff_values(path: &str, go: &Value, rust: &Value, out: &mut Found) {
    match (go, rust) {
        (Value::Object(left), Value::Object(right)) => {
            let keys: std::collections::BTreeSet<_> = left.keys().chain(right.keys()).collect();
            for key in keys {
                let child = format!("{path}.{key}");
                match (left.get(key), right.get(key)) {
                    (Some(a), Some(b)) => diff_values(&child, a, b, out),
                    (a, b) => out.push((child, a.cloned(), b.cloned())),
                }
            }
        }
        (Value::Array(left), Value::Array(right)) if left.len() == right.len() => {
            for (index, (a, b)) in left.iter().zip(right).enumerate() {
                diff_values(&format!("{path}[{index}]"), a, b, out);
            }
        }
        _ if go != rust => out.push((path.into(), Some(go.clone()), Some(rust.clone()))),
        _ => {}
    }
}

/// Classify every difference and render a report. Returns (report, failures).
pub fn report(
    go: &Recorder,
    rust: &Recorder,
    allowlist: &[Allowed],
) -> (String, usize, BTreeMap<&'static str, usize>) {
    let differences = diff_runs(go, rust);
    let mut text = String::new();
    let mut failures = 0;
    let mut hits = BTreeMap::<&'static str, usize>::new();
    let mut current = String::new();
    for (difference, go_step, rust_step) in &differences {
        if difference.step != current {
            current.clone_from(&difference.step);
            let _ = writeln!(text, "\n[{}]", difference.step);
        }
        let verdict = allowlist
            .iter()
            .find(|entry| (entry.matches)(difference, go_step, rust_step));
        let tag = match verdict {
            Some(entry) => {
                *hits.entry(entry.id).or_default() += 1;
                format!("allowed:{}", entry.id)
            }
            None => {
                failures += 1;
                "UNEXPECTED".into()
            }
        };
        let _ = writeln!(
            text,
            "  {tag:<34} {}\n      go:   {}\n      rust: {}",
            difference.path,
            render(difference.go.as_ref()),
            render(difference.rust.as_ref()),
        );
    }
    let _ = writeln!(
        text,
        "\nCompared {} steps: {} differences, {} allowlisted, {failures} unexpected.",
        go.steps.len(),
        differences.len(),
        differences.len() - failures,
    );
    let _ = writeln!(text, "\nAllowlist:");
    for entry in allowlist {
        let _ = writeln!(
            text,
            "  {:<34} hits={:<3} plan: {}\n      {}",
            entry.id,
            hits.get(entry.id).copied().unwrap_or_default(),
            entry.plan,
            entry.why,
        );
    }
    (text, failures, hits)
}

fn render(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return "<absent>".into();
    };
    let text = value.to_string();
    if text.chars().count() > 400 {
        format!("{}…", text.chars().take(400).collect::<String>())
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(target: &'static str, steps: &[(&str, Value)]) -> Recorder {
        let mut recorder = Recorder::new(target);
        for (label, value) in steps {
            recorder.note(label, value.clone());
        }
        recorder
    }

    const ALLOW_DESCRIPTION: &[Allowed] = &[Allowed {
        id: "description-text",
        plan: "test",
        why: "test",
        matches: |d, _, _| d.path == ".body.error_description",
    }];

    #[test]
    fn unexpected_differences_fail_and_allowed_ones_are_counted() {
        let go = run(
            "go",
            &[
                ("same", json!({"status": 200, "body": {"a": 1}})),
                (
                    "text",
                    json!({"status": 400, "body": {"error": "x", "error_description": "Key: 'A'"}}),
                ),
                ("status", json!({"status": 200, "body": {}})),
                ("go only", json!({})),
            ],
        );
        let rust = run(
            "rust",
            &[
                ("same", json!({"status": 200, "body": {"a": 1}})),
                (
                    "text",
                    json!({"status": 400, "body": {"error": "x", "error_description": "a is required"}}),
                ),
                ("status", json!({"status": 201, "body": {"extra": true}})),
                ("rust only", json!({})),
            ],
        );
        let (text, failures, hits) = report(&go, &rust, ALLOW_DESCRIPTION);
        // status + extra key + go-only step + rust-only step.
        assert_eq!(failures, 4, "{text}");
        assert_eq!(hits.get("description-text"), Some(&1));
        assert!(text.contains("UNEXPECTED") && text.contains(".status"));
    }

    #[test]
    fn normalizer_aliases_consistently_and_keeps_query_encoding() {
        let mut normalizer = Normalizer::default();
        let id = "01900000-0000-7000-8000-000000000123";
        let code = "A".repeat(43);
        let body = json!({"account": {"id": id}, "sub": id, "other": "01900000-0000-7000-8000-000000000999"});
        assert_eq!(
            normalizer.json(&body),
            json!({"account": {"id": "<uuid-v7#1>"}, "sub": "<uuid-v7#1>", "other": "<uuid-v7#2>"})
        );
        assert_eq!(
            normalizer.url(&format!(
                "http://cb.test/x?code={code}&keep=a+b&state=s%2A#f"
            )),
            "http://cb.test/x?code=<opaque#1>&keep=a+b&state=s%2A#f"
        );
    }
}
