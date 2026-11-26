//! `observability.go` `StructuredLogger`: one JSON line per request.
//!
//! Keys (sorted, as Go marshals a map): `client_ip`, `error` (only when a
//! handler recorded [`LogErrors`]), `latency_ms`, `method`, `path`,
//! `request_id` (`-` when unset), `status`, `time`. `path` is the decoded
//! path without the query string (Sprint-0 PDPA rule). `time` is the end of
//! the request in UTC, formatted like Go `time.RFC3339Nano`.

use std::{collections::BTreeMap, io::Write, sync::Arc, time::Instant};

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use serde_json::Value;
use time::OffsetDateTime;

use super::{client_ip::client_ip, request_id::RequestId};
use crate::{go_url, json::to_go_json};

/// Error messages a handler attaches to its response for the access log
/// (gin `c.Error(err)`). Rendered like gin's `errorMsgs.String()`, trimmed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogErrors(pub Vec<String>);

impl LogErrors {
    fn render(&self) -> String {
        let mut out = String::new();
        for (i, message) in self.0.iter().enumerate() {
            out.push_str(&format!("Error #{:02}: {message}\n", i + 1));
        }
        out.trim().to_owned()
    }
}

type Sink = dyn Fn(&str) + Send + Sync;

/// Where access-log lines go. Defaults to stdout, like gin's
/// `DefaultWriter`.
#[derive(Clone)]
pub struct AccessLog {
    sink: Arc<Sink>,
}

impl std::fmt::Debug for AccessLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessLog").finish_non_exhaustive()
    }
}

impl Default for AccessLog {
    fn default() -> Self {
        Self::stdout()
    }
}

impl AccessLog {
    /// Writes each line, newline-terminated, to stdout.
    #[must_use]
    pub fn stdout() -> Self {
        Self::new(|line| {
            let mut out = std::io::stdout().lock();
            // A failed log write must not fail the request.
            let _ = writeln!(out, "{line}");
        })
    }

    /// Sends each line (without a trailing newline) to `sink`.
    pub fn new(sink: impl Fn(&str) + Send + Sync + 'static) -> Self {
        Self {
            sink: Arc::new(sink),
        }
    }
}

/// Go `time.RFC3339Nano` for a UTC instant: fractional seconds with trailing
/// zeros trimmed, no fraction when it is zero.
#[must_use]
pub fn format_rfc3339_nano_utc(at: OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    let mut out = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    );
    let nanos = at.nanosecond();
    if nanos != 0 {
        let fraction = format!("{nanos:09}");
        out.push('.');
        out.push_str(fraction.trim_end_matches('0'));
    }
    out.push('Z');
    out
}

/// One finished request, as the access log records it.
#[derive(Debug, Clone)]
pub struct AccessLogEntry<'a> {
    /// End of the request (gin `param.TimeStamp`).
    pub at: OffsetDateTime,
    pub status: u16,
    /// Whole milliseconds, truncated (Go `Duration.Milliseconds`).
    pub latency_ms: i64,
    pub client_ip: &'a str,
    pub method: &'a str,
    /// Decoded path, no query string.
    pub path: &'a str,
    /// Empty renders as `-`.
    pub request_id: &'a str,
    pub errors: Option<&'a LogErrors>,
}

impl AccessLogEntry<'_> {
    /// The JSON log line, without a trailing newline.
    #[must_use]
    pub fn render(&self) -> String {
        let request_id = if self.request_id.is_empty() {
            "-"
        } else {
            self.request_id
        };
        let mut entry: BTreeMap<&str, Value> = BTreeMap::new();
        entry.insert("time", Value::from(format_rfc3339_nano_utc(self.at)));
        entry.insert("status", Value::from(self.status));
        entry.insert("latency_ms", Value::from(self.latency_ms));
        entry.insert("client_ip", Value::from(self.client_ip));
        entry.insert("method", Value::from(self.method));
        entry.insert("path", Value::from(self.path));
        entry.insert("request_id", Value::from(request_id));
        if let Some(errors) = self.errors {
            let rendered = errors.render();
            if !rendered.is_empty() {
                entry.insert("error", Value::from(rendered));
            }
        }
        match to_go_json(&entry) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(_) => {
                format!("{{\"error\":\"logger_marshal_failed\",\"request_id\":\"{request_id}\"}}")
            }
        }
    }
}

/// The access-log middleware.
pub async fn access_log(State(log): State<AccessLog>, request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().as_str().to_owned();
    let raw_path = request.uri().path();
    let path = go_url::unescape_path(raw_path).unwrap_or_else(|_| raw_path.to_owned());
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|id| id.0.clone())
        .unwrap_or_default();
    let ip = client_ip(request.headers(), request.extensions());

    let response = next.run(request).await;

    let latency_ms = i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX);
    let line = AccessLogEntry {
        at: OffsetDateTime::now_utc(),
        status: response.status().as_u16(),
        latency_ms,
        client_ip: &ip,
        method: &method,
        path: &path,
        request_id: &request_id,
        errors: response.extensions().get::<LogErrors>(),
    }
    .render();
    (log.sink)(&line);
    response
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    #[test]
    fn rfc3339_nano_trims_like_go() {
        assert_eq!(
            format_rfc3339_nano_utc(datetime!(2026-11-26 01:02:03.120 UTC)),
            "2026-11-26T01:02:03.12Z"
        );
        assert_eq!(
            format_rfc3339_nano_utc(datetime!(2026-11-26 01:02:03 UTC)),
            "2026-11-26T01:02:03Z"
        );
        assert_eq!(
            format_rfc3339_nano_utc(datetime!(2026-11-26 01:02:03.000000001 +07:00)),
            "2026-11-25T18:02:03.000000001Z"
        );
    }

    #[test]
    fn line_has_sorted_keys_and_gin_error_format() {
        let errors = LogErrors(vec!["boom".into(), "bang".into()]);
        let line = AccessLogEntry {
            at: datetime!(2026-01-02 03:04:05.5 UTC),
            status: 404,
            latency_ms: 12,
            client_ip: "203.0.113.9",
            method: "GET",
            path: "/a<b>",
            request_id: "",
            errors: Some(&errors),
        }
        .render();
        assert_eq!(
            line,
            "{\"client_ip\":\"203.0.113.9\",\"error\":\"Error #01: boom\\nError #02: bang\",\
             \"latency_ms\":12,\"method\":\"GET\",\"path\":\"/a\\u003cb\\u003e\",\
             \"request_id\":\"-\",\"status\":404,\"time\":\"2026-01-02T03:04:05.5Z\"}"
        );
    }
}
