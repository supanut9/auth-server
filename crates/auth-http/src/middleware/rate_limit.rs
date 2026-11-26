//! `ratelimit.go`: in-memory sliding-window log limiter and the OTP
//! middleware built on it.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::Response,
};
use serde_json::json;

use super::client_ip::client_ip;
use crate::{json::json_response, routing::FullPath};

/// OTP limit window (`time.Minute`).
pub const OTP_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
/// OTP hits allowed per key per window.
pub const OTP_RATE_LIMIT: usize = 20;

/// Sliding-window log limiter for one process (Go `RateLimiter`).
///
/// A request is allowed iff fewer than `limit` earlier allowed requests for
/// the key fall within `window` (entries exactly at the cutoff still count).
/// Rejected requests are not recorded.
#[derive(Debug)]
pub struct RateLimiter {
    window: Duration,
    limit: usize,
    requests: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    #[must_use]
    pub fn new(window: Duration, limit: usize) -> Self {
        Self {
            window,
            limit,
            requests: Mutex::new(HashMap::new()),
        }
    }

    /// 20 requests per 60 seconds (`RegisterRoutes` `otpLimiter`).
    #[must_use]
    pub fn otp() -> Self {
        Self::new(OTP_RATE_LIMIT_WINDOW, OTP_RATE_LIMIT)
    }

    /// `Ok(())` when allowed (and recorded); otherwise `Err(retry_after)`,
    /// the time until the oldest entry in the window expires.
    pub fn allow(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let mut requests = self.requests.lock().unwrap_or_else(PoisonError::into_inner);
        let hits = requests.entry(key.to_owned()).or_default();
        drop_expired(hits, now.checked_sub(self.window));
        if hits.len() >= self.limit {
            let oldest = hits.front().copied().unwrap_or(now);
            return Err((oldest + self.window).saturating_duration_since(now));
        }
        hits.push_back(now);
        Ok(())
    }

    /// Drops expired entries and keys left empty.
    pub fn prune(&self, now: Instant) {
        let cutoff = now.checked_sub(self.window);
        let mut requests = self.requests.lock().unwrap_or_else(PoisonError::into_inner);
        requests.retain(|_, hits| {
            drop_expired(hits, cutoff);
            !hits.is_empty()
        });
    }

    #[cfg(test)]
    fn has_key(&self, key: &str) -> bool {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(key)
    }
}

/// Go `hits[idx].Before(cutoff)`: strictly older entries expire. With no
/// representable cutoff (process younger than the window) nothing expires.
fn drop_expired(hits: &mut VecDeque<Instant>, cutoff: Option<Instant>) {
    let Some(cutoff) = cutoff else { return };
    while hits.front().is_some_and(|&hit| hit < cutoff) {
        hits.pop_front();
    }
}

/// `Retry-After` seconds: Go `int(retryAfter.Seconds())` (truncated), at
/// least 1.
#[must_use]
pub fn retry_after_seconds(retry_after: Duration) -> i64 {
    // Mirrors Go's float conversion: Seconds() then int() truncation.
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    let seconds =
        (retry_after.as_secs() as f64 + f64::from(retry_after.subsec_nanos()) / 1e9) as i64;
    seconds.max(1)
}

/// `otp:` + route full path + `:` + client IP (`otpRateLimitKey`).
#[must_use]
pub fn otp_rate_limit_key(full_path: &str, client_ip: &str) -> String {
    format!("otp:{full_path}:{client_ip}")
}

/// `OTPRateLimitMiddleware`, for `MethodRouter::route_layer(
/// axum::middleware::from_fn_with_state(limiter, otp_rate_limit))`.
///
/// The full path comes from the [`FullPath`] extension that
/// [`crate::routing::GinRouter`] sets (empty if absent).
pub async fn otp_rate_limit(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    let full_path = request
        .extensions()
        .get::<FullPath>()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_default();
    let key = otp_rate_limit_key(
        &full_path,
        &client_ip(request.headers(), request.extensions()),
    );
    match limiter.allow(&key, Instant::now()) {
        Ok(()) => next.run(request).await,
        Err(retry_after) => {
            let mut response = json_response(
                StatusCode::TOO_MANY_REQUESTS,
                &json!({
                    "error": "rate_limited",
                    "error_description": "too many requests; try again in a moment",
                }),
            );
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from(retry_after_seconds(retry_after)),
            );
            response
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Port of ratelimit_test.go.

    #[test]
    fn allows_up_to_limit() {
        let limiter = RateLimiter::new(Duration::from_secs(60), 3);
        let now = Instant::now();
        for i in 0..3 {
            assert!(
                limiter.allow("k", now).is_ok(),
                "request {} should be allowed",
                i + 1
            );
        }
        let retry = limiter
            .allow("k", now)
            .expect_err("4th request should be blocked");
        assert!(
            retry > Duration::ZERO && retry <= Duration::from_secs(60),
            "{retry:?}"
        );
    }

    #[test]
    fn window_slides() {
        let limiter = RateLimiter::new(Duration::from_millis(100), 2);
        let now = Instant::now();
        let _ = limiter.allow("k", now);
        let _ = limiter.allow("k", now);
        assert!(limiter.allow("k", now + Duration::from_millis(150)).is_ok());
    }

    #[test]
    fn keys_are_isolated() {
        let limiter = RateLimiter::new(Duration::from_secs(60), 1);
        let now = Instant::now();
        assert!(limiter.allow("a", now).is_ok());
        assert!(limiter.allow("b", now).is_ok());
        assert!(limiter.allow("a", now).is_err());
    }

    #[test]
    fn prune_drops_expired_keys() {
        let limiter = RateLimiter::new(Duration::from_millis(50), 5);
        let now = Instant::now();
        let _ = limiter.allow("k", now);
        limiter.prune(now + Duration::from_secs(1));
        assert!(!limiter.has_key("k"));
    }

    // Beyond the Go tests.

    #[test]
    fn entry_exactly_at_cutoff_still_counts() {
        let window = Duration::from_secs(60);
        let limiter = RateLimiter::new(window, 1);
        let start = Instant::now();
        assert!(limiter.allow("k", start).is_ok());
        assert_eq!(limiter.allow("k", start + window), Err(Duration::ZERO));
        assert!(
            limiter
                .allow("k", start + window + Duration::from_nanos(1))
                .is_ok()
        );
    }

    #[test]
    fn rejected_requests_are_not_recorded() {
        let limiter = RateLimiter::new(Duration::from_secs(60), 1);
        let start = Instant::now();
        assert!(limiter.allow("k", start).is_ok());
        for offset in 1..10 {
            assert!(
                limiter
                    .allow("k", start + Duration::from_secs(offset))
                    .is_err()
            );
        }
        assert!(limiter.allow("k", start + Duration::from_secs(61)).is_ok());
    }

    #[test]
    fn retry_after_truncates_with_floor_of_one() {
        assert_eq!(retry_after_seconds(Duration::ZERO), 1);
        assert_eq!(retry_after_seconds(Duration::from_millis(999)), 1);
        assert_eq!(retry_after_seconds(Duration::from_millis(1_999)), 1);
        assert_eq!(retry_after_seconds(Duration::from_millis(59_999)), 59);
        assert_eq!(retry_after_seconds(Duration::from_secs(60)), 60);
    }
}
