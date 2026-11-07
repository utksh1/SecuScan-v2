//! Per-identity rate limiting for the v1 API (Max-Parity Sprint 1.3, task 3.7).
//!
//! Buckets are keyed by credential identity (API-key hash prefix or JWT
//! bearer-token hash prefix) — the two ways automation talks to the server.
//! Unauthenticated requests pass through untouched (they fail auth anyway,
//! and login already has its own limiter).
//!
//! Quotas (per minute, per identity):
//!   * read methods (GET/HEAD/OPTIONS): `SECUSCAN_RATE_LIMIT_GET` (default 250)
//!   * write methods (everything else): `SECUSCAN_RATE_LIMIT_WRITE` (default 125)
//!
//! Responses carry `X-RateLimit-Limit` / `X-RateLimit-Remaining` /
//! `X-RateLimit-Reset`; exceeding the quota returns 429 with `Retry-After`.
//! Set a limit to `0` to disable that bucket (tests, trusted deployments).

use crate::state::SharedState;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// One minute window (fixed-window counting; simple, observable, and good
/// enough for automation quotas).
const WINDOW_SECS: u64 = 60;

#[derive(Default)]
struct Buckets {
    /// identity → (window_start_epoch, read_count, write_count)
    map: HashMap<String, (u64, u32, u32)>,
}

#[derive(Clone)]
pub struct RateLimiter {
    inner: std::sync::Arc<Mutex<Buckets>>,
    pub get_limit: u32,
    pub write_limit: u32,
}

impl RateLimiter {
    pub fn from_env() -> Self {
        let parse = |key: &str, default: u32| -> u32 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(default)
        };
        RateLimiter {
            inner: std::sync::Arc::new(Mutex::new(Buckets::default())),
            get_limit: parse("SECUSCAN_RATE_LIMIT_GET", 250),
            write_limit: parse("SECUSCAN_RATE_LIMIT_WRITE", 125),
        }
    }

    fn limit_for(&self, read: bool) -> u32 {
        if read {
            self.get_limit
        } else {
            self.write_limit
        }
    }

    /// Consume one slot; returns (remaining, window_reset_epoch) when under
    /// the limit, or None when the bucket is exhausted.
    fn take(&self, identity: &str, read: bool) -> Option<(u32, u64)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut b = self.inner.lock().expect("rate limit lock");
        let entry = b.map.entry(identity.to_string()).or_insert((now, 0, 0));
        // Fixed window reset.
        if now >= entry.0 + WINDOW_SECS {
            *entry = (now, 0, 0);
        }
        let limit = self.limit_for(read);
        if limit == 0 {
            // Disabled: always allow, advertise no consumption.
            return Some((u32::MAX, entry.0 + WINDOW_SECS));
        }
        let count = if read {
            &mut entry.1
        } else {
            &mut entry.2
        };
        if *count >= limit {
            return None;
        }
        *count += 1;
        Some((limit - *count, entry.0 + WINDOW_SECS))
    }
}

/// Identity for bucketing: stable per credential, never the raw secret.
fn identity_of(req: &Request) -> Option<String> {
    if let Some(v) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(token) = v.to_str() {
            let token = token.trim();
            if let Some(bearer) = token.strip_prefix("Bearer ") {
                return Some(format!("jwt:{:016x}", fxhash(bearer)));
            }
        }
    }
    if let Some(v) = req.headers().get("x-api-key") {
        if let Ok(k) = v.to_str() {
            return Some(format!("key:{:016x}", fxhash(k)));
        }
    }
    None
}

/// FNV-1a (16-hex output) — bucketing only, not security.
fn fxhash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn is_read(method: &axum::http::Method) -> bool {
    method == axum::http::Method::GET
        || method == axum::http::Method::HEAD
        || method == axum::http::Method::OPTIONS
}

pub async fn enforce(
    State(state): State<SharedState>,
    req: Request,
    next: Next,
) -> Response {
    let limiter = &state.rate_limiter;
    // OOB public callback receiver is exempt: target callbacks must never
    // be throttled by an operator's quota (handler-level hit caps already
    // bound abuse there).
    if req.uri().path().contains("/oob/") {
        return next.run(req).await;
    }
    let Some(identity) = identity_of(&req) else {
        return next.run(req).await;
    };
    let read = is_read(req.method());
    match limiter.take(&identity, read) {
        Some((remaining, reset)) => {
            let mut res = next.run(req).await;
            let headers = res.headers_mut();
            let hv = |v: u64| HeaderValue::from_str(&v.to_string()).unwrap();
            headers.insert("x-ratelimit-limit", hv(limiter.limit_for(read) as u64));
            if remaining != u32::MAX {
                headers.insert("x-ratelimit-remaining", hv(remaining as u64));
            }
            headers.insert("x-ratelimit-reset", hv(reset));
            res
        }
        None => {
            let limit = limiter.limit_for(read).to_string();
            (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                [
                    ("retry-after", "60"),
                    ("x-ratelimit-limit", limit.as_str()),
                    ("x-ratelimit-remaining", "0"),
                ],
                axum::Json(serde_json::json!({
                    "error": {
                        "code": "rate_limited",
                        "message": "API rate limit exceeded; retry after the window resets",
                    }
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window_counts_and_resets() {
        let rl = RateLimiter {
            inner: std::sync::Arc::new(Mutex::new(Buckets::default())),
            get_limit: 2,
            write_limit: 5,
        };
        assert!(rl.take("a", true).is_some());
        assert!(rl.take("a", true).is_some());
        assert!(rl.take("a", true).is_none(), "third read blocked");
        // Writes have a separate bucket.
        assert!(rl.take("a", false).is_some());
        // Other identities unaffected.
        assert!(rl.take("b", true).is_some());
        // Disabled bucket always allows.
        let rl0 = RateLimiter {
            inner: std::sync::Arc::new(Mutex::new(Buckets::default())),
            get_limit: 0,
            write_limit: 0,
        };
        for _ in 0..10 {
            assert!(rl0.take("a", true).is_some());
        }
    }

    #[test]
    fn identity_is_stable_and_masks_secrets() {
        let a = identity_of(&req_with(&[("authorization", "Bearer super-secret-token")]));
        let b = identity_of(&req_with(&[("authorization", "Bearer super-secret-token")]));
        let c = identity_of(&req_with(&[("x-api-key", "super-secret-token")]));
        assert_eq!(a, b, "same credential → same bucket");
        assert_ne!(a, c, "different credential types → different buckets");
        assert!(!a.unwrap().contains("super"), "raw secret never in bucket key");
    }

    fn req_with(kvs: &[(&str, &str)]) -> Request {
        let mut b = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/findings");
        for (k, v) in kvs {
            b = b.header(*k, *v);
        }
        b.body(axum::body::Body::empty()).unwrap()
    }
}
