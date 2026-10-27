//! Auth material for authenticated scanning (Max-Parity Sprint 1.1, 1.4).
//!
//! Resolves an auth profile's stored config into concrete HTTP attachment
//! material (cookies / headers / basic-auth), performing a form login when
//! the profile uses the `form` method. Native HTTP scanners apply the
//! material to every request via [`apply_auth`], so a scan runs with the
//! analyst's session instead of hitting login walls.

use crate::events::EventSink;
use secuscan_db::repo;
use serde_json::Value;
use sqlx::SqlitePool;
use std::collections::BTreeMap;
use std::time::Duration;

/// Resolved authentication material attached to every scan request.
#[derive(Debug, Clone, Default)]
pub struct AuthMaterial {
    /// Profile method label (cookie/header/form/recorded) for diagnostics.
    pub method: String,
    /// Session cookies sent as a single Cookie header.
    pub cookies: Vec<(String, String)>,
    /// Extra headers (e.g. Authorization: Bearer …, X-API-Key: …).
    pub headers: Vec<(String, String)>,
}

impl AuthMaterial {
    /// The value for a Cookie header, or None when no cookies.
    pub fn cookie_header(&self) -> Option<String> {
        if self.cookies.is_empty() {
            return None;
        }
        Some(
            self.cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// Apply cookies + headers to a request builder.
    pub fn apply(&self, mut rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(cookie) = self.cookie_header() {
            rb = rb.header(reqwest::header::COOKIE, cookie);
        }
        for (name, value) in &self.headers {
            rb = rb.header(name.as_str(), value.as_str());
        }
        rb
    }
}

/// Apply optional auth material to a request builder (no-op when None).
pub fn apply_auth(auth: Option<&AuthMaterial>, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match auth {
        Some(a) => a.apply(rb),
        None => rb,
    }
}

/// Build a scan client whose every request carries the auth material as
/// default headers (cookies + custom headers). This covers request sites
/// the scanner can't wrap individually — e.g. the DAST engine's probes —
/// and keeps the same-host redirect policy/timeout profile as
/// [`super::http_headers::build_client`].
pub fn authed_client(
    follow: bool,
    timeout: Duration,
    auth: Option<&AuthMaterial>,
) -> Result<reqwest::Client, String> {
    let cb = super::http_headers::client_builder(follow, timeout)?;
    let cb = match auth {
        Some(a) if !a.cookies.is_empty() || !a.headers.is_empty() => {
            let mut hm = reqwest::header::HeaderMap::new();
            if let Some(cookie) = a.cookie_header() {
                if let Ok(v) = reqwest::header::HeaderValue::from_str(&cookie) {
                    hm.insert(reqwest::header::COOKIE, v);
                }
            }
            for (name, value) in &a.headers {
                if let (Ok(n), Ok(v)) = (
                    reqwest::header::HeaderName::from_bytes(name.as_bytes()),
                    reqwest::header::HeaderValue::from_str(value),
                ) {
                    hm.insert(n, v);
                }
            }
            cb.default_headers(hm)
        }
        _ => cb,
    };
    cb.build()
        .map_err(|e| format!("authed client build failed: {e}"))
}

/// Load and resolve the auth material for a task's attached auth profile.
/// Returns Ok(None) when the task has no profile attached.
pub async fn resolve_for_task(
    pool: &SqlitePool,
    auth_profile_id: Option<&str>,
    sink: &EventSink,
) -> Result<Option<AuthMaterial>, String> {
    let Some(profile_id) = auth_profile_id else {
        return Ok(None);
    };
    let profile = repo::auth_profiles::get(pool, profile_id)
        .await
        .map_err(|e| format!("auth profile {profile_id} not loadable: {e}"))?;
    let material = resolve(&profile.method, &profile.config_json, sink).await?;
    if let Some(m) = &material {
        sink.emit(crate::events::TaskEvent::Info(format!(
            "authenticated scan: applying `{}` auth profile `{}` ({} cookie(s), {} header(s))",
            profile.method,
            profile.name,
            m.cookies.len(),
            m.headers.len(),
        )))
        .await;
    }
    Ok(material)
}

/// Parse + resolve a stored config into request material.
pub async fn resolve(
    method: &str,
    config_json: &str,
    sink: &EventSink,
) -> Result<Option<AuthMaterial>, String> {
    let config: Value = serde_json::from_str(config_json)
        .map_err(|e| format!("auth profile config is not valid JSON: {e}"))?;
    match method {
        "cookie" => {
            let cookies = parse_pairs(&config, "cookies");
            if cookies.is_empty() {
                return Err("cookie auth profile has no cookies".into());
            }
            Ok(Some(AuthMaterial { method: method.into(), cookies, headers: Vec::new() }))
        }
        "header" => {
            let headers = parse_pairs(&config, "headers");
            if headers.is_empty() {
                return Err("header auth profile has no headers".into());
            }
            Ok(Some(AuthMaterial { method: method.into(), cookies: Vec::new(), headers }))
        }
        "form" => {
            let login_url = config.get("login_url").and_then(|v| v.as_str()).unwrap_or("");
            let username = config.get("username").and_then(|v| v.as_str()).unwrap_or("");
            let password = config.get("password").and_then(|v| v.as_str()).unwrap_or("");
            if login_url.is_empty() || username.is_empty() {
                return Err("form auth profile missing login_url/username".into());
            }
            form_login(login_url, username, password, sink).await
        }
        "recorded" => Err(
            "recorded (multi-step) auth profiles are not yet supported by the executor; \
             use a cookie or header profile for now"
                .into(),
        ),
        other => Err(format!("unknown auth method `{other}`")),
    }
}

/// [{name, value}] arrays shared by the cookie and header methods.
fn parse_pairs(config: &Value, key: &str) -> Vec<(String, String)> {
    config
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    let name = c.get("name")?.as_str()?.to_string();
                    let value = c.get("value")?.as_str()?.to_string();
                    if name.is_empty() || value.is_empty() {
                        None
                    } else {
                        Some((name, value))
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Perform a form login and harvest the session cookies it sets.
async fn form_login(
    login_url: &str,
    username: &str,
    password: &str,
    sink: &EventSink,
) -> Result<Option<AuthMaterial>, String> {
    let client = super::http_headers::build_client(true, Duration::from_secs(15))
        .map_err(|e| format!("build login client: {e}"))?;
    let form: BTreeMap<&str, &str> = BTreeMap::from([
        ("username", username),
        ("password", password),
    ]);
    let resp = client
        .post(login_url)
        .header("user-agent", "SecuScan-2.0 (auth)")
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("login request to {login_url} failed: {e}"))?;
    let status = resp.status().as_u16();
    // Harvest Set-Cookie pairs from the response (and any redirects the
    // client followed).
    let mut cookies: Vec<(String, String)> = Vec::new();
    for sc in resp.headers().get_all(reqwest::header::SET_COOKIE) {
        if let Ok(line) = sc.to_str() {
            if let Some(pair) = line.split(';').next() {
                if let Some((name, value)) = pair.split_once('=') {
                    let (name, value) = (name.trim().to_string(), value.trim().to_string());
                    if !name.is_empty() && !value.is_empty() {
                        cookies.retain(|(n, _)| n != &name);
                        cookies.push((name, value));
                    }
                }
            }
        }
    }
    if cookies.is_empty() {
        return Err(format!(
            "form login to {login_url} returned HTTP {status} but set no cookies — \
             credentials rejected or login flow changed",
        ));
    }
    sink.emit(crate::events::TaskEvent::Info(format!(
        "form login to {login_url} succeeded (HTTP {status}, {} session cookie(s))",
        cookies.len(),
    )))
    .await;
    Ok(Some(AuthMaterial { method: "form".into(), cookies, headers: Vec::new() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_header_joins_pairs() {
        let a = AuthMaterial {
            method: "cookie".into(),
            cookies: vec![("session".into(), "abc".into()), ("lang".into(), "en".into())],
            headers: vec![],
        };
        assert_eq!(a.cookie_header().unwrap(), "session=abc; lang=en");
    }

    #[test]
    fn no_cookie_header_when_empty() {
        assert!(AuthMaterial::default().cookie_header().is_none());
    }

    #[test]
    fn parse_cookie_config() {
        let config = r#"{"cookies": [{"name": "sid", "value": "42"}, {"name": "", "value": "x"}]}"#;
        // resolve() for cookie is sync-ish but async fn; test parse_pairs directly.
        let v: Value = serde_json::from_str(config).unwrap();
        let pairs = parse_pairs(&v, "cookies");
        assert_eq!(pairs, vec![("sid".to_string(), "42".to_string())]);
    }

    #[test]
    fn parse_header_config_skips_empty_values() {
        let config = r#"{"headers": [{"name": "Authorization", "value": "Bearer tok"}, {"name": "X-Empty", "value": ""}]}"#;
        let v: Value = serde_json::from_str(config).unwrap();
        let pairs = parse_pairs(&v, "headers");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "Authorization");
    }

    #[tokio::test]
    async fn unknown_method_rejected() {
        let sink = crate::events::EventSink::new(uuid::Uuid::new_v4(), tokio::sync::mpsc::channel(16).0);
        assert!(resolve("bogus", "{}", &sink).await.is_err());
    }

    #[tokio::test]
    async fn recorded_method_not_yet_supported() {
        let sink = crate::events::EventSink::new(uuid::Uuid::new_v4(), tokio::sync::mpsc::channel(16).0);
        let err = resolve("recorded", r#"{"steps": []}"#, &sink).await.unwrap_err();
        assert!(err.contains("not yet supported"), "{err}");
    }

    #[tokio::test]
    async fn cookie_method_parses() {
        let sink = crate::events::EventSink::new(uuid::Uuid::new_v4(), tokio::sync::mpsc::channel(16).0);
        let m = resolve(
            "cookie",
            r#"{"cookies": [{"name": "sid", "value": "42"}]}"#,
            &sink,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(m.cookies, vec![("sid".to_string(), "42".to_string())]);
        assert_eq!(m.cookie_header().unwrap(), "sid=42");
    }

    #[tokio::test]
    async fn header_method_parses() {
        let sink = crate::events::EventSink::new(uuid::Uuid::new_v4(), tokio::sync::mpsc::channel(16).0);
        let m = resolve(
            "header",
            r#"{"headers": [{"name": "X-API-Key", "value": "k-123"}]}"#,
            &sink,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(m.headers, vec![("X-API-Key".to_string(), "k-123".to_string())]);
    }
}
