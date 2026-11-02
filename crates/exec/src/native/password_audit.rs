//! Native password auditor: tests a small set of common default credentials
//! against HTTP Basic authentication on a URL.
//!
//! Fields (see `plugins/password-audit.toml`):
//! - `target` (string, required) — URL protected by Basic auth
//! - `wordlist` (string, optional) — path to `user:pass` pairs
//!   (defaults to the embedded top-30 default-credential list)
//! - `timeout_ms` (integer, default 8000)
//!
//! Safety: intrusive — it sends authentication attempts. The default list is
//! intentionally tiny (default/never-changed credentials only), requests are
//! rate-limited by the plugin's max_per_hour.

use super::http_headers::build_client;
use super::{get_i64_or, get_str_or, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

const DEFAULT_PAIRS: &str = include_str!("default_creds.txt");

pub struct PasswordAuditScanner;

#[async_trait]
impl NativeScanner for PasswordAuditScanner {
    fn id(&self) -> &'static str {
        "password_audit"
    }

    fn name(&self) -> &'static str {
        "Password Auditor (HTTP Basic)"
    }

    fn description(&self) -> &'static str {
        "Test HTTP Basic authentication on a URL against a short list of \
         default/never-changed credentials (admin:admin, root:toor, …). \
         Reports any pair that authenticates successfully."
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let target = super::http_headers::normalize_url(get_str_or(inputs, "target", ""))?;
        let timeout = Duration::from_millis(
            get_i64_or(inputs, "timeout_ms", 8_000).clamp(500, 30_000) as u64,
        );
        let pairs = load_pairs(get_str_or(inputs, "wordlist", ""))?;
        let protocol = get_str_or(inputs, "protocol", "http-basic");

        let client = build_client(false, timeout)?;

        if protocol == "http-form" {
            return run_form(&client, &target, inputs, &pairs, ctx).await;
        }

        // Sanity: is the target actually Basic-auth protected? If the first
        // request returns 200 with no WWW-Authenticate, the audit is moot.
        let (pre_status, has_www_auth) = preflight(&client, &target).await?;
        if pre_status == 200 && !has_www_auth {
            return Ok(vec![finding(
                Severity::Info,
                "Target is not protected by HTTP Basic auth",
                format!(
                    "GET {target} answered HTTP 200 without a `WWW-Authenticate` \
                     challenge, so there is nothing to audit with this scanner. \
                     Use the web scanners (nikto/nuclei) for form-based logins."
                ),
                "n/a — target has no Basic-auth gate.",
                format!("GET {target} → 200, no WWW-Authenticate"),
                json!({"protected": false}),
            )]);
        }

        ctx.sink
            .emit(crate::events::TaskEvent::Info(format!(
                "testing {} credential pairs against {target}",
                pairs.len()
            )))
            .await;

        let mut successes: Vec<(String, String)> = Vec::new();
        let mut set = tokio::task::JoinSet::new();
        for (u, p) in &pairs {
            let client = client.clone();
            let target = target.clone();
            let (u, p) = (u.clone(), p.clone());
            set.spawn(async move {
                let auth = basic_auth(&u, &p);
                let resp = client
                    .get(&target)
                    .header("authorization", format!("Basic {auth}"))
                    .header("user-agent", "SecuScan-2.0 (password-audit)")
                    .send()
                    .await
                    .ok()?;
                (resp.status().as_u16() != 401 && resp.status().as_u16() != 403).then_some((u, p))
            });
        }
        while let Some(item) = set.join_next().await {
            if ctx.cancel.is_cancelled() {
                set.abort_all();
                break;
            }
            if let Ok(Some(pair)) = item {
                successes.push(pair);
            }
        }

        Ok(audit_findings(&target, &successes))
    }
}

async fn run_form(
    client: &reqwest::Client,
    target: &str,
    inputs: &BTreeMap<String, serde_json::Value>,
    pairs: &[(String, String)],
    ctx: &NativeCtx,
) -> Result<Vec<Finding>, String> {
    let login_url = {
        let raw = get_str_or(inputs, "login_url", "");
        if raw.is_empty() {
            target.to_string()
        } else {
            super::http_headers::normalize_url(raw)?
        }
    };
    let user_field = get_str_or(inputs, "user_field", "username");
    let pass_field = get_str_or(inputs, "pass_field", "password");
    ctx.sink
        .emit(crate::events::TaskEvent::Info(format!(
            "form-login audit: {} pairs against {login_url} ({user_field}/{pass_field})",
            pairs.len()
        )))
        .await;
    let mut successes = Vec::new();
    for (u, p) in pairs {
        if ctx.cancel.is_cancelled() {
            break;
        }
        let form = [(user_field, u.as_str()), (pass_field, p.as_str())];
        let Ok(resp) = client.post(&login_url).form(&form).send().await else {
            continue;
        };
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = resp.text().await.unwrap_or_default();
        if form_login_accepted(status, &location, &login_url, &body) {
            successes.push((u.clone(), p.clone()));
        }
    }
    Ok(audit_findings(&login_url, &successes))
}

/// Conservative success: redirect away from the login URL, or 200 that
/// looks logged-in and does not contain a failure phrase.
pub fn form_login_accepted(status: u16, location: &str, login_url: &str, body: &str) -> bool {
    let fail = [
        "invalid",
        "incorrect",
        "failed",
        "unauthor",
        "denied",
        "wrong password",
    ];
    let lower = body.to_ascii_lowercase();
    if fail.iter().any(|w| lower.contains(w)) {
        return false;
    }
    if (300..400).contains(&status) && !location.is_empty() && !location.contains(login_url) {
        return true;
    }
    status == 200
        && (lower.contains("logout") || lower.contains("sign out") || lower.contains("dashboard"))
}

async fn preflight(client: &reqwest::Client, target: &str) -> Result<(u16, bool), String> {
    let resp = client
        .get(target)
        .header("user-agent", "SecuScan-2.0 (password-audit)")
        .send()
        .await
        .map_err(|e| format!("request to {target} failed: {e}"))?;
    let status = resp.status().as_u16();
    let has_www_auth = resp.headers().contains_key("www-authenticate");
    Ok((status, has_www_auth))
}

fn basic_auth(user: &str, pass: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
}

/// `user:pass` lines → pairs; empty lines and comments skipped.
fn load_pairs(path: &str) -> Result<Vec<(String, String)>, String> {
    let raw: &str = if path.is_empty() {
        DEFAULT_PAIRS
    } else {
        &std::fs::read_to_string(path).map_err(|e| format!("cannot read wordlist `{path}`: {e}"))?
    };
    let mut out = Vec::new();
    for line in raw.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let Some((u, p)) = l.split_once(':') else {
            continue;
        };
        if u.is_empty() || p.is_empty() {
            continue;
        }
        out.push((u.to_string(), p.to_string()));
    }
    if out.is_empty() {
        return Err("credential list produced no user:pass pairs".into());
    }
    Ok(out)
}

/// Pure conversion — unit-testable.
pub(super) fn audit_findings(target: &str, successes: &[(String, String)]) -> Vec<Finding> {
    if successes.is_empty() {
        vec![finding(
            Severity::Info,
            "No default credentials accepted",
            format!(
                "None of the tested default/never-changed credential pairs \
                 authenticated against {target}. The Basic-auth gate did not \
                 accept well-known defaults."
            ),
            "Keep enforcing strong passwords and consider rate-limiting \
             authentication attempts at the reverse proxy.",
            format!("0 accepted pairs on {target}"),
            json!({"target": target, "count": 0}),
        )]
    } else {
        successes
            .iter()
            .map(|(u, p)| {
                finding(
                    Severity::Critical,
                    format!("Default credentials accepted: {u}:{p}"),
                    format!(
                        "The endpoint at {target} authenticated successfully with \
                         `{u}:{p}` — a well-known default pair. Anyone with a \
                         default-credential list can get in."
                    ),
                    "Change the credential immediately, disable the account if it \
                     is unused, and enforce a strong-password policy.",
                    format!("authenticated with {u}:{p}"),
                    json!({"target": target, "user": u, "password": p}),
                )
            })
            .collect()
    }
}

fn finding(
    severity: Severity,
    title: impl Into<String>,
    description: impl Into<String>,
    remediation: &str,
    proof: impl Into<String>,
    metadata: serde_json::Value,
) -> Finding {
    let mut f = Finding::new(
        title,
        "Authentication",
        severity,
        FindingKind::SuspectedIssue,
    );
    f.description = description.into();
    f.remediation = remediation.to_string();
    f.proof = proof.into();
    f.metadata = metadata;
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_pairs_load() {
        let pairs = load_pairs("").unwrap();
        assert!(pairs.len() >= 20, "got {}", pairs.len());
        assert!(pairs.contains(&("admin".to_string(), "admin".to_string())));
    }

    #[test]
    fn malformed_lines_skipped() {
        let path = std::env::temp_dir().join("secuscan-pw-test.txt");
        std::fs::write(
            &path,
            "admin:admin\n# comment\nnouserpwd\n:emptyuser\nok:pass\n\n",
        )
        .unwrap();
        let pairs = load_pairs(path.to_str().unwrap()).unwrap();
        assert_eq!(
            pairs,
            vec![
                ("admin".into(), "admin".into()),
                ("ok".into(), "pass".into())
            ]
        );
    }

    #[test]
    fn no_successes_is_info() {
        let fs = audit_findings("http://x/", &[]);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].severity, Severity::Info);
    }

    #[test]
    fn success_is_critical() {
        let fs = audit_findings("http://x/", &[("admin".to_string(), "admin".to_string())]);
        assert_eq!(fs[0].severity, Severity::Critical);
        assert!(fs[0].title.contains("admin:admin"));
    }

    #[tokio::test]
    async fn basic_auth_matches_rfc() {
        assert_eq!(basic_auth("admin", "admin"), "YWRtaW46YWRtaW4=");
    }

    #[test]
    fn form_success_is_conservative() {
        assert!(form_login_accepted(302, "/home", "https://app/login", ""));
        assert!(!form_login_accepted(
            200,
            "",
            "https://app/login",
            "invalid password"
        ));
        assert!(form_login_accepted(
            200,
            "",
            "https://app/login",
            "Welcome — logout"
        ));
        assert!(!form_login_accepted(401, "", "https://app/login", ""));
    }
}
