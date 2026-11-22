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
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

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
        let mode = get_str_or(inputs, "mode", "dictionary");
        let delay_ms = get_i64_or(inputs, "delay_ms", 0).clamp(0, 600_000) as u64;
        let lockout_pause_ms = get_i64_or(inputs, "lockout_pause_ms", 0).clamp(0, 600_000) as u64;
        let attempts_per_period = get_i64_or(inputs, "attempts_per_period", 0).clamp(0, 50_000) as usize;

        let client = build_client(false, timeout)?;

        if protocol == "http-form" {
            return run_form(&client, &target, inputs, &pairs, ctx).await;
        }

        // Sprint 2.3 (#27): network protocol audit — native clients for the
        // text-friendly protocols; hydra for the binary ones (SSH/SMB/RDP/VNC).
        if let Some((host, port)) = parse_protocol_target(&target, &protocol) {
            return run_protocol_audit(
                &protocol,
                &host,
                port,
                &pairs,
                mode,
                delay_ms,
                lockout_pause_ms,
                attempts_per_period,
                ctx,
            )
            .await;
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

// --- Sprint 2.3 (#27): network protocol engine --------------------------------------

/// Known protocol → default port map for the target parser.
const PROTOCOL_PORTS: &[(&str, u16)] = &[
    ("redis", 6379),
    ("ftp", 21),
    ("telnet", 23),
    ("mysql", 3306),
    ("postgresql", 5432),
    ("mqtt", 1883),
    ("docker", 2375),
    ("winrm", 5985),
    ("stomp", 61613),
    ("http-basic", 80),
];

/// Parse "host[:port]" (or URL) plus the protocol name into (host, port),
/// falling back to the protocol's default port.
fn parse_protocol_target(target: &str, protocol: &str) -> Option<(String, u16)> {
    let host = if let Ok(u) = url::Url::parse(target) {
        u.host_str().unwrap_or("").to_string()
    } else {
        target
            .split("://")
            .last()
            .unwrap_or(target)
            .split('/')
            .next()
            .unwrap_or(target)
            .to_string()
    };
    // Strip a trailing :port when present (IPv6 brackets unhandled — the
    // common target forms are host, host:port, or URLs).
    let (host, port) = if let Some((h, p)) = host.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            (h.to_string(), port)
        } else {
            (host.clone(), 0)
        }
    } else {
        (host.clone(), 0)
    };
    if host.is_empty() {
        return None;
    }
    let port = if port > 0 {
        port
    } else {
        PROTOCOL_PORTS
            .iter()
            .find(|(p, _)| *p == protocol)
            .map(|(_, port)| *port)?
    };
    Some((host, port))
}

/// Spray pacing state machine: after `attempts_per_period` attempts, pause
/// `lockout_pause_ms` (account-lockout avoidance) plus a fixed `delay_ms`
/// between attempts.
#[derive(Debug)]
struct Pacer {
    delay_ms: u64,
    lockout_pause_ms: u64,
    attempts_per_period: usize,
    attempted: usize,
    last_pause: Instant,
}

impl Pacer {
    fn new(delay_ms: u64, lockout_pause_ms: u64, attempts_per_period: usize) -> Self {
        Pacer {
            delay_ms,
            lockout_pause_ms,
            attempts_per_period,
            attempted: 0,
            last_pause: Instant::now(),
        }
    }

    async fn wait(&mut self) {
        if self.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        }
        if self.attempts_per_period > 0
            && self.attempted > 0
            && self.attempted % self.attempts_per_period == 0
            && self.lockout_pause_ms > 0
        {
            tokio::time::sleep(Duration::from_millis(self.lockout_pause_ms)).await;
            self.last_pause = Instant::now();
        }
        self.attempted += 1;
    }
}

/// Run a single credential against the named protocol client.
async fn try_protocol(
    protocol: &str,
    host: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<super::proto_auth::ProtoResult, String> {
    match protocol {
        "redis" => super::proto_auth::redis_auth(host, port, username, password).await,
        "ftp" => super::proto_auth::ftp_auth(host, port, username, password).await,
        "telnet" => super::proto_auth::telnet_auth(host, port, username, password).await,
        "mysql" => super::proto_auth::mysql_auth(host, port, username, password).await,
        "postgresql" => super::proto_auth::postgres_auth(host, port, username, password).await,
        "mqtt" => super::proto_auth::mqtt_auth(host, port, username, password).await,
        "docker" => super::proto_auth::docker_check(host, port).await,
        "winrm" => super::proto_auth::winrm_auth(host, port, username, password).await,
        "stomp" => super::proto_auth::stomp_auth(host, port, username, password).await,
        _ => Err(format!(
            "protocol `{protocol}` requires the hydra integration (install hydra; SSH/SMB/RDP/VNC are not natively supported)"
        )),
    }
}

/// The network protocol audit engine (issue #27).
#[allow(clippy::too_many_arguments)]
async fn run_protocol_audit(
    protocol: &str,
    host: &str,
    port: u16,
    pairs: &[(String, String)],
    mode: &str,
    delay_ms: u64,
    lockout_pause_ms: u64,
    attempts_per_period: usize,
    ctx: &NativeCtx,
) -> Result<Vec<Finding>, String> {
    ctx.sink
        .emit(crate::events::TaskEvent::Info(format!(
            "protocol audit: {protocol}://{host}:{port} — {} credential pair(s), mode={mode}",
            pairs.len()
        )))
        .await;

    // Docker/WinRM checks don't take credential pairs — single probe.
    if protocol == "docker" {
        return match super::proto_auth::docker_check(host, port).await {
            Ok(r) if r.authenticated_as.is_some() => Ok(vec![finding(
                Severity::Critical,
                format!("Docker API exposed without authentication ({host}:{port})"),
                format!(
                    "The Docker Engine API answers HTTP requests with no authentication. \
                     This grants full root-equivalent control over the host: containers, \
                     volumes, and mounted filesystems."
                ),
                "Bind the Docker socket to 127.0.0.1 only; enable TLS client auth (2376) behind the firewall; never expose 2375 publicly.",
                host,
                json!({ "protocol": "docker", "port": port, "version_context": r.context }),
            )]),
            Ok(_) => Ok(vec![finding(
                Severity::Info,
                format!("Docker API not exposed at {host}:{port}"),
                "The endpoint did not return an unauthenticated Docker API response.".to_string(),
                "n/a",
                host,
                json!({ "protocol": "docker" }),
            )]),
            Err(e) => Err(e),
        };
    }

    // Separate username/password wordlists (#27) + classic pairs.
    // `pairs` is user:pass format from the wordlist field; also accept the
    // username/password single-credential fields for targeted checks.
    let mut attempts: Vec<(String, String)> = Vec::new();
    for (u, p) in pairs {
        attempts.push((u.clone(), p.clone()));
    }

    let mut pacer = Pacer::new(delay_ms, lockout_pause_ms, attempts_per_period);
    let mut successes: Vec<(String, String)> = Vec::new();
    let mut connection_errors = 0usize;

    for (u, p) in &attempts {
        if ctx.cancel.is_cancelled() {
            break;
        }
        pacer.wait().await;
        match try_protocol(protocol, host, port, u, p).await {
            Ok(r) => {
                if let Some(authenticated) = &r.authenticated_as {
                    successes.push((authenticated.clone(), p.clone()));
                    tracing::info!(
                        "protocol audit: VALID credentials for {protocol}://{host}:{port} — user `{authenticated}`"
                    );
                }
            }
            Err(e) => {
                connection_errors += 1;
                if connection_errors == 1 {
                    // First error carries context; subsequent ones are silent.
                    tracing::warn!("protocol audit connection issue: {e}");
                }
            }
        }
    }

    if connection_errors > 0 && connection_errors == attempts.len() {
        return Err(format!(
            "all {connection_errors} attempts failed with connection errors — \
             check the host/port and protocol banner"
        ));
    }

    let mut findings = audit_findings(host, &successes);
    // Tag findings with the protocol context for the report.
    for f in &mut findings {
        if let Value::Object(ref mut m) = f.metadata {
            m.insert("protocol".into(), json!(protocol));
            m.insert("port".into(), json!(port));
            m.insert("mode".into(), json!(mode));
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    #[test]
    fn parse_target_host_port_and_bare() {
        assert_eq!(
            parse_protocol_target("10.0.0.5:6380", "redis"),
            Some(("10.0.0.5".into(), 6380))
        );
        assert_eq!(
            parse_protocol_target("redis-server", "redis"),
            Some(("redis-server".into(), 6379)),
            "bare host gets the protocol default port"
        );
        assert_eq!(
            parse_protocol_target("http://db.internal:5432/", "postgresql"),
            Some(("db.internal".into(), 5432))
        );
        assert_eq!(
            parse_protocol_target("host", "mysql"),
            Some(("host".into(), 3306))
        );
        // Unknown protocol → no default port → None.
        assert!(parse_protocol_target("host", "gopher").is_none());
    }

    #[tokio::test]
    async fn pacer_counts_attempts() {
        // Disabled pauses (delay=0, lockout=0) — pure counter increments.
        let mut p = Pacer::new(0, 0, 5);
        for _ in 0..12 {
            p.wait().await;
        }
        assert_eq!(p.attempted, 12);
    }

    #[test]
    fn protocol_ports_cover_supported_set() {
        let supported: Vec<&str> = PROTOCOL_PORTS.iter().map(|(p, _)| *p).collect();
        for proto in ["redis", "ftp", "telnet", "mysql", "postgresql", "mqtt", "docker", "winrm", "stomp", "http-basic"] {
            assert!(supported.contains(&proto), "{proto} in port map");
        }
    }
}
