//! Website Scanner — first-cut professional DAST (native).
//!
//! Stages:
//!  1. Fetch landing page (fingerprint + passive headers)
//!  2. Bounded same-host spider
//!  3. Sensitive-path discovery
//!  4. Passive: emails, directory listings, missing security headers
//!  5. Active (detection only): unique canary reflection, SQL error strings
//!
//! Proof is stored as request/response excerpts on each finding. No
//! keylogging, no exploit shells.

use super::{get_i64_or, get_str, get_str_or, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub struct WebsiteScanner;

const DISCOVERY_PATHS: &[&str] = &[
    "/.env",
    "/.env.local",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/.DS_Store",
    "/admin",
    "/administrator",
    "/backup.zip",
    "/backup.sql",
    "/dump.sql",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/debug",
    "/console",
    "/swagger.json",
    "/swagger-ui",
    "/swagger-ui.html",
    "/openapi.json",
    "/graphql",
    "/graphiql",
    "/wp-admin/",
    "/wp-login.php",
    "/wp-json/wp/v2/users",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
];

const SQL_ERRORS: &[&str] = &[
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlite3.operationalerror",
    "pg_query()",
    "mysql_fetch",
    "odbc sql server driver",
    "ora-01756",
    "ora-00933",
    "postgresql query failed",
    "syntax error at or near",
    "unrecognized token",
    "sqlstate[",
    "jdbcsql",
];

const REDIRECT_PARAMS: &[&str] = &[
    "next",
    "url",
    "redirect",
    "return",
    "returnto",
    "return_to",
    "dest",
    "destination",
    "continue",
    "goto",
    "redir",
    "redirect_uri",
];

#[async_trait]
impl NativeScanner for WebsiteScanner {
    fn id(&self) -> &'static str {
        "website_scanner"
    }
    fn name(&self) -> &'static str {
        "Website Scanner"
    }
    fn description(&self) -> &'static str {
        "DAST: spider, discovery, cookies/CORS/open-redirect/SSTI/host-header \
         and form-canary checks with request/response proof"
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let target = super::http_headers::normalize_url(get_str(inputs, "target")?)?;
        let timeout = Duration::from_millis(
            get_i64_or(inputs, "timeout_ms", 12_000).clamp(1_000, 60_000) as u64,
        );
        let max_pages = get_i64_or(inputs, "max_pages", 15).clamp(1, 40) as usize;
        let exclude = get_str_or(inputs, "exclude", "/logout,/signout,/delete");
        let exclude: Vec<&str> = exclude
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        // Max-Parity Sprint 1.1 — authenticated DAST: when the task carries
        // an auth profile, its cookies/headers ride on EVERY request (crawl,
        // discovery, active probes, DAST engine) via client-level default
        // headers, so the scan sees the authenticated surface.
        let auth = ctx.auth.clone();
        let client = super::auth::authed_client(true, timeout, auth.as_ref())?;
        let no_follow = super::auth::authed_client(false, timeout, auth.as_ref())?;
        let marker = format!("ptt{}", uuid_like());
        let mut findings = Vec::new();
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut queue = vec![target.clone()];
        let mut forms: Vec<(String, String, Vec<String>)> = Vec::new();
        let mut cookie_seen = false;
        let mut server_seen = false;

        ctx.sink
            .emit(crate::events::TaskEvent::Info(format!(
                "website-scanner starting on {target} (max_pages={max_pages}, marker={marker})"
            )))
            .await;

        while let Some(url) = queue.pop() {
            if ctx.cancel.is_cancelled() {
                break;
            }
            if visited.len() >= max_pages {
                break;
            }
            if !visited.insert(url.clone()) {
                continue;
            }
            if exclude.iter().any(|e| url.contains(e)) {
                continue;
            }

            let resp = match client
                .get(&url)
                .header("user-agent", "SecuScan-2.0 (website-scanner)")
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };
            let status = resp.status().as_u16();
            let headers = header_map(resp.headers());
            let body = resp.text().await.unwrap_or_default();
            let excerpt = truncate(&body, 800);

            if visited.len() == 1 {
                passive_headers(&url, status, &headers, &excerpt, &mut findings);
                findings.extend(super::dast_engine::passive_page(
                    &url, status, &headers, &body,
                ));
            }
            if !server_seen {
                if let Some(srv) = headers
                    .get("server")
                    .or_else(|| headers.get("x-powered-by"))
                {
                    if looks_versioned(srv) {
                        server_seen = true;
                        findings.push(issue(
                            Severity::Info,
                            FindingKind::Observation,
                            format!("Server banner discloses version: {srv}"),
                            "A versioned Server / X-Powered-By header helps attackers pick exploits.",
                            "Strip or genericize the banner at the reverse proxy.",
                            &url, "GET", status, srv,
                            "CWE-200", "A05:2021-Security Misconfiguration",
                        ));
                    }
                }
            }
            if !cookie_seen {
                if let Some(sc) = headers.get("set-cookie") {
                    let https = url.starts_with("https://");
                    for (cwe, title) in cookie_issues(sc, https) {
                        cookie_seen = true;
                        findings.push(issue(
                            Severity::Low,
                            FindingKind::SuspectedIssue,
                            title,
                            format!("Set-Cookie on {url} is missing a hardening flag."),
                            "Set HttpOnly, Secure (HTTPS), and SameSite=Lax or Strict.",
                            &url,
                            "GET",
                            status,
                            sc,
                            cwe,
                            "A05:2021-Security Misconfiguration",
                        ));
                    }
                }
            }
            for (method, action, names) in extract_forms(&url, &body) {
                if forms.len() < 12 {
                    forms.push((method, action, names));
                }
            }
            for path in harvest_js_paths(&body).into_iter().take(8) {
                if let Some(abs) = join_url(&target, &path) {
                    if same_origin(&target, &abs) && !visited.contains(&abs) {
                        queue.push(abs);
                    }
                }
            }
            if body.to_ascii_lowercase().contains("index of /") {
                findings.push(issue(
                    Severity::Medium,
                    FindingKind::SuspectedIssue,
                    format!("Directory listing at {url}"),
                    "The response looks like an autoindex page.",
                    "Disable autoindex / Options Indexes.",
                    &url,
                    "GET",
                    status,
                    &excerpt,
                    "CWE-548",
                    "A01:2021-Broken Access Control",
                ));
            }
            for email in email_re().find_iter(&body).take(5) {
                findings.push(issue(
                    Severity::Low,
                    FindingKind::Observation,
                    format!("Email address exposed: {}", email.as_str()),
                    "A crawlable page contains an email address.",
                    "Avoid publishing personal mailboxes on public pages.",
                    &url,
                    "GET",
                    status,
                    email.as_str(),
                    "CWE-359",
                    "A01:2021-Broken Access Control",
                ));
            }
            for href in link_re().captures_iter(&body) {
                if let Some(h) = href.get(1) {
                    if let Some(abs) = join_url(&target, h.as_str()) {
                        if same_origin(&target, &abs) && !visited.contains(&abs) {
                            queue.push(abs);
                        }
                    }
                }
            }
        }

        // Discovery
        let origin = origin_of(&target);
        for path in DISCOVERY_PATHS {
            if ctx.cancel.is_cancelled() {
                break;
            }
            let url = format!("{origin}{path}");
            let Ok(resp) = client.get(&url).send().await else {
                continue;
            };
            let status = resp.status().as_u16();
            if !(200..400).contains(&status) {
                continue;
            }
            let body = resp.text().await.unwrap_or_default();
            if is_soft_404(&body) {
                continue;
            }
            let sev = if path.contains(".env") || path.contains(".git") || path.contains("phpinfo")
            {
                Severity::High
            } else {
                Severity::Low
            };
            findings.push(issue(
                sev,
                FindingKind::SuspectedIssue,
                format!("Sensitive path reachable: {path} ({status})"),
                "A commonly sensitive URL returned a non-error response.",
                "Remove or authenticate the path; deny directory listing of backups and VCS.",
                &url,
                "GET",
                status,
                &truncate(&body, 400),
                "CWE-538",
                "A01:2021-Broken Access Control",
            ));
        }

        // Active: canary reflection + SQL error probe on the landing URL.
        let canary_url = append_query(&target, "secuscan", &marker);
        if let Ok(resp) = client.get(&canary_url).send().await {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if body.contains(&marker) {
                findings.push(issue(
                    Severity::Medium,
                    FindingKind::SuspectedIssue,
                    "Reflected input (XSS candidate)".into(),
                    "A unique marker sent in a query parameter was echoed in the HTML response.",
                    "Encode output by context; apply a strict CSP.",
                    &canary_url, "GET", status, &truncate(&body, 600),
                    "CWE-79", "A03:2021-Injection",
                ).with_category("XSS"));
            }
        }
        let sqli_url = append_query(&target, "secuscan", "'\"");
        if let Ok(resp) = client.get(&sqli_url).send().await {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if looks_like_sql_error(&body) {
                findings.push(
                    issue(
                        Severity::High,
                        FindingKind::SuspectedIssue,
                        "SQL error string reflected".into(),
                        "A quote-bearing parameter produced a database error in the response.",
                        "Use parameterized queries; do not leak SQL errors to clients.",
                        &sqli_url,
                        "GET",
                        status,
                        &truncate(&body, 600),
                        "CWE-89",
                        "A03:2021-Injection",
                    )
                    .with_category("SQL"),
                );
            }
        }

        // CORS preflight (detection only).
        if let Ok(resp) = client
            .request(reqwest::Method::OPTIONS, &target)
            .header("origin", "https://canary.secuscan.test")
            .header("access-control-request-method", "GET")
            .send()
            .await
        {
            let status = resp.status().as_u16();
            let headers = header_map(resp.headers());
            let acao = headers
                .get("access-control-allow-origin")
                .cloned()
                .unwrap_or_default();
            let acac = headers
                .get("access-control-allow-credentials")
                .cloned()
                .unwrap_or_default();
            if cors_is_permissive(&acao, &acac) {
                findings.push(
                    issue(
                        Severity::Medium,
                        FindingKind::SuspectedIssue,
                        "Permissive CORS policy".into(),
                        format!("Preflight answered ACAO=`{acao}` ACAC=`{acac}`."),
                        "Echo only trusted origins; never combine `*` with credentials.",
                        &target,
                        "OPTIONS",
                        status,
                        &format!("acao={acao}; acac={acac}"),
                        "CWE-942",
                        "A05:2021-Security Misconfiguration",
                    )
                    .with_category("CORS"),
                );
            }
        }

        // Open redirect: one canary per common parameter, no-follow.
        let redirect_canary = "https://canary.secuscan.test/secuscan";
        for param in REDIRECT_PARAMS {
            if ctx.cancel.is_cancelled() {
                break;
            }
            let url = append_query(&target, param, redirect_canary);
            let Ok(resp) = no_follow.get(&url).send().await else {
                continue;
            };
            let status = resp.status().as_u16();
            let loc = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if open_redirect_hit(loc, "canary.secuscan.test") {
                findings.push(issue(
                    Severity::Medium,
                    FindingKind::SuspectedIssue,
                    format!("Open redirect via `{param}`"),
                    "The Location header followed an attacker-controlled absolute URL.",
                    "Allow only relative paths or an explicit allow-list of destinations.",
                    &url,
                    "GET",
                    status,
                    loc,
                    "CWE-601",
                    "A01:2021-Broken Access Control",
                ));
                break;
            }
        }

        // Host-header reflection.
        if let Ok(resp) = client
            .get(&target)
            .header("host", "canary.secuscan.test")
            .send()
            .await
        {
            let status = resp.status().as_u16();
            let loc = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let body = resp.text().await.unwrap_or_default();
            if host_header_hit(&body, loc.as_deref(), "canary.secuscan.test") {
                findings.push(issue(
                    Severity::Medium,
                    FindingKind::SuspectedIssue,
                    "Host header reflected".into(),
                    "The application echoed an injected Host header in the body or Location.",
                    "Use a configured canonical host; ignore the request Host for redirects.",
                    &target,
                    "GET",
                    status,
                    &truncate(&body, 400),
                    "CWE-644",
                    "A05:2021-Security Misconfiguration",
                ));
            }
        }

        // SSTI canary (detection: expression evaluates to 49).
        let ssti_url = append_query(&target, "secuscan", "{{7*7}}");
        if let Ok(resp) = client.get(&ssti_url).send().await {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if ssti_hit(&body) {
                findings.push(issue(
                    Severity::High,
                    FindingKind::SuspectedIssue,
                    "SSTI canary evaluated".into(),
                    "The probe `{{7*7}}` produced `49` in the response — a template engine may be interpolating input.",
                    "Never render user input as a template; use a logic-less engine or sandbox.",
                    &ssti_url, "GET", status, &truncate(&body, 400),
                    "CWE-1336", "A03:2021-Injection",
                ));
            }
        }

        // Form canary: GET forms only (no destructive POSTs).
        for (method, action, names) in forms {
            if ctx.cancel.is_cancelled() {
                break;
            }
            if !method.eq_ignore_ascii_case("get") {
                continue;
            }
            if exclude.iter().any(|e| action.contains(e)) {
                continue;
            }
            let field = names.first().map(String::as_str).unwrap_or("q");
            let url = append_query(&action, field, &marker);
            let Ok(resp) = client.get(&url).send().await else {
                continue;
            };
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if body.contains(&marker) {
                findings.push(
                    issue(
                        Severity::Medium,
                        FindingKind::SuspectedIssue,
                        format!("Form parameter `{field}` reflects input"),
                        "A crawled GET form echoed the unique marker.",
                        "Encode output by context; validate parameter types.",
                        &url,
                        "GET",
                        status,
                        &truncate(&body, 400),
                        "CWE-79",
                        "A03:2021-Injection",
                    )
                    .with_category("XSS"),
                );
                break;
            }
        }

        findings.extend(super::dast_engine::run_active(&client, &target, &ctx.cancel).await);

        if findings.is_empty() {
            findings.push(issue(
                Severity::Info,
                FindingKind::Observation,
                format!("Website scan completed for {target}"),
                format!("Crawled {} page(s); no suspected issues from the built-in catalog.", visited.len()),
                "Re-run with a larger max_pages or follow up with nuclei/nikto for broader coverage.",
                &target, "GET", 0, "",
                "", "",
            ));
        }
        Ok(findings)
    }
}

fn passive_headers(
    url: &str,
    status: u16,
    headers: &BTreeMap<String, String>,
    excerpt: &str,
    out: &mut Vec<Finding>,
) {
    for (name, cwe) in [
        ("strict-transport-security", "CWE-319"),
        ("content-security-policy", "CWE-693"),
        ("x-content-type-options", "CWE-693"),
        ("x-frame-options", "CWE-1021"),
    ] {
        if !headers.keys().any(|k| k.eq_ignore_ascii_case(name)) {
            out.push(issue(
                Severity::Low,
                FindingKind::SuspectedIssue,
                format!("Missing header: {name}"),
                format!("The landing page at {url} does not send `{name}`."),
                "Send the header on every HTTPS response.",
                url,
                "GET",
                status,
                excerpt,
                cwe,
                "A05:2021-Security Misconfiguration",
            ));
        }
    }
}

// This stable helper signature is shared by many detection probes.
// Bundle the evidence parameters in a follow-up API refactor.
#[allow(clippy::too_many_arguments)]
fn issue(
    severity: Severity,
    kind: FindingKind,
    title: String,
    description: impl AsRef<str>,
    remediation: impl AsRef<str>,
    url: &str,
    method: &str,
    status: u16,
    body: &str,
    cwe: &str,
    owasp: &str,
) -> Finding {
    let proof = format!("{method} {url} → {status}\n\n{body}");
    Finding {
        title,
        category: "Web".into(),
        severity,
        kind,
        description: description.as_ref().into(),
        remediation: remediation.as_ref().into(),
        proof,
        url: Some(url.into()),
        metadata: json!({
            "request": { "method": method, "url": url },
            "response": { "status": status, "body_excerpt": body },
        }),
        cve: None,
        cvss_v3: None,
        cvss_vector: None,
        epss_score: None,
        epss_percentile: None,
        cisa_kev: false,
        cwe: if cwe.is_empty() {
            None
        } else {
            Some(cwe.into())
        },
        owasp: if owasp.is_empty() {
            None
        } else {
            Some(owasp.into())
        },
        confidence: Some(
            if kind == FindingKind::SuspectedIssue {
                "uncertain"
            } else {
                "certain"
            }
            .into(),
        ),
    }
}

trait WithCategory {
    fn with_category(self, category: &str) -> Self;
}

impl WithCategory for Finding {
    fn with_category(mut self, category: &str) -> Self {
        self.category = category.into();
        self
    }
}

fn header_map(h: &reqwest::header::HeaderMap) -> BTreeMap<String, String> {
    h.iter()
        .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
        .collect()
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

fn uuid_like() -> String {
    format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(1)
    )
}

fn email_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap()
    })
}

fn link_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r#"(?i)href=["']([^"'#]+)"#).unwrap())
}

pub fn join_url(base: &str, href: &str) -> Option<String> {
    if href.starts_with("javascript:") || href.starts_with("mailto:") {
        return None;
    }
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }
    let origin = origin_of(base);
    if href.starts_with('/') {
        Some(format!("{origin}{href}"))
    } else {
        Some(format!("{}/{href}", base.trim_end_matches('/')))
    }
}

fn origin_of(url: &str) -> String {
    let parts: Vec<&str> = url.split('/').collect();
    if parts.len() >= 3 {
        format!("{}//{}", parts[0], parts[2])
    } else {
        url.trim_end_matches('/').to_string()
    }
}

pub fn same_origin(a: &str, b: &str) -> bool {
    origin_of(a) == origin_of(b)
}

pub fn append_query(url: &str, key: &str, value: &str) -> String {
    let enc = value.replace(' ', "+");
    if url.contains('?') {
        format!("{url}&{key}={enc}")
    } else {
        format!("{url}?{key}={enc}")
    }
}

pub fn is_soft_404(body: &str) -> bool {
    let l = body.to_ascii_lowercase();
    l.contains("not found") && body.len() < 800 && !l.contains("<form")
}

pub fn looks_like_sql_error(body: &str) -> bool {
    let l = body.to_ascii_lowercase();
    SQL_ERRORS.iter().any(|e| l.contains(e))
}

pub fn cookie_issues(set_cookie: &str, https: bool) -> Vec<(&'static str, String)> {
    let lower = set_cookie.to_ascii_lowercase();
    let mut out = Vec::new();
    if !lower.contains("httponly") {
        out.push(("CWE-1004", "Cookie missing HttpOnly".into()));
    }
    if https && !lower.contains("secure") {
        out.push(("CWE-614", "Cookie missing Secure on HTTPS".into()));
    }
    if !lower.contains("samesite") {
        out.push(("CWE-1275", "Cookie missing SameSite".into()));
    }
    out
}

pub fn cors_is_permissive(acao: &str, acac: &str) -> bool {
    let star = acao.trim() == "*";
    let creds = acac.eq_ignore_ascii_case("true");
    let reflected = acao.contains("canary.secuscan.test");
    (star && creds) || reflected
}

pub fn open_redirect_hit(location: &str, canary_host: &str) -> bool {
    let l = location.to_ascii_lowercase();
    (l.starts_with("http://") || l.starts_with("https://")) && l.contains(canary_host)
}

pub fn host_header_hit(body: &str, location: Option<&str>, canary: &str) -> bool {
    body.contains(canary) || location.unwrap_or("").contains(canary)
}

pub fn ssti_hit(body: &str) -> bool {
    body.contains("49") && !body.contains("{{7*7}}")
}

pub fn looks_versioned(banner: &str) -> bool {
    banner.chars().any(|c| c.is_ascii_digit()) && banner.contains('.')
}

pub fn harvest_js_paths(body: &str) -> Vec<String> {
    let re = js_path_re();
    let mut out = Vec::new();
    for cap in re.captures_iter(body) {
        let p = cap
            .get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");
        if p.starts_with('/') && !p.starts_with("//") {
            out.push(p.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

pub fn extract_forms(page_url: &str, body: &str) -> Vec<(String, String, Vec<String>)> {
    let mut out = Vec::new();
    for cap in form_re().captures_iter(body) {
        let tag = cap.get(0).map(|m| m.as_str()).unwrap_or("");
        let method = attr(tag, "method").unwrap_or_else(|| "get".into());
        let action_raw = attr(tag, "action").unwrap_or_default();
        let action = join_url(
            page_url,
            if action_raw.is_empty() {
                page_url
            } else {
                &action_raw
            },
        )
        .unwrap_or_else(|| page_url.to_string());
        let names: Vec<String> = input_name_re()
            .captures_iter(tag)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect();
        out.push((method, action, names));
    }
    out
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let re = regex::Regex::new(&format!(r#"(?i){name}=["']([^"']*)["']"#)).ok()?;
    re.captures(tag)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn js_path_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)(?:src|href)\s*=\s*["']([^"']+)|(?:fetch|axios\.(?:get|post))\(\s*["']([^"']+)"#,
        )
        .unwrap()
    })
}

fn form_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?is)<form\b[^>]*>.*?</form>").unwrap())
}

fn input_name_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r#"(?i)<input[^>]+name=["']([^"']+)"#).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_and_query() {
        assert_eq!(
            join_url("https://a.test/app", "/x"),
            Some("https://a.test/x".into())
        );
        assert_eq!(
            append_query("https://a.test/", "q", "1"),
            "https://a.test/?q=1"
        );
        assert_eq!(
            append_query("https://a.test/?a=1", "q", "2"),
            "https://a.test/?a=1&q=2"
        );
    }

    #[test]
    fn sql_error_detect() {
        assert!(looks_like_sql_error(
            "You have an error in your SQL syntax near"
        ));
        assert!(looks_like_sql_error(
            "ORA-01756: quoted string not properly terminated"
        ));
        assert!(!looks_like_sql_error("welcome to the shop"));
        assert!(is_soft_404("404 not found"));
        assert!(!is_soft_404(&"x".repeat(2000)));
    }

    #[test]
    fn cookie_and_cors_and_redirect() {
        let issues = cookie_issues("sid=abc; Path=/", true);
        assert!(issues.iter().any(|(_, t)| t.contains("HttpOnly")));
        assert!(issues.iter().any(|(_, t)| t.contains("Secure")));
        assert!(cors_is_permissive("*", "true"));
        assert!(cors_is_permissive("https://canary.secuscan.test", "true"));
        assert!(!cors_is_permissive("https://app.example", "false"));
        assert!(open_redirect_hit(
            "https://canary.secuscan.test/x",
            "canary.secuscan.test"
        ));
        assert!(!open_redirect_hit("/local", "canary.secuscan.test"));
        assert!(ssti_hit("result=49"));
        assert!(!ssti_hit("literal {{7*7}}"));
        assert!(host_header_hit(
            "welcome canary.secuscan.test",
            None,
            "canary.secuscan.test"
        ));
        assert!(looks_versioned("nginx/1.25.3"));
        assert!(!looks_versioned("cloudflare"));
    }

    #[test]
    fn harvest_and_forms() {
        let paths =
            harvest_js_paths(r#"<script src="/static/app.js"></script> fetch("/api/users")"#);
        assert!(paths.contains(&"/static/app.js".into()));
        assert!(paths.contains(&"/api/users".into()));
        let forms = extract_forms(
            "https://a.test/search",
            r#"<form method="get" action="/q"><input name="q"></form>"#,
        );
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].0.to_ascii_lowercase(), "get");
        assert!(forms[0].2.contains(&"q".into()));
    }
}
