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
use std::collections::{BTreeSet, BTreeMap};
use std::time::Duration;

pub struct WebsiteScanner;

const DISCOVERY_PATHS: &[&str] = &[
    "/.env",
    "/.git/HEAD",
    "/admin",
    "/administrator",
    "/backup.zip",
    "/phpinfo.php",
    "/server-status",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
    "/wp-admin/",
    "/robots.txt",
    "/sitemap.xml",
];

const SQL_ERRORS: &[&str] = &[
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlite3.operationalerror",
    "pg_query()",
    "mysql_fetch",
    "odbc sql server driver",
];

#[async_trait]
impl NativeScanner for WebsiteScanner {
    fn id(&self) -> &'static str { "website_scanner" }
    fn name(&self) -> &'static str { "Website Scanner" }
    fn description(&self) -> &'static str {
        "DAST: spider, sensitive-path discovery, passive header/secret checks, \
         reflected-input and SQL-error detection with request/response proof"
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
        let exclude: Vec<&str> = exclude.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();

        let client = super::http_headers::build_client(true, timeout)?;
        let marker = format!("ptt{}", &uuid_like());
        let mut findings = Vec::new();
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut queue = vec![target.clone()];

        ctx.sink
            .emit(crate::events::TaskEvent::Info(format!(
                "website-scanner starting on {target} (max_pages={max_pages}, marker={marker})"
            )))
            .await;

        while let Some(url) = queue.pop() {
            if ctx.cancel.is_cancelled() { break; }
            if visited.len() >= max_pages { break; }
            if !visited.insert(url.clone()) { continue; }
            if exclude.iter().any(|e| url.contains(e)) { continue; }

            let resp = match client.get(&url).header("user-agent", "SecuScan-2.0 (website-scanner)").send().await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let status = resp.status().as_u16();
            let headers = header_map(resp.headers());
            let body = resp.text().await.unwrap_or_default();
            let excerpt = truncate(&body, 800);

            if visited.len() == 1 {
                passive_headers(&url, status, &headers, &excerpt, &mut findings);
            }
            if body.to_ascii_lowercase().contains("index of /") {
                findings.push(issue(
                    Severity::Medium,
                    FindingKind::SuspectedIssue,
                    format!("Directory listing at {url}"),
                    "The response looks like an autoindex page.",
                    "Disable autoindex / Options Indexes.",
                    &url, "GET", status, &excerpt,
                    "CWE-548", "A01:2021-Broken Access Control",
                ));
            }
            for email in email_re().find_iter(&body).take(5) {
                findings.push(issue(
                    Severity::Low,
                    FindingKind::Observation,
                    format!("Email address exposed: {}", email.as_str()),
                    "A crawlable page contains an email address.",
                    "Avoid publishing personal mailboxes on public pages.",
                    &url, "GET", status, email.as_str(),
                    "CWE-359", "A01:2021-Broken Access Control",
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
            if ctx.cancel.is_cancelled() { break; }
            let url = format!("{origin}{path}");
            let Ok(resp) = client.get(&url).send().await else { continue };
            let status = resp.status().as_u16();
            if !(200..400).contains(&status) { continue; }
            let body = resp.text().await.unwrap_or_default();
            if is_soft_404(&body) { continue; }
            let sev = if path.contains(".env") || path.contains(".git") || path.contains("phpinfo") {
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
                &url, "GET", status, &truncate(&body, 400),
                "CWE-538", "A01:2021-Broken Access Control",
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
                ));
            }
        }
        let sqli_url = append_query(&target, "secuscan", "'\"");
        if let Ok(resp) = client.get(&sqli_url).send().await {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let lower = body.to_ascii_lowercase();
            if SQL_ERRORS.iter().any(|e| lower.contains(e)) {
                findings.push(issue(
                    Severity::High,
                    FindingKind::SuspectedIssue,
                    "SQL error string reflected".into(),
                    "A quote-bearing parameter produced a database error in the response.",
                    "Use parameterized queries; do not leak SQL errors to clients.",
                    &sqli_url, "GET", status, &truncate(&body, 600),
                    "CWE-89", "A03:2021-Injection",
                ));
            }
        }

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
                url, "GET", status, excerpt,
                cwe, "A05:2021-Security Misconfiguration",
            ));
        }
    }
}

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
        cwe: if cwe.is_empty() { None } else { Some(cwe.into()) },
        owasp: if owasp.is_empty() { None } else { Some(owasp.into()) },
        confidence: Some(if kind == FindingKind::SuspectedIssue { "uncertain" } else { "certain" }.into()),
    }
}

fn header_map(h: &reqwest::header::HeaderMap) -> BTreeMap<String, String> {
    h.iter()
        .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
        .collect()
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n { s.to_string() } else { format!("{}…", &s[..n]) }
}

fn uuid_like() -> String {
    format!("{:x}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1))
}

fn email_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap())
}

fn link_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r#"(?i)href=["']([^"'#]+)"#).unwrap())
}

pub fn join_url(base: &str, href: &str) -> Option<String> {
    if href.starts_with("javascript:") || href.starts_with("mailto:") { return None; }
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

fn same_origin(a: &str, b: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_and_query() {
        assert_eq!(join_url("https://a.test/app", "/x"), Some("https://a.test/x".into()));
        assert_eq!(append_query("https://a.test/", "q", "1"), "https://a.test/?q=1");
        assert_eq!(append_query("https://a.test/?a=1", "q", "2"), "https://a.test/?a=1&q=2");
    }

    #[test]
    fn sql_error_detect() {
        assert!(looks_like_sql_error("You have an error in your SQL syntax near"));
        assert!(!looks_like_sql_error("welcome to the shop"));
        assert!(is_soft_404("404 not found"));
        assert!(!is_soft_404(&"x".repeat(2000)));
    }
}
