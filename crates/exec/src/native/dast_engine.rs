//! Extra DAST checks ported from the classes used by cyweb, scant3r, and
//! crlfuzz — original detection logic, not a copy of those codebases.
//!
//! All probes are detection-only: unique canaries, error strings, or
//! response-header proof. No shells, no key dumps.

use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::time::Duration;

use super::website_scanner::{append_query, looks_like_sql_error};

pub fn finding(
    severity: Severity,
    kind: FindingKind,
    category: &str,
    title: impl Into<String>,
    description: impl Into<String>,
    remediation: impl Into<String>,
    url: &str,
    method: &str,
    status: u16,
    body: &str,
    cwe: &str,
    owasp: &str,
) -> Finding {
    Finding {
        title: title.into(),
        category: category.into(),
        severity,
        kind,
        description: description.into(),
        remediation: remediation.into(),
        proof: format!("{method} {url} → {status}\n\n{body}"),
        url: Some(url.into()),
        metadata: json!({
            "request": { "method": method, "url": url },
            "response": { "status": status },
        }),
        cwe: if cwe.is_empty() { None } else { Some(cwe.into()) },
        owasp: if owasp.is_empty() { None } else { Some(owasp.into()) },
        confidence: Some(if kind == FindingKind::SuspectedIssue { "uncertain" } else { "certain" }.into()),
        ..Default::default()
    }
}

pub fn stack_trace_hit(body: &str) -> bool {
    let l = body.to_ascii_lowercase();
    l.contains("traceback (most recent call last)")
        || l.contains("stacktrace:")
        || l.contains(".java:") && l.contains("exception")
        || l.contains("at /var/www/")
        || l.contains("django.core.exceptions")
}

pub fn nosql_error_hit(body: &str) -> bool {
    let l = body.to_ascii_lowercase();
    l.contains("mongodberror")
        || l.contains("bson field")
        || l.contains("cast to objectid failed")
        || l.contains("unexpected token") && l.contains("$gt")
}

pub fn jwt_alg(cookie_header: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let v = part.trim().split_once('=').map(|(_, val)| val.trim()).unwrap_or("");
        if let Some(alg) = decode_jwt_alg(v) {
            return Some(alg);
        }
    }
    None
}

pub fn decode_jwt_alg(token: &str) -> Option<String> {
    let header = token.strip_prefix("Bearer ").unwrap_or(token).split('.').next()?;
    if !header.starts_with("eyJ") {
        return None;
    }
    let padded = match header.len() % 4 {
        2 => format!("{header}=="),
        3 => format!("{header}="),
        _ => header.to_string(),
    };
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, header)
        .or_else(|_| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &padded))
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("alg").and_then(|a| a.as_str()).map(|s| s.to_string())
}

pub fn csrf_missing(form_html: &str) -> bool {
    let l = form_html.to_ascii_lowercase();
    if !l.contains("<form") || !l.contains("method=\"post\"") && !l.contains("method='post'") {
        return false;
    }
    let tokenish = ["csrf", "xsrf", "_token", "authenticity_token", "nonce", "__requestverificationtoken"];
    !tokenish.iter().any(|t| l.contains(t))
}

pub fn login_form_over_http(page_url: &str, body: &str) -> bool {
    page_url.starts_with("http://")
        && body.to_ascii_lowercase().contains("type=\"password\"")
}

pub fn autocomplete_password(body: &str) -> bool {
    let l = body.to_ascii_lowercase();
    l.contains("type=\"password\"") && !l.contains("autocomplete=\"off\"") && !l.contains("autocomplete='off'") && !l.contains("autocomplete=\"new-password\"")
}

pub fn source_map_ref(body: &str) -> Option<String> {
    let re = regex::Regex::new(r"sourceMappingURL=(\S+)").ok()?;
    re.captures(body).and_then(|c| c.get(1)).map(|m| m.as_str().trim().to_string())
}

pub fn crlf_injected(headers: &[(String, String)], canary: &str) -> bool {
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("set-cookie") && v.contains(canary)
            || k.to_ascii_lowercase().contains(canary)
    })
}

pub fn lfi_hit(body: &str) -> bool {
    body.contains("root:x:0:0") || body.contains("[extensions]") && body.contains("for 16-bit")
}

pub fn firebase_open(body: &str) -> bool {
    let l = body.to_ascii_lowercase();
    l.contains("firebaseio.com")
}

pub fn extra_header_gaps(headers: &std::collections::BTreeMap<String, String>) -> Vec<(&'static str, &'static str)> {
    let mut missing = Vec::new();
    for (name, cwe) in [
        ("referrer-policy", "CWE-200"),
        ("permissions-policy", "CWE-693"),
    ] {
        if !headers.keys().any(|k| k.eq_ignore_ascii_case(name)) {
            missing.push((name, cwe));
        }
    }
    missing
}

pub fn passive_page(
    url: &str,
    status: u16,
    headers: &std::collections::BTreeMap<String, String>,
    body: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    if stack_trace_hit(body) {
        out.push(finding(
            Severity::Medium, FindingKind::SuspectedIssue, "Web",
            "Stack trace or framework exception leaked",
            "The response body looks like a developer stack trace.",
            "Disable debug mode; map exceptions to generic error pages.",
            url, "GET", status, &body.chars().take(400).collect::<String>(),
            "CWE-209", "A05:2021-Security Misconfiguration",
        ));
    }
    if nosql_error_hit(body) {
        out.push(finding(
            Severity::High, FindingKind::SuspectedIssue, "SQL",
            "NoSQL / Mongo error string in response",
            "The page leaked a Mongo/BSON driver error.",
            "Catch driver errors; never return them to clients.",
            url, "GET", status, &body.chars().take(400).collect::<String>(),
            "CWE-89", "A03:2021-Injection",
        ));
    }
    if let Some(sc) = headers.get("set-cookie").cloned().or_else(|| headers.get("cookie").cloned()) {
        if let Some(alg) = jwt_alg(&sc) {
            let sev = if alg.eq_ignore_ascii_case("none") { Severity::High } else { Severity::Info };
            out.push(finding(
                sev, FindingKind::Observation, "JWT",
                format!("JWT in cookie (alg={alg})"),
                "A session cookie looks like a JWT. `alg=none` is a validated issue; otherwise this is inventory.",
                "Reject `alg=none`; use RS256/ES256 and short TTLs.",
                url, "GET", status, &format!("alg={alg}"),
                "CWE-347", "A02:2021-Cryptographic Failures",
            ));
        }
    }
    if login_form_over_http(url, body) {
        out.push(finding(
            Severity::High, FindingKind::SuspectedIssue, "Auth",
            "Password form served over HTTP",
            "A password field was observed on a cleartext page.",
            "Serve the login form only on HTTPS and set HSTS.",
            url, "GET", status, "type=password on http://",
            "CWE-319", "A02:2021-Cryptographic Failures",
        ));
    }
    if autocomplete_password(body) {
        out.push(finding(
            Severity::Low, FindingKind::Observation, "Web",
            "Password field allows browser autocomplete",
            "No autocomplete=off/new-password on a password input.",
            "Set autocomplete=\"new-password\" on password fields.",
            url, "GET", status, "type=password",
            "CWE-522", "A07:2021-Identification and Authentication Failures",
        ));
    }
    if csrf_missing(body) {
        out.push(finding(
            Severity::Medium, FindingKind::SuspectedIssue, "Web",
            "POST form without an anti-CSRF token field",
            "A POST form has no csrf/xsrf/_token hidden field in the HTML.",
            "Add a synchronizer token (or SameSite=Strict plus custom header).",
            url, "GET", status, "POST form",
            "CWE-352", "A01:2021-Broken Access Control",
        ));
    }
    if body.to_ascii_lowercase().contains("firebaseio.com") && firebase_open(body) {
        out.push(finding(
            Severity::Medium, FindingKind::Observation, "Web",
            "Firebase host referenced in the page",
            "The response mentions firebaseio.com. Confirm security rules deny public read/write.",
            "Lock Firebase rules to authenticated users; never ship an open database URL.",
            url, "GET", status, "firebaseio.com",
            "CWE-200", "A01:2021-Broken Access Control",
        ));
    }
    if let Some(map) = source_map_ref(body) {
        out.push(finding(
            Severity::Low, FindingKind::Observation, "Web",
            format!("JavaScript source map referenced: {map}"),
            "sourceMappingURL exposes original source to anyone who can fetch the .map.",
            "Strip sourceMappingURL from production bundles.",
            url, "GET", status, &map,
            "CWE-540", "A05:2021-Security Misconfiguration",
        ));
    }
    for (name, cwe) in extra_header_gaps(headers) {
        out.push(finding(
            Severity::Low, FindingKind::SuspectedIssue, "HTTP",
            format!("Missing header: {name}"),
            format!("The response does not send `{name}`."),
            "Send the header on every HTML/API response.",
            url, "GET", status, "",
            cwe, "A05:2021-Security Misconfiguration",
        ));
    }
    out
}

pub async fn run_active(
    client: &reqwest::Client,
    target: &str,
    cancel: &tokio_util::sync::CancellationToken,
) -> Vec<Finding> {
    let mut out = Vec::new();
    if cancel.is_cancelled() {
        return out;
    }

    // TRACE / XST
    if let Ok(resp) = client.request(reqwest::Method::TRACE, target).send().await {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        if status == 200 && (body.contains("TRACE") || body.len() > 20) {
            out.push(finding(
                Severity::Medium, FindingKind::SuspectedIssue, "Web",
                "HTTP TRACE enabled",
                "TRACE echoed the request. Combined with XSS this is Cross-Site Tracing.",
                "Disable TRACE on the server and reverse proxy.",
                target, "TRACE", status, &body.chars().take(200).collect::<String>(),
                "CWE-693", "A05:2021-Security Misconfiguration",
            ));
        }
    }

    // CRLF (crlfuzz-class): inject Set-Cookie via %0d%0a and see if it lands.
    let crlf_canary = format!("secuscan{}", &uuid_short());
    let crlf_url = append_query(target, "q", &format!("%0d%0aSet-Cookie:%20{crlf_canary}=1"));
    if let Ok(resp) = client.get(&crlf_url).send().await {
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
            .collect();
        if crlf_injected(&headers, &crlf_canary) {
            out.push(finding(
                Severity::High, FindingKind::SuspectedIssue, "CRLF",
                "CRLF header injection (Set-Cookie)",
                "A %0d%0a sequence in a query parameter produced an extra Set-Cookie.",
                "Reject CR/LF in input used for headers; use a well-tested HTTP stack.",
                &crlf_url, "GET", status, &crlf_canary,
                "CWE-113", "A03:2021-Injection",
            ));
        }
    }

    // LFI canary (passwd / win.ini signatures only).
    for payload in ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini"] {
        if cancel.is_cancelled() { break; }
        let url = append_query(target, "file", payload);
        let Ok(resp) = client.get(&url).send().await else { continue };
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        if lfi_hit(&body) {
            out.push(finding(
                Severity::High, FindingKind::SuspectedIssue, "LFI",
                "Local file inclusion canary matched",
                "A path-traversal parameter returned passwd or win.ini content.",
                "Canonicalize paths; never concatenate user input into file APIs.",
                &url, "GET", status, &body.chars().take(200).collect::<String>(),
                "CWE-22", "A01:2021-Broken Access Control",
            ));
            break;
        }
    }

    // Cache / host poisoning via X-Forwarded-Host reflection.
    if let Ok(resp) = client
        .get(target)
        .header("x-forwarded-host", "canary.secuscan.test")
        .send()
        .await
    {
        let status = resp.status().as_u16();
        let loc = resp.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let body = resp.text().await.unwrap_or_default();
        if body.contains("canary.secuscan.test") || loc.contains("canary.secuscan.test") {
            out.push(finding(
                Severity::Medium, FindingKind::SuspectedIssue, "Web",
                "X-Forwarded-Host reflected",
                "The app used X-Forwarded-Host when building links or redirects.",
                "Ignore untrusted forwarding headers unless the proxy strips them.",
                target, "GET", status, &body.chars().take(200).collect::<String>(),
                "CWE-644", "A05:2021-Security Misconfiguration",
            ));
        }
    }

    // NoSQL operator canary (error-based only).
    let nosql_url = append_query(target, "id", "[$gt]=");
    if let Ok(resp) = client.get(&nosql_url).send().await {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        if nosql_error_hit(&body) || looks_like_sql_error(&body) {
            out.push(finding(
                Severity::High, FindingKind::SuspectedIssue, "SQL",
                "NoSQL operator produced a driver error",
                "A `[$gt]` parameter triggered a database error page.",
                "Use an allow-list of types; never pass raw objects from query string to the driver.",
                &nosql_url, "GET", status, &body.chars().take(300).collect::<String>(),
                "CWE-943", "A03:2021-Injection",
            ));
        }
    }

    let _ = Duration::from_secs(0);
    out
}

fn uuid_short() -> String {
    format!("{:x}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() % 0xffff_ffff)
        .unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_and_crlf_and_lfi() {
        let token = {
            // {"alg":"none","typ":"JWT"}
            let h = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, br#"{"alg":"none","typ":"JWT"}"#);
            format!("{h}.e30.")
        };
        assert_eq!(decode_jwt_alg(&token).as_deref(), Some("none"));
        assert!(crlf_injected(&[("Set-Cookie".into(), "secuscan1=1".into())], "secuscan1"));
        assert!(lfi_hit("root:x:0:0:root:/root:/bin/bash"));
        assert!(stack_trace_hit("Traceback (most recent call last):\n File"));
        assert!(csrf_missing(r#"<form method="post" action="/x"><input name="u"></form>"#));
        assert!(!csrf_missing(r#"<form method="post"><input name="csrf" value="a"></form>"#));
        assert!(login_form_over_http("http://a.test/login", r#"<input type="password">"#));
        assert_eq!(source_map_ref("//# sourceMappingURL=app.js.map").as_deref(), Some("app.js.map"));
    }
}
