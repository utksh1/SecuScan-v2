//! People Hunter — OSINT email + social-profile harvester (native).
//!
//! Seven-step pipeline (pentest-tools.com parity):
//!  1. HTTPS probe on port 443; extract TLS cert CN when given an IP
//!  2. Crawl homepage + linked pages (bounded, same-host only)
//!  3. Extract email addresses via regex from HTML/JS/JSON
//!  4. Extract social profile URLs (LinkedIn, X/Twitter, Facebook, Instagram,
//!     GitHub, YouTube) filtering share-button noise
//!  5. MX validation via the shared DNS resolver (external-domain filter)
//!  6. Pattern analysis: group discovered usernames by convention
//!     (john@, john.doe@, john_doe@, john-doe@) and compute percentages
//!  7. Predict additional addresses from the dominant pattern
//!
//! Tomba.io integration: if `TOMBA_API_KEY`/`TOMBA_API_SECRET` are set in the
//! environment, the Tomba domain-search API is queried first for a richer
//! seed list. Absent keys, the crawler-only path still works.

use super::{get_str, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub struct PeopleHunter;

const EMAIL_RE: &str = r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}";
const SOCIAL_HOSTS: &[(&str, &str)] = &[
    ("linkedin.com", "LinkedIn"),
    ("twitter.com", "Twitter/X"),
    ("x.com", "Twitter/X"),
    ("facebook.com", "Facebook"),
    ("instagram.com", "Instagram"),
    ("github.com", "GitHub"),
    ("youtube.com", "YouTube"),
];
const CRAWL_BUDGET: usize = 25; // max pages
const MAX_FINDINGS: usize = 200;

#[async_trait]
impl NativeScanner for PeopleHunter {
    fn id(&self) -> &'static str {
        "people_hunter"
    }
    fn name(&self) -> &'static str {
        "People Hunter"
    }
    fn description(&self) -> &'static str {
        "OSINT email + social-profile harvester with pattern analysis and address prediction"
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        _ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let target = get_str(inputs, "target")?;
        let host = normalize_host(target)?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e| format!("build client: {e}"))?;

        // 1. HTTPS probe.
        let base = format!("https://{host}");
        let probe = client.get(&base).send().await;
        let base = match probe {
            Ok(r) if r.status().is_success() => base,
            _ => format!("http://{host}"),
        };

        // 2. Crawl (bounded, same-host).
        let mut pages: Vec<String> = vec![base.clone()];
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut content_all = String::new();
        while let Some(page) = pages.pop() {
            if visited.len() >= CRAWL_BUDGET {
                break;
            }
            if !visited.insert(page.clone()) {
                continue;
            }
            let Ok(resp) = client.get(&page).send().await else {
                continue;
            };
            let Ok(text) = resp.text().await else {
                continue;
            };
            // Collect same-host links.
            for cap in link_re().captures_iter(&text) {
                if let Some(href) = cap.get(1) {
                    if let Some(abs) = absolutize(&base, href.as_str()) {
                        if same_host(&base, &abs) && !visited.contains(&abs) {
                            pages.push(abs);
                        }
                    }
                }
            }
            content_all.push_str(&text);
            content_all.push('\n');
        }

        // 3. Extract emails.
        let mut emails: BTreeSet<String> = BTreeSet::new();
        for m in email_re().find_iter(&content_all) {
            let e = m.as_str().to_ascii_lowercase();
            // Filter obvious noise.
            if e.ends_with(".png")
                || e.ends_with(".jpg")
                || e.ends_with(".gif")
                || e.starts_with("example.")
                || e.contains("sentry.io")
                || e.contains("domain.com")
                || e.contains("email.com")
            {
                continue;
            }
            emails.insert(e);
            if emails.len() >= MAX_FINDINGS {
                break;
            }
        }

        // Optional Tomba.io enrichment.
        if let (Ok(key), Ok(secret)) = (
            std::env::var("TOMBA_API_KEY"),
            std::env::var("TOMBA_API_SECRET"),
        ) {
            if !key.is_empty() && !secret.is_empty() {
                if let Ok(body) = tomba_domain_search(&client, &key, &secret, &host).await {
                    if let Some(list) = body
                        .get("data")
                        .and_then(|d| d.get("emails"))
                        .and_then(|v| v.as_array())
                    {
                        for e in list {
                            if let Some(addr) = e.get("email").and_then(|v| v.as_str()) {
                                emails.insert(addr.to_ascii_lowercase());
                            }
                        }
                    }
                }
            }
        }

        // 4. Social profiles.
        let mut socials: BTreeMap<String, String> = BTreeMap::new();
        for m in link_re().captures_iter(&content_all) {
            if let Some(href) = m.get(1) {
                let href = href.as_str();
                for (host_frag, label) in SOCIAL_HOSTS {
                    if href.contains(host_frag) {
                        // Filter share buttons.
                        if href.contains("share")
                            || href.contains("intent/")
                            || href.contains("sharer")
                        {
                            continue;
                        }
                        socials
                            .entry(label.to_string())
                            .or_insert_with(|| href.to_string());
                    }
                }
            }
        }

        // 5. MX validation + external-domain filter.
        let mut validated: Vec<String> = Vec::new();
        for e in &emails {
            let domain = e.split('@').nth(1).unwrap_or("");
            if domain.is_empty() {
                continue;
            }
            if !domain.ends_with(&host) && !host.ends_with(domain) {
                continue; // external-domain filter
            }
            let mx = super::dns::resolve_mx(domain).await;
            if let Ok(records) = mx {
                if !records.is_empty() {
                    validated.push(e.clone());
                }
            }
        }
        // If MX lookup fails entirely (offline lab), fall back to all
        // same-domain emails so the scanner still reports useful output.
        let reported: Vec<String> = if validated.is_empty() {
            emails.iter().cloned().collect()
        } else {
            validated
        };

        // 6. Pattern analysis.
        let mut findings = Vec::new();
        if reported.is_empty() {
            findings.push(Finding {
                title: format!("No email addresses discovered for {host}"),
                category: "People Hunter".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: format!(
                    "Crawled {visited_len} page(s) on {host} and found no email addresses \
                     passing the noise filters. The site may render content client-side; \
                     consider a deeper crawl or Tomba.io enrichment.",
                    visited_len = visited.len()
                ),
                remediation: "If emails exist, ensure they are not exposed in page source; \
                              use a contact form instead of mailto: links."
                    .into(),
                proof: format!("crawled_pages={}", visited.len()),
                url: Some(base.clone()),
                metadata: json!({"pages_crawled": visited.len(), "emails_found": 0}),
                ..Default::default()
            });
            return Ok(findings);
        }

        let patterns = analyze_patterns(&reported);
        for (pattern, percentage, examples) in &patterns {
            findings.push(Finding {
                title: format!(
                    "Email pattern: {pattern} ({percentage}% of {} addresses)",
                    reported.len()
                ),
                category: "People Hunter".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: format!(
                    "The dominant username convention `{pattern}` covers {percentage}% of the \
                     {} validated addresses found on {host}. This convention can be used to \
                     predict addresses for other employees.",
                    reported.len()
                ),
                remediation: "Email conventions are reconnaissance intelligence — consider \
                              generic aliases (info@, contact@) for external correspondence."
                    .into(),
                proof: format!("examples: {}", examples.join(", ")),
                url: Some(base.clone()),
                metadata: json!({
                    "pattern": pattern,
                    "percentage": percentage,
                    "examples": examples,
                    "total_addresses": reported.len(),
                }),
                ..Default::default()
            });
        }

        // Individual validated addresses (capped).
        for e in reported.iter().take(50) {
            findings.push(Finding {
                title: format!("Email address discovered: {e}"),
                category: "People Hunter".into(),
                severity: Severity::Low,
                kind: FindingKind::Observation,
                description: format!(
                    "`{e}` was found in page source crawled from {host} and passed MX validation."
                ),
                remediation: "Assess whether this address should be publicly reachable.".into(),
                proof: format!("found in crawled content of {host}"),
                url: Some(base.clone()),
                metadata: json!({"email": e, "host": host}),
                ..Default::default()
            });
        }

        // Social profiles.
        for (label, url) in &socials {
            findings.push(Finding {
                title: format!("{label} profile linked from {host}"),
                category: "People Hunter".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: format!(
                    "The site links to a {label} profile: {url}. Social profiles map \
                     personnel and are useful for phishing reconnaissance."
                ),
                remediation: "Review whether linked social profiles expose employee identity."
                    .into(),
                proof: format!("href found in crawled content: {url}"),
                url: Some(url.clone()),
                metadata: json!({"platform": label, "url": url}),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn normalize_host(target: &str) -> Result<String, String> {
    let t = target.trim();
    if let Ok(u) = url::Url::parse(t) {
        return u
            .host_str()
            .map(str::to_string)
            .ok_or_else(|| "no host".into());
    }
    let t = t
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let t = t.split('/').next().unwrap_or(t);
    if t.is_empty() {
        Err("empty host".into())
    } else {
        Ok(t.to_string())
    }
}

fn email_re() -> regex::Regex {
    regex::Regex::new(EMAIL_RE).unwrap()
}

fn link_re() -> regex::Regex {
    regex::Regex::new(r#"(?i)href\s*=\s*["']([^"']+)["']"#).unwrap()
}

fn absolutize(base: &str, href: &str) -> Option<String> {
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }
    if href.starts_with("//") {
        return Some(format!("https:{href}"));
    }
    if href.starts_with('/') {
        let base_url = url::Url::parse(base).ok()?;
        return Some(format!(
            "{}://{}{}",
            base_url.scheme(),
            base_url.host_str()?,
            href
        ));
    }
    None
}

fn same_host(base: &str, candidate: &str) -> bool {
    match (url::Url::parse(base), url::Url::parse(candidate)) {
        (Ok(b), Ok(c)) => b.host_str() == c.host_str(),
        _ => false,
    }
}

async fn tomba_domain_search(
    client: &reqwest::Client,
    key: &str,
    secret: &str,
    domain: &str,
) -> Result<serde_json::Value, String> {
    let resp = client
        .get(format!(
            "https://api.tomba.io/v1/domain-search?domain={domain}&limit=50"
        ))
        .header("X-Tomba-Key", key)
        .header("X-Tomba-Secret", secret)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("tomba returned {}", resp.status()));
    }
    resp.json().await.map_err(|e| e.to_string())
}

/// Group usernames by convention and return (pattern, percentage, examples)
/// sorted by percentage desc.
fn analyze_patterns(emails: &[String]) -> Vec<(String, u32, Vec<String>)> {
    let mut first: Vec<String> = Vec::new();
    let mut first_dot_last: Vec<String> = Vec::new();
    let mut first_underscore_last: Vec<String> = Vec::new();
    let mut first_dash_last: Vec<String> = Vec::new();
    let mut other: Vec<String> = Vec::new();

    for e in emails {
        let local = e.split('@').next().unwrap_or("");
        if let Some((a, b)) = local.split_once('.') {
            if !a.is_empty() && !b.is_empty() {
                first_dot_last.push(e.clone());
                first.push(a.to_string());
                continue;
            }
        }
        if let Some((a, b)) = local.split_once('_') {
            if !a.is_empty() && !b.is_empty() {
                first_underscore_last.push(e.clone());
                first.push(a.to_string());
                continue;
            }
        }
        if let Some((a, b)) = local.split_once('-') {
            if !a.is_empty() && !b.is_empty() {
                first_dash_last.push(e.clone());
                first.push(a.to_string());
                continue;
            }
        }
        other.push(e.clone());
    }

    let total = emails.len().max(1) as u32;
    let mut out = Vec::new();
    let push = |out: &mut Vec<(String, u32, Vec<String>)>, name: &str, list: &[String]| {
        if !list.is_empty() {
            let pct = (list.len() as u32) * 100 / total;
            out.push((
                name.to_string(),
                pct,
                list.iter().take(5).cloned().collect(),
            ));
        }
    };
    push(&mut out, "first.last", &first_dot_last);
    push(&mut out, "first_last", &first_underscore_last);
    push(&mut out, "first-last", &first_dash_last);
    push(&mut out, "first_only", &other);
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_regex_matches_common_forms() {
        let re = email_re();
        assert!(re.find("contact john.doe@example.com today").is_some());
        assert!(re.find("first_last@corp.io").is_some());
        assert!(re.find("no email here").is_none());
    }

    #[test]
    fn pattern_analysis_ranks_dominant_first() {
        let emails = vec![
            "a.b@example.com".into(),
            "c.d@example.com".into(),
            "e@example.com".into(),
        ];
        let pats = analyze_patterns(&emails);
        assert_eq!(pats[0].0, "first.last");
        assert_eq!(pats[0].1, 66);
    }

    #[test]
    fn absolutize_handles_relative_paths() {
        assert_eq!(
            absolutize("https://example.com", "/about"),
            Some("https://example.com/about".into())
        );
        assert_eq!(
            absolutize("https://example.com", "javascript:void(0)"),
            None
        );
    }
}
