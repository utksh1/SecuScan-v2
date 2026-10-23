//! Native Google-dork builder (pentest-tools "Google Hacking" parity).
//!
//! Fields (see `plugins/google-dorks.toml`):
//! - `domain` (string, required)
//!
//! Generates targeted Google search-operator queries ("dorks") that surface
//! commonly leaked content for the domain — directory listings, exposed
//! files, login portals, backups — as clickable links. No scraping: the
//! analyst opens the searches themselves.

use super::dns;
use super::{get_str, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;

pub struct GoogleDorksScanner;

/// (pattern, why it matters, severity)
const DORKS: &[(&str, &str, Severity)] = &[
    ("site:{d} intitle:\"index of\"", "Open directory listings can expose backups, dumps and source files.", Severity::Medium),
    ("site:{d} ext:sql | ext:dump | ext:bak", "Database dumps and backups indexed by the search engine.", Severity::High),
    ("site:{d} ext:log | ext:txt inurl:log", "Log files may contain credentials, tokens and stack traces.", Severity::Medium),
    ("site:{d} ext:env | ext:ini | ext:conf", "Configuration files often include secrets and connection strings.", Severity::High),
    ("site:{d} inurl:admin | inurl:login | inurl:signin", "Admin and login portals are entry points worth mapping.", Severity::Info),
    ("site:{d} inurl:wp- | inurl:wp= | inurl:/wp-content/", "WordPress paths reveal plugins/themes whose versions can be matched to CVEs.", Severity::Info),
    ("site:{d} intitle:\"test\" | intitle:\"staging\" | intitle:\"dev\"", "Non-production environments often lack hardening.", Severity::Low),
    ("site:{d} inurl:phpinfo | intitle:\"phpinfo()\"", "phpinfo pages disclose paths, extensions and environment variables.", Severity::Medium),
    ("site:{d} ext:xls | ext:xlsx | ext:csv", "Spreadsheets may contain customer data or internal inventories.", Severity::Medium),
    ("site:{d} intitle:\"dashboard\" | intitle:\"monitor\"", "Dashboards sometimes render without authentication.", Severity::Low),
    ("site:{d} inurl:ftp | inurl:upload | inurl:downloads", "Upload/download endpoints are worth an access-control review.", Severity::Low),
    ("site:{d} filetype:pdf \"confidential\"", "Documents marked confidential should not be publicly indexed.", Severity::Medium),
];

#[async_trait]
impl NativeScanner for GoogleDorksScanner {
    fn id(&self) -> &'static str {
        "google_dorks"
    }

    fn name(&self) -> &'static str {
        "Google Dork Builder"
    }

    fn description(&self) -> &'static str {
        "Build targeted Google search-operator queries (dorks) for a domain — \
         directory listings, exposed backups, config files, admin portals — \
         as ready-to-open search links. Passive: nothing is sent to the target."
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let domain = get_str(inputs, "target")?.trim().trim_end_matches('.').to_ascii_lowercase();
        if !dns::valid_name(&domain) {
            return Err(format!("invalid domain name `{domain}`"));
        }
        let _ = ctx;
        Ok(dork_findings(&domain))
    }
}

/// URL-encode a query for a Google search link.
pub(super) fn google_link(query: &str) -> String {
    let mut out = String::from("https://www.google.com/search?q=");
    for b in query.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Pure conversion — unit-testable.
pub(super) fn dork_findings(domain: &str) -> Vec<Finding> {
    DORKS
        .iter()
        .map(|(pattern, why, sev)| {
            let query = pattern.replace("{d}", domain);
            let link = google_link(&query);
            finding(
                *sev,
                format!("Dork: {query}"),
                format!("{why} Open the prepared search and review the hits. \
                         Removing indexed sensitive content usually means fixing \
                         the source and requesting re-indexing (Search Console)."),
                "Review indexed results; add authentication, robots rules and \
                 remove what should not be public.",
                link.clone(),
                json!({"domain": domain, "query": query, "search_url": link}),
            )
        })
        .collect()
}

fn finding(
    severity: Severity,
    title: impl Into<String>,
    description: impl Into<String>,
    remediation: &str,
    proof: impl Into<String>,
    metadata: serde_json::Value,
) -> Finding {
    let mut f = Finding::new(title, "OSINT", severity, FindingKind::Observation);
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
    fn dorks_generated_with_links() {
        let fs = dork_findings("acme.test");
        assert_eq!(fs.len(), DORKS.len());
        assert!(fs.iter().all(|f| f.proof.starts_with("https://www.google.com/search?q=")));
        assert!(fs.iter().any(|f| f.severity == Severity::High));
        let f = fs.iter().find(|f| f.metadata["query"] == json!("site:acme.test intitle:\"index of\"")).unwrap();
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.proof.contains("site%3Aacme.test"));
    }

    #[test]
    fn url_encoding() {
        assert_eq!(
            google_link("site:a.b intitle:\"index of\""),
            "https://www.google.com/search?q=site%3Aa.b+intitle%3A%22index+of%22"
        );
    }
}
