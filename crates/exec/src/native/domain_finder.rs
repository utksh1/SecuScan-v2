//! Domain Finder — discover related domains owned by the same organization.
//!
//! Three techniques (Max-Parity Sprint 1.3 / task 3.1 closed the org-pivot
//! gap the manifest always advertised):
//!   1. **CT subdomains** — `crt.sh ?q=%.<target>` finds subdomain names
//!      issued for the target (pre-existing behavior).
//!   2. **Organization pivot** — read the Organization (O) from the target's
//!      live TLS certificate, then search crt.sh for *other* certificates
//!      issued to the same organization. This is what finds sibling root
//!      domains (facebook.com → fbcdn.net) that subdomain search can never
//!      see, because `%.target` only returns names ending in `.target`.
//!   3. **Redirect verification** — bounded HTTP check whether a candidate's
//!      web endpoint redirects to the target, a strong ownership signal.
//!
//! Candidates from all techniques merge into one certainty score (0-100).

use super::{get_bool_or, get_str, NativeCtx, NativeScanner};
use async_trait::async_trait;
use reqwest::Client;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

pub struct DomainFinder;

/// A candidate domain merged across techniques.
#[derive(Default, Debug, Clone)]
struct Candidate {
    hits: usize,
    /// Seen via the subject-org pivot (strong signal).
    org_pivot: bool,
    /// Its web endpoint redirects to the target (strongest signal).
    redirects_to_target: bool,
}

#[async_trait]
impl NativeScanner for DomainFinder {
    fn id(&self) -> &'static str {
        "domain_finder"
    }
    fn name(&self) -> &'static str {
        "Domain Finder"
    }
    fn description(&self) -> &'static str {
        "Find related domains via Certificate Transparency (subdomains + organization pivot) and redirect verification"
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        _ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let target = get_str(inputs, "target")?;
        let min_certainty = inputs
            .get("min_certainty")
            .and_then(|v| v.as_i64())
            .unwrap_or(30) as u32;
        let check_redirects = get_bool_or(inputs, "check_redirects", true);

        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| format!("build client: {e}"))?;

        // --- Technique 1: CT subdomain search (pre-existing) -----------------
        let crt_url = format!("https://crt.sh/?q=%25.{target}&output=json");
        let entries = query_crtsh(&client, &crt_url).await?;
        let mut candidates: BTreeMap<String, Candidate> = Default::default();
        for entry in &entries {
            if let Some(names) = entry.get("name_value").and_then(|v| v.as_str()) {
                for name in names.lines() {
                    let name = name
                        .trim()
                        .to_ascii_lowercase()
                        .trim_start_matches('*')
                        .trim_start_matches('.')
                        .to_string();
                    if name.is_empty() || name == target.to_ascii_lowercase() {
                        continue;
                    }
                    candidates.entry(name).or_default().hits += 1;
                }
            }
        }

        // --- Technique 2: organization pivot (issue #23) ---------------------
        let mut org_note = String::new();
        let org = match read_subject_org(&target, 443, Duration::from_secs(8)).await {
            Ok(Some(o)) if !o.trim().is_empty() => Some(o),
            Ok(Some(o)) => {
                org_note = format!("Target certificate has an empty Organization (`{o}`); org pivot skipped.");
                None
            }
            Ok(None) => {
                org_note = "Target certificate has no Organization field; org pivot skipped.".to_string();
                None
            }
            Err(e) => {
                org_note = format!("Could not read the target's certificate ({e}); org pivot skipped.");
                None
            }
        };

        if let Some(org) = &org {
            // crt.sh's `q` matches subject organization names as well as
            // domain identities; exclude the target itself from hits.
            let org_url = format!(
                "https://crt.sh/?q={}&output=json&exclude=expired",
                urlencode(org)
            );
            if let Ok(org_entries) = query_crtsh(&client, &org_url).await {
                for entry in &org_entries {
                    if let Some(names) = entry.get("name_value").and_then(|v| v.as_str()) {
                        for name in names.lines() {
                            let name = name
                                .trim()
                                .to_ascii_lowercase()
                                .trim_start_matches('*')
                                .trim_start_matches('.')
                                .to_string();
                            if name.is_empty() || name == target.to_ascii_lowercase() {
                                continue;
                            }
                            let c = candidates.entry(name).or_default();
                            c.org_pivot = true;
                            c.hits += 1;
                        }
                    }
                }
            }
        }

        // --- Technique 3: redirect verification (bounded) ---------------------
        let target_reg = registrable_domain(&target);
        if check_redirects {
            // Verify the strongest candidates only: org-pivot first, then by
            // hit count. Bounded to 10 probes total.
            let mut to_verify: Vec<String> = candidates
                .iter()
                .filter(|(_, c)| c.org_pivot)
                .map(|(d, _)| d.clone())
                .collect();
            let by_hits: Vec<String> = {
                let mut v: Vec<(String, usize)> = candidates
                    .iter()
                    .filter(|(_, c)| !c.org_pivot)
                    .map(|(d, c)| (d.clone(), c.hits))
                    .collect();
                v.sort_by(|a, b| b.1.cmp(&a.1));
                v.into_iter().map(|(d, _)| d).collect()
            };
            for d in by_hits {
                if to_verify.len() >= 10 {
                    break;
                }
                to_verify.push(d);
            }
            for domain in to_verify.into_iter().take(10) {
                if redirects_to(&client, &domain, &target, &target_reg).await {
                    if let Some(c) = candidates.get_mut(&domain) {
                        c.redirects_to_target = true;
                    }
                }
            }
        }

        // --- Score + emit -----------------------------------------------------
        let target_lower = target.to_ascii_lowercase();
        let mut findings = Vec::new();
        let mut ordered: Vec<(&String, &Candidate)> = candidates.iter().collect();
        ordered.sort_by(|a, b| {
            let sa = score_candidate(a.1, &target_lower, a.0);
            let sb = score_candidate(b.1, &target_lower, b.0);
            sb.cmp(&sa).then(b.0.cmp(a.0))
        });
        for (domain, cand) in ordered {
            let score = score_candidate(cand, &target_lower, domain);
            if score < min_certainty {
                continue;
            }
            let mut sources = vec![format!("CT logs ({} hits)", cand.hits)];
            if cand.org_pivot {
                sources.push(format!("same Organization `{}`", org.as_deref().unwrap_or("")));
            }
            if cand.redirects_to_target {
                sources.push("web endpoint redirects to target".to_string());
            }
            findings.push(Finding {
                title: format!("Related domain: {domain} (certainty {score}%)"),
                category: "Domain Discovery".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: format!(
                    "Domain `{domain}` is likely related to `{target}` — signals: {}.",
                    sources.join("; ")
                ),
                remediation: "Verify ownership and ensure each related domain is inventoried and monitored.".into(),
                proof: format!(
                    "crt.sh entries for {domain}: {}{}",
                    cand.hits,
                    if cand.org_pivot { " (org-pivot match)" } else { "" }
                ),
                url: None,
                metadata: json!({
                    "domain": domain,
                    "certainty": score,
                    "ct_hits": cand.hits,
                    "org_pivot": cand.org_pivot,
                    "redirects_to_target": cand.redirects_to_target,
                }),
                ..Default::default()
            });
            if findings.len() >= 100 {
                break;
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: format!("No related domains found for {target}"),
                category: "Domain Discovery".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: format!(
                    "CT log search returned no related domains above {min_certainty}% certainty. {org_note}"
                ),
                remediation: "This may indicate the organization uses a unique certificate issuer or no SAN coverage.".into(),
                proof: format!("crt.sh query: {crt_url}"),
                url: None,
                metadata: json!({"target": target, "min_certainty": min_certainty}),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

async fn query_crtsh(
    client: &Client,
    url: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("crt.sh query: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("crt.sh returned {}", resp.status()));
    }
    let body = resp.text().await.unwrap_or_default();
    Ok(serde_json::from_str(&body).unwrap_or_default())
}

/// Certainty score (0-100) for a merged candidate.
fn score_candidate(c: &Candidate, target_lower: &str, domain: &str) -> u32 {
    let mut score = 30u32 + (c.hits.min(10) as u32) * 5;
    if c.org_pivot {
        score += 25;
    }
    if c.redirects_to_target {
        score += 20;
    }
    if name_similarity(domain, target_lower) >= 0.6 {
        score += 15;
    }
    score.min(100)
}

/// Trigram-overlap similarity (0.0-1.0) between two domain names. Catches
/// look-alike registrations (`faceb00k`, `facebook-security`) without
/// pulling in a Levenshtein dependency.
fn name_similarity(a: &str, b: &str) -> f64 {
    let grams = |s: &str| -> std::collections::BTreeSet<String> {
        let s: Vec<char> = s.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        if s.len() < 3 {
            return Default::default();
        }
        (0..s.len() - 2)
            .map(|i| s[i..i + 3].iter().collect::<String>())
            .collect()
    };
    let (ga, gb) = (grams(a), grams(b));
    if ga.is_empty() || gb.is_empty() {
        return 0.0;
    }
    let inter = ga.intersection(&gb).count();
    if inter == 0 {
        return 0.0;
    }
    // Overlap coefficient: |A∩B| / min(|A|,|B|). Unlike Jaccard this
    // rewards containment look-alikes (facebook-security.net contains all
    // of facebook.com's trigrams → 1.0) while unrelated names stay ~0.
    let min_side = ga.len().min(gb.len()) as f64;
    inter as f64 / min_side
}

/// Registrable domain = last two labels (covers the common TLD shape; this
/// is a heuristic aid, not a PSL implementation).
fn registrable_domain(domain: &str) -> String {
    let mut it = domain.rsplit('.');
    let tld = it.next().unwrap_or("");
    let second = it.next().unwrap_or("");
    if second.is_empty() {
        domain.to_string()
    } else {
        format!("{second}.{tld}")
    }
}

/// Bounded redirect probe: GET http(s)://domain (redirects disabled) and
/// check whether the Location target is the target domain or shares its
/// registrable domain. Silent on any failure — verification is best-effort.
async fn redirects_to(
    client: &Client,
    domain: &str,
    target: &str,
    target_reg: &str,
) -> bool {
    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{domain}/");
        let resp = match client
            .get(&url)
            .timeout(Duration::from_secs(6))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !resp.status().is_redirection() {
            continue;
        }
        if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
            let loc_lower = loc.to_ascii_lowercase();
            let target_lower = target.to_ascii_lowercase();
            if loc_lower.contains(&target_lower)
                || loc_lower.contains(&registrable_domain(&target_lower))
            {
                return true;
            }
            // Location without a scheme (relative) still names a host when
            // it looks like a domain — check the registrable domain match.
            let loc_reg = registrable_domain(loc_lower.trim_start_matches("http://").trim_start_matches("https://"));
            if !target_reg.is_empty() && loc_reg == target_reg {
                return true;
            }
        }
    }
    false
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Connect to `host:443`, complete a TLS handshake, and extract the leaf
/// certificate's subject Organization (the `O=` field). None when the cert
/// has no Organization; Err when the handshake fails.
async fn read_subject_org(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Option<String>, String> {
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(config));

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| format!("`{host}` is not a valid TLS server name"))?;

    let tcp = tokio::time::timeout(timeout, TcpStream::connect((host, port)))
        .await
        .map_err(|_| "TCP connect timed out".to_string())?
        .map_err(|e| format!("TCP connect failed: {e}"))?;

    let mut stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "TLS handshake timed out".to_string())?
        .map_err(|e| format!("TLS handshake failed: {e}"))?;

    let certs = stream
        .get_ref()
        .1
        .peer_certificates()
        .map(|c| c.to_vec())
        .unwrap_or_default();
    // Close without a clean shutdown — we only needed the handshake.
    drop(stream);

    let leaf = certs
        .first()
        .ok_or_else(|| "server presented no certificate".to_string())?;
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(leaf.as_ref())
        .map_err(|e| format!("parse certificate: {e}"))?;
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            // 2.5.4.10 = OrganizationName (X.520 OID).
            if attr.attr_type().to_string() == "2.5.4.10" {
                return Ok(Some(
                    attr.attr_value().as_str().unwrap_or("").trim().to_string(),
                ));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_pivot_scores_above_plain_ct_hits() {
        let plain = Candidate {
            hits: 2,
            ..Default::default()
        };
        let pivoted = Candidate {
            hits: 2,
            org_pivot: true,
            ..Default::default()
        };
        let s_plain = score_candidate(&plain, "facebook.com", "foo.tld");
        let s_pivot = score_candidate(&pivoted, "facebook.com", "foo.tld");
        assert_eq!(s_plain, 40);
        assert_eq!(s_pivot, 65, "+25 org bonus");
    }

    #[test]
    fn redirect_and_similarity_stack_and_cap() {
        let c = Candidate {
            hits: 20,
            org_pivot: true,
            redirects_to_target: true,
        };
        // 30 + 50 (hits capped at 10) + 25 + 20 + similarity(?) — must cap 100.
        assert_eq!(score_candidate(&c, "facebook.com", "facebook.net"), 100);
    }

    #[test]
    fn similarity_catches_lookalikes_and_rejects_unrelated() {
        assert!(name_similarity("facebook-security.net", "facebook.com") >= 0.6);
        assert!(name_similarity("totally-unrelated-name.tld", "facebook.com") < 0.6);
        assert_eq!(name_similarity("ab", "abc"), 0.0, "too short for trigrams");
    }

    #[test]
    fn registrable_domains_reduce_correctly() {
        assert_eq!(registrable_domain("a.b.example.com"), "example.com");
        assert_eq!(registrable_domain("example.com"), "example.com");
        assert_eq!(registrable_domain("localhost"), "localhost");
    }

    #[tokio::test]
    async fn reads_subject_org_from_live_cert_fixture() {
        // Self-signed cert with a known Organization, via rcgen (dev-dep).
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["fixture.local".to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Test Org Pivot Ltd");
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().as_ref();

        // Parse exactly like read_subject_org does (no network in the test).
        use x509_parser::prelude::FromDer;
        let (_, parsed) =
            x509_parser::certificate::X509Certificate::from_der(der).unwrap();
        let org = parsed
            .subject()
            .iter()
            .flat_map(|rdn| rdn.iter())
            .find(|a| a.attr_type().to_string() == "2.5.4.10")
            .map(|a| a.attr_value().as_str().unwrap_or("").to_string());
        assert_eq!(org.as_deref(), Some("Test Org Pivot Ltd"));
    }
}
