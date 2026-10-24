//! Fixture tests: feed each power-engine plugin the output shape of its
//! real binary and assert the *shipped* manifest parser produces the
//! findings Sniper / the UI depend on. A regex tweak that silently
//! drops nuclei CVE lines fails here, not in a 20-minute live scan.

use secuscan_core::models::{FindingKind, Severity};
use secuscan_core::{parse_output, PluginManifest, PluginRegistry};
use std::path::PathBuf;

fn plugins_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins")
}

fn manifest(id: &str) -> PluginManifest {
    let reg = PluginRegistry::load_dir(&plugins_dir());
    assert!(
        reg.issues().is_empty(),
        "catalog load issues: {:?}",
        reg.issues()
    );
    reg.get(id)
        .unwrap_or_else(|| panic!("plugin `{id}` not in catalog"))
        .clone()
}

fn parse(id: &str, output: &str) -> Vec<secuscan_core::Finding> {
    let m = manifest(id);
    parse_output(&m.parser, &m.static_rules, output).expect("parser accepted fixture")
}

#[test]
fn nuclei_jsonl_maps_tags_cve_and_curl_proof() {
    let out = concat!(
        r#"{"info":{"name":"Git Config Exposure","severity":"medium","tags":["config","exposure","git"],"description":"git config leaked","classification":{"cve-id":null,"cvss-score":5.3,"cvss-vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}},"matched-at":"http://t/.git/config","curl-command":"curl -sk http://t/.git/config","template-id":"git-config","host":"t","type":"http"}"#,
        "\n",
        r#"{"info":{"name":"WP SQLi","severity":"high","tags":["wordpress","wp-plugin","sqli"],"description":"sql","classification":{"cve-id":["CVE-2024-1234"],"cvss-score":8.8,"cvss-vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}},"matched-at":"http://t/wp","curl-command":"curl -sk 'http://t/wp?id=1'","template-id":"wp-sqli","host":"t","type":"http"}"#,
        "\n",
        "this is not json and must be ignored\n"
    );
    let findings = parse("nuclei", out);
    assert_eq!(findings.len(), 2);

    assert_eq!(findings[0].title, "Git Config Exposure");
    assert_eq!(findings[0].severity, Severity::Medium);
    assert_eq!(findings[0].category, "Vulnerability");
    assert!(
        findings[0].proof.contains("curl"),
        "curl proof: {}",
        findings[0].proof
    );
    assert_eq!(findings[0].cve, None);

    assert_eq!(findings[1].title, "WP SQLi");
    assert_eq!(findings[1].severity, Severity::High);
    assert_eq!(findings[1].category, "WordPress");
    assert_eq!(findings[1].cve.as_deref(), Some("CVE-2024-1234"));
    assert_eq!(findings[1].cvss_v3, Some(8.8));
}

#[test]
fn dalfox_skips_meta_line_and_marks_validated_xss() {
    let out = concat!(
        r#"{"type":"finish","duration":12}"#,
        "\n",
        r#"{"message_str":"Triggered XSS Payload (DOM marker): q=<svg onload=alert(1)>","type_description":"Vulnerable (verified)","severity":"high","data":"http://t/?q=x","payload":"<svg onload=alert(1)>","evidence":"reflected in HTML","detection_method":"DOM","cwe":"CWE-79","param":"q","type":"V","inject_type":"inHTML","location":"Query","method":"GET","confidence":9}"#,
        "\n"
    );
    let findings = parse("xss-scanner", out);
    assert_eq!(
        findings.len(),
        1,
        "meta line without message_str must be dropped"
    );
    assert_eq!(findings[0].category, "XSS");
    assert_eq!(findings[0].kind, FindingKind::ValidatedIssue);
    assert_eq!(findings[0].severity, Severity::High);
    assert_eq!(findings[0].metadata["param"], "q");
    assert_eq!(findings[0].metadata["cwe"], "CWE-79");
    assert!(findings[0].proof.contains("svg"), "payload in proof");
}

#[test]
fn httpx_status_code_maps_severity_and_keeps_tech() {
    let out = concat!(
        r#"{"url":"https://t/","status_code":200,"title":"Example","scheme":"https","webserver":"nginx","tech":["nginx","React"],"host":"t","content_type":"text/html","method":"GET"}"#,
        "\n",
        r#"{"url":"https://t/admin","status_code":401,"title":"Login","scheme":"https","webserver":"nginx","host":"t"}"#,
        "\n"
    );
    let findings = parse("http-probe", out);
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].title, "Example");
    assert_eq!(findings[0].severity, Severity::Info);
    assert_eq!(findings[0].category, "Web Service");
    assert_eq!(findings[0].url.as_deref(), Some("https://t/"));
    assert_eq!(findings[1].severity, Severity::Low);
}

#[test]
fn katana_endpoint_and_401_elevate() {
    let out = concat!(
        r#"{"request":{"endpoint":"https://t/api/users","method":"GET"},"response":{"status_code":200},"source":"body"}"#,
        "\n",
        r#"{"request":{"endpoint":"https://t/admin","method":"GET"},"response":{"status_code":401},"source":"href"}"#,
        "\n"
    );
    let findings = parse("crawler", out);
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].title, "https://t/api/users");
    assert_eq!(findings[0].category, "Crawled Endpoint");
    assert_eq!(findings[0].severity, Severity::Info);
    assert_eq!(findings[1].severity, Severity::Low);
}

#[test]
fn naabu_port_22_is_low() {
    let out = concat!(
        r#"{"ip":"10.0.0.8","port":22,"host":"lab"}"#,
        "\n",
        r#"{"ip":"10.0.0.8","port":443,"host":"lab"}"#,
        "\n"
    );
    let findings = parse("fast-port-scan", out);
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].title, "22");
    assert_eq!(findings[0].severity, Severity::Low);
    assert_eq!(findings[0].category, "Network Service");
    assert_eq!(findings[1].title, "443");
    assert_eq!(findings[1].severity, Severity::Info);
}

#[test]
fn smuggler_captures_clte_class() {
    let out = concat!(
        "[*] starting\n",
        "[+] Found CL.TE smuggling on endpoint /admin with method POST\n",
        "[-] no luck on /\n"
    );
    let findings = parse("http-smuggling", out);
    assert!(
        findings.iter().any(|f| f.category == "Request Smuggling"
            && f.title.contains("CL.TE")
            && f.severity == Severity::High),
        "expected CL.TE finding, got {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[test]
fn commix_static_rules_split_hit_and_clean() {
    let hit = parse(
        "command-injection",
        "The injected parameter 'q' seems vulnerable to command injection.\n",
    );
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].category, "Command Injection");
    assert_eq!(hit[0].severity, Severity::Critical);

    let point = parse(
        "command-injection",
        "(*) Injection point detected: parameter id\n",
    );
    assert_eq!(point[0].severity, Severity::High);

    let clean = parse("command-injection", "The target is not vulnerable\n");
    assert_eq!(clean[0].severity, Severity::Info);
}

#[test]
fn gitleaks_aws_rule_is_critical() {
    let out = concat!(
        "/tmp/mirror/.env:3:aws-access-token: AKIAEXAMPLEKEYID0001\n",
        "/tmp/mirror/app.js:40:slack-token: xoxb-test-token\n",
        "leaks: 2\n"
    );
    let findings = parse("secrets-scanner", out);
    let aws = findings
        .iter()
        .find(|f| f.title.contains("aws-access-token"))
        .expect("aws finding");
    assert_eq!(aws.severity, Severity::Critical);
    assert_eq!(aws.category, "Secret Exposure");
    assert!(aws.proof.contains(".env"));

    let slack = findings
        .iter()
        .find(|f| f.title.contains("slack-token"))
        .expect("slack finding");
    assert_eq!(slack.severity, Severity::High);
}

#[test]
fn subzy_parses_vulnerable_cname() {
    let out = "VULNERABLE https://dev.example.com service=GitHub\n";
    let findings = parse("subdomain-takeover", out);
    assert!(
        findings.iter().any(|f| f.category == "Subdomain Takeover"
            && f.title.contains("dev.example.com")
            && f.title.contains("GitHub")
            && f.severity == Severity::High),
        "expected takeover finding, got {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}
