//! Cloud Scanner — S3/GCS bucket misconfiguration auditor (native).

use super::{get_str, NativeCtx, NativeScanner};
use async_trait::async_trait;
use reqwest::Client;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

pub struct CloudScanner;

#[async_trait]
impl NativeScanner for CloudScanner {
    fn id(&self) -> &'static str {
        "cloud_scanner"
    }
    fn name(&self) -> &'static str {
        "Cloud Scanner"
    }
    fn description(&self) -> &'static str {
        "S3/GCS bucket permission + configuration auditing"
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        _ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let target = get_str(inputs, "target")?;
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e| format!("build client: {e}"))?;

        let (provider, bucket_name, base_url) = classify_target(target);
        if provider == "unknown" {
            return Err(format!(
                "Could not classify target as AWS S3 or GCS: {target}. Use a URL like https://bucket.s3.amazonaws.com or https://storage.googleapis.com/bucket"
            ));
        }

        let mut findings = Vec::new();

        // Test public listing.
        let list_url = match provider {
            "aws" => format!("https://{bucket_name}.s3.amazonaws.com/"),
            "gcs" => format!("https://storage.googleapis.com/{bucket_name}/?max-keys=1000"),
            _ => base_url.clone(),
        };
        if let Ok(resp) = client.get(&list_url).send().await {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status.is_success()
                && (body.contains("<ListBucketResult") || body.contains("<Contents>"))
            {
                let object_count = body.matches("<Contents>").count();
                findings.push(Finding {
                    title: "Public bucket listing enabled".into(),
                    category: "Cloud Misconfiguration".into(),
                    severity: Severity::High,
                    kind: FindingKind::ValidatedIssue,
                    description: format!("Bucket `{bucket_name}` ({provider}) allows anonymous listing — {object_count} objects visible."),
                    remediation: "Apply bucket policy denying s3:ListBucket / storage.objects.list to anonymous principals.".into(),
                    proof: format!("GET {list_url} returned {status} with {object_count} <Contents> entries"),
                    url: Some(list_url.clone()),
                    metadata: json!({"provider": provider, "bucket": bucket_name, "object_count": object_count}),
                    cwe: Some("CWE-284".into()),
                    confidence: Some("certain".into()),
                    ..Default::default()
                });
            }
        }

        // Test public write.
        let write_url = match provider {
            "aws" => format!(
                "https://{bucket_name}.s3.amazonaws.com/secuscan-probe-{}.txt",
                rand_hex()
            ),
            "gcs" => format!(
                "https://storage.googleapis.com/{bucket_name}/secuscan-probe-{}.txt",
                rand_hex()
            ),
            _ => base_url.clone(),
        };
        if let Ok(resp) = client
            .put(&write_url)
            .body("SecuScan probe — please delete")
            .send()
            .await
        {
            if resp.status().is_success() {
                findings.push(Finding {
                    title: "Public bucket write enabled".into(),
                    category: "Cloud Misconfiguration".into(),
                    severity: Severity::Critical,
                    kind: FindingKind::ValidatedIssue,
                    description: format!("Bucket `{bucket_name}` ({provider}) allows anonymous writes — anyone can upload arbitrary files."),
                    remediation: "Apply bucket policy denying s3:PutObject / storage.objects.create to anonymous principals immediately.".into(),
                    proof: format!("PUT {write_url} returned {}", resp.status()),
                    url: Some(write_url.clone()),
                    metadata: json!({"provider": provider, "bucket": bucket_name}),
                    cwe: Some("CWE-284".into()),
                    confidence: Some("certain".into()),
                    ..Default::default()
                });
                let _ = client.delete(&write_url).send().await;
            }
        }

        // Look for sensitive files.
        let sensitive_files = [
            "wp-config.php",
            "wp-config.bak",
            ".env",
            "credentials.json",
            "id_rsa",
            "secret.key",
            "backup.sql",
            "db_dump.sql",
            ".git/config",
            "config.php.bak",
        ];
        for fname in &sensitive_files {
            let probe_url = match provider {
                "aws" => format!("https://{bucket_name}.s3.amazonaws.com/{fname}"),
                "gcs" => format!("https://storage.googleapis.com/{bucket_name}/{fname}"),
                _ => continue,
            };
            if let Ok(resp) = client.get(&probe_url).send().await {
                if resp.status().is_success() {
                    findings.push(Finding {
                        title: format!("Sensitive file exposed: {fname}"),
                        category: "Sensitive File Exposure".into(),
                        severity: Severity::High,
                        kind: FindingKind::ValidatedIssue,
                        description: format!("Bucket `{bucket_name}` ({provider}) publicly exposes `{fname}`."),
                        remediation: format!("Remove `{fname}` from the bucket and audit access logs for prior downloads."),
                        proof: format!("GET {probe_url} returned {}", resp.status()),
                        url: Some(probe_url.clone()),
                        metadata: json!({"provider": provider, "bucket": bucket_name, "file": fname}),
                        cwe: Some("CWE-200".into()),
                        confidence: Some("certain".into()),
                        ..Default::default()
                    });
                }
            }
        }

        Ok(findings)
    }
}

fn classify_target(target: &str) -> (&'static str, String, String) {
    let (host, path) = if let Ok(u) = url::Url::parse(target) {
        (
            u.host_str().unwrap_or("").to_string(),
            u.path().trim_start_matches('/').to_string(),
        )
    } else {
        (target.to_string(), String::new())
    };
    if host.contains(".s3.amazonaws.com") || host.contains(".s3-") {
        let bucket = host.split(".s3").next().unwrap_or("").to_string();
        ("aws", bucket.clone(), format!("https://{host}"))
    } else if host == "s3.amazonaws.com" {
        let bucket = path.split('/').next().unwrap_or("").to_string();
        ("aws", bucket.clone(), format!("https://{host}/{bucket}"))
    } else if host.contains("storage.googleapis.com") {
        let bucket = if path.is_empty() {
            host.split('.').next().unwrap_or("").to_string()
        } else {
            path.split('/').next().unwrap_or("").to_string()
        };
        ("gcs", bucket.clone(), format!("https://{host}/{bucket}"))
    } else if host.contains(".storage.googleapis.com") {
        let bucket = host.split(".storage").next().unwrap_or("").to_string();
        ("gcs", bucket.clone(), format!("https://{host}"))
    } else {
        ("unknown", host, target.to_string())
    }
}

fn rand_hex() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_aws_bucket_subdomain() {
        let (p, b, _) = classify_target("https://mybucket.s3.amazonaws.com");
        assert_eq!(p, "aws");
        assert_eq!(b, "mybucket");
    }

    #[test]
    fn classify_gcs_path_style() {
        let (p, b, _) = classify_target("https://storage.googleapis.com/mybucket");
        assert_eq!(p, "gcs");
        assert_eq!(b, "mybucket");
    }
}
