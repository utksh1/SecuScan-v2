//! Native HTTP reconnaissance scanner.
//!
//! Fields (see `plugins/http-recon.toml`):
//! - `target` (string, required) — full URL
//! - `timeout_ms` (integer, 500..=30000, default 10000)

use super::{get_i64_or, get_str, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

pub struct HttpReconScanner;

#[async_trait]
impl NativeScanner for HttpReconScanner {
    fn id(&self) -> &'static str {
        "http_recon"
    }

    fn name(&self) -> &'static str {
        "HTTP Reconnaissance"
    }

    fn description(&self) -> &'static str {
        "Fingerprint a web endpoint: page title, server/generator technology \
         hints, allowed HTTP methods, robots.txt and sitemap.xml presence."
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        _ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let base = super::http_headers::normalize_url(get_str(inputs, "target")?)?;
        let base = base
            .trim_end_matches('/')
            .to_string();
        let timeout =
            Duration::from_millis(get_i64_or(inputs, "timeout_ms", 10_000).clamp(500, 30_000) as u64);
        let client = super::http_headers::build_client(true, timeout)?;

        let mut findings = Vec::new();

        // --- main page ------------------------------------------------------
        let resp = client
            .get(&base)
            .header("user-agent", "SecuScan-2.0 (recon)")
            .send()
            .await
            .map_err(|e| format!("request to {base} failed: {e}"))?;
        let status = resp.status().as_u16();
        let _headers = resp.headers().clone();
        let body = resp
            .text()
            .await
            .map_err(|e| format!("failed reading body: {e}"))?;

        findings.push(observation(
            format!("HTTP {status} at {base}"),
            format!("The endpoint responded with status {status} to an unauthenticated GET."),
            format!("status code {status}"),
            json!({"status": status, "url": base}),
        ));

        if let Some(title) = extract_title(&body) {
            findings.push(observation(
                format!("Page title: {title}"),
                format!("HTML title of {base} is `{title}`."),
                format!("<title>{title}</title>"),
                json!({"title": title}),
            ));
        }

        if let Some(generator) = extract_generator(&body) {
            findings.push(observation(
                format!("Generator meta tag discloses technology: `{generator}`"),
                "The page publishes its generator/CMS in a meta tag.",
                format!("<meta name=\"generator\" content=\"{generator}\">"),
                json!({"generator": generator}),
            ));
        }

        // --- OPTIONS ---------------------------------------------------------
        if let Ok(resp) = client
            .request(reqwest::Method::OPTIONS, &base)
            .header("user-agent", "SecuScan-2.0 (recon)")
            .send()
            .await
        {
            if let Some(allow) = resp
                .headers()
                .get("allow")
                .and_then(|v| v.to_str().ok())
                .filter(|s| !s.trim().is_empty())
            {
                let dangerous = ["PUT", "DELETE", "TRACE", "CONNECT"];
                let has_dangerous = allow.to_ascii_uppercase().split(',').any(|m| {
                    dangerous.iter().any(|d| m.trim().eq_ignore_ascii_case(d))
                });
                findings.push(observation(
                    format!("Allowed HTTP methods: {allow}"),
                    "The server advertises these methods via an OPTIONS response.".to_string(),
                    format!("allow: {allow}"),
                    json!({"allow": allow, "risky_methods": has_dangerous}),
                ));
            }
        }

        // --- robots.txt / sitemap.xml ----------------------------------------
        for (path, name) in [("/robots.txt", "robots.txt"), ("/sitemap.xml", "sitemap.xml")] {
            if let Ok(resp) = client
                .get(format!("{base}{path}"))
                .header("user-agent", "SecuScan-2.0 (recon)")
                .send()
                .await
            {
                if resp.status().as_u16() == 200 {
                    findings.push(observation(
                        format!("{name} is publicly accessible"),
                        format!("A {name} exists at {base}{path}; review it for entries that \
                                 disclose sensitive or hidden paths."),
                        format!("GET {base}{path} → 200"),
                        json!({"path": path}),
                    ));
                }
            }
        }

        Ok(findings)
    }
}

fn observation(title: impl Into<String>, description: impl Into<String>, proof: String, metadata: serde_json::Value) -> Finding {
    let mut f = Finding::new(title, "Reconnaissance", Severity::Info, FindingKind::Observation);
    f.description = description.into();
    f.remediation =
        "Review the disclosed information and remove anything unnecessary for public \
         operation (hardening, not a vulnerability per se)."
            .to_string();
    f.proof = proof;
    f.metadata = metadata;
    f
}

fn extract_title(body: &str) -> Option<String> {
    let re = regex::Regex::new(r"(?is)<title[^>]*>(.*?)</title>").ok()?;
    re.captures(body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().chars().take(200).collect::<String>())
        .filter(|s| !s.is_empty())
}

fn extract_generator(body: &str) -> Option<String> {
    let re = regex::Regex::new(r#"(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']"#)
        .ok()?;
    re.captures(body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().chars().take(200).collect::<String>())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use axum::routing::get;
    use axum::Router;

    #[tokio::test]
    async fn recon_collects_observations() {
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    (
                        [("content-type", "text/html")],
                        "<html><head><title>My Test Site</title><meta name=\"generator\" content=\"WordPress 6.4\"></head><body>x</body></html>",
                    )
                }),
            )
            .route("/robots.txt", get(|| async { "User-agent: *\nDisallow: /admin\n" }))
            .route(
                "/sitemap.xml",
                get(|| async { ([( "content-type", "application/xml")], "<urlset/>") }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://{addr}");

        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let ctx = NativeCtx {
            sink: crate::events::EventSink::new(uuid::Uuid::new_v4(), tx),
            cancel: tokio_util::sync::CancellationToken::new(),
            timeout: std::time::Duration::from_secs(10),
        };
        let inputs: BTreeMap<String, serde_json::Value> =
            [("target".to_string(), serde_json::json!(base))].into_iter().collect();
        let findings = HttpReconScanner.run(&inputs, &ctx).await.unwrap();
        let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        assert!(titles.iter().any(|t| t.contains("My Test Site")), "{titles:?}");
        assert!(titles.iter().any(|t| t.contains("WordPress 6.4")));
        assert!(titles.iter().any(|t| t.contains("robots.txt")));
        assert!(titles.iter().any(|t| t.contains("sitemap.xml")));
        assert!(findings.iter().all(|f| f.severity == Severity::Info));
        let _ = HeaderMap::new();
    }

    #[test]
    fn title_extraction() {
        assert_eq!(
            extract_title("<html><head><TITLE>Hello \n World</TITLE></head>").as_deref(),
            Some("Hello \n World")
        );
        assert_eq!(extract_title("<html><title></title>").as_deref(), None);
        assert_eq!(extract_title("no title at all").as_deref(), None);
    }
}
