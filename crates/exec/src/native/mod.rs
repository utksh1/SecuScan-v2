//! Native (in-process Rust) scanners.
//!
//! Native plugins make SecuScan v2 useful with zero external tooling. They
//! implement the same contract as CLI wrappers — validated inputs in,
//! [`Finding`]s and live events out — with strict timeouts and cancellation.

pub mod api_scanner;
pub mod auth;
pub mod cloud_scanner;
pub mod cors_check;
pub mod dast_engine;
pub mod dns;
pub mod dns_lookup;
pub mod domain_finder;
pub mod drupal_scanner;
pub mod email_security;
pub mod google_dorks;
pub mod http_headers;
pub mod http_recon;
pub mod http_request_logger;
pub mod js_analyzer;
pub mod param_finder;
pub mod password_audit;
pub mod people_hunter;
pub mod net_guard;
pub mod port_scanner;
pub mod proto_auth;
pub mod reverse_dns;
pub mod subdomain_finder;
pub mod tls_check;
pub mod vhost_finder;
pub mod wordpress_audit;
pub mod website_scanner;
pub mod xss_exploiter;

pub use auth::{apply_auth, resolve_for_task, AuthMaterial};

use crate::events::EventSink;
use async_trait::async_trait;
use secuscan_core::models::Finding;
use sqlx::SqlitePool;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use tokio_util::sync::CancellationToken;

// --- v3.0.0 global DB pool for native scanners that need persistence ---
// Set by the API server at startup so OOB-handler-creating scanners can
// reach the database without changing the NativeScanner trait signature.
static DB_POOL: OnceLock<SqlitePool> = OnceLock::new();

pub fn set_db_pool(pool: SqlitePool) {
    let _ = DB_POOL.set(pool);
}

pub fn current_db_pool() -> Option<&'static SqlitePool> {
    DB_POOL.get()
}

/// Execution context handed to native scanners.
#[derive(Clone)]
pub struct NativeCtx {
    pub sink: EventSink,
    pub cancel: CancellationToken,
    pub timeout: std::time::Duration,
    /// Auth material for authenticated scanning (Max-Parity Sprint 1.1):
    /// resolved from the task's auth_profile_id by the manager before the
    /// task starts; None = unauthenticated scan.
    pub auth: Option<AuthMaterial>,
    /// Out-of-band callback context (Max-Parity Sprint 1.2): task identity,
    /// per-scan marker and the deployment's public URL. None = OOB disabled
    /// (`SECUSCAN_PUBLIC_URL` unset) — blind-vuln tooling fails loudly.
    pub oob: Option<OobCtx>,
}

/// Out-of-band callback context for a task (Max-Parity Sprint 1.2).
///
/// Built by the manager from the task row + `SECUSCAN_PUBLIC_URL`; threaded
/// through `NativeCtx` so scanners can embed marker-correlated callback URLs
/// in blind payloads. Hits that echo the marker are auto-correlated to this
/// task by the `/oob/:secret` receiver, which then opens a finding.
#[derive(Clone, Default, Debug)]
pub struct OobCtx {
    pub task_id: String,
    pub workspace_id: Option<String>,
    /// Per-scan marker (`ptt…`); embedded in callback URLs so hits correlate
    /// back to this task even through multiple hops.
    pub marker: Option<String>,
    /// Public base URL of this deployment (no trailing slash). None = OOB
    /// disabled and blind-vuln tooling must fail loudly rather than emit
    /// dead `secuscan.local` URLs.
    pub public_url: Option<String>,
}

impl OobCtx {
    /// Absolute, marker-correlated callback URL for a handler secret, or
    /// None when the deployment has no public URL configured.
    pub fn callback_url(&self, secret: &str) -> Option<String> {
        let base = self.public_url.as_ref()?.trim_end_matches('/');
        let mut url = format!("{base}/api/v1/oob/{secret}");
        if let Some(m) = &self.marker {
            url.push_str(&format!("?m={m}"));
        }
        Some(url)
    }
}

impl std::fmt::Debug for NativeCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeCtx")
            .field("timeout", &self.timeout)
            .field("oob_armed", &self.oob.is_some())
            .finish()
    }
}

/// A native scanner registered under a well-known id.
#[async_trait]
pub trait NativeScanner: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    /// Human description shown in the plugin catalog.
    fn description(&self) -> &'static str;
    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String>;
}

/// Static registry of native scanners.
pub struct NativeRegistry {
    scanners: Vec<&'static dyn NativeScanner>,
}

impl NativeRegistry {
    pub fn lookup(&self, id: &str) -> Option<&'static dyn NativeScanner> {
        self.scanners.iter().copied().find(|s| s.id() == id)
    }

    pub fn all(&self) -> &[&'static dyn NativeScanner] {
        &self.scanners
    }
}

pub fn registry() -> &'static NativeRegistry {
    static REGISTRY: OnceLock<NativeRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| NativeRegistry {
        scanners: vec![
            &port_scanner::PortScanner,
            &http_headers::HttpHeadersScanner,
            &http_recon::HttpReconScanner,
            &tls_check::TlsCheckScanner,
            &dns_lookup::DnsLookupScanner,
            &reverse_dns::ReverseDnsScanner,
            &subdomain_finder::SubdomainFinderScanner,
            &email_security::EmailSecurityScanner,
            &cors_check::CorsCheckScanner,
            &vhost_finder::VhostFinderScanner,
            &password_audit::PasswordAuditScanner,
            &google_dorks::GoogleDorksScanner,
            // v3.0.0 scanners
            &drupal_scanner::DrupalScanner,
            &cloud_scanner::CloudScanner,
            &domain_finder::DomainFinder,
            &http_request_logger::HttpRequestLogger,
            &xss_exploiter::XssExploiter,
            &people_hunter::PeopleHunter,
            &website_scanner::WebsiteScanner,
            &wordpress_audit::WordpressAudit,
            &api_scanner::ApiScanner,
            &param_finder::ParamFinder,
            &js_analyzer::JsAnalyzer,
        ],
    })
}

// ---------------------------------------------------------------------------
// Input helpers shared by native scanners
// ---------------------------------------------------------------------------

pub(crate) fn get_str<'a>(
    inputs: &'a BTreeMap<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str, String> {
    inputs
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing string field `{key}`"))
}

pub(crate) fn get_str_or<'a>(
    inputs: &'a BTreeMap<String, serde_json::Value>,
    key: &str,
    default: &'a str,
) -> &'a str {
    inputs.get(key).and_then(|v| v.as_str()).unwrap_or(default)
}

pub(crate) fn get_bool_or(
    inputs: &BTreeMap<String, serde_json::Value>,
    key: &str,
    default: bool,
) -> bool {
    inputs.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

pub(crate) fn get_i64_or(
    inputs: &BTreeMap<String, serde_json::Value>,
    key: &str,
    default: i64,
) -> i64 {
    inputs.get(key).and_then(|v| v.as_i64()).unwrap_or(default)
}

#[cfg(test)]
mod oob_ctx_tests {
    use super::OobCtx;

    fn ctx(public_url: Option<&str>, marker: Option<&str>) -> OobCtx {
        OobCtx {
            task_id: "task-1".into(),
            workspace_id: None,
            marker: marker.map(String::from),
            public_url: public_url.map(String::from),
        }
    }

    #[test]
    fn callback_url_embeds_base_secret_and_marker() {
        let c = ctx(Some("http://oob.example.com"), Some("pttabcdef123456"));
        assert_eq!(
            c.callback_url("deadbeef").as_deref(),
            Some("http://oob.example.com/api/v1/oob/deadbeef?m=pttabcdef123456")
        );
    }

    #[test]
    fn trailing_slash_is_trimmed() {
        let c = ctx(Some("http://oob.example.com/"), None);
        assert_eq!(
            c.callback_url("deadbeef").as_deref(),
            Some("http://oob.example.com/api/v1/oob/deadbeef")
        );
    }

    #[test]
    fn no_public_url_means_no_callback() {
        assert!(ctx(None, Some("pttabcdef123456")).callback_url("x").is_none());
    }
}
