//! HTTP client for the SecuScan REST API. Used by the MCP tools.

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde_json::Value;
use std::sync::RwLock;

pub struct SecuScanClient {
    base: String,
    api_key: Option<String>,
    /// Login credentials for token-based auth (alternative to api_key).
    /// Loaded lazily on first 401 response.
    creds: Option<(String, String)>,
    /// Cached JWT access token (with the expiry decoded from the JWT).
    token: RwLock<Option<String>>,
    http: Client,
}

impl SecuScanClient {
    pub fn new(base_url: impl Into<String>, api_key: Option<String>) -> Self {
        Self::with_creds(base_url, api_key, None, None)
    }

    /// Construct with email/password credentials used as a fallback when no
    /// API key is supplied. The MCP server logs in with these on first use.
    pub fn with_creds(
        base_url: impl Into<String>,
        api_key: Option<String>,
        email: Option<String>,
        password: Option<String>,
    ) -> Self {
        let creds = match (email, password) {
            (Some(e), Some(p)) => Some((e, p)),
            _ => None,
        };
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            api_key,
            creds,
            token: RwLock::new(None),
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(600))
                .build()
                .expect("reqwest client"),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn ensure_authed(&self) -> Result<()> {
        // If we already have a token, keep using it (no expiry check for now).
        if self.token.read().unwrap().is_some() {
            return Ok(());
        }
        if self.api_key.is_some() {
            return Ok(()); // API key auth — no token needed.
        }
        let (email, password) = match &self.creds {
            Some(c) => c.clone(),
            None => return Ok(()), // anonymous; let the server reject if it must.
        };
        let resp = self
            .http
            .post(self.url("/api/v1/auth/login"))
            .json(&serde_json::json!({"email": email, "password": password}))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("login failed: HTTP {}", resp.status()));
        }
        let body: Value = resp.json().await?;
        let token = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("login response missing access_token"))?
            .to_string();
        *self.token.write().unwrap() = Some(token);
        Ok(())
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        // Try up to 2 times: first with cached token, then refresh on 401.
        for attempt in 0..2 {
            self.ensure_authed().await?;
            let mut req = self.http.request(method.clone(), self.url(path));
            if let Some(k) = &self.api_key {
                // API keys are authenticated with X-API-Key, not JWT Bearer.
                req = req.header("x-api-key", k);
            } else if let Some(t) = self.token.read().unwrap().clone() {
                req = req.bearer_auth(t);
            }
            if let Some(b) = &body {
                req = req.json(b);
            }
            let resp = req.send().await?;
            let status = resp.status();
            if status.as_u16() == 401 && attempt == 0 {
                // Token expired — clear and retry.
                *self.token.write().unwrap() = None;
                continue;
            }
            let text = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!("HTTP {}: {}", status.as_u16(), text));
            }
            if text.is_empty() {
                return Ok(Value::Null);
            }
            return serde_json::from_str(&text)
                .map_err(|e| anyhow!("JSON parse: {e}; body: {text}"));
        }
        Err(anyhow!("request failed after retry"))
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        self.request(reqwest::Method::GET, path, None).await
    }
    pub async fn post(&self, path: &str, body: Value) -> Result<Value> {
        self.request(reqwest::Method::POST, path, Some(body)).await
    }
    pub async fn patch(&self, path: &str, body: Value) -> Result<Value> {
        self.request(reqwest::Method::PATCH, path, Some(body)).await
    }
    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.request(reqwest::Method::DELETE, path, None).await
    }

    /// Read a resource URI like `secuscan://plugins` and return its body as a
    /// JSON string.
    pub async fn get_resource(&self, uri: &str) -> Result<String> {
        let path = match uri {
            "secuscan://plugins" => "/api/v1/plugins",
            "secuscan://tasks" => "/api/v1/tasks?limit=50",
            "secuscan://findings" => "/api/v1/findings?limit=50",
            "secuscan://workspaces" => "/api/v1/workspaces",
            "secuscan://attack-surface" => "/api/v1/attack-surface?limit=100",
            other => return Err(anyhow!("unknown resource uri: {other}")),
        };
        let v = self.get(path).await?;
        Ok(serde_json::to_string_pretty(&v)?)
    }
}
